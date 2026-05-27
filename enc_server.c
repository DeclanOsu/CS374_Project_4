// enc_server.c -- the encryption server, runs in the background as a daemon.
// listens on a port passed as argv[1], forks a child per connection to handle
// encryption. the child checks the client is enc_client, then does the
// otp encryption and sends the encrypted text back.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>

#define BACKLOG 10    // how many pending connections queue will hold
#define BUFSIZE 256000 // big enough for the largest plaintext files
#define CHUNKSIZE 1000 // at most this many bytes at a time

//most of this is copied verbatinm from server.c

void sigchld_handler(int s)
{
    (void)s; // quiet unused variable warning

    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;

    while(waitpid(-1, NULL, WNOHANG) > 0);

    errno = saved_errno;
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

// send_all loops over send() until every byte is written.
// needed because a single send() call might not send everything at once.
// returns 0 on success, -1 on error.
int send_all(int fd, char *buf, int len)
{
    int total = 0;
    int left  = len;
    int n;

    while (total < len) {
        int to_send = left < CHUNKSIZE ? left : CHUNKSIZE; //cap at chunk size
        n = send(fd, buf + total, to_send, 0);
        if (n == -1) return -1;
        total += n;
        left  -= n;
    }
    return 0;
}

//recv_all reads one byte at a time until we see '@' which is the end of the message
//we use '@' because it's not one of the 27 valid characters, so it won't appear in data.
//strips the '@' and null-terminates. returns byte count or -1 on error
int recv_all(int fd, char *buf, int maxlen)
{
    int total = 0;
    int n;

    while (total < maxlen - 1) {
        n = recv(fd, buf + total, 1, 0);
        if (n <= 0) return -1;
        if (buf[total] == '@') {
            buf[total] = '\0'; // strip the terminator
            return total;
        }
        total += n;
    }
    buf[total] = '\0';
    return total;
}

//maps a valid character to its 0-26 value
// A=0, B=1, ..., Z=25, space=26
int convert_char(char c)
{
    if (c == ' ') return 26;
    return c - 'A';
}

// handle_client runs in the child process after a connection is accepted.
// it verifies the client is enc_client, receives plaintext + key,
// encrypts using otp mod 27, then sends back ciphertext.
void handle_client(int new_fd)
{
    char id_buf[32];
    char plaintext[BUFSIZE];
    char key[BUFSIZE];
    char ciphertext[BUFSIZE];
    int pt_len, i;

    //read client identity. we expect "enc_client"
    memset(id_buf, 0, sizeof(id_buf));
    if (recv_all(new_fd, id_buf, sizeof(id_buf)) < 0) {
        fprintf(stderr, "enc_server: error reading client id\n");
        exit(1);
    }

    //reject anyone who isn't enc_client
    if (strcmp(id_buf, "enc_client") != 0) {
        send_all(new_fd, "reject@", 7);
        fprintf(stderr, "enc_server: rejected non-enc_client connection\n");
        close(new_fd);
        exit(1);
    }

    // tell the client we're good
    send_all(new_fd, "ok@", 3);

    // receive the plaintext
    memset(plaintext, 0, sizeof(plaintext));
    pt_len = recv_all(new_fd, plaintext, sizeof(plaintext));
    if (pt_len < 0) {
        fprintf(stderr, "enc_server: error reading plaintext\n");
        exit(1);
    }

    // receive the key
    memset(key, 0, sizeof(key));
    if (recv_all(new_fd, key, sizeof(key)) < 0) {
        fprintf(stderr, "enc_server: error reading key\n");
        exit(1);
    }

    //for each char, add plaintext value + key value, then mod 27
    for (i = 0; i < pt_len; i++) {
        int p = convert_char(plaintext[i]);
        int k = convert_char(key[i]);
        int c = (p + k) % 27;
        ciphertext[i] = (c == 26) ? ' ' : 'A' + c;
    }
    ciphertext[pt_len] = '\0';

    // send ciphertext back with our '@' terminator
    char *send_buf = malloc(pt_len + 2);
    memcpy(send_buf, ciphertext, pt_len);
    send_buf[pt_len]     = '@';
    send_buf[pt_len + 1] = '\0';
    if (send_all(new_fd, send_buf, pt_len + 1) < 0) {
        fprintf(stderr, "enc_server: error sending ciphertext\n");
    }
    free(send_buf);

    close(new_fd);
    exit(0);
}

int main(int argc, char *argv[])
{
    // listen on sock_fd, new connection on new_fd
    int sockfd, new_fd;
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr; // connector's address info
    socklen_t sin_size;
    struct sigaction sa;
    int yes=1;
    char s[INET6_ADDRSTRLEN];
    int rv;

    if (argc != 2) {
        fprintf(stderr, "usage: enc_server port\n");
        exit(1);
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, argv[1], &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and bind to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo); // all done with this structure

    if (p == NULL)  {
        fprintf(stderr, "server: failed to bind\n");
        exit(1);
    }

    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    printf("server: waiting for connections...\n");

    while(1) {  // main accept() loop
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr,
            &sin_size);
        if (new_fd == -1) {
            perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family,
            get_in_addr((struct sockaddr *)&their_addr),
            s, sizeof s);
        printf("server: got connection from %s\n", s);

        if (!fork()) { // this is the child process
            close(sockfd); // child doesn't need the listener
            handle_client(new_fd); //do the encryption and send back result
            exit(0);
        }
        close(new_fd);  //parent doesn't need this
    }

    return 0;
}

