//dec_client.c -- connects to dec_server to decrypt a ciphertext file with a key.
//same as enc_client, but sends ciphertext and expects plaintext back.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#define BUFSIZE   256000 //big enough for the largest ciphertext files
#define CHUNKSIZE 1000   //at most this many bytes at a time

// loops over send() until every byte is written.
// needed becauseone send() might not send everything at once.
// returns 0 on success, -1 on error.
int send_all(int fd, char *buf, int len)
{
    int total = 0;
    int left  = len;
    int n;

    while (total < len) {
        int to_send = left < CHUNKSIZE ? left : CHUNKSIZE; // cap at chunk size
        n = send(fd, buf + total, to_send, 0);
        if (n == -1) return -1;
        total += n;
        left  -= n;
    }
    return 0;
}

// same as before, reads one byte at a time until we see '@'
// strips the '@' and null-terminates.
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

//opens a file and reads its contents into buf
//returns number of characters read, or -1 if the file can't be opened.
int read_file(const char *filename, char *buf, int maxlen)
{
    FILE *f = fopen(filename, "r");
    if (f == NULL) return -1;

    int len = 0;
    int c;
    while ((c = fgetc(f)) != EOF && len < maxlen - 1) {
        if (c == '\n') break; // strip the newline — we'll add one back on output
        buf[len++] = (char)c;
    }
    buf[len] = '\0';
    fclose(f);
    return len;
}

//returns 1 if the character is one of the 27 allowed chars (A-Z or space)
int is_valid_char(char c)
{
    return (c >= 'A' && c <= 'Z') || c == ' ';
}

int main(int argc, char *argv[])
{
    int sockfd, numbytes;
    char buf[BUFSIZE];
    struct addrinfo hints, *servinfo, *p;
    int rv;

    if (argc != 4) {
        fprintf(stderr, "usage: dec_client ciphertext key port\n");
        exit(1);
    }

    const char *ct_file  = argv[1];
    const char *key_file = argv[2];
    const char *port     = argv[3];

    //read and validate the ciphertext file
    char ciphertext[BUFSIZE];
    memset(ciphertext, 0, sizeof(ciphertext));
    int ct_len = read_file(ct_file, ciphertext, sizeof(ciphertext));
    if (ct_len < 0) {
        fprintf(stderr, "dec_client error: could not open '%s'\n", ct_file);
        exit(1);
    }

    //read and validate the key file
    char key[BUFSIZE];
    memset(key, 0, sizeof(key));
    int key_len = read_file(key_file, key, sizeof(key));
    if (key_len < 0) {
        fprintf(stderr, "dec_client error: could not open '%s'\n", key_file);
        exit(1);
    }

    //check for bad characters in ciphertext
    for (int i = 0; i < ct_len; i++) {
        if (!is_valid_char(ciphertext[i])) {
            fprintf(stderr, "dec_client error: input contains bad characters\n");
            exit(1);
        }
    }

    //check for bad characters in key
    for (int i = 0; i < key_len; i++) {
        if (!is_valid_char(key[i])) {
            fprintf(stderr, "dec_client error: key contains bad characters\n");
            exit(1);
        }
    }

    //key must be at least as long as the ciphertext
    if (key_len < ct_len) {
        fprintf(stderr, "Error: key '%s' is too short\n", key_file);
        exit(1);
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // use IPv4, same as the servers — AF_UNSPEC would try IPv6 first and spam stderr
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo("localhost", port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 2;
    }

    // loop through all the results and connect to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("client: socket");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            perror("client: connect");
            close(sockfd);
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "Error: could not contact dec_server on port %s\n", port);
        return 2;
    }

    freeaddrinfo(servinfo); // all done with this structure

    // send our identity so the server can verify we're dec_client
    if (send_all(sockfd, "dec_client@", 11) < 0) {
        fprintf(stderr, "dec_client: error sending identity\n");
        exit(2);
    }

    // read server's response. "ok" means we're talking to dec_server
    char id_response[32];
    memset(id_response, 0, sizeof(id_response));
    if (recv_all(sockfd, id_response, sizeof(id_response)) < 0) {
        fprintf(stderr, "dec_client: error reading server response\n");
        exit(2);
    }

    // if the server rejected us, we probably connected to enc_server
    if (strcmp(id_response, "ok") != 0) {
        fprintf(stderr, "Error: could not contact dec_server on port %s\n", port);
        close(sockfd);
        exit(2);
    }

    //send ciphertext terminated with '@'
    char *ct_send = malloc(ct_len + 2);
    memcpy(ct_send, ciphertext, ct_len);
    ct_send[ct_len]     = '@';
    ct_send[ct_len + 1] = '\0';
    if (send_all(sockfd, ct_send, ct_len + 1) < 0) {
        fprintf(stderr, "dec_client: error sending ciphertext\n");
        free(ct_send);
        exit(2);
    }
    free(ct_send);

    //send key (only as many chars as we need) terminated with '@'
    char *key_send = malloc(ct_len + 2);
    memcpy(key_send, key, ct_len);
    key_send[ct_len]     = '@';
    key_send[ct_len + 1] = '\0';
    if (send_all(sockfd, key_send, ct_len + 1) < 0) {
        fprintf(stderr, "dec_client: error sending key\n");
        free(key_send);
        exit(2);
    }
    free(key_send);

    //receive the plaintext back from dec_server
    memset(buf, 0, sizeof(buf));
    numbytes = recv_all(sockfd, buf, sizeof(buf));
    if (numbytes < 0) {
        fprintf(stderr, "dec_client: error receiving plaintext\n");
        close(sockfd);
        exit(2);
    }

    //use fwrite so we output exactly numbytes, then add the newline separately
    fwrite(buf, 1, numbytes, stdout);
    putchar('\n');

    close(sockfd);

    return 0;
}
