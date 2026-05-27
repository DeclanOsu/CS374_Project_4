// keygen.c -- generates a random key of the requested length.
// outputs keylength characters chosen from the 27 valid chars (A-Z and space),
// followed by a newline. use stdout redirection to save to a file.
//
// usage: keygen keylength

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "usage: keygen keylength\n");
        exit(1);
    }

    int length = atoi(argv[1]);
    if (length < 1) {
        fprintf(stderr, "keygen error: key length must be at least 1\n");
        exit(1);
    }

    //seed rng with current time
    srand(time(NULL));

    //pick length random chars from our 27-character alphabet (0-25 = A-Z, 26 = space)
    for (int i = 0; i < length; i++) {
        int r = rand() % 27;
        if (r == 26) {
            putchar(' ');
        } else {
            putchar('A' + r);
        }
    }

    putchar('\n'); //terminate with newline

    return 0;
}

