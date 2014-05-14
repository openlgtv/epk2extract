#ifndef FORMATS_H
#define	FORMATS_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <minigzip.h>

extern int endianswap;
#define SWAP(x) SwapBytes(&x, sizeof(x));

#define GZIP_CHUNK 0x4000
#define windowBits 15
#define ENABLE_ZLIB_GZIP 32

#define CALL_ZLIB(x) {                                                  \
        int status;                                                     \
        status = x;                                                     \
        if (status < 0) {                                               \
            fprintf (stderr,                                            \
                     "%s:%d: %s returned a bad status of %d.\n",        \
                     __FILE__, __LINE__, #x, status);                   \
            exit (EXIT_FAILURE);                                        \
        }                                                               \
    }


#endif	/* FORMATS_H */

