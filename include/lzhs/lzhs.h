#ifndef _LZHS_H
#define _LZHS_H

#include <stdint.h>

struct lzhs_header {
    uint32_t uncompressedSize, compressedSize;
    uint8_t checksum, spare[7];
};

/* for LZSS */
#define N             4096
#define F             34
#define THRESHOLD     2

#endif
