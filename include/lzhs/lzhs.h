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

/*for Huffman */
typedef struct __attribute__ ((__packed__)) {
	uint32_t code;
	uint32_t len;
} t_code;

int is_lzhs_mem(struct lzhs_header *header);
void extract_lzhs(const char *filename);
void lzhs_decode(const char *infile, const char *outfile);
void lzhs_encode(const char *infile, const char *outfile);
void scan_lzhs(const char *filename, int extract);

#endif
