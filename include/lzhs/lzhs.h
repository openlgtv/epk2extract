#ifndef _LZHS_H
#define _LZHS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "mfile.h"

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

void unlzss(cursor_t *in, cursor_t *out);
void unhuff(cursor_t *in, cursor_t *out);

MFILE *is_lzhs(const char *filename);
bool _is_lzhs_mem(struct lzhs_header *header);
bool is_lzhs_mem(MFILE *file, off_t offset);

void lzss(FILE * infile, FILE * outfile, unsigned long int *p_textsize, unsigned long int *p_codesize);
void huff(FILE * in, FILE * out, unsigned long int *p_textsize, unsigned long int *p_codesize);

int extract_lzhs(MFILE *in_file);
int lzhs_decode(MFILE *in_file, const char *out_path);
void lzhs_encode(const char *infile, const char *outfile);
void scan_lzhs(const char *filename, int extract);

#endif
