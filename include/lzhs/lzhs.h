/**
 * Copyright 2016 Smx <smxdev4@gmail.com>
 * Copyright 2016 lprot
 * All right reserved
 */
#ifndef _LZHS_H
#define _LZHS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "mfile.h"

struct lzhs_header {
	uint32_t uncompressedSize, compressedSize;
	uint16_t checksum; /* checksum is 1 byte, segment number is 2 bytes */
	uint8_t spare[6];
};

/* for LZSS */
#define N             4096
#define F             34
#define THRESHOLD     2

struct lzhs_ctx {
	/* LZSS  */
	unsigned long int textsize, codesize;
	uint8_t text_buf[N + F - 1];
	int32_t match_length, match_position, lson[N + 1], rson[N + 257], dad[N + 1];

	/* Huffman  */
	int32_t i, j, k;
	uint32_t c, code, len, code_buf_ptr;
	uint8_t code_buf[32], mask, bitno;
	uint32_t preno, precode;
};

/*for Huffman */
typedef struct __attribute__ ((__packed__)) {
	uint32_t code;
	uint32_t len;
} t_code;

struct lzhs_ctx *lzhs_ctx_new();
void lzhs_init_lookup();
void unlzss(struct lzhs_ctx *ctx, cursor_t *in, cursor_t *out);
void unhuff(struct lzhs_ctx *ctx, cursor_t *in, cursor_t *out);

MFILE *is_lzhs(const char *filename);
bool _is_lzhs_mem(struct lzhs_header *header);
bool is_lzhs_mem(MFILE *file, off_t offset);

void lzss(struct lzhs_ctx *ctx, FILE * infile, FILE * outfile, unsigned long int *p_textsize, unsigned long int *p_codesize);
void huff(struct lzhs_ctx *ctx, FILE * in, FILE * out, unsigned long int *p_textsize, unsigned long int *p_codesize);

int extract_lzhs(MFILE *in_file);
cursor_t *lzhs_decode(MFILE *in_file, off_t offset, const char *out_path, uint8_t *out_checksum);
void lzhs_encode(const char *infile, const char *outfile);
void scan_lzhs(const char *filename, int extract);

#endif
