/**
 * LZHS Encoder
 * Copyright 2016 Smx <smxdev4@gmail.com>
 * Copyright 2016 lprot
 * All right reserved
 */
/**************************************************************
        LZSS.C -- A Data Compression Program
        (tab = 4 spaces)
***************************************************************
        4/6/1989 Haruhiko Okumura
        Use, distribute, and modify this program freely.
        Please send me your improved versions.
                PC-VAN          SCIENCE
                NIFTY-Serve     PAF01022
                CompuServe      74050,1022
**************************************************************/
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "common.h"
#include "util.h"
#include "lzhs/lzhs.h"
#include "lzhs/tables.h"

/*** Huffman decoding tables ***/
static t_code(*huff_charlen)[1] = (void *)&charlen_table;	// Raw LZSS Characters + Length of LZSS match
static t_code(*huff_pos)[1] = (void *)&pos_table;		// Position of LZSS match

/*** Huffman lookup tables ***/
// indices 0-287 for charlen, 0-31 for charpos
// signed -1 is used as the invalid/unpopulated index
static int16_t lookup_charlen[131072];	//2^(13 + 4 bits for key_charlen)
static int16_t lookup_charpos[512];		//2^( 6 + 3 bits for key_charpos)

/*
 * Pack together length and code to create a key for the lookup table
 * [length][code]
 */
static inline uint32_t key_charlen(uint32_t code, uint32_t len){
	return ((len & 0xF) << 13) | (code & 0x1FFF);
}
static inline uint16_t key_charpos(uint32_t code, uint32_t len){
	return ((len & 0x7) << 6) | (code & 0x3F);
}


void lzhs_init_lookup(){
	memset(&lookup_charlen, 0xFF, sizeof(lookup_charlen));
	memset(&lookup_charpos, 0xFF, sizeof(lookup_charpos));
}

struct lzhs_ctx *lzhs_ctx_new(){
	struct lzhs_ctx *ctx = calloc(1, sizeof(struct lzhs_ctx));
	ctx->bitno = 8;
	return ctx;
}

///////////// LZSS ALGO /////////////
static void InitTree(struct lzhs_ctx *ctx) {
	int i;
	for (i = N + 1; i <= N + 256; i++)
		ctx->rson[i] = N;
	for (i = 0; i < N; i++)
		ctx->dad[i] = N;
}

static void lazy_match(struct lzhs_ctx *ctx, int r) {
	unsigned char *key;
	int i, p, cmp = 1, tmp = 0;

	if (ctx->match_length <= F - THRESHOLD) {
		key = &ctx->text_buf[r + 1];
		p = key[0] + N + 1;
		while (1) {
			if (cmp >= 0) {
				if (ctx->rson[p] != N)
					p = ctx->rson[p];
				else
					break;
			} else {
				if (ctx->lson[p] != N)
					p = ctx->lson[p];
				else
					break;
			}
			for (i = 1; i <= F - 1; i++) {
				cmp = key[i] - ctx->text_buf[p + i];
				if (key[i] != ctx->text_buf[p + i])
					break;
			}
			if (i > tmp)
				if ((tmp = i) > F - 1)
					break;
		}
	}
	if (tmp > ctx->match_length)
		ctx->match_length = 0;
}

static void InsertNode(struct lzhs_ctx *ctx, int r) {
	unsigned char *key = &ctx->text_buf[r];
	int tmp, p, i, cmp = 1;

	p = ctx->text_buf[r] + N + 1;
	ctx->lson[r] = ctx->rson[r] = N;

	ctx->match_length = 0;
	while (1) {
		if (cmp < 0) {
			if (ctx->lson[p] == N) {
				ctx->lson[p] = r;
				ctx->dad[r] = p;
				return lazy_match(ctx, r);
			}
			p = ctx->lson[p];
		} else {
			if (ctx->rson[p] == N) {
				ctx->rson[p] = r;
				ctx->dad[r] = p;
				return lazy_match(ctx, r);
			}
			p = ctx->rson[p];
		}
		for (i = 1;; ++i) {
			if (i < F) {
				cmp = key[i] - ctx->text_buf[p + i];
				if (key[i] == ctx->text_buf[p + i])
					continue;
			}
			break;
		}
		if (i >= ctx->match_length) {
			if (r < p)
				tmp = r - p + N;
			else
				tmp = r - p;
		}
		if (i >= ctx->match_length) {
			if (i == ctx->match_length) {
				if (tmp < ctx->match_position)
					ctx->match_position = tmp;
			} else
				ctx->match_position = tmp;
			if ((ctx->match_length = i) > F - 1)
				break;
		}
	}
	ctx->dad[r] = ctx->dad[p];
	ctx->lson[r] = ctx->lson[p];
	ctx->rson[r] = ctx->rson[p];
	ctx->dad[ctx->lson[p]] = ctx->dad[ctx->rson[p]] = r;
	if (ctx->rson[ctx->dad[p]] == p)
		ctx->rson[ctx->dad[p]] = r;
	else
		ctx->lson[ctx->dad[p]] = r;
	ctx->dad[p] = N;
}

static void DeleteNode(struct lzhs_ctx *ctx, int p) {
	int q;
	if (ctx->dad[p] == N)
		return;
	if (ctx->rson[p] == N)
		q = ctx->lson[p];
	else if (ctx->lson[p] == N)
		q = ctx->rson[p];
	else {
		q = ctx->lson[p];
		if (ctx->rson[q] != N) {
			do {
				q = ctx->rson[q];
			} while (ctx->rson[q] != N);
			ctx->rson[ctx->dad[q]] = ctx->lson[q];
			ctx->dad[ctx->lson[q]] = ctx->dad[q];
			ctx->lson[q] = ctx->lson[p];
			ctx->dad[ctx->lson[p]] = q;
		}
		ctx->rson[q] = ctx->rson[p];
		ctx->dad[ctx->rson[p]] = q;
	}
	ctx->dad[q] = ctx->dad[p];
	if (ctx->rson[ctx->dad[p]] == p)
		ctx->rson[ctx->dad[p]] = q;
	else
		ctx->lson[ctx->dad[p]] = q;
	ctx->dad[p] = N;
}

///////////// HUFFMAN ALGO /////////////
static void InitHuffman(struct lzhs_ctx *ctx) {
	ctx->code = ctx->len = 0;
	ctx->preno = ctx->precode = 0;
	// Clear the huffman code buffer
	memset(&ctx->code_buf, 0x00, sizeof(ctx->code_buf));
	// Initial bit no (to fetch next byte at first iteration)
	ctx->bitno = 8;
}

static void putChar(struct lzhs_ctx *ctx, uint32_t code, uint32_t no, FILE *out) {
	uint32_t tmpno, tmpcode;
	if (ctx->preno + no > 7) {
		do {
			no -= tmpno = 8 - ctx->preno;
			tmpcode = ctx->code >> no;
			fputc(tmpcode | (ctx->precode << tmpno), out);
			ctx->code -= tmpcode << no;
			ctx->preno = ctx->precode = 0;
		} while (no > 7);
		ctx->preno = no;
		ctx->precode = code;
	} else {
		ctx->preno += no;
		ctx->precode = code | (ctx->precode << no);
	}
}

static inline int getData(struct lzhs_ctx *ctx, cursor_t *in) {
	if (ctx->bitno > 7) {
		ctx->bitno = 0;
		if((ctx->c = cgetc(in)) == EOF){
			return 0;
		}
	}
	ctx->code = (ctx->code << 1) | ((ctx->c >> (7 - ctx->bitno++)) & 1);	// get bit msb - index
	ctx->len++;
	return 1;
}

///////////// EXPORTS /////////////

/*
 * Huffman encodes the specified stream
 */
void huff(struct lzhs_ctx *ctx, FILE * in, FILE * out, unsigned long int *p_textsize, unsigned long int *p_codesize) {
	ctx->textsize = ctx->codesize;
	ctx->codesize = 0;
	int c, i, j, m, flags = 0;
	while (1) {
		if (((flags >>= 1) & 256) == 0) {
			if ((c = getc(in)) == EOF)
				break;
			flags = c | 0xFF00;
		}
		if (flags & 1) {
			if ((c = getc(in)) == EOF)
				break;
			putChar(ctx, huff_charlen[c]->code, huff_charlen[c]->len, out);	// lookup in char table
		} else {
			if ((j = getc(in)) == EOF)
				break;			// match length
			if ((i = getc(in)) == EOF)
				break;			// byte1 of match position
			if ((m = getc(in)) == EOF)
				break;			// byte0 of match position
			putChar(ctx, huff_charlen[256 + j]->code, huff_charlen[256 + j]->len, out);	// lookup in len table
			i = m | (i << 8);
			putChar(ctx, huff_pos[(i >> 7)]->code, huff_pos[(i >> 7)]->len, out);	// lookup in pos table
			putChar(ctx, i - (i >> 7 << 7), 7, out);
		}
	}
	putc(ctx->precode << (8 - ctx->preno), out);
	ctx->codesize = ftell(out) - sizeof(struct lzhs_header);
	if(p_textsize)
		*p_textsize = ctx->textsize;
	if(p_codesize)
		*p_codesize = ctx->codesize;
	printf("LZHS Out(%ld)/In(%ld): %.4f\n", ctx->codesize, ctx->textsize, (double)ctx->codesize / ctx->textsize);
}

/*
 * Huffman decodes the specified stream
 */
void unhuff(struct lzhs_ctx *ctx, cursor_t *in, cursor_t *out) {
	InitHuffman(ctx);
	ctx->code_buf[0] = 0;
	ctx->code_buf_ptr = ctx->mask = 1;

	uint found, found_pos = 0;
	while (1) {
		if (UNLIKELY(!getData(ctx, in)))
			goto flush_ret;
		if (ctx->len < 4)
			continue; // len in code_len table should be min 4
		uint32_t key = key_charlen(ctx->code, ctx->len);
		ctx->i = lookup_charlen[key];
		found = (ctx->i > -1);
		if(!found){
			for (ctx->i = 0; ctx->i < 288; ctx->i++) {
				if (huff_charlen[ctx->i]->len == ctx->len &&
					huff_charlen[ctx->i]->code == ctx->code
				){
					lookup_charlen[key] = ctx->i;
					found = 1;
					break;
				}
			}
		}

		if(!found)
			continue;

		if(ctx->i > 255){
			ctx->code_buf[ctx->code_buf_ptr++] = ctx->i - 256;
			ctx->code = ctx->len = 0;
			while (1) {
				if (UNLIKELY(!getData(ctx, in)))
					goto flush_ret;
				if (ctx->len < 2)
					continue;	// len in pos table should be min 2
				uint32_t key = key_charpos(ctx->code, ctx->len);
				ctx->j = lookup_charpos[key];
				found_pos = (ctx->j > -1); 
				if(!found_pos){
					for (ctx->j = 0; ctx->j < 32; ctx->j++) {
						if (huff_pos[ctx->j]->len == ctx->len &&
							huff_pos[ctx->j]->code == ctx->code
						){
							lookup_charpos[key] = ctx->j;
							found_pos = 1;
							break;
						}
					}
				}
				if(found_pos){
					ctx->code_buf[ctx->code_buf_ptr++] = ctx->j >> 1;
					ctx->k = -1;
					break;
				}
			}
			ctx->code = 0;
			for (ctx->k = 0; ctx->k < 7; ctx->k++)
				if (UNLIKELY(!getData(ctx, in)))
					goto flush_ret;
			ctx->code_buf[ctx->code_buf_ptr++] = ctx->code | (ctx->j << 7);
			ctx->code = ctx->len = 0;
		} else {
			ctx->code_buf[0] |= ctx->mask;
			ctx->code_buf[ctx->code_buf_ptr++] = ctx->i;
			ctx->code = ctx->len = 0;
		}
		if ((ctx->mask <<= 1) == 0) {
			for (ctx->j = 0; ctx->j < ctx->code_buf_ptr; ctx->j++){
				if(UNLIKELY(cputc(ctx->code_buf[ctx->j], out) == EOF))
					return;
			}
			ctx->code_buf[0] = 0;
			ctx->code_buf_ptr = ctx->mask = 1;
		}
	}
	
	flush_ret:
	if (ctx->code_buf_ptr > 1)	// flushing buffer
		for (ctx->i = 0; ctx->i < ctx->code_buf_ptr; ctx->i++){
			if(UNLIKELY(cputc(ctx->code_buf[ctx->i], out) == EOF))
				return;
		}
	return;
}

/*
 * LZSS encodes the specified stream
 */
void lzss(struct lzhs_ctx *ctx, FILE * infile, FILE * outfile, unsigned long int *p_textsize, unsigned long int *p_codesize) {
	int c, i, len, r, s, last_match_length, code_buf_ptr;
	unsigned char code_buf[32], mask;

	InitTree(ctx);
	code_buf[0] = 0;
	code_buf_ptr = mask = 1;
	s = ctx->codesize = 0;
	r = N - F;

	for (len = 0; len < F && (c = getc(infile)) != EOF; len++)
		ctx->text_buf[r + len] = c;
	if ((ctx->textsize = len) == 0)
		return;

	InsertNode(ctx, r);
	do {
		if (ctx->match_length > len)
			ctx->match_length = len;
		if (ctx->match_length <= THRESHOLD) {
			ctx->match_length = 1;
			code_buf[0] |= mask;
			code_buf[code_buf_ptr++] = ctx->text_buf[r];
		} else {
			code_buf[code_buf_ptr++] = ctx->match_length - THRESHOLD - 1;
			code_buf[code_buf_ptr++] = (ctx->match_position >> 8) & 0xff;
			code_buf[code_buf_ptr++] = ctx->match_position;
		}
		if ((mask <<= 1) == 0) {
			for (i = 0; i < code_buf_ptr; i++) {
				putc(code_buf[i], outfile);
				ctx->codesize++;
			}
			code_buf[0] = 0;
			code_buf_ptr = mask = 1;
		}
		last_match_length = ctx->match_length;
		for (i = 0; i < last_match_length && (c = getc(infile)) != EOF; i++) {
			DeleteNode(ctx, s);
			ctx->text_buf[s] = c;
			if (s < F - 1)
				ctx->text_buf[s + N] = c;
			s = (s + 1) & (N - 1);
			r = (r + 1) & (N - 1);
			InsertNode(ctx, r);
		}
		ctx->textsize += i;
		while (i++ < last_match_length) {
			DeleteNode(ctx, s);
			s = (s + 1) & (N - 1);
			r = (r + 1) & (N - 1);
			if (--len)
				InsertNode(ctx, r);
		}
	} while (len > 0);
	if (code_buf_ptr > 1) {
		for (i = 0; i < code_buf_ptr; i++) {
			putc(code_buf[i], outfile);
			ctx->codesize++;
		}
	}
	if(p_textsize)
		*p_textsize = ctx->textsize;
	if(p_codesize)
		*p_codesize = ctx->codesize;
	printf("LZSS Out(%ld)/In(%ld): %.3f\n", ctx->codesize, ctx->textsize, (double)ctx->codesize / ctx->textsize);
}

/*
 * LZSS decodes the specified stream
 */
void unlzss(struct lzhs_ctx *ctx, cursor_t *in, cursor_t *out) {
	int c, i, j, k, m, r = 0, flags = 0;
	while (1) {
		if (((flags >>= 1) & 256) == 0) {
			if ((c = cgetc(in)) == EOF)
				break;
			flags = c | 0xff00;
		}
		if (flags & 1) {
			if((c = cgetc(in)) == EOF)
				break;
			
			if(cputc((ctx->text_buf[r++] = c), out) == EOF)
				return;
			r &= (N - 1);
		} else {
			if((j = cgetc(in)) == EOF) // match length
				break;
			if((i = cgetc(in)) == EOF) // byte1 of match position
				break;
			if((m = cgetc(in)) == EOF) // byte0 of match position
				break;

			i = (i << 8) | m;
			for (k = 0; k <= j + THRESHOLD; k++) {
				m = ctx->text_buf[(r - i) & (N - 1)];				
				if(cputc((ctx->text_buf[r++] = m), out) == EOF)
					return;
				r &= (N - 1);
			}
		}
	}
}