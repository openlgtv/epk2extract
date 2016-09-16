#include <string.h>
#include "lzhs/lzhs.h"
#include "lzhs/tables.h"

/* LZSS globals */
static unsigned long int textsize = 0, codesize = 0;
static uint8_t text_buf[N + F - 1];
static int32_t match_length, match_position, lson[N + 1], rson[N + 257], dad[N + 1];
/* Huffman decoding tables */
static t_code(*huff_char)[1] = (void *)&char_table;
static t_code(*huff_len)[1] = (void *)&len_table;
static t_code(*huff_pos)[1] = (void *)&pos_table;
/* Huffman globals */
static uint32_t i, j, k, c, code = 0, len = 0, code_buf_ptr;
static uint8_t code_buf[32], mask, bitno = 8;
static uint32_t preno = 0, precode = 0;

///////////// LZSS ALGO /////////////
static void InitTree(void) {
	int i;
	for (i = N + 1; i <= N + 256; i++)
		rson[i] = N;
	for (i = 0; i < N; i++)
		dad[i] = N;
}

static void lazy_match(int r) {
	unsigned char *key;
	int i, p, cmp = 1, tmp = 0;

	if (match_length <= F - THRESHOLD) {
		key = &text_buf[r + 1];
		p = key[0] + N + 1;
		while (1) {
			if (cmp >= 0) {
				if (rson[p] != N)
					p = rson[p];
				else
					break;
			} else {
				if (lson[p] != N)
					p = lson[p];
				else
					break;
			}
			for (i = 1; i <= F - 1; i++) {
				cmp = key[i] - text_buf[p + i];
				if (key[i] != text_buf[p + i])
					break;
			}
			if (i > tmp)
				if ((tmp = i) > F - 1)
					break;
		}
	}
	if (tmp > match_length)
		match_length = 0;
}

static void InsertNode(int r) {
	unsigned char *key = &text_buf[r];
	int tmp, p, i, cmp = 1;

	p = text_buf[r] + N + 1;
	lson[r] = rson[r] = N;

	match_length = 0;
	while (1) {
		if (cmp < 0) {
			if (lson[p] == N) {
				lson[p] = r;
				dad[r] = p;
				return lazy_match(r);
			}
			p = lson[p];
		} else {
			if (rson[p] == N) {
				rson[p] = r;
				dad[r] = p;
				return lazy_match(r);
			}
			p = rson[p];
		}
		for (i = 1;; ++i) {
			if (i < F) {
				cmp = key[i] - text_buf[p + i];
				if (key[i] == text_buf[p + i])
					continue;
			}
			break;
		}
		if (i >= match_length) {
			if (r < p)
				tmp = r - p + N;
			else
				tmp = r - p;
		}
		if (i >= match_length) {
			if (i == match_length) {
				if (tmp < match_position)
					match_position = tmp;
			} else
				match_position = tmp;
			if ((match_length = i) > F - 1)
				break;
		}
	}
	dad[r] = dad[p];
	lson[r] = lson[p];
	rson[r] = rson[p];
	dad[lson[p]] = dad[rson[p]] = r;
	if (rson[dad[p]] == p)
		rson[dad[p]] = r;
	else
		lson[dad[p]] = r;
	dad[p] = N;
}

static void DeleteNode(int p) {
	int q;
	if (dad[p] == N)
		return;
	if (rson[p] == N)
		q = lson[p];
	else if (lson[p] == N)
		q = rson[p];
	else {
		q = lson[p];
		if (rson[q] != N) {
			do {
				q = rson[q];
			} while (rson[q] != N);
			rson[dad[q]] = lson[q];
			dad[lson[q]] = dad[q];
			lson[q] = lson[p];
			dad[lson[p]] = q;
		}
		rson[q] = rson[p];
		dad[rson[p]] = q;
	}
	dad[q] = dad[p];
	if (rson[dad[p]] == p)
		rson[dad[p]] = q;
	else
		lson[dad[p]] = q;
	dad[p] = N;
}

///////////// HUFFMAN ALGO /////////////
static void InitHuffman(void) {
	code = len = 0;
	preno = precode = 0;
	// Clear the huffman code buffer
	memset(&code_buf, 0x00, sizeof(code_buf));
	// Initial bit no (to fetch next byte at first iteration)
	bitno = 8;
}

static void putChar(uint32_t code, uint32_t no, FILE *out) {
	uint32_t tmpno, tmpcode;
	if (preno + no > 7) {
		do {
			no -= tmpno = 8 - preno;
			tmpcode = code >> no;
			fputc(tmpcode | (precode << tmpno), out);
			code -= tmpcode << no;
			preno = precode = 0;
		} while (no > 7);
		preno = no;
		precode = code;
	} else {
		preno += no;
		precode = code | (precode << no);
	}
}

static int getData(cursor_t *in) {
	if (bitno > 7) {
		bitno = 0;
		if((c = cgetc(in)) == EOF){
			return 0;
		}
	}
	code = (code << 1) | ((c >> (7 - bitno++)) & 1);	// get bit msb - index
	len++;
	return 1;
}

///////////// EXPORTS /////////////

/*
 * Huffman encodes the specified stream
 */
void huff(FILE * in, FILE * out, unsigned long int *p_textsize, unsigned long int *p_codesize) {
	textsize = codesize;
	codesize = 0;
	int c, i, j, k, m, flags = 0;
	while (1) {
		if (((flags >>= 1) & 256) == 0) {
			if ((c = getc(in)) == EOF)
				break;
			flags = c | 0xFF00;
		}
		if (flags & 1) {
			if ((c = getc(in)) == EOF)
				break;
			putChar(huff_char[c]->code, huff_char[c]->len, out);	// lookup in char table
		} else {
			if ((j = getc(in)) == EOF)
				break;			// match length
			if ((i = getc(in)) == EOF)
				break;			// byte1 of match position
			if ((m = getc(in)) == EOF)
				break;			// byte0 of match position
			putChar(huff_len[j]->code, huff_len[j]->len, out);	// lookup in len table
			i = m | (i << 8);
			putChar(huff_pos[(i >> 7)]->code, huff_pos[(i >> 7)]->len, out);	// lookup in pos table
			putChar(i - (i >> 7 << 7), 7, out);
		}
	}
	putc(precode << (8 - preno), out);
	codesize = ftell(out) - sizeof(struct lzhs_header);
	if(p_textsize)
		*p_textsize = textsize;
	if(p_codesize)
		*p_codesize = codesize;
	printf("LZHS Out(%ld)/In(%ld): %.4f\n", codesize, textsize, (double)codesize / textsize);
}

/*
 * Huffman decodes the specified stream
 */
void unhuff(cursor_t *in, cursor_t *out) {
	InitHuffman();
	code_buf[0] = 0;
	code_buf_ptr = mask = 1;

	while (1) {
		if (!getData(in))
			goto flush_ret;
		if (len < 4)
			continue; // len in code_len table should be min 4
		for (i = 0; i < 288; i++) {
			if (huff_char[i]->len == len &&
				huff_char[i]->code == code
			){
				if (i > 255) {
					code_buf[code_buf_ptr++] = i - 256;
					code = len = 0;
					while (1) {
						if (!getData(in))
							goto flush_ret;
						if (len < 2)
							continue;	// len in pos table should be min 2
						for (j = 0; j < 32; j++) {
							if (huff_pos[j]->len == len &&
								huff_pos[j]->code == code
							){
								code_buf[code_buf_ptr++] = j >> 1;
								k = -1;
								break;
							}
						}
						if (k == -1)
							break;
					}
					code = 0;
					for (k = 0; k < 7; k++)
						if (!getData(in))
							goto flush_ret;
					code_buf[code_buf_ptr++] = code | (j << 7);
					code = len = 0;
				} else {
					code_buf[0] |= mask;
					code_buf[code_buf_ptr++] = i;
					code = len = 0;
				}
				if ((mask <<= 1) == 0) {
					for (j = 0; j < code_buf_ptr; j++){
						if(cputc(code_buf[j], out) == EOF)
							return;
					}
					code_buf[0] = 0;
					code_buf_ptr = mask = 1;
				}
				break;
			}
		}
	}
	
	flush_ret:
	if (code_buf_ptr > 1)	// flushing buffer
		for (i = 0; i < code_buf_ptr; i++){
			if(cputc(code_buf[i], out) == EOF)
				return;
		}
	return;
}

/*
 * LZSS encodes the specified stream
 */
void lzss(FILE * infile, FILE * outfile, unsigned long int *p_textsize, unsigned long int *p_codesize) {
	int c, i, len, r, s, last_match_length, code_buf_ptr;
	unsigned char code_buf[32], mask;

	InitTree();
	code_buf[0] = 0;
	code_buf_ptr = mask = 1;
	s = codesize = 0;
	r = N - F;

	for (len = 0; len < F && (c = getc(infile)) != EOF; len++)
		text_buf[r + len] = c;
	if ((textsize = len) == 0)
		return;

	InsertNode(r);
	do {
		if (match_length > len)
			match_length = len;
		if (match_length <= THRESHOLD) {
			match_length = 1;
			code_buf[0] |= mask;
			code_buf[code_buf_ptr++] = text_buf[r];
		} else {
			code_buf[code_buf_ptr++] = match_length - THRESHOLD - 1;
			code_buf[code_buf_ptr++] = (match_position >> 8) & 0xff;
			code_buf[code_buf_ptr++] = match_position;
		}
		if ((mask <<= 1) == 0) {
			for (i = 0; i < code_buf_ptr; i++) {
				putc(code_buf[i], outfile);
				codesize++;
			}
			code_buf[0] = 0;
			code_buf_ptr = mask = 1;
		}
		last_match_length = match_length;
		for (i = 0; i < last_match_length && (c = getc(infile)) != EOF; i++) {
			DeleteNode(s);
			text_buf[s] = c;
			if (s < F - 1)
				text_buf[s + N] = c;
			s = (s + 1) & (N - 1);
			r = (r + 1) & (N - 1);
			InsertNode(r);
		}
		textsize += i;
		while (i++ < last_match_length) {
			DeleteNode(s);
			s = (s + 1) & (N - 1);
			r = (r + 1) & (N - 1);
			if (--len)
				InsertNode(r);
		}
	} while (len > 0);
	if (code_buf_ptr > 1) {
		for (i = 0; i < code_buf_ptr; i++) {
			putc(code_buf[i], outfile);
			codesize++;
		}
	}
	if(p_textsize)
		*p_textsize = textsize;
	if(p_codesize)
		*p_codesize = codesize;
	printf("LZSS Out(%ld)/In(%ld): %.3f\n", codesize, textsize, (double)codesize / textsize);
}

/*
 * LZSS decodes the specified stream
 */
void unlzss(cursor_t *in, cursor_t *out) {
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
			
			if(cputc(text_buf[r++] = c, out) == EOF)
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
				m = text_buf[(r - i) & (N - 1)];				
				if(cputc((text_buf[r++] = m), out) == EOF)
					return;
				r &= (N - 1);
			}
		}
	}
}