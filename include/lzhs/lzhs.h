#ifndef _LZHS_H
#define _LZHS_H

#include <stdint.h>

struct lzhs_header {
    uint32_t uncompressedSize, compressedSize;
	uint8_t checksum, spare[7];
};

/* for LZSS */
#define N		 4096
#define F		   34
#define THRESHOLD	2
#define NIL			N

/* for huffman */
struct huff_entry2 {
	int count;
	int unk0;
	int unk1;
	int code;
	int len;
};

struct huff_entry {
	int code;
	int len;
};

/*	there are 2 physical huffman tables (code, pos), holding 3 tables (code, len, pos)
		size	element_size	elements	range
code	2304		8				256		 code[0:256]
len		256			8				32		 code[256:288]
pos		256			8				32		 pos[0:32]

	there are other 2 tables that are used at runtime (elements in format huff_entry2). It starts empty,
	has an element size of 20 and it's filled with the 2 hardcoded tables
*/

#define n_tablecode 288
#define n_tablepos F
#define n_tablelen F

#endif
