/**
 * LZHS Encoder
 * Copyright 2016 Smx <smxdev4@gmail.com>
 * Copyright 2016 lprot
 * All right reserved
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <libgen.h>

#include "config.h"
#include "mfile.h"
#include "lzhs/lzhs.h"
#include "mediatek.h"
#include "util.h"

#define LZHS_SIZE_THRESHOLD (20 * 1024 * 1024) //20 MB (a random sane value)

static bool lzhs_lookup_initialized = false;

bool _is_lzhs_mem(struct lzhs_header *header){
	if (
		!memcmp(header->spare, "\0\0\0\0\0\0\0", sizeof(header->spare)) &&
		header->compressedSize > 0 && header->compressedSize <= LZHS_SIZE_THRESHOLD &&
		header->uncompressedSize > 0 && header->uncompressedSize <= LZHS_SIZE_THRESHOLD
	){
		return true;
	}
	return false;
}

bool is_lzhs_mem(MFILE *file, off_t offset){
	struct lzhs_header *header = (struct lzhs_header *)(mdata(file, uint8_t) + offset);
	if(msize(file) < offset + sizeof(struct lzhs_header)){
		return false;
	}
	return _is_lzhs_mem(header);
}

MFILE *is_lzhs(const char *filename) {
	MFILE *file = mopen(filename, O_RDONLY);
	if (file == NULL) {
		err_exit("Can't open file %s\n", filename);
	}
	if(is_lzhs_mem(file, 0))
		return file;

	mclose(file);
	return NULL;
}

static void ARMThumb_Convert(unsigned char *data, uint32_t size, uint32_t nowPos, int encoding) {
	uint32_t i;
	for (i = 0; i + 4 <= size; i += 2) {
		if ((data[i + 1] & 0xF8) == 0xF0 && (data[i + 3] & 0xF8) == 0xF8) {
			uint32_t src = ((data[i + 1] & 0x7) << 19) | (data[i + 0] << 11) | ((data[i + 3] & 0x7) << 8) | (data[i + 2]);
			src <<= 1;
			uint32_t dest;
			if (encoding)
				dest = nowPos + i + 4 + src;
			else
				dest = src - (nowPos + i + 4);
			dest >>= 1;
			data[i + 1] = 0xF0 | ((dest >> 19) & 0x7);
			data[i + 0] = (dest >> 11);
			data[i + 3] = 0xF8 | ((dest >> 8) & 0x7);
			data[i + 2] = (dest);
			i += 2;
		}
	}
}

static int lzhs_pad_file(const char *filename, const char *outfilename) {
	int input_filesize;
	size_t n;
	char *ptr;
	FILE *infile, *outfile;
	infile = fopen(filename, "rb");
	if (infile) {
		outfile = fopen(outfilename, "wb");
		if (outfile) {
			fseek(infile, 0, SEEK_END);
			size_t filesize = ftell(infile);
			rewind(infile);
			ptr = malloc(sizeof(char) * filesize);
			int extrabytes = 0;
			for (input_filesize = 0;; input_filesize += n) {	//start a loop. add read elements every iteration
				n = fread(ptr, 1u, 0x200u, infile);	//read 512 bytes from input into ptr
				if (n <= 0)
					break;
				if (n % 16 != 0) {
					unsigned int x = (n / 8) * 8;	//it will be truncated, so we get next multiple
					if (x < n)
						x += 8;
					x = x - n;	//how many bytes we need to add
					extrabytes += x;	//add the bytes to the counter
				}
				fwrite(ptr, 1u, n, outfile);	//write read bytes to output
			}
			printf("We need to fill extra %d bytes\n", extrabytes);
			int i;
			for (i = 1; i <= extrabytes; i++)
				putc(0xff, outfile);
			fclose(infile);
			fclose(outfile);
			return 0;
		} else {
			printf("Open file %s failed.\n", outfilename);
			return 1;
		}
	} else {
		printf("open file %s fail \n", filename);
		return 1;
	}
	return 0;
}

unsigned char lzhs_calc_checksum(unsigned char *buf, int fsize) {
	unsigned char checksum = 0;
	int i;
	for (i = 0; i < fsize; ++i)
		checksum += buf[i];
	return checksum;
}

void lzhs_encode(const char *infile, const char *outfile) {
	struct lzhs_header header;
	FILE *in, *out;
	unsigned char *buf;
	size_t fsize;

	char *outpath;
	
	unsigned long int textsize, codesize;

	struct lzhs_ctx *ctx = lzhs_ctx_new();

#if 1
//// PADDING
	printf("\n[LZHS] Padding...\n");
	asprintf(&outpath, "%s.tmp", infile);
	lzhs_pad_file(infile, outpath);
	in = fopen(outpath, "rb");
	if (!in) {
		err_exit("Cannot open file %s\n", outpath);
	}
	free(outpath);
#else
	in = fopen(infile, "rb");
#endif

//// ARM 2 THUMB
	asprintf(&outpath, "%s.conv", infile);
	out = fopen(outpath, "wb");
	if (!out) {
		err_exit("Cannot open file conv\n");
	}
	
	fseek(in, 0, SEEK_END);
	fsize = ftell(in);
	rewind(in);

	buf = calloc(1, fsize);
	fread(buf, 1, fsize, in);
	rewind(in);

	printf("[LZHS] Calculating checksum...\n");
	header.checksum = lzhs_calc_checksum(buf, fsize);
	memset(&header.spare, 0, sizeof(header.spare));
	printf("Checksum = %x\n", header.checksum);

	printf("[LZHS] Converting ARM => Thumb...\n");
	ARMThumb_Convert(buf, fsize, 0, 1);
	fwrite(buf, 1, fsize, out);
	
	free(buf);
	
////LZSS
	freopen(outpath, "rb", in);
	if (!in) {
		err_exit("Cannot open file conv\n");
	}

	free(outpath);
	asprintf(&outpath, "%s.lzs", infile);

	freopen(outpath, "wb", out);

	printf("[LZHS] Encoding with LZSS...\n");
	lzss(ctx, in, out, &textsize, &codesize);
	if (!out) {
		err_exit("Cannot open tmp.lzs\n");
	}

////HUFFMAN
	freopen(outpath, "rb", in);
	if (!in) {
		err_exit("Cannot open file tmp.lzs\n");
	}
	
	freopen(outfile, "wb", out);
	if (!out) {
		err_exit("Cannot open file %s\n", outfile);
	}

	header.uncompressedSize = fsize;
	fwrite(&header, 1, sizeof(header), out);
	
	printf("[LZHS] Encoding with Huffman...\n");

	huff(ctx, in, out, &textsize, &codesize); 
	header.compressedSize = codesize;
	printf("[LZHS] Writing Header...\n");
	rewind(out);
	fwrite(&header, 1, sizeof(header), out);
	printf("[LZHS] Done!\n");

	free(outpath);

	fclose(in);
	fclose(out);

	free(ctx);
}

cursor_t *lzhs_decode(MFILE *in_file, off_t offset, const char *out_path, uint8_t *out_checksum){
	if(!lzhs_lookup_initialized){
		lzhs_init_lookup();
		lzhs_lookup_initialized = true;
	}

	struct lzhs_header *header = (struct lzhs_header *)(mdata(in_file, uint8_t) + offset);
	printf("\n---LZHS details---\n");
	printf("Compressed:\t%u\n", header->compressedSize);
	printf("Uncompressed:\t%u\n", header->uncompressedSize);
	printf("Checksum:\t0x%x\n\n", header->checksum);


	/*
	 * There are a few cases where the huffman data can result in a bigger LZSS set than the final output size.
	 * To work around this problem, we set temp memory to twice the uncompressedSize.
	 */
	size_t tempSize = header->uncompressedSize * 2;

	void *tmp = MFILE_ANON(tempSize);
	if(tmp == MAP_FAILED){
		perror("mmap tmp for lzhs\n");
		return (cursor_t *)-1;
	}
	memset(tmp, 0x00, tempSize);

	MFILE *out_file = NULL;
	uint8_t *out_bytes = NULL;

	if(out_path == NULL){
		out_bytes = MFILE_ANON(header->uncompressedSize);
		if(out_bytes == MAP_FAILED){
			perror("mmap out for lzhs\n");
			return (cursor_t *)-1;
		}
	} else {
		out_file = mfopen(out_path, "w+");
		if(!out_file){
			fprintf(stderr, "Cannot open output file %s\n", out_path);
			return (cursor_t *)-1;
		}
		mfile_map(out_file, header->uncompressedSize);
		out_bytes = mdata(out_file, uint8_t);
	}

	uint8_t *in_bytes = mdata(in_file, uint8_t);

	/* Input file */
	cursor_t in_cur = {
		.ptr = in_bytes + offset + sizeof(*header),
		.size = header->compressedSize,
		.offset = 0
	};
	
	/* Temp memory */
	cursor_t out_cur = {
		.ptr = tmp,
		.size = tempSize,
		.offset = 0
	};

	struct lzhs_ctx *ctx = lzhs_ctx_new();

	printf("[LZHS] Decoding Huffman...\n");
	// Input file -> Temp memory
	unhuff(ctx, &in_cur, &out_cur);
	
	printf("[LZHS] Decoding LZSS...\n");
	
	// Rewind the huffman cursor and change ends
	out_cur.offset = 0;
	memcpy((void *)&in_cur, (void *)&out_cur, sizeof(cursor_t));

	// Setup output cursor for the final file
	out_cur.ptr = out_bytes;
	out_cur.size = header->uncompressedSize;

	// Temp memory -> Output file
	unlzss(ctx, &in_cur, &out_cur);

	free(ctx);

	// We don't need the temp memory anymore
	munmap(tmp, tempSize);

	printf("[LZHS] Converting Thumb => ARM...\n");
	ARMThumb_Convert(out_bytes, out_cur.size, 0, 0);

	printf("[LZHS] Calculating checksum...\n");
	uint8_t checksum = lzhs_calc_checksum(out_bytes, out_cur.size);
	if(out_checksum != NULL){
		*out_checksum = checksum;
	}
	printf("Calculated checksum = 0x%x\n", checksum);
	if (checksum != header->checksum)
		printf("[LZHS] WARNING: Checksum mismatch (got 0x%x, expected 0x%x)!!\n", checksum, header->checksum);
	if (out_cur.size != header->uncompressedSize)
		printf("[LZHS] WARNING: Size mismatch (got %zu, expected %u)!!\n", out_cur.size, header->uncompressedSize);	
	
	if(out_file != NULL){
		mclose(out_file);
		return NULL;
	} else {
		cursor_t *cpy = calloc(1, sizeof(out_cur));
		memcpy(cpy, &out_cur, sizeof(out_cur));
		return cpy;
	}
}

int process_segment(MFILE *in_file, off_t offset, const char *name){
	int r = 0;
	char *file_dir = my_dirname(in_file->path);
	
	char *out_path;
	asprintf(&out_path, "%s/%s.lzhs", file_dir, name);	
	printf("[MTK] Extracting %s to %s...\n", name, out_path);
	
	MFILE *out_file = mfopen(out_path, "w+");
	if (!out_file) {
		fprintf(stderr, "Cannot open file %s for writing\n", out_path);
		r = -1;
		goto exit;
	}
	
	uint8_t *bytes = &(mdata(in_file, uint8_t))[offset];
	struct lzhs_header *lzhs_hdr = (struct lzhs_header *)bytes;
	
	/* Allocate file */
	mfile_map(out_file,
		sizeof(*lzhs_hdr) +	lzhs_hdr->compressedSize
	);
	
	/* Copy compressed file */
	memcpy(
		(void *)(mdata(out_file, uint8_t)),
		(void *)bytes,
		lzhs_hdr->compressedSize + sizeof(*lzhs_hdr)
	);
	
	printf("[MTK] UnLZHS %s\n", out_path);
	
	asprintf(&out_path, "%s/%s.unlzhs", file_dir, name);
	
	// Decode the file we just wrote
	lzhs_decode(out_file, 0, out_path, NULL);
	mclose(out_file);
	
	exit:
		free(out_path);
		free(file_dir);
		return r;
}

int extract_lzhs(MFILE *in_file) {
	int r;
	if(is_lzhs_mem(in_file, MTK_LOADER_OFF) && (r=process_segment(in_file, MTK_LOADER_OFF, "mtkloader")) < 0){
		return r;
	} else if(is_lzhs_mem(in_file, MTK_LOADER_OFF1) && (r=process_segment(in_file, MTK_LOADER_OFF1, "mtkloader")) < 0){
		return r;
	}

	if(is_lzhs_mem(in_file, MTK_UBOOT_OFF) && (r=process_segment(in_file, MTK_UBOOT_OFF, "uboot")) < 0)
		return r;
	if(is_lzhs_mem(in_file, MTK_HISENSE_UBOOT_OFF) && (r=process_segment(in_file, MTK_HISENSE_UBOOT_OFF, "uboot")) < 0)
		return r;	
		

	if(msize(in_file) < MTK_UBOOT_OFF){
		return 0;
	}
	struct lzhs_header *uboot_hdr = (struct lzhs_header *)(&(mdata(in_file, uint8_t))[MTK_UBOOT_OFF]);

	uint pad;
	pad = (pad = (uboot_hdr->compressedSize % 16)) == 0 ? 0 : (16 - pad);

	off_t mtk_tz = (
		//Offset of uboot
		MTK_UBOOT_OFF +
		//Size of its lzhs header
		sizeof(struct lzhs_header) +
		//uboot compressed size
		uboot_hdr->compressedSize +
		//Align to the next "line"
		pad +
		//TZ relative offset 
		MTK_TZ_OFF
	);
	
	/* Do we have the TZ segment? (mtk5369 only) */
	if(mtk_tz < msize(in_file)){
		if(is_lzhs_mem(in_file, mtk_tz) && (r=process_segment(in_file, mtk_tz, "boot_tz")) < 0)
			return r;
	}
	
	return 0;
}