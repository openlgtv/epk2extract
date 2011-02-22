/* lzopack.c -- LZO example program: a simple file packer

 This file is part of the LZO real-time data compression library.

 Copyright (C) 2008 Markus Franz Xaver Johannes Oberhumer
 Copyright (C) 2007 Markus Franz Xaver Johannes Oberhumer
 Copyright (C) 2006 Markus Franz Xaver Johannes Oberhumer
 Copyright (C) 2005 Markus Franz Xaver Johannes Oberhumer
 Copyright (C) 2004 Markus Franz Xaver Johannes Oberhumer
 Copyright (C) 2003 Markus Franz Xaver Johannes Oberhumer
 Copyright (C) 2002 Markus Franz Xaver Johannes Oberhumer
 Copyright (C) 2001 Markus Franz Xaver Johannes Oberhumer
 Copyright (C) 2000 Markus Franz Xaver Johannes Oberhumer
 Copyright (C) 1999 Markus Franz Xaver Johannes Oberhumer
 Copyright (C) 1998 Markus Franz Xaver Johannes Oberhumer
 Copyright (C) 1997 Markus Franz Xaver Johannes Oberhumer
 Copyright (C) 1996 Markus Franz Xaver Johannes Oberhumer
 All Rights Reserved.

 Patched by Arno1 (http://lg-hack.info) for LG digital tv firmware

 The LZO library is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License as
 published by the Free Software Foundation; either version 2 of
 the License, or (at your option) any later version.

 The LZO library is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with the LZO library; see the file COPYING.
 If not, write to the Free Software Foundation, Inc.,
 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

 Markus F.X.J. Oberhumer
 <markus@oberhumer.com>
 http://www.oberhumer.com/opensource/lzo/
 */

/*************************************************************************
 // NOTE: this is an example program, so do not use to backup your data.
 //
 // This program lacks things like sophisticated file handling but is
 // pretty complete regarding compression - it should provide a good
 // starting point for adaption for your applications.
 //
 // Please study LZO.FAQ and simple.c first.
 **************************************************************************/

#include "lzo/lzoconf.h"
#include "lzo/lzo1x.h"

/* portability layer */
#define WANT_LZO_MALLOC 1
#define WANT_LZO_FREAD 1
#define WANT_LZO_WILDARGV 1
#include "lzo/portab.h"



static unsigned long total_in = 0;
static unsigned long total_out = 0;
static lzo_bool opt_debug = 0;

lzo_uint32 fi_size = 0;

/* magic file header for lzopack-compressed files */
static const unsigned char magic[8] = { 0x00, 0xe9, 0x4c, 0x5a, 0x4f, 0xff,
		0x1a, 0x00 };

/*************************************************************************
 // file IO
 **************************************************************************/

lzo_uint xread(FILE *fp, lzo_voidp buf, lzo_uint len, lzo_bool allow_eof) {
	lzo_uint l;

	l = (lzo_uint) lzo_fread(fp, buf, len);
	if (l > len) {
		fprintf(stderr, "\nsomething's wrong with your C library !!!\n");
		exit(1);
	}
	if (l != len && !allow_eof) {
		fprintf(stderr, "\nread error - premature end of file\n");
		exit(1);
	}
	total_in += (unsigned long) l;
	return l;
}

lzo_uint xwrite(FILE *fp, const lzo_voidp buf, lzo_uint len) {
	if (fp != NULL && lzo_fwrite(fp, buf, len) != len) {
		fprintf(stderr, "\nwrite error  (disk full ?)\n");
		exit(1);
	}
	total_out += (unsigned long) len;
	return len;
}

int xgetc(FILE *fp) {
	unsigned char c;
	xread(fp, (lzo_voidp) &c, 1, 0);
	return c;
}

void xputc(FILE *fp, int c) {
	unsigned char cc = (unsigned char) (c & 0xff);
	xwrite(fp, (const lzo_voidp) &cc, 1);
}

/* read and write portable 32-bit integers */

lzo_uint32 xread32(FILE *fp) {
	unsigned char b[4];
	lzo_uint32 v;

	xread(fp, b, 4, 0);
	v = (lzo_uint32) b[3] << 0;
	v |= (lzo_uint32) b[2] << 8;
	v |= (lzo_uint32) b[1] << 16;
	v |= (lzo_uint32) b[0] << 24;
	return v;
}

void xwrite32(FILE *fp, lzo_xint v) {
	unsigned char b[4];

	b[3] = (unsigned char) ((v >> 0) & 0xff);
	b[2] = (unsigned char) ((v >> 8) & 0xff);
	b[1] = (unsigned char) ((v >> 16) & 0xff);
	b[0] = (unsigned char) ((v >> 24) & 0xff);
	xwrite(fp, b, 4);
}

/*************************************************************************
 // compress
 //
 // possible improvement: we could use overlapping compression to
 //   save some memory - see overlap.c. This would require some minor
 //   changes in the decompression code as well, because if a block
 //   turns out to be incompressible we would still have to store it in its
 //   "compressed" (i.e. then slightly enlarged) form because the original
 //   (uncompressed) data would have been lost during the overlapping
 //   compression.
 **************************************************************************/

int do_compress(FILE *fi, FILE *fo, int level, lzo_uint block_size) {
	int r = 0;
	lzo_bytep in = NULL;
	lzo_bytep out = NULL;
	lzo_bytep wrkmem = NULL;
	lzo_uint in_len;
	lzo_uint out_len;
	lzo_uint32 wrk_len = 0;
	lzo_uint32 flags = 1; /* do compute a checksum */
	int method = 1; /* compression method: LZO1X */
	lzo_uint32 checksum;

	total_in = total_out = 0;

	/*
	 * Step 1: write magic header, flags & block size, init checksum
	 */
	xwrite(fo, magic, sizeof(magic));
	xwrite32(fo, fi_size);
	printf("Decompressed size : %d\n", fi_size);
	xwrite32(fo, flags);
	xputc(fo, method); /* compression method */
	xputc(fo, level); /* compression level */
	xwrite32(fo, block_size);
	checksum = lzo_adler32(0, NULL, 0);

	/*
	 * Step 2: allocate compression buffers and work-memory
	 */
	in = (lzo_bytep) lzo_malloc(block_size);
	out = (lzo_bytep) lzo_malloc(block_size + block_size / 16 + 64 + 3);
	if (level == 9)
		wrk_len = LZO1X_999_MEM_COMPRESS;
	else
		wrk_len = LZO1X_1_MEM_COMPRESS;
	wrkmem = (lzo_bytep) lzo_malloc(wrk_len);
	if (in == NULL || out == NULL || wrkmem == NULL) {
		printf("out of memory\n");
		r = 1;
		goto err;
	}

	/*
	 * Step 3: process blocks
	 */
	for (;;) {
		/* read block */
		in_len = xread(fi, in, block_size, 1);
		if (in_len <= 0)
			break;

		/* update checksum */
		if (flags & 1)
			checksum = lzo_adler32(checksum, in, in_len);

		/* clear wrkmem (not needed, only for debug/benchmark purposes) */
		if (opt_debug)
			lzo_memset(wrkmem, 0xff, wrk_len);

		/* compress block */
		if (level == 9)
			r = lzo1x_999_compress(in, in_len, out, &out_len, wrkmem);
		else
			r = lzo1x_1_compress(in, in_len, out, &out_len, wrkmem);
		if (r != LZO_E_OK || out_len > in_len + in_len / 16 + 64 + 3) {
			/* this should NEVER happen */
			printf("internal error - compression failed: %d\n", r);
			r = 2;
			goto err;
		}

		/* write uncompressed block size */
		xwrite32(fo, in_len);

		if (out_len < in_len) {
			/* write compressed block */
			xwrite32(fo, out_len);
			xwrite(fo, out, out_len);
		} else {
			/* not compressible - write uncompressed block */
			xwrite32(fo, in_len);
			xwrite(fo, in, in_len);
		}
	}

	/* write EOF marker */
	xwrite32(fo, 0);

	/* write checksum */
	if (flags & 1)
		xwrite32(fo, checksum);

	r = 0;
	err: lzo_free(wrkmem);
	lzo_free(out);
	lzo_free(in);
	return r;
}



/*************************************************************************
 // decompress / test
 //
 // We are using overlapping (in-place) decompression to save some
 // memory - see overlap.c.
 **************************************************************************/

int do_decompress(FILE *fi, FILE *fo) {
	unsigned int r = 0;
	lzo_bytep buf = NULL;
	lzo_uint buf_len;
	unsigned char m[sizeof(magic)];
	lzo_uint32 flags, decomp_size;
	int method;
	int level;
	lzo_uint block_size;
	lzo_uint32 checksum;

	total_in = total_out = 0;

	/*
	 * Step 1: check magic header, read flags & block size, init checksum
	 */
	if (xread(fi, m, sizeof(magic), 1) != sizeof(magic) || memcmp(m, magic,
			sizeof(magic)) != 0) {
		//printf("header error - this file is not compressed by lzopack\n");
		r = 1;
		goto err;
	}

	decomp_size = xread32(fi);

	flags = xread32(fi);

	method = xgetc(fi);

	level = xgetc(fi);

	if (method != 1) {
		printf("header error - invalid method %d (level %d)\n", method, level);
		r = 2;
		goto err;
	}
	block_size = xread32(fi);
	if (block_size < 1024 || block_size > 8 * 1024 * 1024L) {
		printf("header error - invalid block size %ld\n",
				(long) block_size);
		r = 3;
		goto err;
	}
	checksum = lzo_adler32(0, NULL, 0);

	/*
	 * Step 2: allocate buffer for in-place decompression
	 */
	buf_len = block_size + block_size / 16 + 64 + 3;
	buf = (lzo_bytep) lzo_malloc(buf_len);
	if (buf == NULL) {
		printf("out of memory\n");
		r = 4;
		goto err;
	}

	/*
	 * Step 3: process blocks
	 */
	for (;;) {
		lzo_bytep in;
		lzo_bytep out;
		lzo_uint in_len;
		lzo_uint out_len;

		/* read uncompressed size */
		out_len = xread32(fi);

		/* exit if last block (EOF marker) */
		if (out_len == 0)
			break;

		/* read compressed size */
		in_len = xread32(fi);

		/* sanity check of the size values */
		if (in_len > block_size || out_len > block_size || in_len == 0
				|| in_len > out_len) {
			printf("block size error - data corrupted\n");
			r = 5;
			goto err;
		}

		/* place compressed block at the top of the buffer */
		in = buf + buf_len - in_len;
		out = buf;

		/* read compressed block data */
		xread(fi, in, in_len, 0);

		if (in_len < out_len) {
			/* decompress - use safe decompressor as data might be corrupted
			 * during a file transfer */
			lzo_uint new_len = out_len;

			r = lzo1x_decompress_safe(in, in_len, out, &new_len, NULL);
			if (r != LZO_E_OK || new_len != out_len) {
				printf("compressed data violation: %u\n", r);
				r = 6;
				goto err;
			}
			/* write decompressed block */
			xwrite(fo, out, out_len);
			/* update checksum */
			if (flags & 1)
				checksum = lzo_adler32(checksum, out, out_len);
		} else {
			/* write original (incompressible) block */
			xwrite(fo, in, in_len);
			/* update checksum */
			if (flags & 1)
				checksum = lzo_adler32(checksum, in, in_len);
		}
	}

	/* read and verify checksum */
	if (flags & 1) {
		lzo_uint32 c = xread32(fi);
		if (c != checksum) {
			printf("checksum error - data corrupted\n");
			r = 7;
			goto err;
		}
	}

	r = 0;
	err: lzo_free(buf);
	return r;
}

/*************************************************************************
 //
 **************************************************************************/


/* open input file */
static FILE *xopen_fi(const char *name) {
	FILE *fp;

	fp = fopen(name, "rb");
	if (fp == NULL) {
		printf("cannot open input file %s\n",name);
		exit(1);
	} else {
		struct stat st;
		int is_regular = 1;
		if (stat(name, &st) != 0 || !S_ISREG(st.st_mode))
			is_regular = 0;
		else
			fi_size = (lzo_uint32) st.st_size;
		if (!is_regular) {
			printf("%s is not a regular file\n", name);
			fclose(fp);
			fp = NULL;
			exit(1);
		}
	}

	return fp;
}

/* open output file */
static FILE *xopen_fo(const char *name) {
	FILE *fp;

#if 0
	/* this is an example program, so make sure we don't overwrite a file */
	fp = fopen(name, "rb");
	if (fp != NULL)
	{
		printf("%s: file %s already exists -- not overwritten\n", progname, name);
		fclose(fp); fp = NULL;
		exit(1);
	}
#endif
	fp = fopen(name, "wb");
	if (fp == NULL) {
		printf("cannot open output file %s\n", name);
		exit(1);
	}
	return fp;
}

/* close file */
static void xclose(FILE *fp) {
	if (fp) {
		int err;
		err = ferror(fp);
		if (fclose(fp) != 0)
			err = 1;
		if (err) {
			printf("error while closing file\n");
			exit(1);
		}
	}
}

int check_lzo_header(const char *name) {

	FILE *fi = xopen_fi(name);

	unsigned char m[sizeof(magic)];
	int result =  (xread(fi, m, sizeof(magic), 1) != sizeof(magic) || memcmp(m, magic,
				sizeof(magic)) != 0);

	xclose(fi);

	return !result;
}

/*************************************************************************
 //
 **************************************************************************/

int __lzo_cdecl_main lzo_unpack(const char* in_name, const char* out_name) {

	int r = 0;
	FILE *fi = NULL;
	FILE *fo = NULL;
	lzo_uint opt_block_size;

	/*
	 * Step 1: initialize the LZO library
	 */
	if (lzo_init() != LZO_E_OK) {
		printf("internal error - lzo_init() failed !!!\n");
		printf(
				"(this usually indicates a compiler bug - try recompiling\nwithout optimizations, and enable `-DLZO_DEBUG' for diagnostics)\n");
		exit(1);
	}

	/*
	 * Step 2: setup memory
	 */
	opt_block_size = 256 * 1024L;

#if defined(ACC_MM_AHSHIFT)
	/* reduce memory requirements for ancient 16-bit DOS 640kB real-mode */
	if (ACC_MM_AHSHIFT != 3)
	opt_block_size = 16 * 1024L;
#endif


	/*
	 * Step 4: process file(s)
	 */
	fi = xopen_fi(in_name);
	fo = xopen_fo(out_name);
	r = do_decompress(fi, fo);
	if (r == 0)
		printf("decompressed %lu into %lu bytes\n", total_in,
				total_out);

	xclose(fi);
	fi = NULL;
	xclose(fo);
	fo = NULL;
	return r;
}

/*
 vi:ts=4:et
 */

