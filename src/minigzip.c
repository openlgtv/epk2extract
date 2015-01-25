/* minigzip.c -- simulate gzip using the zlib compression library
 * Copyright (C) 1995-1998 Jean-loup Gailly.
 * For conditions of distribution and use, see copyright notice in zlib.h
 */

/*
 * minigzip is a minimal implementation of the gzip utility. This is
 * only an example of using zlib and isn't meant to replace the
 * full-featured gzip. No attempt is made to deal with file systems
 * limiting names to 14 or 8+3 characters, etc... Error checking is
 * very limited. So use minigzip only for testing; use gzip for the
 * real thing. On MSDOS, use only on file names without extension
 * or in pipe mode.
 */

/* @(#) $Id$ */

#include <minigzip.h>

char *prog;

/* ===========================================================================
 * Display error message and exit
 */
void error(const char *msg) {
	fprintf(stderr, "%s: %s\n", prog, msg);
	exit(1);
}

/* ===========================================================================
 * Compress input to output then close both files.
 */

void gz_compress(FILE * in, gzFile out) {
	local char buf[BUFLEN];
	int len;
	int err;

#ifdef USE_MMAP
	/* Try first compressing with mmap. If mmap fails (minigzip used in a
	 * pipe), use the normal fread loop.
	 */
	if (gz_compress_mmap(in, out) == Z_OK)
		return;
#endif
	for (;;) {
		len = fread(buf, 1, sizeof(buf), in);
		if (ferror(in)) {
			perror("fread");
			exit(1);
		}
		if (len == 0)
			break;

		if (gzwrite(out, buf, (unsigned)len) != len)
			error(gzerror(out, &err));
	}
	fclose(in);
	if (gzclose(out) != Z_OK)
		error("failed gzclose");
}

#ifdef USE_MMAP					/* MMAP version, Miguel Albrecht <malbrech@eso.org> */

/* Try compressing the input file at once using mmap. Return Z_OK if
 * if success, Z_ERRNO otherwise.
 */
int gz_compress_mmap(FILE * in, gzFile out) {
	int len;
	int err;
	int ifd = fileno(in);
	caddr_t buf;				/* mmap'ed buffer for the entire input file */
	off_t buf_len;				/* length of the input file */
	struct stat sb;

	/* Determine the size of the file, needed for mmap: */
	if (fstat(ifd, &sb) < 0)
		return Z_ERRNO;
	buf_len = sb.st_size;
	if (buf_len <= 0)
		return Z_ERRNO;

	/* Now do the actual mmap: */
	buf = mmap((caddr_t) 0, buf_len, PROT_READ, MAP_SHARED, ifd, (off_t) 0);
	if (buf == (caddr_t) (-1))
		return Z_ERRNO;

	/* Compress the whole file at once: */
	len = gzwrite(out, (char *)buf, (unsigned)buf_len);

	if (len != (int)buf_len)
		error(gzerror(out, &err));

	munmap(buf, buf_len);
	fclose(in);
	if (gzclose(out) != Z_OK)
		error("failed gzclose");
	return Z_OK;
}
#endif /* USE_MMAP */

/* ===========================================================================
 * Uncompress input to output then close both files.
 */
void gz_uncompress(gzFile in, FILE * out) {
	local char buf[BUFLEN];
	int len;
	int err;

	for (;;) {
		len = gzread(in, buf, sizeof(buf));
		if (len < 0)
			error(gzerror(in, &err));
		if (len == 0)
			break;

		if ((int)fwrite(buf, 1, (unsigned)len, out) != len) {
			error("failed fwrite");
		}
	}
	if (fclose(out))
		error("failed fclose");

	if (gzclose(in) != Z_OK)
		error("failed gzclose");
}

/* ===========================================================================
 * Compress the given file: create a corresponding .gz file and remove the
 * original.
 */
void file_compress(char *file, char *mode) {
	local char outfile[MAX_NAME_LEN];
	FILE *in;
	gzFile out;

	strcpy(outfile, file);
	strcat(outfile, GZ_SUFFIX);

	in = fopen(file, "rb");
	if (in == NULL) {
		perror(file);
		exit(1);
	}
	out = gzopen(outfile, mode);
	if (out == NULL) {
		fprintf(stderr, "%s: can't gzopen %s\n", prog, outfile);
		exit(1);
	}
	gz_compress(in, out);

	//unlink(file);
}

/* ===========================================================================
 * Uncompress the given file and remove the original.
 */
void file_uncompress(char *infile, char *outfile) {
	local char buf[MAX_NAME_LEN];
	FILE *in, *out;
	gzFile gzin;

	gzin = gzopen(infile, "rb");
	if (in == NULL) {
		fprintf(stderr, "%s: can't gzopen %s\n", prog, infile);
		exit(1);
	}
	out = fopen(outfile, "wb");
	if (out == NULL) {
		perror(infile);
		exit(1);
	}

	gz_uncompress(gzin, out);
	//unlink(infile);
}

char *file_uncompress_origname(char *infile, char *path) {
	local char buf[MAX_NAME_LEN];
	FILE *in, *out;
	gzFile gzin;

	char *filename;
	int len = 0, i;
	in = fopen(infile, "rb");
	if (in == NULL) {
		printf("Can't open %s\n", infile);
		exit(1);
	}
	fseek(in, 10, SEEK_SET);
	char c;
	do {
		c = getc(in);
		len++;
	} while (c != '\x00');		//calculate string length
	char *dest = malloc(len + strlen(path));	//allocate space for path+name
	memset(dest, 0x0, strlen(dest));
	filename = malloc(len);		//allocate space for name
	fseek(in, 10, SEEK_SET);
	fread(filename, 1, len, in);	//read filename
	printf("Ungzipping file: %s\n", filename);
	fclose(in);

	strcat(dest, path);
	strcat(dest, filename);

	gzin = gzopen(infile, "rb");
	if (in == NULL) {
		fprintf(stderr, "%s: can't gzopen %s\n", prog, infile);
		exit(1);
	}
	out = fopen(dest, "wb");
	if (out == NULL) {
		perror(infile);
		exit(1);
	}

	gz_uncompress(gzin, out);
	//unlink(infile);
	return dest;

}

/* ===========================================================================
 * Usage:  minigzip [-d] [-f] [-h] [-1 to -9] [files...]
 *   -d : decompress
 *   -f : compress with Z_FILTERED
 *   -h : compress with Z_HUFFMAN_ONLY
 *   -1 to -9 : compression level
 */

/*int main(argc, argv)
    int argc;
    char *argv[];
{
    int uncompr = 0;
    gzFile file;
    char outmode[20];

    strcpy(outmode, "wb6 ");

    prog = argv[0];
    argc--, argv++;

    while (argc > 0) {
      if (strcmp(*argv, "-d") == 0)
	uncompr = 1;
      else if (strcmp(*argv, "-f") == 0)
	outmode[3] = 'f';
      else if (strcmp(*argv, "-h") == 0)
	outmode[3] = 'h';
      else if ((*argv)[0] == '-' && (*argv)[1] >= '1' && (*argv)[1] <= '9' &&
	       (*argv)[2] == 0)
	outmode[2] = (*argv)[1];
      else
	break;
      argc--, argv++;
    }
    if (argc == 0) {
        SET_BINARY_MODE(stdin);
        SET_BINARY_MODE(stdout);
        if (uncompr) {
            file = gzdopen(fileno(stdin), "rb");
            if (file == NULL) error("can't gzdopen stdin");
            gz_uncompress(file, stdout);
        } else {
            file = gzdopen(fileno(stdout), outmode);
            if (file == NULL) error("can't gzdopen stdout");
            gz_compress(stdin, file);
        }
    } else {
        do {
            if (uncompr) {
                file_uncompress(*argv);
            } else {
                file_compress(*argv, outmode);
            }
        } while (argv++, --argc);
    }
    exit(0);
    return 0; // to avoid warning
}*/
