/*
 ============================================================================
 Name        : main.c
 Author      : sirius
 Copyright   : published under GPL
 Description : EPK2 firmware extractor for LG Electronic digital TVs
 ============================================================================
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <getopt.h>
#ifdef __CYGWIN__
#include <sys/cygwin.h>
#endif
#include <epk1.h>
#include <epk2.h>
#include <symfile.h>
#include <formats.h>

char exe_dir[1024];
char *current_dir;
int endianswap;

struct config_opts_t config_opts;

int handle_file(const char *file, struct config_opts_t *config_opts) {
	const char *dest_dir = config_opts->dest_dir;
	const char *file_name = basename(strdup(file));

	char dest_file[1024] = "";
	char lz4pack[1024] = "";

	if (check_lzo_header(file)) {
		constructPath(dest_file, dest_dir, file_name, ".lzounpack");
		printf("Extracting LZO file to: %s\n", dest_file);
		if (lzo_unpack(file, dest_file) == 0) {
			handle_file(dest_file, config_opts);
			return EXIT_SUCCESS;
		}
	} else if (is_nfsb(file)) {
		constructPath(dest_file, dest_dir, file_name, ".unnfsb");
		printf("Extracting nfsb image to: %s.\n\n", dest_file);
		unnfsb(file, dest_file);
		handle_file(dest_file, config_opts);
		return EXIT_SUCCESS;
	} else if (is_lz4(file)) {
		constructPath(dest_file, dest_dir, file_name, ".unlz4");
		printf("UnLZ4 file to: %s\n", dest_file);
		decode_file(file, dest_file);
		return EXIT_SUCCESS;			
	} else if (is_squashfs(file)) {
		constructPath(dest_file, dest_dir, file_name, ".unsquashfs");
		printf("Unsquashfs file to: %s\n", dest_file);
		rmrf(dest_file);
		unsquashfs(file, dest_file);
		return EXIT_SUCCESS;
	} else if (is_gzip(file)) {
		constructPath(dest_file, dest_dir, "", "");
		printf("Ungzip %s to folder %s\n", file, dest_file);
		strcpy(dest_file, file_uncompress_origname((char *)file, dest_file));
		if (dest_file) 
		    handle_file(dest_file, config_opts);
		return EXIT_SUCCESS;
	} else if(is_cramfs_image(file, "be")) {
		constructPath(dest_file, dest_dir, file_name, ".cramswap");
		printf("Swapping cramfs endian for file %s\n", file);
		cramswap(file, dest_file);
		handle_file(dest_file, config_opts);
		return EXIT_SUCCESS;
	} else if(is_cramfs_image(file, "le")) {
		constructPath(dest_file, dest_dir, file_name, ".uncramfs");
		printf("Uncramfs %s to folder %s\n", file, dest_file);
		rmrf(dest_file);
		uncramfs(dest_file, file);
		return EXIT_SUCCESS;
	} else if (isFileEPK2(file)) {
		extractEPK2file(file, config_opts);
		return EXIT_SUCCESS;
	} else if (isFileEPK3(file)) {
		extractEPK3file(file, config_opts);
		return EXIT_SUCCESS;
	} else if (isFileEPK1(file)) {
		extract_epk1_file(file, config_opts);
		return EXIT_SUCCESS;
	} else if (is_kernel(file)) {
		constructPath(dest_file, dest_dir, file_name, ".unpaked");
		printf("Extracting boot image to: %s.\n\n", dest_file);
		extract_kernel(file, dest_file);
		handle_file(dest_file, config_opts);
		return EXIT_SUCCESS;
	} else if(isPartPakfile(file)) {
		constructPath(dest_file, dest_dir, remove_ext(file_name), ".txt");
		printf("Saving Partition info to: %s\n", dest_file);
		dump_partinfo(file, dest_file);
		return EXIT_SUCCESS;
	} else if(is_jffs2(file)) {
		constructPath(dest_file, dest_dir, file_name, ".unjffs2");
		printf("jffs2extract %s to folder %s\n", file, dest_file);
		rmrf(dest_file);
		jffs2extract(file, dest_file, "1234");
		return EXIT_SUCCESS;
	} else if(isSTRfile(file)) {
		constructPath(dest_file, dest_dir, file_name, ".ts");
		setKey();
		printf("\nConverting %s file to TS: %s\n", file, dest_file);
		convertSTR2TS(file, dest_file, 0);
		return EXIT_SUCCESS;
	} else if(!memcmp(&file[strlen(file)-3], "PIF", 3)) {
		constructPath(dest_file, dest_dir, file_name, ".ts");
		setKey();
		printf("\nProcessing PIF file: %s\n", file);
		processPIF(file, dest_file);
		return EXIT_SUCCESS;
	} else if(symfile_load(file) == 0) {
		constructPath(dest_file, dest_dir, file_name, ".idc");
		printf("Converting SYM file to IDC script: %s\n", dest_file);
		symfile_write_idc(dest_file);
		return EXIT_SUCCESS;
	}
	return EXIT_FAILURE;
}

void ARMThumb_Convert(unsigned char* data, uint32_t size, uint32_t nowPos, int encoding) {
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

#define N		 4096
#define F		   34
#define THRESHOLD	2
#define NIL			N

unsigned long int textsize = 0, codesize = 0, printcount = 0;
unsigned char text_buf[N + F - 1];
int	match_length, match_position, lson[N + 1], rson[N + 257], dad[N + 1];

void InitTree(void) { 
	int  i;
	for (i = N + 1; i <= N + 256; i++) rson[i] = NIL;
	for (i = 0; i < N; i++) dad[i] = NIL;
}

void lazy_match(int r) {
	unsigned char *key;
	unsigned i, p, tmp;
    int cmp;
  
  if ( match_length < F - 1 ) {
    cmp = 1;
    key = &text_buf[r + 1];
    p = key[0] + N + 1;
    tmp = 0;
    while ( 1 ) {
      if ( cmp < 0 ) {
        if ( lson[p] == N ) break;
        p = lson[p];
      } else {
        if ( rson[p] == N ) break;
        p = rson[p];
      }
      for ( i = 1; ; ++i ) {
        if ( i < F ) {
          cmp = key[i] - text_buf[p + i];
          if ( key[i] == text_buf[p + i] ) continue;
        }
        break;
      }
      if ( i > tmp ) {
        tmp = i;
        if ( i > F - 1 ) break;
      }
    }
  }
  if ( tmp > match_length ) match_length = 0;
}

void InsertNode(int r) {
  unsigned char *key;
  unsigned tmp, p, i; 
  int cmp = 1;

  key = &text_buf[r];
  p = text_buf[r] + N + 1;
  lson[r] = rson[r] = N;

  match_length = 0;
  while ( 1 ) {
    if ( cmp < 0 ) {
      if ( lson[p] == N ) {
        lson[p] = r;
        dad[r] = p;
        return lazy_match(r);
      }
      p = lson[p];
    } else {
      if ( rson[p] == N ) {
        rson[p] = r;
        dad[r] = p;
        return lazy_match(r);
      }
      p = rson[p];
    }
    for ( i = 1; ; ++i ) {
      if ( i < F ) {
        cmp = key[i] - text_buf[p + i];
        if ( key[i] == text_buf[p + i] ) continue;
      }
      break;
    }
    if ( i >= match_length ) {
      if ( r < p )
        tmp = r - p + N;
      else
        tmp = r - p;
    }
    if ( i >= match_length ) {
      if ( i == match_length ) {
        if ( tmp < match_position )
           match_position = tmp;
      } else 
        match_position = tmp;
      match_length = i;
      if ( i > F - 1 ) break;
    }
  }
  dad[r] = dad[p];
  lson[r] = lson[p];
  rson[r] = rson[p];
  dad[lson[p]] = dad[rson[p]] = r;
  if ( rson[dad[p]] == p )
    rson[dad[p]] = r;
  else
    lson[dad[p]] = r;
  dad[p] = N;
}

void DeleteNode(int p) {
	int q;
	if (dad[p] == NIL) return; 
	if (rson[p] == NIL) q = lson[p];
	else if (lson[p] == NIL) q = rson[p];
	else {
		q = lson[p];
		if (rson[q] != NIL) {
			do {  q = rson[q];  } while (rson[q] != NIL);
			rson[dad[q]] = lson[q];  dad[lson[q]] = dad[q];
			lson[q] = lson[p];  dad[lson[p]] = q;
		}
		rson[q] = rson[p];  dad[rson[p]] = q;
	}
	dad[q] = dad[p];
	if (rson[dad[p]] == p) rson[dad[p]] = q;  else lson[dad[p]] = q;
	dad[p] = NIL;
}

uint32_t charcode[20 * 288];
uint32_t poscode[20 * 32];

void lzss(FILE* infile, FILE* outfile) {
    int charno = 0, posno = 0;
	int c, i, len, r, s, last_match_length, code_buf_ptr;
	unsigned char code_buf[32], mask;
    for ( i = 0; i < 288; ++i ) {
        charcode[20 * i] = 0;
        charcode[20 * i + 16] = 0;
        charcode[20 * i + 12] = 0;
    }
    for ( i = 0; i < 32; ++i ) {
        poscode[20 * i] = 0;
        poscode[20 * i + 16] = 0;
        charcode[20 * i + 12] = 0;
    }
	InitTree(); 
	code_buf[0] = 0; 
	code_buf_ptr = mask = 1;
	s = 0;  r = N - F;

	for (len = 0; len < F && (c = getc(infile)) != EOF; len++)
		text_buf[r + len] = c;  
	if ((textsize = len) == 0) return; 

	InsertNode(r);  
	do {
		if (match_length > len) match_length = len; 
        if (match_length <= THRESHOLD) {
			match_length = 1;  
			code_buf[0] |= mask; 
			code_buf[code_buf_ptr++] = text_buf[r]; 
            ++charcode[20 * text_buf[r]];
		} else {
            code_buf[code_buf_ptr++] = match_length - THRESHOLD - 1;
            code_buf[code_buf_ptr++] = (match_position >> 8) & 0xff;
            code_buf[code_buf_ptr++] = match_position;        
            ++charcode[20 * match_length + 5060];
            ++poscode[20 * (match_position >> 7)];
		}
		if ((mask <<= 1) == 0) { 
			for (i = 0; i < code_buf_ptr; i++)
				putc(code_buf[i], outfile); 
			codesize += code_buf_ptr;
			code_buf[0] = 0;  
            code_buf_ptr = mask = 1;
		}
		last_match_length = match_length;
		for (i = 0; i < last_match_length && (c = getc(infile)) != EOF; i++) {
			DeleteNode(s);
			text_buf[s] = c;
			if (s < F - 1) text_buf[s + N] = c; 
			s = (s + 1) & (N - 1);  
            r = (r + 1) & (N - 1);
			InsertNode(r);
		}
		textsize += i;
		while (i++ < last_match_length) {	
			DeleteNode(s);					
			s = (s + 1) & (N - 1);  
            r = (r + 1) & (N - 1);
			if (--len) InsertNode(r);		
		}
	} while (len > 0);	
	if (code_buf_ptr > 1) {
		for (i = 0; i < code_buf_ptr; i++) 
            putc(code_buf[i], outfile);
		codesize += code_buf_ptr;
	}
	printf("In : %ld bytes\n", textsize);
	printf("Out: %ld bytes\n", codesize);
	printf("Out/In: %.3f\n", (double)codesize / textsize);
    for ( i = 0; i < 288; ++i ) {
      if (charcode[20 * i]) ++charno;
      else charcode[20 * i] = -1;
    }
    for ( i = 0; i < 32; ++i ) {
      if (poscode[20 * i]) ++posno;
      else poscode[20 * i] = -1;
    }
}

void unlzss(FILE *in, FILE *out) {
    unsigned char text_buf[N];
    int c, i, j, k, m, r = 0;
    unsigned int flags = 0;
    while (1) {
        if (((flags >>= 1) & 256) == 0) {
            if ((c = getc(in)) == EOF) break;
            flags = c | 0xff00;
        }
        if (flags & 1) {
            if ((c = getc(in)) == EOF) break;
            putc(text_buf[r++] = c, out);  
            r &= (N - 1);
        } else {
            if ((j = getc(in)) == EOF) break;
            if ((i = getc(in)) == EOF) break;
            if ((m = getc(in)) == EOF) break;
            i = (i << 8) + m;
            for (k = 0; k <= j + 2; k++) {
                putc(text_buf[r++] = text_buf[(r - 1 - i) & (N - 1)], out);
                r &= (N - 1);
            }
        }
    }
}

#include <fcntl.h>

void test(void) {
	FILE *in = fopen("u-boot.lzhs", "rb");
	FILE* out = fopen("tmp2.lzs", "r+b");
	struct header_t {
		uint32_t uncompressedSize;
		uint32_t compressedSize;
		uint8_t checksum;
        uint8_t spare[7];
	} header;
	fread(&header, 1, sizeof(header), in);
	printf("Uncompressed size: %d, compressed size: %d, checksum: %02X\n", header.uncompressedSize, header.compressedSize, header.checksum);
    unsigned char* buffer = (unsigned char*) malloc(sizeof(char) * header.compressedSize);
    fread(buffer, 1, header.compressedSize, in);
	fclose(in);	
	fclose(out);	

	in = fopen("conv", "rb");
	out = fopen("tmp2.lzs", "wb");
	lzss(in, out);

	fclose(in);	
	fclose(out);	

	//return;
	in = fopen("tmp.lzs", "rb");
	out = fopen("conv2", "r+b");
	unlzss(in, out);
	fclose(in);	
	int fileSize = ftell(out);

    buffer = (unsigned char*) malloc(sizeof(char) * fileSize);
	rewind(out);
	fread(buffer, 1, fileSize, out);
	fclose(out);
	
	ARMThumb_Convert(buffer, fileSize, 0, 0);
	out = fopen("u-boot.tmp", "wb");
	fwrite(buffer, 1, fileSize, out);
	fclose(out);
	
	unsigned char checksum = 0;	int i;
	for (i = 0; i < fileSize; ++i) checksum += buffer[i];
	printf("Unlzss file size: %d bytes, checksum: %02X\n", fileSize, checksum);
    free(buffer);
	exit(0);
}

int main(int argc, char *argv[]) {
	//test();
    printf("\nLG Electronics digital TV firmware package (EPK) extractor 3.9 by sirius (http://openlgtv.org.ru)\n\n");
	if (argc < 2) {
		printf("Thanks to xeros, tbage, jenya, Arno1, rtokarev, cronix, lprot, Smx and all other guys from openlgtv project for their kind assistance.\n\n");
		printf("Usage: epk2extract [-options] FILENAME\n\n");
		printf("Options:\n");
		printf("  -c : extract to current directory instead of source file directory\n");
		#ifdef __CYGWIN__
			puts("\nPress any key to continue...");
			getch();
		#endif
		exit(1);
	}

	current_dir = malloc(PATH_MAX);
	getcwd(current_dir, PATH_MAX);
	printf("Current directory: %s\n", current_dir);
	readlink("/proc/self/exe", exe_dir, 1024);
	config_opts.config_dir = dirname(exe_dir);
	config_opts.dest_dir = NULL;

	int opt;
	while ((opt = getopt(argc, argv, "c")) != -1) {
		switch (opt) {
		case 'c': {
			config_opts.dest_dir = current_dir;
			break;
		}
		case ':': {
			printf("Option `%c' needs a value\n\n", optopt);
			exit(1);
			break;
		}
		case '?': {
			printf("Unknown option: `%c'\n\n", optopt);
			exit(1);
		}
		}
	}

	#ifdef __CYGWIN__
		char posix[PATH_MAX];
		cygwin_conv_path(CCP_WIN_A_TO_POSIX, argv[optind], posix, PATH_MAX);
		char *input_file = posix;
	#else
		char *input_file = argv[optind];
	#endif
	printf("Input file: %s\n", input_file);
	if (config_opts.dest_dir == NULL) config_opts.dest_dir = dirname(strdup(input_file));
	printf("Destination directory: %s\n", config_opts.dest_dir);
	int exit_code = handle_file(input_file, &config_opts);
	if(exit_code == EXIT_FAILURE) {
		printf("Unsupported input file format: %s\n\n", input_file);
		#ifdef __CYGWIN__
			puts("Press any key to continue...");
			getch();
		#endif
		return exit_code;
	}
	printf("\nExtraction is finished.\n\n");
	#ifdef __CYGWIN__
		puts("Press any key to continue...");
		getch();
	#endif
	return exit_code;
}