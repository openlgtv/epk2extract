#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>

#include <config.h>
#include <lzhs/lzhs.h>
#include <lzhs/tables.h>

//globals
unsigned long int textsize = 0, codesize = 0;
unsigned char text_buf[N + F - 1];
int match_length, match_position, lson[N + 1], rson[N + 257], dad[N + 1];
t_code (*huff_char)[1] = (void *)&char_table;
t_code (*huff_len)[1]  = (void *)&len_table;
t_code (*huff_pos)[1]  = (void *)&pos_table;

void InitTree(void) { 
    int  i;
    for (i = N + 1; i <= N + 256; i++) rson[i] = N;
    for (i = 0; i < N; i++) dad[i] = N;
}

static void lazy_match(int r) {
    unsigned char *key;
    int i, p, cmp = 1, tmp = 0;
	
    if (match_length <= F - THRESHOLD ) {
       key = &text_buf[r + 1];
       p = key[0] + N + 1;
       while(1) {
           if (cmp >= 0) {
               if (rson[p] != N) p = rson[p];
               else break;
           } else {
               if (lson[p] != N) p = lson[p];
               else break;
           }
           for (i = 1; i <= F - 1; i++) {
               cmp = key[i] - text_buf[p + i];
               if (key[i] != text_buf[p + i]) break;
           }
           if (i > tmp)
               if ((tmp = i) > F - 1) break;
       }
    }
    if (tmp > match_length) match_length = 0;
}

void InsertNode(int r) {
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
        for (i = 1; ; ++i) {
            if (i < F) {
                cmp = key[i] - text_buf[p + i];
                if (key[i] == text_buf[p + i]) continue;
            }
            break;
        }
        if (i >= match_length) {
            if ( r < p )
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
                if ((match_length = i) > F - 1) break;
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
	if (dad[p] == N) return; 
	if (rson[p] == N)
        q = lson[p];
	else 
        if (lson[p] == N) 
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
            rson[q] = rson[p];  dad[rson[p]] = q;
        }
	dad[q] = dad[p];
	if (rson[dad[p]] == p)
        rson[dad[p]] = q;
    else 
        lson[dad[p]] = q;
	dad[p] = N;
}

void lzss(FILE* infile, FILE* outfile) {
     int c, i, len, r, s, last_match_length, code_buf_ptr;
     unsigned char code_buf[32], mask;

     InitTree();
     code_buf[0] = 0;
     code_buf_ptr = mask = 1;
     s = codesize = 0; r = N - F;

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
        for (i = 0; i < code_buf_ptr; i++) {
            putc(code_buf[i], outfile);
            codesize++;
        }
     }
     printf("LZSS Out(%ld)/In(%ld): %.3f\n", codesize, textsize, (double)codesize / textsize);
}

void unlzss(FILE *in, FILE *out) {
    int c, i, j, k, m, r = 0, flags = 0;
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
            if ((j = getc(in)) == EOF) break; // match length
            if ((i = getc(in)) == EOF) break; // byte1 of match position
            if ((m = getc(in)) == EOF) break; // byte0 of match position
            i = (i << 8) | m;
            for (k = 0; k <= j + THRESHOLD; k++) {
                m = text_buf[(r - i) & (N - 1)];
                putc(text_buf[r++] = m, out);
                r &= (N - 1);
            }
        }
    }
}

void huff(FILE* in, FILE* out) {
    uint32_t preno = 0, precode = 0;
    void putChar(uint32_t code, uint32_t no) {
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
    textsize = codesize; codesize = 0;
    int c, i, j, k, m, flags = 0;
    while (1) {
        if (((flags >>= 1) & 256) == 0) {
            if ((c = getc(in)) == EOF) break;
            flags = c | 0xFF00;
        }
        if (flags & 1) {
            if ((c = getc(in)) == EOF) break;
            putChar(huff_char[c]->code, 
	                huff_char[c]->len); // lookup in char table
        } else {
            if ((j = getc(in)) == EOF) break; // match length
            if ((i = getc(in)) == EOF) break; // byte1 of match position
            if ((m = getc(in)) == EOF) break; // byte0 of match position
            putChar(huff_len[j]->code,
					huff_len[j]->len); // lookup in len table
            i = m | (i << 8);            
            putChar(huff_pos[(i >> 7)]->code,
	    huff_pos[(i >> 7)]->len); // lookup in pos table
            putChar(i - (i >> 7 << 7), 7);
        }
    }
    putc(precode << (8 - preno), out);
    codesize = ftell(out) - sizeof(struct lzhs_header);
    printf("LZHS Out(%ld)/In(%ld): %.4f\n", codesize, textsize, (double)codesize / textsize);
}

void unhuff(FILE* in, FILE* out) {
    uint32_t i, j, k, c, code = 0, index = 8, len = 0, code_buf_ptr;
    unsigned char code_buf[32], mask;
    code_buf[0] = 0;
    code_buf_ptr = mask = 1;
    
    int getData() {
        if (index > 7) {
            index = 0;
            if ((c = getc(in)) == EOF) {
                if (code_buf_ptr > 1) // flushing buffer
                    for (i = 0; i < code_buf_ptr; i++)
                        putc(code_buf[i], out);
                return 0;        
            }
        }
        code = (code << 1) | (c >> 7 - index++) & 1; // get bit msb - index
        len++;
        return 1;
    }
  
    while (1) {
        if (!getData()) return;
        if (len < 4) continue; // len in code_len table should be min 4
        for (i = 0; i < 288; i++) {
            if (huff_char[i]->len == len && huff_char[i]->code == code) {
                if (i > 255) {
                    code_buf[code_buf_ptr++] = i - 256;
                    code = len = 0;
                    while (1) {
                        if (!getData()) return;
                        if (len < 2) continue; // len in pos table should be min 2
                        for (j = 0; j < 32; j++) {
                            if (huff_pos[j]->len == len && huff_pos[j]->code == code) {
                                code_buf[code_buf_ptr++] = j >> 1;
                                k = -1;
                                break;
                            }
                        }
                        if (k == -1) break;
                    }
                    code = 0;
                    for (k = 0; k < 7; k++) 
                        if (!getData()) return;
                    code_buf[code_buf_ptr++] = code | (j << 7);
                    code = len = 0;
                } else {
            		code_buf[0] |= mask; 
                    code_buf[code_buf_ptr++] = i; 
                    code = len = 0;
                }
                if ((mask <<= 1) == 0) { 
                    for (j = 0; j < code_buf_ptr; j++)
                        putc(code_buf[j], out); 
                    code_buf[0] = 0;  
                    code_buf_ptr = mask = 1;
                }
                break;
            }
        }
    }
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

int lzhs_pad_file(const char *filename, const char *outfilename) {
    int input_filesize;
    size_t n;
    char *ptr;
    FILE *infile, *outfile;
    infile = fopen(filename, "rb");
    if (infile) {
       outfile = fopen(outfilename, "wb");
       if (outfile) {
          fseek (infile , 0, SEEK_END);
	  size_t filesize = ftell(infile);
	  rewind(infile);
          ptr = malloc(sizeof(char)*filesize);
	  int extrabytes = 0;
          for (input_filesize = 0; ; input_filesize += n ) { //start a loop. add read elements every iteration
              n = fread(ptr, 1u, 0x200u, infile); //read 512 bytes from input into ptr
              if (n <= 0) break;
              if (n % 16 != 0) {
	         unsigned int x = (n/8)*8; //it will be truncated, so we get next multiple
		 if (x < n) x += 8;
		 x = x - n; //how many bytes we need to add
		 extrabytes += x; //add the bytes to the counter
              }
              fwrite(ptr, 1u, n, outfile); //write read bytes to output
          }
	  printf("We need to fill extra %d bytes\n", extrabytes);
	  int i;
	  for (i=1; i <= extrabytes; i++) putc(0xff, outfile);
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
     unsigned char checksum = 0; int i;
     for (i = 0; i < fsize; ++i) checksum += buf[i];
     return checksum;
}

void lzhs_encode(const char *infile, const char *outfile){
     struct lzhs_header header;
     FILE *in, *out;
     unsigned char *buf;
     int fsize;

     char *filedir = malloc(strlen(infile));
     char *outtmp = malloc(strlen(infile)+5);

     printf("\n[LZHS] Padding...\n");
     sprintf(outtmp, "%s.tmp", infile);
     lzhs_pad_file(infile, outtmp);

     in = fopen(outtmp, "rb");
     if(!in){ printf("Cannot open file %s\n", infile); exit(1); }

     strcpy(outtmp, infile);
     strcpy(filedir, dirname(outtmp));
     strcpy(outtmp, filedir);
     strcat(outtmp, "/conv");

     out = fopen(outtmp, "wb");
     if(!out){ printf("Cannot open file conv\n"); exit(1); }

     fseek(in, 0, SEEK_END);
     fsize = ftell(in);
     rewind(in);

     buf = malloc(fsize);
     fread(buf, 1, fsize, in);

     printf("[LZHS] Calculating checksum...\n");
     header.checksum = lzhs_calc_checksum(buf, fsize);
     memset(&header.spare, 0, sizeof(header.spare));
     printf("Checksum = %x\n", header.checksum);

     printf("[LZHS] Converting ARM => Thumb...\n");
     ARMThumb_Convert(buf, fsize, 0, 1);
     fwrite(buf, 1, fsize, out);
     free(buf);

     freopen(outtmp, "rb", in);
     if(!in){ printf("Cannot open file conv\n", infile); exit(1); }

     strcpy(outtmp, filedir);
     strcat(outtmp, "/tmp.lzs");
     freopen(outtmp, "wb", out);

     printf("[LZHS] Encoding with LZSS...\n");
     lzss(in, out);
     if(!out){ printf("Cannot open tmp.lzs\n"); exit(1); }

     freopen(outtmp, "rb", in);
     if(!in){ printf("Cannot open file tmp.lzs\n", infile); exit(1); }
     freopen(outfile, "wb", out);
     if(!out){ printf("Cannot open file %s\n", outfile); exit(1); }

     printf("[LZHS] Encoding with Huffman...\n");
     header.uncompressedSize = textsize;
     fwrite(&header, 1, sizeof(header), out);

     huff(in, out);
     header.compressedSize = codesize;
     printf("[LZHS] Writing Header...\n");
     rewind(out);
     fwrite(&header, 1, sizeof(header), out);
     printf("[LZHS] Done!\n");

     fclose(in);
     fclose(out);
}

void lzhs_decode(const char *infile, const char *outfile){
	FILE *in, *out;
	unsigned char *buf;
	struct lzhs_header header;
	int fsize;

	in = fopen(infile, "rb");
	if(!in){ printf("Cannot open %s\n", infile); exit(1); }
	out = fopen("tmp.lzs", "wb");
	if(!out){ printf("Cannot open %s\n", outfile); exit(1); }
    
	fread(&header, 1, sizeof(header), in);
	printf("\n---LZHS details---\n");
	printf("Compressed:\t%d\n", header.compressedSize);
	printf("Uncompressed:\t%d\n", header.uncompressedSize);
	printf("Checksum:\t0x%x\n\n", header.checksum);

	printf("[LZHS] Decoding Huffman...\n");
	unhuff(in, out);

	freopen("tmp.lzs", "rb", in);
	if(!in){ printf("Cannot open %s\n", infile); exit(1); }
	freopen("conv", "wb", out);
	if(!out){ printf("Cannot open %s\n", outfile); exit(1); }
	printf("[LZHS] Decoding LZSS...\n");
	unlzss(in, out);
	fsize = ftell(out);

	freopen("conv", "rb", in);
	if(!in){ printf("Cannot open %s\n", infile); exit(1); }
	freopen(outfile, "wb", out);
	if(!out){ printf("Cannot open %s\n", outfile); exit(1); }

	buf = malloc(fsize);
	fread(buf, 1, fsize, in);
	printf("[LZHS] Converting Thumb => ARM...\n");
	ARMThumb_Convert(buf, fsize, 0, 0);
	fwrite(buf, 1, fsize, out);

        printf("[LZHS] Calculating checksum...\n");
	uint8_t checksum = lzhs_calc_checksum(buf, fsize);
        printf("Calculated checksum = 0x%x\n", checksum);
	if(checksum != header.checksum)
		printf("[LZHS] WARNING: Checksum mismatch (expected 0x%x)!!\n", header.checksum);
	if(fsize != header.uncompressedSize)
		printf("[LZHS] WARNING: Size mismatch (got %d, expected %d)!!\n", fsize, header.uncompressedSize);
	free(buf);
	fclose(in);
	fclose(out);
	//unlink("tmp.lzs");
	//unlink("conv");
}

void extract_lzhs(const char *filename) {
	int fsize, i, n, pos;
	int count=0;
	struct lzhs_header header;
	char *outname, *outdecode;
	unsigned char *buf;
   
	outname = malloc(PATH_MAX);
	outdecode = malloc(PATH_MAX);

	FILE *file = fopen(filename, "rb");
	FILE *out = NULL;
	if(file == NULL){
		printf("Can't open file %s\n", filename);
		exit(1);
	}

	sprintf(outname, "%s/%s_file%d.lzhs", dirname(strdup(filename)), basename(strdup(filename)), count);
	printf("Extracting to %s\n", outname);
	out = fopen(outname, "wb");
	if(out == NULL){
		printf("Cannot open file %s for writing\n", outname);
		fclose(file);
		exit(1);
	}
    fseek(file, 0xA040, SEEK_SET);
    fread(&header, 1, sizeof(header), file);
    fwrite(&header, 1, sizeof(header), out);
    buf = malloc(header.compressedSize);
    fread(buf, 1, header.compressedSize, file);
    fwrite(buf, 1, header.compressedSize, out);
    fclose(out);
    free(buf);
    sprintf(outdecode, "%s/%s_file%d.unlzhs", dirname(strdup(filename)), basename(strdup(filename)), count++);
	lzhs_decode(outname, outdecode);

	sprintf(outname, "%s/%s_file%d.lzhs", dirname(strdup(filename)), basename(strdup(filename)), count);
	printf("Extracting to %s\n", outname);
	out = fopen(outname, "wb");
	if(out == NULL){
		printf("Cannot open file %s for writing\n", outname);
		fclose(file);
		exit(1);
	}
    fseek(file, 0x80000, SEEK_SET);
    fread(&header, 1, sizeof(header), file);
    fwrite(&header, 1, sizeof(header), out);
    buf = malloc(header.compressedSize);
    fread(buf, 1, header.compressedSize, file);
    fwrite(buf, 1, header.compressedSize, out);
    fclose(out);
    free(buf);
    sprintf(outdecode, "%s/%s_file%d.unlzhs", dirname(strdup(filename)), basename(strdup(filename)), count++);
	lzhs_decode(outname, outdecode);

    fseek(file, 0, SEEK_END);
    fsize = ftell(file);
    if (0x80000 + 0x10 + header.compressedSize + (16 - header.compressedSize % 16) + 0x200 < fsize) {
	sprintf(outname, "%s/%s_file%d.lzhs", dirname(strdup(filename)), basename(strdup(filename)), count);
	printf("Extracting to %s\n", outname);
	out = fopen(outname, "wb");
	if(out == NULL){
		printf("Cannot open file %s for writing\n", outname);
		fclose(file);
		exit(1);
	}
    fseek(file, 0x80000 + 0x10 + header.compressedSize + (16 - header.compressedSize % 16) + 0x200, SEEK_SET);
    fread(&header, 1, sizeof(header), file);
    fwrite(&header, 1, sizeof(header), out);
    buf = malloc(header.compressedSize);
    fread(buf, 1, header.compressedSize, file);
    fwrite(buf, 1, header.compressedSize, out);
    fclose(out);
    free(buf);
    sprintf(outdecode, "%s/%s_file%d.unlzhs", dirname(strdup(filename)), basename(strdup(filename)), count);
	lzhs_decode(outname, outdecode);
    }
}

void scan_lzhs(const char *filename, int extract){
    int is_lzhs_mem(struct lzhs_header *header){
        if ((header->compressedSize <= 0xFFFFFF) && (header->uncompressedSize >= 0x1FFFFFF)) return 0;
        if (header->compressedSize && header->uncompressedSize && (header->compressedSize <= header->uncompressedSize) && 
            !memcmp(&header->spare, "\0\0\0\0\0\0\0", sizeof(header->spare))) return 1;
        return 0;
    }

	int fsize, i, n, pos;
	int count=0;
	struct lzhs_header header;
	char *outname, *outdecode;
	unsigned char *buf;

	if(extract){
		outname = malloc(PATH_MAX);
		outdecode = malloc(PATH_MAX);
	}

	FILE *file = fopen(filename, "rb");
	FILE *out = NULL;
	if(file == NULL){
		printf("Can't open file %s\n", filename);
		exit(1);
	}

	for(i=0; ;i+=sizeof(header)){
		n = fread(&header, 1, sizeof(header), file);
		if(n<sizeof(header)) break;
		if(is_lzhs_mem(&header)){
			count++;
			pos = ftell(file)-sizeof(header);
			printf("\nFound LZHS header at 0x%x\n", pos);
			if(extract){
				sprintf(outname, "%s/%s_file%d.lzhs", dirname(strdup(filename)), basename(strdup(filename)), count);
				printf("Extracting to %s\n", outname);
				out = fopen(outname, "wb");
				if(out == NULL){
					printf("Cannot open file %s for writing\n", outname);
					fclose(file);
					exit(1);
				}
				fseek(file, pos, SEEK_SET);
				buf = malloc(header.compressedSize);
				fread(buf, 1, header.compressedSize, file);
				fwrite(buf, 1, header.compressedSize, out);
				fclose(out);
				free(buf);

				if(is_lzhs(outname)){
					sprintf(outdecode, "%s/%s_file%d.unlzhs", dirname(strdup(filename)), basename(strdup(filename)), count);
					lzhs_decode(outname, outdecode);
				} else
					printf("%s is not a valid lzhs file!, skipping...\n", outname);
			}
		}
	}
}