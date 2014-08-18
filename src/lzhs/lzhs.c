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
int	match_len, match_pos, lson[N + 1], rson[N + 257], dad[N + 1];


void init_tree(void) { 
		unsigned i;
	/* For i = 0 to N - 1, g_right_child[i] and g_left_child[i] will be the right and
	   left children of node i.  These nodes need not be initialized.
	   Also, g_parent[i] is the parent of node i.  These are initialized to
	   NIL (= N), which stands for 'not used.'
	   For i = 0 to 255, g_right_child[N + i + 1] is the root of the tree
	   for strings that begin with character i.  These are initialized
	   to NIL.  Note there are 256 trees. */
	for(i = N + 1; i <= N + 256; i++)
		rson[i] = NIL;
	for(i = 0; i < N; i++)
		dad[i] = NIL;
}

void lazy_match(int r)
{
	unsigned char *key;
	int i, p;
	int cmp;
	unsigned tmp;
	
	tmp=0;
	if(match_len <= F-THRESHOLD ){
		cmp = 1;
		key = &text_buf[r+1];
		p = key[0] + N + 1;
		tmp=0;
		while(1)
		{
			if(cmp >= 0)
			{
				if(rson[p] != NIL)
					p = rson[p];
				else break;
			}
			else
			{
				if(lson[p] != NIL)
					p = lson[p];
				else break;
			}
			for(i = 1; i <= F-1; i++)
			{
				cmp = key[i] - text_buf[p + i];
				if(key[i] != text_buf[p + i])
					break;
			}
			if(i > tmp)
			{
				tmp = i;
				if(i > F-1)
					break;
			}
		}
	}
	if (tmp > match_len) match_len = 0;
}

void insert_node(int r)
{
	unsigned char *key;
	unsigned i, p;
	int cmp;
	unsigned tmp;

	cmp = 1;
	key = &text_buf[r];
	p = N + 1 + key[0];
	rson[r] = lson[r] = NIL;
	match_len = 0;
	while(1)
	{
		if(cmp >= 0)
		{
			if(rson[p] != NIL)
				p = rson[p];
			else
			{
				rson[p] = r;
				dad[r] = p;
				lazy_match(r);
				return;
			}
		}
		else
		{
			if(lson[p] != NIL)
				p = lson[p];
			else
			{
				lson[p] = r;
				dad[r] = p;
				lazy_match(r);
				return;
			}
		}
		for(i = 1; i < F; i++)
		{
			cmp = key[i] - text_buf[p + i];
			if(cmp != 0)
				break;
		}
		if(i >= match_len){
			if(r<p) tmp=r-p+N;
			else tmp=r-p;
			if(i==match_len){
				if(tmp<match_pos) match_pos=tmp;
			} else {
				match_pos=tmp;
			}
			match_len=i;
			if(i>F-1) break;
		}

	}
	dad[r] = dad[p];
	lson[r] = lson[p];
	rson[r] = rson[p];
	dad[lson[p]] = r;
	dad[rson[p]] = r;
	if(rson[dad[p]] == p)
		rson[dad[p]] = r;
	else
		lson[dad[p]] = r;
	dad[p] = NIL;  /* remove p */
}

void delete_node(unsigned p) {
	unsigned q;

	if(dad[p] == NIL)
		return; /* not in tree */
	if(rson[p] == NIL)
		q = lson[p];
	else if(lson[p] == NIL)
		q = rson[p];
	else
	{
		q = lson[p];
		if(rson[q] != NIL)
		{
			do q = rson[q];
			while(rson[q] != NIL);
			rson[dad[q]] = lson[q];
			dad[lson[q]] = dad[q];
			lson[q] = lson[p];
			dad[lson[p]] = q;
		}
		rson[q] = rson[p];
		dad[rson[p]] = q;
	}
	dad[q] = dad[p];
	if(rson[dad[p]] == p)
		rson[dad[p]] = q;
	else
		lson[dad[p]] = q;
	dad[p] = NIL;
}

void lzss(FILE *infile, FILE *outfile)
{
	unsigned i, len, r, s, last_match_length, code_buf_ptr;
	unsigned char code_buf[32], mask;
	int c;

	init_tree();  /* initialize trees */
	/* code_buf[1..16] saves eight units of code, and code_buf[0] works as
	eight flags, "1" representing that the unit is an unencoded letter (1 byte),
	"0" a position-and-length pair (3 bytes). Thus, eight units require at most
	16 bytes of code. */
	code_buf[0] = 0;
	code_buf_ptr = mask = 1;
	s = 0;
	r = N - F;
	/* Clear the buffer with any character that will appear often. */
	memset(text_buf + s, ' ', r - s);
	/* Read F bytes into the last F bytes of the buffer */
	for(len = 0; len < F; len++)
	{
		c = getc(infile);
		if(c == EOF)
			break;
		text_buf[r + len] = c;
	}
	textsize = len;
	if(textsize == 0) /* text of size zero */
		return;
	/* Insert the whole string just read. The global variables
	match_len and match_pos are set. */
	insert_node(r);
	do
	{
	/* match_len may be spuriously long near the end of text. */
		if(match_len > len)
			match_len = len;
	/* Not long enough match.  Send one byte. */
		if(match_len <= THRESHOLD)
		{
			match_len = 1;
			code_buf[0] |= mask;  /* 'send one byte' flag */
			code_buf[code_buf_ptr++] = text_buf[r];  /* Send uncoded. */
	/* Send position and length pair. Note match_len > THRESHOLD. */
		}
		else
		{
			code_buf[code_buf_ptr++] = (unsigned char)match_len - (THRESHOLD + 1); //store length
			code_buf[code_buf_ptr++] = match_pos >> 8;
			code_buf[code_buf_ptr++] = (unsigned char)match_pos;
		}
		/* Shift mask left one bit. */
		mask <<= 1;
		if(mask == 0)
		{
			/* Send at most 8 units of code together */
			for(i = 0; i < code_buf_ptr; i++)
				putc(code_buf[i], outfile);
			codesize += code_buf_ptr;
			code_buf[0] = 0;
			code_buf_ptr = mask = 1;
		}
		last_match_length = match_len;
		for(i = 0; i < last_match_length; i++)
		{
			c = getc(infile);
			if(c == EOF)
				break;
			/* Delete old strings and read new bytes */
			delete_node(s);
			text_buf[s] = c;
		/* If the position is near the end of buffer, extend the buffer
		to make string comparison easier. */
			if(s < F - 1)
				text_buf[s + N] = c;
		/* Since this is a ring buffer, increment the position modulo N. */
			s = (s + 1) & (N - 1);
			r = (r + 1) & (N - 1);
		/* Register the string in text_buf[r..r+F-1] */
			insert_node(r);
		}
		/* Reports progress each time the textsize exceeds multiples of 1024. */
		textsize += i;
		/*if(textsize > g_print_count)
		{
			printf("%12ld\r", textsize);
			g_print_count += 1024;
		}*/
		while(i++ < last_match_length)/* After the end of text, */
		{
			delete_node(s);		/* no need to read, but */
			s = (s + 1) & (N - 1);
			r = (r + 1) & (N - 1);
			len--;
			if(len)
				insert_node(r);/* buffer may not be empty. */
		}
	} while(len > 0); /* until length of string to be processed is zero */
	/* Send remaining code. */
	if(code_buf_ptr > 1)
	{
		for(i = 0; i < code_buf_ptr; i++)
			putc(code_buf[i], outfile);
		codesize += code_buf_ptr;
	}
	/* Encoding is done. */
	printf("LZSS In : %ld bytes\n", textsize);
	printf("LZSS Out: %ld bytes\n", codesize);
	/* xxx - floating-point math: */
	printf("LZSS Out/In: %.3f\n", (double)codesize / textsize);

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
                putc(text_buf[r++] = text_buf[(r - 1 - i) & (N - 1)], out);
                r &= (N - 1);
            }
        }
    }
}

void huff(FILE* in, FILE* out) {
    uint32_t preno = 0, precode = 0;
    void putChar(uint32_t code, uint32_t no) {
        uint32_t tmpno, tmpcode;
        codesize += no;
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
            putChar(*(uint32_t*)&char_len_table[8 * c], 
                *(uint32_t*)&char_len_table[8 * c + 4]); // lookup in char table
        } else {
            if ((j = getc(in)) == EOF) break; // match length
            if ((i = getc(in)) == EOF) break; // byte1 of match position
            if ((m = getc(in)) == EOF) break; // byte0 of match position
            putChar(*(uint32_t*)&char_len_table[8 * (j + 256)], *(uint32_t*)&char_len_table[8 * (j + 256) + 4]); // lookup in len table
            i = m | (i << 8);            
            putChar(*(uint32_t*)&pos_table[8 * (i >> 7)], *(uint32_t*)&pos_table[8 * (i >> 7) + 4]); // lookup in pos table
            putChar(i - (i >> 7 << 7), 7);
        }
    }
    putc(precode << (8 - preno), out);
    codesize += preno;
    codesize = (unsigned int)codesize >> 3;
    printf("LZHS Out(%d)/In(%d): %.4f\n", codesize, textsize, (double)codesize / textsize);
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
        for (i = 0; i < 288; i++) {
            if ( *(uint32_t*)&char_len_table[8 * i + 4] == len && *(uint32_t*)&char_len_table[8 * i] == code) {
                if (i > 255) {
                    code_buf[code_buf_ptr++] = i - 256;
                    code = len = 0;
                    while (1) {
                        if (!getData()) return;
                        for (j = 0; j < 32; j++) {
                            if ( *(uint32_t*)&pos_table[8 * j + 4] == len && *(uint32_t*)&pos_table[8 * j] == code) {
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


int PreprocessInputFile(const char *filename, const char *outfilename){
  signed int result;
  int v4;
  size_t n;
  char *ptr;
  FILE *infile, *outfile;
  int input_filesize;
  infile = fopen(filename, "rb");
  if ( infile )
  {
    outfile = fopen(outfilename, "wb");
	if ( outfile )
    {
	
	fseek (infile , 0 , SEEK_END);
	size_t filesize = ftell(infile);
	rewind(infile);
    ptr = malloc (sizeof(char)*filesize);
	int extrabytes=0;
      for ( input_filesize = 0; ; input_filesize += n ) //start a loop. add read elements every iteration
      {
		n = fread(ptr, 1u, 0x200u, infile); //read 512 bytes from input into ptr
        if ( n <= 0 ){
		  break;
		  }
		if(n%16 != 0){
			unsigned int x = (n/8)*8; //it will be truncated, so we get next multiple
			if(x < n) x+=8;
			x = x - n; //how many bytes we need to add
			extrabytes+=x; //add the bytes to the counter
		}
        fwrite(ptr, 1u, n, outfile); //write read bytes to output
      }
	  printf("We need to fill extra %d bytes\n",extrabytes);
		int i;
		for(i=1; i<=extrabytes; i++){
		putc(0xff, outfile);
	  }
      fclose(infile);
      fclose(outfile);
      result = 0;
    }
    else
    {
      printf("open file %s fail\n", outfilename);
      result = 1;
    }
  }
  else
  {
    printf("open file %s fail \n", filename);
    result = 1;
  }
  return result;
}

int is_lzhs_mem(unsigned char *buf){
	int result = 0;
	struct lzhs_header *header = (struct lzhs_header *)buf;
	if (!header->compressedSize || !header->uncompressedSize) return result;
	if ((header->compressedSize <= header->uncompressedSize) && !memcmp(&header->spare, "\x00\x00\x00\x00\x00\x00\x00", sizeof(header->spare))) result=1;
	return result;
}

void lzhs_encode(const char *infile, const char *outfile){
	FILE *in, *out;
	unsigned char *buf;
	int fsize;

	char *filedir = malloc(strlen(infile));
	char *outtmp = malloc(strlen(infile)+5);

	printf("\nStep1: Padding...\n");
	sprintf(outtmp, "%s.tmp", infile);
	PreprocessInputFile(infile, outtmp);

	in=fopen(outtmp, "rb");
	if(!in){ printf("Cannot open file %s\n", infile); exit(1); }

	strcpy(outtmp, infile);
	strcpy(filedir, dirname(outtmp));

	strcpy(outtmp, filedir);
	strcat(outtmp, "/conv");

	out=fopen(outtmp, "wb");
	if(!out){ printf("Cannot open file conv\n"); exit(1); }

	fseek(in, 0, SEEK_END);
	fsize = ftell(in);
	buf = malloc(fsize);

	rewind(in);
	fread(buf, 1, fsize, in);

	printf("Step 2: Calculating Checksum...\n");
	unsigned char checksum = 0; int i;
 	for (i = 0; i < fsize; ++i) checksum += buf[i];
	printf("Checksum = %x\n", checksum); 

	printf("Step 3: Converting ARM => Thumb...\n");
	ARMThumb_Convert(buf, fsize, 0, 1);
	fwrite(buf, 1, fsize, out);
	free(buf);

	freopen(outtmp, "rb", in);
	if(!in){ printf("Cannot open file conv\n", infile); exit(1); }

	strcpy(outtmp, filedir);
	strcat(outtmp, "/tmp.lzs");

	freopen(outtmp, "wb", out);

	printf("Step 4: Encoding with LZSS...\n");
	lzss(in, out);
	if(!out){ printf("Cannot open tmp.lzs\n"); exit(1); }

	freopen(outtmp, "rb", in);
	if(!in){ printf("Cannot open file tmp.lzs\n", infile); exit(1); }
	freopen(outfile, "wb", out);
	if(!out){ printf("Cannot open file %s\n", outfile); exit(1); }

	printf("Step 5: Encoding with Huffman...\n");
	
	for(i=0; i<sizeof(struct lzhs_header); i++)
		fputc(0x00, out); //prepare header

	huff(in, out);
	printf("Writing Header...\n");
	printf("!!FIXME: header uncompressed and compressed sizes are not correct!!\n");
	rewind(out);
	fwrite(&textsize, 1, sizeof(unsigned int), out);
	fwrite(&codesize, 1, sizeof(unsigned int), out);
	fputc(checksum, out);
	printf("Done!\n");

	fclose(in);
	fclose(out);
	/*unlink("tmp.lzs");
	unlink("conv");*/
}

void lzhs_decode(const char *infile, const char *outfile){
	FILE *in, *out;
	unsigned char *buf;
	struct lzhs_header *header;
	int fsize;

	in = fopen(infile, "rb");
	if(!in){ printf("Cannot open %s\n", infile); exit(1); }
	out = fopen("tmp.lzs", "wb");
	if(!out){ printf("Cannot open %s\n", outfile); exit(1); }

	header = malloc(sizeof(struct lzhs_header));
	fread((unsigned char *)header, 1, sizeof(struct lzhs_header), in);
	printf("\n---LZHS Details---\n");
	printf("Compressed:\t%d\n", header->compressedSize);
	printf("Uncompressed:\t%d\n", header->uncompressedSize);
	printf("Checksum:\t0x%x\n\n", header->checksum);

	printf("Step 1: Decoding Huffman...\n");
	unhuff(in, out);

	freopen("tmp.lzs", "rb", in);
	if(!in){ printf("Cannot open %s\n", infile); exit(1); }
	freopen("conv", "wb", out);
	if(!out){ printf("Cannot open %s\n", outfile); exit(1); }
	printf("Step 2: Decoding LZSS...\n");
	unlzss(in, out);
	fsize = ftell(out);

	freopen("conv", "rb", in);
	if(!in){ printf("Cannot open %s\n", infile); exit(1); }
	freopen(outfile, "wb", out);
	if(!out){ printf("Cannot open %s\n", outfile); exit(1); }

	buf = malloc(fsize);
	fread(buf, 1, fsize, in);
	printf("Step 3: Converting Thumb => ARM...\n");
	ARMThumb_Convert(buf, fsize, 0, 0);
	fwrite(buf, 1, fsize, out);
	free(buf);

	fclose(in);
	fclose(out);

	unlink("tmp.lzs");
	unlink("conv");
}

void scan_lzhs(const char *filename, int extract){
	int fsize, i, n, pos;
	unsigned char hdata[16];
	int count=0;
	lzhs_header_t *header = malloc(sizeof(lzhs_header_t));
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

	for(i=0; ;i+=16){
		n = fread(hdata, 1, 16, file);
		if(n<16) break;
		if(is_lzhs_mem(hdata)){
			count++;
			pos = ftell(file)-16;
			header = (lzhs_header_t *)hdata;
			printf("\nFound LZHS Header at 0x%x\n", pos);
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
				buf = malloc(header->compressedSize);
				fread(buf, 1, header->compressedSize, file);
				fwrite(buf, 1, header->compressedSize, out);
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
