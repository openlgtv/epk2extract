#include <stdio.h>
#include <ctype.h>
#define __USE_XOPEN_EXTENDED
#include <ftw.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <termios.h>
#include <config.h>
#include <openssl/aes.h>
#include <inttypes.h>

void getch(void) {
    struct termios oldattr, newattr;
    int ch;
    tcgetattr( STDIN_FILENO, &oldattr );
    newattr = oldattr;
    newattr.c_lflag &= ~( ICANON | ECHO );
    tcsetattr( STDIN_FILENO, TCSANOW, &newattr );
    ch = getchar();
    tcsetattr( STDIN_FILENO, TCSANOW, &oldattr );
}

void hexdump(void *pAddressIn, long lSize) {
	char szBuf[100];
	long lIndent = 1;
	long lOutLen, lIndex, lIndex2, lOutLen2;
	long lRelPos;
	struct {
		char *pData;
		unsigned long lSize;
	} buf;
	unsigned char *pTmp, ucTmp;
	unsigned char *pAddress = (unsigned char *) pAddressIn;

	buf.pData = (char *) pAddress;
	buf.lSize = lSize;

	while (buf.lSize > 0) {
		pTmp = (unsigned char *) buf.pData;
		lOutLen = (int) buf.lSize;
		if (lOutLen > 16) lOutLen = 16;

		// create a 64-character formatted output line:
		sprintf(szBuf, " >                                                      %08zX", pTmp - pAddress);
		lOutLen2 = lOutLen;

		for (lIndex = 1 + lIndent, lIndex2 = 53 - 15 + lIndent, lRelPos = 0; lOutLen2; lOutLen2--, lIndex += 2, lIndex2++) {
			ucTmp = *pTmp++;
			sprintf(szBuf + lIndex, "%02X ", (unsigned short) ucTmp);
			if (!isprint(ucTmp))
				ucTmp = '.'; // nonprintable char
			szBuf[lIndex2] = ucTmp;

			if (!(++lRelPos & 3)) { // extra blank after 4 bytes
				lIndex++;
				szBuf[lIndex + 2] = ' ';
			}
		}
		if (!(lRelPos & 3)) lIndex--;
		szBuf[lIndex] = '<';
		szBuf[lIndex + 1] = ' ';
		printf("%s\n", szBuf);
		buf.pData += lOutLen;
		buf.lSize -= lOutLen;
	}
}

int unlink_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    int rv = remove(fpath);
    if (rv) perror(fpath);
    return rv;
}

void rmrf(char *path) {
	struct stat status;
	if (stat(path, &status) == 0) nftw(path, unlink_cb, 64, FTW_DEPTH | FTW_PHYS);
}

void createFolder(const char *directory) {
	struct stat st;
	if (stat(directory, &st) != 0) {
		if (mkdir((const char*) directory, 0744) != 0) {
			printf("FATAL: Can't create directory '%s'", directory);
			exit(1);
		}
	}
}

void constructPath(char *result_path, const char *first, const char *second, const char* postfix) {
	strcat(result_path, first);
	strcat(result_path, G_DIR_SEPARATOR_S);
	strcat(result_path, second);
	if(postfix != NULL) strcat(result_path, postfix);
}

int is_nfsb(const char *filename) {
	FILE *file = fopen(filename, "r");
	if (file == NULL) {
		printf("Can't open file %s", filename);
		exit(1);
	}
	size_t headerSize = 0x10;
	unsigned char* buffer = (unsigned char*) malloc(sizeof(char) * headerSize);
	int read = fread(buffer, 1, headerSize, file);
	int result = 0;
	if (read == headerSize) {
		result = !memcmp(&buffer[0x0], "NFSB", 4);
		if (!result) result = !memcmp(&buffer[0xE], "md5", 3);
	}
	fclose(file);
	free(buffer);
	return result;
}

void unnfsb(char* filename, char* extractedFile) {
	int fdin, fdout;
	char *src, *dst;
	struct stat statbuf;
	int headerSize = 0x1000;
	/* open the input file */
	if ((fdin = open (filename, O_RDONLY)) < 0) printf("Can't open %s for reading", filename);

	/* open/create the output file */
	if ((fdout = open (extractedFile, O_RDWR | O_CREAT | O_TRUNC, (mode_t)0600)) < 0) 
		printf("Can't create %s for writing", extractedFile);

	/* find size of input file */
	if (fstat (fdin, &statbuf) < 0) printf("fstat error");

	/* mmap the input file */
	if ((src = mmap (0, statbuf.st_size, PROT_READ, MAP_SHARED, fdin, 0)) == (caddr_t) -1)
		printf("mmap error for input");

	/* go to the location corresponding to the last byte */
	if (lseek (fdout, statbuf.st_size - headerSize - 1, SEEK_SET) == -1) printf("lseek error");
 
	/* write a dummy byte at the last location */
	if (write (fdout, "", 1) != 1) printf("write error");

	/* mmap the output file */
	if ((dst = mmap (0, statbuf.st_size - headerSize, PROT_READ | PROT_WRITE, MAP_SHARED, fdout, 0)) == (caddr_t) -1)
		printf("mmap error for output");
	/* this copies the input file to the output file */
		memcpy(dst, &src[headerSize], statbuf.st_size - headerSize);

	/* Don't forget to free the mmapped memory */
	if (munmap(src, statbuf.st_size) == -1) printf("Error un-mmapping the file");
	if (munmap(dst, statbuf.st_size - headerSize) == -1) printf("Error un-mmapping the file");

	/* Un-mmaping doesn't close the file, so we still need to do that. */
	close(fdout);
	close(fdin);
}

int isSTRfile(const char *filename) {
	FILE *file = fopen(filename, "r");
	if (file == NULL) {
		printf("Can't open file %s", filename);
		exit(1);
	}
	size_t headerSize = 0xC0*4;
	unsigned char* buffer = (unsigned char*) malloc(sizeof(char) * headerSize);
	int read = fread(buffer, 1, headerSize, file);
	int result = 0;
	if (read == headerSize && buffer[4] == 0x47 && buffer[0xC0+4] == 0x47 && buffer[0xC0*2+4] == 0x47 && buffer[0xC0*3+4] == 0x47) result=1;
	fclose(file);
	free(buffer);
	return result;
}

#define TS_FRAME_SIZE 192
unsigned char drm_key[0x10];
AES_KEY UnwrappedKey;

//Sync byte				8		0x47
//Transport Error Indicator (TEI)	1		Set by demodulator if can't correct errors in the stream, to tell the demultiplexer that the packet has an uncorrectable error [11]
//Payload Unit Start Indicator		1		1 means start of PES data or PSI otherwise zero only.
//Transport Priority			1		1 means higher priority than other packets with the same PID.
//PID					13		Packet ID
//Scrambling control			2		'00' = Not scrambled.   The following per DVB spec:[12]   
//							'01' = Reserved for future use,   
//							'10' = Scrambled with even key,   
//							'11' = Scrambled with odd key
//Adaptation field exist		2		01 = no adaptation fields, payload only
//							10 = adaptation field only
//							11 = adaptation field and payload
//Continuity counter			4		Incremented only when a payload is present (i.e., adaptation field exist is 01 or 11)[13]
//Note: the total number of bits above is 32 and is called the transport stream 4-byte prefix or Transport Stream Header.

unsigned char process_section (unsigned char *data , unsigned char *outdata, const uint64_t dec_count) {
	unsigned char *inbuf, *outbuf;
	unsigned int i, rounds;
	int offset = 4;	

	memcpy(outdata, data, TS_FRAME_SIZE);

	if( (data[3] & 0xC0) != 0xC0 && (data[3] & 0xC0) != 0x80) return 0;
		
	if (data[3] & 0x20) offset += (data[4] + 1);	// skip adaption field
	outdata[3] &= 0x3F;				// remove scrambling bits
	if (offset > TS_FRAME_SIZE) { //application will crash without this check when file is corrupted
		printf("\nInvalid data @ %" PRIx64 "\n", dec_count);
		offset = TS_FRAME_SIZE;
	}
	inbuf = data + offset;
	outbuf = outdata + offset;
		
	rounds = (TS_FRAME_SIZE - offset) / 0x10;
	for (i = 0; i < rounds; i++) AES_decrypt(inbuf + i* 0x10, outbuf + i * 0x10, &UnwrappedKey); // AES CBC
	return 1;
}

void convertSTR2TS(char* filename, char* outfilename) {
	FILE *file = fopen("dvr", "r");
	if (file == NULL) {
		printf("Can't open file %s", filename);
		exit(1);
	}
	unsigned char wKey[24];
	int read = fread(&wKey, 1, 24, file);
	uint64_t i;
	printf("Wrapped key: ");
	for (i = 0; i < sizeof(wKey); i++) printf("%02X", wKey[i]);
	printf("\nUnwrap key: ");
	for (i = 0; i < sizeof(drm_key); i++) {
		drm_key[i]=i;
		printf("%02X", drm_key[i]);
	}
	static const unsigned char iv[] = {
		0xB7,0xB7,0xB7,0xB7,0xB7,0xB7,0xB7,0xB7,
	};
	AES_KEY AESkey;
	AES_set_decrypt_key(&drm_key[0], 128, &AESkey);
	unsigned char uwKey[16];
	AES_unwrap_key(&AESkey, iv, &drm_key[0], &wKey[0], 24);
	printf("\nUnwrapped key: ");
	for (i = 0; i < sizeof(drm_key); i++) printf("%02X", drm_key[i]);
	printf("\n");
	fclose(file);
	
	AES_set_decrypt_key(&drm_key[0], 128, &UnwrappedKey);
	
	int sync_find = 0, j;
	uint64_t filesize = 0, dec_count = 0;

	unsigned char buf[1024];
	unsigned char outdata[1024];

	FILE *inputfp = fopen(filename, "r");
	if (inputfp  == NULL) {
		printf("Can't open file %s", filename);
		exit(1);
	}
	
	FILE *outputfp = fopen(outfilename, "w");
	if (outputfp  == NULL) {
		printf("Can't open file %s", outfilename);
		exit(1);
	}

	fseeko(inputfp,0,2);
	filesize = ftello(inputfp); 
	rewind(inputfp);
	
	fread(buf, 1, 1024, inputfp);

	for (i=0; i < (1024 - TS_FRAME_SIZE); i++) {
		if (buf[i] == 0x47 && buf[i+TS_FRAME_SIZE] == 0x47 && buf[i+TS_FRAME_SIZE+TS_FRAME_SIZE] == 0x47) {
			sync_find = 1;
			fseeko(inputfp, i, SEEK_SET); 
			break;
		}
	}
	if (sync_find) {
		for (i = 0; i < filesize; i += TS_FRAME_SIZE) {
			fread(buf, 1, TS_FRAME_SIZE, inputfp);
			if (buf[0] != 0x47) {
				printf("\nLost sync at %" PRIx64 "\n", i);
				fseeko(inputfp, i, SEEK_SET); 
				sync_find = 0;
				while (sync_find == 0) {
					if (fread(buf, 1, 1024, inputfp) < 1024) break; //prevent infinite loop at end of file
					for (j=0; j < (1024 - TS_FRAME_SIZE); j++) {
						if (buf[j] == 0x47 && buf[j+TS_FRAME_SIZE] == 0x47 && buf[j+TS_FRAME_SIZE+TS_FRAME_SIZE] == 0x47) {
							sync_find = 1;
							fseeko(inputfp, i+j, SEEK_SET); 
							break;
						}
					}
					i+=1024;
				}
			} else {
				dec_count += TS_FRAME_SIZE;
				process_section (buf, outdata, dec_count);
				fwrite(outdata, 1, TS_FRAME_SIZE, outputfp);
			}
		}
		printf("\nWritten %" PRIu64 " bytes to output file.\n", dec_count);
	}
	fclose(inputfp);
	fclose(outputfp);
}
