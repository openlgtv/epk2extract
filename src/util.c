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
	if ((fdin = open (filename, O_RDONLY)) < 0) printf("Can't open file %s for reading\n", filename);

	/* open/create the output file */
	if ((fdout = open (extractedFile, O_RDWR | O_CREAT | O_TRUNC, (mode_t)0600)) < 0) 
		printf("Can't create file %s for writing\n", extractedFile);

	/* find size of input file */
	if (fstat (fdin, &statbuf) < 0) printf("fstat error\n");

	/* mmap the input file */
	if ((src = mmap (0, statbuf.st_size, PROT_READ, MAP_SHARED, fdin, 0)) == (caddr_t) -1)
		printf("mmap error for input\n");

	/* go to the location corresponding to the last byte */
	if (lseek (fdout, statbuf.st_size - headerSize - 1, SEEK_SET) == -1) printf("lseek error\n");
 
	/* write a dummy byte at the last location */
	if (write (fdout, "", 1) != 1) printf("write error\n");

	/* mmap the output file */
	if ((dst = mmap (0, statbuf.st_size - headerSize, PROT_READ | PROT_WRITE, MAP_SHARED, fdout, 0)) == (caddr_t) -1)
		printf("mmap error for output\n");
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

#define TS_PACKET_SIZE 192
AES_KEY AESkey;

void setKey() {
	FILE *keyFile = fopen("dvr", "r");
	if (keyFile == NULL) {
		printf("dvr is not found.\n");
		return;
	}
	unsigned char wKey[24];
	int read = fread(&wKey, 1, 24, keyFile);
	fclose(keyFile);

	printf("Wrapped key: ");
	int i;
	for (i = 0; i < sizeof(wKey); i++) printf("%02X", wKey[i]);
	
	unsigned char drm_key[0x10];
	printf("\nUnwrap key: ");
	for (i = 0; i < sizeof(drm_key); i++) {
		drm_key[i]=i;
		printf("%02X", drm_key[i]);
	}
	static const unsigned char iv[] = {
		0xB7,0xB7,0xB7,0xB7,0xB7,0xB7,0xB7,0xB7,
	};
	AES_set_decrypt_key(&drm_key[0], 128, &AESkey);
	AES_unwrap_key(&AESkey, iv, &drm_key[0], &wKey[0], 24);
	printf("\nUnwrapped key: ");
	for (i = 0; i < sizeof(drm_key); i++) printf("%02X", drm_key[i]);
	AES_set_decrypt_key(&drm_key[0], 128, &AESkey);
}

void convertSTR2TS(char* inFilename, char* outFilename, int notOverwrite) {
	FILE *inFile = fopen(inFilename, "rb");
	if (inFile  == NULL) {
		printf("Can't open file %s\n", inFilename);
		return;
	}

	fseeko(inFile, 0, SEEK_END);
	uint64_t filesize = ftello(inFile); 
	rewind(inFile);
	
	FILE *outFile;
	if (notOverwrite) outFile = fopen(outFilename, "a+b"); 
	else outFile = fopen(outFilename, "wb");
	
	if (outFile  == NULL) {
		printf("Can't open file %s\n", outFilename);
		return;
	}
	
	if (notOverwrite) fseeko(outFile, 0, SEEK_END);

	unsigned char inBuf[TS_PACKET_SIZE*10];
	unsigned char outBuf[TS_PACKET_SIZE];
	unsigned int k, rounds;			
	int syncFound = 0, j;
	fread(inBuf, 1, sizeof(inBuf), inFile);

	uint64_t i;
	for (i = 0; i < (sizeof(inBuf) - TS_PACKET_SIZE*2); i++) {
		if (inBuf[i] == 0x47 && inBuf[i+TS_PACKET_SIZE] == 0x47 && inBuf[i+TS_PACKET_SIZE*2] == 0x47) {
			fseeko(inFile, i-4, SEEK_SET); 
			for (i = 0; i < filesize; i += TS_PACKET_SIZE) {
				fread(inBuf, 1, TS_PACKET_SIZE, inFile);
				if (inBuf[4] != 0x47) {
					printf("\nLost sync at offset %" PRIx64 "\n", i);
					fseeko(inFile, i, SEEK_SET); 
					syncFound = 0;
					while (syncFound == 0) {
						if (fread(inBuf, 1, sizeof(inBuf), inFile) < sizeof(inBuf)) break; //prevent infinite loop at end of file
						for (j = 0; j < (sizeof(inBuf) - TS_PACKET_SIZE); j++) {
							if (inBuf[j] == 0x47 && inBuf[j+TS_PACKET_SIZE] == 0x47 && inBuf[j+TS_PACKET_SIZE*2] == 0x47) {
								syncFound = 1;
								fseeko(inFile, i+j, SEEK_SET); 
								break;
							}
						}
						i+=sizeof(inBuf);
					}
				} else {
					memcpy(outBuf, inBuf, TS_PACKET_SIZE);
					int offset = 8;
					if ((inBuf[7] & 0xC0) == 0xC0 || (inBuf[7] & 0xC0) == 0x80) { // decrypt only scrambled packets
						if (inBuf[7] & 0x20) offset += (inBuf[8] + 1);	// skip adaption field
						outBuf[7] &= 0x3F;	// remove scrambling bits
						if (offset > TS_PACKET_SIZE) offset = TS_PACKET_SIZE; //application will crash without this check when file is corrupted
						rounds = (TS_PACKET_SIZE - offset) / 0x10;
						for (k = 0; k < rounds; k++) AES_decrypt(inBuf + offset + k*0x10, outBuf + offset + k*0x10, &AESkey); // AES CBC
					};
					fwrite(outBuf, 1, TS_PACKET_SIZE, outFile);
				}
			}
			break;
		}
	}
	fclose(inFile);
	fclose(outFile);
}

/* Transport Stream Header (or 4-byte prefix) consists of 32-bit:
	Sync byte						8		0x47
	Transport Error Indicator (TEI)	1		Set by demodulator if can't correct errors in the stream, to tell the demultiplexer that the packet
											has an uncorrectable error [11]
	Payload Unit Start Indicator	1		1 means start of PES data or PSI otherwise zero only.
	Transport Priority				1		1 means higher priority than other packets with the same PID.
	PID								13		Packet ID
	Scrambling control				2		'00' = Not scrambled. The following per DVB spec:[12]   
											'01' = Reserved for future use, '10' = Scrambled with even key, '11' = Scrambled with odd key
	Adaptation field exist			2		'01' = no adaptation fields, payload only, '10' = adaptation field only, '11' = adaptation field and payload
	Continuity counter				4		Incremented only when a payload is present (i.e., adaptation field exist is 01 or 11)[13]
*/

void processPIF(const char* filename, char* dest_file) {
	FILE *file = fopen(filename, "r");
	if (file == NULL) {
		printf("Can't open file %s\n", filename);
		exit(1);
	}
	fseek(file, 0, SEEK_END);
	int filesize = ftell(file);
	rewind(file);

	int append = 0;
	unsigned char* buffer = (unsigned char*) malloc(filesize);
	int read = fread(buffer, 1, filesize, file);
	if (read == filesize) {
		int i;
		for (i = 0; i < (filesize-5); i++) {
			if (!memcmp(&buffer[i], "/mnt/", 5) && !memcmp(&buffer[i+strlen(&buffer[i])-3], "STR", 3)) {
				printf("Converting file: %s\n", strrchr(&buffer[i], '/')+1);
				convertSTR2TS(strrchr(&buffer[i], '/')+1, dest_file, append);
				append = 1;
			}
		}
	}
	fclose(file);
	free(buffer);
}