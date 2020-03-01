#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <openssl/aes.h>

#include <sys/stat.h>
#include <unistd.h>

#include "stream/crc32.h"
#include "util.h"

#define TS_PACKET_SIZE 192
static AES_KEY AESkey;

static int setKey(char *keyPath) {
	int ret = -1;
	
	FILE *keyFile = fopen(keyPath, "r");
	if (keyFile == NULL) {
		fprintf(stderr, "%s not found.\n", keyPath);
		return ret;
	}
		
	struct stat statBuf;
	if((ret=fstat(fileno(keyFile), &statBuf)) < 0){
		fprintf(stderr, "setKey: stat failed\n");
		return ret;
	}
	
	bool doUnwrap;
	
	switch(statBuf.st_size){
		case 16:
			printf("=> Unwrapped AES-128 key detected\n");
			doUnwrap = false;
			break;
		case 24:
			printf("=> Wrapped AES-128 key detected\n");
			doUnwrap = true;
			break;
		default:
			fprintf(stderr, "Unknown or invalid key found (key size=%zu)\n", statBuf.st_size);
			break;
	}
	int keySz = statBuf.st_size;
	
	uint8_t aes_key[keySz];
	memset(&aes_key, 0x00, keySz);

	int read = fread(&aes_key, keySz, 1, keyFile);
	fclose(keyFile);
	if(read != 1){
		fprintf(stderr, "key read error\n");
		return -1;
	}
	
	if(doUnwrap){
		uint8_t unwrapped_key[16];
		
		puts("Wrapped key: ");
		for(int i = 0; i<keySz; i++){
			printf("%hhX", aes_key[i]);
		}
		
		// 01..02..03....
		uint8_t unwrap_key[16];
		for (int i = 0; i < sizeof(unwrap_key); i++){
			unwrap_key[i] = i;
			printf("%hhX", unwrap_key[i]);
		}
		
		// B7..B7..
		uint8_t wrap_iv[8];
		memset(&wrap_iv, 0xB7, sizeof(wrap_iv));
		
		// unwrap 'aes_key' with 'unwrap_key' into 'unwrapped_key'
		AES_set_decrypt_key(unwrap_key, 128, &AESkey);
		AES_unwrap_key(&AESkey, wrap_iv, unwrapped_key, aes_key, 24);
		
		puts("\nUnwrapped key: ");
		for (int i = 0; i < sizeof(unwrapped_key); i++){
			printf("%hhX", unwrapped_key[i]);
		}
		puts("\n");
		
		AES_set_decrypt_key(unwrapped_key, 128, &AESkey);
	} else {
		AES_set_decrypt_key(aes_key, 128, &AESkey);
	}
	
	return 0;
}

void convertSTR2TS_internal(char *inFilename, char *outFilename, int notOverwrite) {
	FILE *inFile = fopen(inFilename, "rb");
	if (inFile == NULL) {
		printf("Can't open file %s\n", inFilename);
		return;
	}

	fseeko(inFile, 0, SEEK_END);
	uint64_t filesize = ftello(inFile);
	rewind(inFile);

	FILE *outFile;
	if (notOverwrite)
		outFile = fopen(outFilename, "a+b");
	else
		outFile = fopen(outFilename, "wb");

	if (outFile == NULL) {
		printf("Can't open file %s\n", outFilename);
		return;
	}

	unsigned char inBuf[TS_PACKET_SIZE * 10];
	unsigned char outBuf[TS_PACKET_SIZE];
	unsigned int k, rounds;
	int syncFound = 0, j;
	fread(inBuf, 1, sizeof(inBuf), inFile);

	uint64_t i;
	struct tables {
		int number[8192];
		unsigned char type[8192];
		int pcr_count[8192];
	};

	struct tables PIDs;
	memset(&PIDs, 0, sizeof(PIDs));
	int PATnotWritten = 0;
	for (i = 0; i < (sizeof(inBuf) - TS_PACKET_SIZE * 2); i++) {
		if (inBuf[i] == 0x47 && inBuf[i + TS_PACKET_SIZE] == 0x47 && inBuf[i + TS_PACKET_SIZE * 2] == 0x47) {
			fseeko(inFile, i - 4, SEEK_SET);
			for (i = 0; i < filesize; i += TS_PACKET_SIZE) {
				fread(inBuf, 1, TS_PACKET_SIZE, inFile);
				if (inBuf[4] != 0x47) {
					printf("\nLost sync at offset %" PRIx64 "\n", i);
					fseeko(inFile, i, SEEK_SET);
					syncFound = 0;
					while (syncFound == 0) {
						if (fread(inBuf, 1, sizeof(inBuf), inFile) < sizeof(inBuf))
							break;	//prevent infinite loop at end of file
						for (j = 0; j < (sizeof(inBuf) - TS_PACKET_SIZE); j++) {
							if (inBuf[j] == 0x47 && inBuf[j + TS_PACKET_SIZE] == 0x47 && inBuf[j + TS_PACKET_SIZE * 2] == 0x47) {
								syncFound = 1;
								fseeko(inFile, i + j, SEEK_SET);
								break;
							}
						}
						i += sizeof(inBuf);
					}
				} else {
					if (!notOverwrite && !PATnotWritten) {
						// Construct PAT
						memset(outBuf, 0xFF, TS_PACKET_SIZE);
						unsigned char PAT[21] = { 0x47, 0x40, 0x00, 0x10, 0x00, 0x00, 0xB0, 0x0D, 0x00, 0x06, 0xC7, 0x00, 0x00, 0x00, 0x01,
							0xE0, 0xB1, 0xA2, 0x89, 0x69, 0x78
						};
						memcpy(outBuf, &PAT, sizeof(PAT));
						fwrite(outBuf, 1, TS_PACKET_SIZE - 4, outFile);

						// Allocate PMT
						memset(outBuf, 0xFF, TS_PACKET_SIZE);
						fwrite(outBuf, 1, TS_PACKET_SIZE - 4, outFile);
						PATnotWritten = 1;
					}
					memcpy(outBuf, inBuf, TS_PACKET_SIZE);
					int offset = 8;
					if ((inBuf[7] & 0xC0) == 0xC0 || (inBuf[7] & 0xC0) == 0x80) {	// decrypt only scrambled packets
						if (inBuf[7] & 0x20)
							offset += (inBuf[8] + 1);	// skip adaption field
						outBuf[7] &= 0x3F;	// remove scrambling bits
						if (offset > TS_PACKET_SIZE)
							offset = TS_PACKET_SIZE;	//application will crash without this check when file is corrupted
						rounds = (TS_PACKET_SIZE - offset) / 0x10;
						for (k = 0; k < rounds; k++)
							AES_decrypt(inBuf + offset + k * 0x10, outBuf + offset + k * 0x10, &AESkey);	// AES CBC
					};

					// Search PCR
					if (inBuf[7] & 0x20) {	// adaptation field exists
						if (outBuf[9] & 0x10)	// check if PCR exists
							PIDs.pcr_count[(inBuf[5] << 8 | inBuf[6]) & 0x1FFF]++;
					}
					// Count PES packets only
					if (!notOverwrite && outBuf[8] == 0 && outBuf[9] == 0 && outBuf[10] == 1) {
						PIDs.number[(inBuf[5] << 8 | inBuf[6]) & 0x1FFF]++;
						PIDs.type[(inBuf[5] << 8 | inBuf[6]) & 0x1FFF] = outBuf[11];
					}
					fwrite(outBuf + 4, 1, TS_PACKET_SIZE - 4, outFile);
				}
			}
			break;
		}
	}
	fclose(inFile);
	if (!notOverwrite) {
		// Fill PMT
		memset(outBuf, 0xFF, TS_PACKET_SIZE);
		unsigned char PMT[31] = { 0x47, 0x40, 0xB1, 0x10, 0x00, 0x02, 0xB0,
			0x17,				// section length in bytes including crc
			0x00, 0x01,			// program number
			0xC1, 0x00, 0x00,
			0xE4, 0x7E,			// PCR PID
			0xF0, 0x00,			// Program info length
			0x1B,				// stream type ITU_T_H264
			0xE4, 0x7E,			// PID
			0xF0, 0x00,			// ES info length
			0x04,				// stream type ISO/IEC 13818-3 Audio (MPEG-2)
			0xE4, 0x7F,			// PID
			0xF0, 0x00,			// ES info length
			0xFF, 0xFF, 0xFF, 0xFF	// crc32
		};

		for (i = 0; i < 8192; i++)
			if (PIDs.number[i] > 0) {
				//printf("PID %zX : %d Type: %zX PCRs: %zX\n", i, PIDs.number[i], PIDs.type[i], PIDs.pcr_count[i]);
				if (PIDs.pcr_count[i] > 0) {	// Set PCR PID
					PMT[13] = ((i >> 8) & 0xff) + 0xE0;
					PMT[14] = i & 0xff;
				}
				//Fill video stream PID (0xE0-0xEF)
				if (PIDs.type[i] >= 0xE0 && PIDs.type[i] <= 0xEF) {
					PMT[18] = ((i >> 8) & 0xff) + 0xE0;
					PMT[19] = i & 0xff;
				}
				//Fill audio stream PID (0xC0-0xDF)
				if (PIDs.type[i] >= 0xC0 && PIDs.type[i] <= 0xDF) {
					PMT[23] = ((i >> 8) & 0xff) + 0xE0;
					PMT[24] = i & 0xff;
				}
			}
		// Set CRC32
		uint32_t crc = str_crc32(&PMT[5], PMT[7] - 1);
		PMT[27] = (crc >> 24) & 0xff;
		PMT[28] = (crc >> 16) & 0xff;
		PMT[29] = (crc >> 8) & 0xff;
		PMT[30] = crc & 0xff;
		memcpy(outBuf, &PMT, sizeof(PMT));
		fseek(outFile, 0xBC, SEEK_SET);
		fwrite(outBuf, 1, TS_PACKET_SIZE - 4, outFile);
	}
	fclose(outFile);
}

/* Transport Stream Header (or 4-byte prefix) consists of 32-bit:
	Sync byte						8bit	0x47
	Transport Error Indicator (TEI)	1bit	Set by demodulator if can't correct errors in the stream, to tell the demultiplexer that the packet
											has an uncorrectable error [11]
	Payload Unit Start Indicator	1bit	1 means start of PES data or PSI otherwise zero only.
	Transport Priority				1bit	1 means higher priority than other packets with the same PID.
	PID								13bit	Packet ID
	Scrambling control				2bit	'00' = Not scrambled. The following per DVB spec:[12]   
											'01' = Reserved for future use, '10' = Scrambled with even key, '11' = Scrambled with odd key
	Adaptation field exist			2bit	'01' = no adaptation fields, payload only, '10' = adaptation field only, '11' = adaptation field and payload
	Continuity counter				4bit	Incremented only when a payload is present (i.e., adaptation field exist is 01 or 11)[13]
*/

void convertSTR2TS(char *inFilename, int notOverwrite) {
	char *baseDir = my_dirname(inFilename);
	char *keyPath;
	
	asprintf(&keyPath, "%s/dvr", baseDir);
	setKey(keyPath);
	free(keyPath);

	char *baseName = my_basename(inFilename);
	char *outFilename;
	asprintf(&outFilename, "%s/%s.ts", baseDir, baseName);
	
	printf("Output File: %s\n", outFilename);
	convertSTR2TS_internal(inFilename, outFilename, notOverwrite);
	
	free(baseName);
	free(baseDir);
}

void processPIF(const char *filename, char *dest_file) {
	FILE *file = fopen(filename, "r");
	if (file == NULL) {
		err_exit("Can't open file %s\n", filename);
	}
	
	struct stat statBuf;
	if(stat(filename, &statBuf) < 0){
		err_exit("stat() failed for %s\n", filename);
	}
	
	size_t filesize = statBuf.st_size;

	char *baseDir = my_dirname(filename);
	
	char *keyPath;	
	asprintf(&keyPath, "%s/dvr", baseDir);
	setKey(keyPath);
	free(keyPath);
	
	int append = 0;
	char *buffer = calloc(1, filesize);
	int read = fread(buffer, 1, filesize, file);
	if (read == filesize) {
		int i;
		for (i = 0; i < (filesize - 5); i++) {
			if (!memcmp(&buffer[i], "/mnt/", 5) && !memcmp(&buffer[i + strlen(&buffer[i]) - 3], "STR", 3)) {
				
				char *strName = strrchr(&buffer[i], '/') + 1;
				char *filePath;
				asprintf(&filePath, "%s/%s", baseDir, strName);
				
				printf("Converting file: %s -> %s\n", filePath, dest_file);
				convertSTR2TS_internal(filePath, dest_file, append);
				free(filePath);
				
				append = 1;
			}
		}
	}
	fclose(file);
	free(buffer);
	
	free(baseDir);
}
