/**
 * TS file Decryption
 * (C) 2020 the epk2extract authors
 **/

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

static int do_unwrap_func(uint8_t unwrap_key[], uint8_t aes_key[], uint8_t unwrapped_key[]){
	uint8_t zero_cnt = 0;
		
	puts("Wrapped key: ");
	for(int i = 0; i<24; i++){
		printf("%02X", aes_key[i]);
	}
	
	// B7..B7..
	uint8_t wrap_iv[8];
	memset(&wrap_iv, 0xB7, sizeof(wrap_iv));
	
	// unwrap 'aes_key' with 'unwrap_key' into 'unwrapped_key'
	AES_set_decrypt_key(unwrap_key, 128, &AESkey);
	AES_unwrap_key(&AESkey, wrap_iv, unwrapped_key, aes_key, 24);
	
	puts("\nUnwrapped key: ");
	for (int i = 0; i < 16; i++){
		printf("%02X", unwrapped_key[i]);
		zero_cnt = zero_cnt + unwrapped_key[i]; // check if all Bits are zero
	}
	puts("\n");
	if(zero_cnt == 0) {
		return -1;
	}
	else {
		return 0;
	}
}

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
			fprintf(stderr, "Unknown or invalid key found (key size=%ld)\n", statBuf.st_size);
			return -1;
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
		uint8_t unwrap_key[16];
		// set unwrap_key: 0x01, 0x02, 0x03, ... 0x0F
		for (int i = 0; i < sizeof(unwrap_key); i++){
			unwrap_key[i] = i;
			//printf("%02X", unwrap_key[i]);
		}
		printf("\n");
		if (0 != do_unwrap_func(unwrap_key, aes_key, unwrapped_key)){ // if failed try alternative unwrap from ww#8543
			puts("Unwrap key failed, try alternative unwrap key\n");
			uint8_t unwrap_key2[16] = {0xb1, 0x52, 0x73, 0x3f, 0x68, 0x61, 0x3b, 0x6a, 0x40, 0x6c, 0x7a, 0xa4, 0xbe, 0x28, 0xb8, 0xb6};
			if (0 != do_unwrap_func(unwrap_key2, aes_key, unwrapped_key)){
				puts("Unwrap key failed\n");
				return -1;
			}
		}
		AES_set_decrypt_key(unwrapped_key, 128, &AESkey);
	}
	else {
		AES_set_decrypt_key(aes_key, 128, &AESkey);
	}
	
	return 0;
}

// minimum number of TS packets (sync bytes) that must be present
#define MIN_TS_PACKETS 3

uint8_t *findTsPacket(MFILE *tsFile, long offset){
	if(offset >= msize(tsFile)){
		return NULL;
	}

	uint8_t *head;
	uint8_t *cur;
	
	int syncPackets;
	
	do {
		syncPackets = 0;

		// find initial sync position sequentially
		for(head = mdata(tsFile, uint8_t) + offset;
			moff(tsFile, head) < msize(tsFile) && *head != 0x47;
			head++
		);

		// EOF condition
		if(*head != 0x47) break;

		++syncPackets;
		cur = head;

		// found the initial sync. now check next packets
		for(int i=0;
			//
			syncPackets<MIN_TS_PACKETS
			&& moff (tsFile, cur) < msize(tsFile)
			&& cur[TS_PACKET_SIZE * i] == 0x47;
			//
			syncPackets++,
			cur+=TS_PACKET_SIZE,
			i++);

	} while(syncPackets<MIN_TS_PACKETS);

	if(syncPackets < MIN_TS_PACKETS){
		return NULL;
	}

	if((head - 4) < mdata(tsFile, uint8_t)){
		// corrupted file, we went before the file's beginning
		return NULL;
	}

	// go to the beginning of the "Transport Stream Header"
	return head - 4;
}

void writeHeaders(FILE *outFile){
	uint8_t outBuf[TS_PACKET_SIZE];

	{ // Construct and write PAT
		memset(outBuf, 0xFF, TS_PACKET_SIZE);
		uint8_t PAT[] = {
			0x47, 0x40, 0x00, 0x10, 0x00, 0x00, 0xB0, 0x0D,
			0x00, 0x06, 0xC7, 0x00, 0x00, 0x00, 0x01, 0xE0,
			0xB1, 0xA2, 0x89, 0x69, 0x78
		};
		memcpy(outBuf, &PAT, sizeof(PAT));
		fwrite(outBuf, 1, TS_PACKET_SIZE - 4, outFile);
	}

	{ // Write empty PMT
		memset(outBuf, 0xFF, TS_PACKET_SIZE);
		fwrite(outBuf, 1, TS_PACKET_SIZE - 4, outFile);
	}
}


struct tables {
	int number[8192];
	unsigned char type[8192];
	int pcr_count[8192];
};

void writePMT(struct tables *PIDs, FILE *outFile){
	// Gather information for PMT construction
	unsigned char stream_count = 0;
	for (unsigned int i = 0; i < 8192; i++) {
		//Count video stream PIDs (0xE0-0xEF)
		if (PIDs->type[i] >= 0xE0 && PIDs->type[i] <= 0xEF) {
			stream_count++;
		}
		//Count audio stream PIDs (0xC0-0xDF)
		else if (PIDs->type[i] >= 0xC0 && PIDs->type[i] <= 0xDF) {
			stream_count++;
		}
	}
	unsigned char PMT_size = 21 + stream_count * 5;

	uint8_t outBuf[TS_PACKET_SIZE];
	// Fill PMT
	memset(outBuf, 0xFF, TS_PACKET_SIZE);
	
	uint8_t PMT[TS_PACKET_SIZE - 4];
	memset(PMT, 0xFF, TS_PACKET_SIZE - 4);

	const uint8_t PMT_header[17] = {
		0x47, 0x40, 0xB1, 0x10, 0x00, 0x02, 0xB0,
		0x00,				// section length in bytes including crc
		0x00, 0x01,			// program number
		0xC1, 0x00, 0x00,
		0xE4, 0x7E,			// PCR PID
		0xF0, 0x00			// Program info length
	};
	memcpy(PMT, PMT_header, sizeof(PMT_header));
	PMT[7] = 13 + stream_count * 5;

	stream_count = 0;
	for (unsigned int i = 0; i < 8192; i++)
		if (PIDs->number[i] > 0) {
			//printf("PID %zX : %d Type: %zX PCRs: %zX\n", i, PIDs.number[i], PIDs.type[i], PIDs.pcr_count[i]);
			if (PIDs->pcr_count[i] > 0) {	// Set PCR PID
				PMT[13] = ((i >> 8) & 0xFF) + 0xE0;
				PMT[14] = i & 0xFF;
			}
			//Set video stream data in PMT
			if (PIDs->type[i] >= 0xE0 && PIDs->type[i] <= 0xEF) {
				PMT[17 + stream_count * 5] = 0x1B; 						// stream type ITU_T_H264
				PMT[18 + stream_count * 5] = ((i >> 8) & 0xFF) + 0xE0;	// PID
				PMT[19 + stream_count * 5] = i & 0xFF;
				PMT[20 + stream_count * 5] = 0xF0;						// ES info length
				PMT[21 + stream_count * 5] = 0x00;
				stream_count++;
			}
			//Set audio stream data in PMT
			else if (PIDs->type[i] >= 0xC0 && PIDs->type[i] <= 0xDF) {
				PMT[17 + stream_count * 5] = 0x04; 						// stream type ISO/IEC 13818-3 Audio (MPEG-2)
				PMT[18 + stream_count * 5] = ((i >> 8) & 0xFF) + 0xE0;	//PID
				PMT[19 + stream_count * 5] = i & 0xFF;
				PMT[20 + stream_count * 5] = 0xF0;						// ES info length
				PMT[21 + stream_count * 5] = 0x00;
				stream_count++;
			}
		}
	// Set CRC32
	uint32_t crc = str_crc32(&PMT[5], PMT[7] - 1);
	PMT[PMT_size - 4] = (crc >> 24) & 0xFF;
	PMT[PMT_size - 3] = (crc >> 16) & 0xFF;
	PMT[PMT_size - 2] = (crc >> 8) & 0xFF;
	PMT[PMT_size - 1] = crc & 0xFF;
	memcpy(outBuf, PMT, sizeof(PMT));
	
	fseek(outFile, 0xBC, SEEK_SET);
	fwrite(outBuf, 1, TS_PACKET_SIZE - 4, outFile);
}

void processTsPacket(uint8_t *packet, struct tables *PIDs, FILE *outFile){
	uint8_t outBuf[TS_PACKET_SIZE];

	int offset = 8;
	if ((packet[7] & 0xC0) == 0xC0 || (packet[7] & 0xC0) == 0x80) {	// decrypt only scrambled packets
		// packet is encrypted, so we copy the original (readonly) for modifications
		memcpy(outBuf, packet, TS_PACKET_SIZE);
		// now set the pointer to the copy
		packet = &outBuf[0];

		if (packet[7] & 0x20){
			offset += (packet[8] + 1);	// skip adaption field
		}
		packet[7] &= 0x3F;	// remove scrambling bits
		if (offset > TS_PACKET_SIZE){
			//application will crash without this check when file is corrupted
			offset = TS_PACKET_SIZE;
		}
		unsigned int blocks = (TS_PACKET_SIZE - offset) / AES_BLOCK_SIZE;
		for (unsigned int i = 0; i < blocks; i++){
			// in-place decrypt (ECB)
			AES_decrypt(
				&packet[offset + i * AES_BLOCK_SIZE],
				&packet[offset + i * AES_BLOCK_SIZE],
				&AESkey);
		}
	};

	// Search PCR
	if (packet[7] & 0x20) {	// adaptation field exists
		if (packet[9] & 0x10)	// check if PCR exists
			PIDs->pcr_count[(packet[5] << 8 | packet[6]) & 0x1FFF]++;
	}
	// Count PES packets only
	if (packet[8] == 0 && packet[9] == 0 && packet[10] == 1) {
		PIDs->number[(packet[5] << 8 | packet[6]) & 0x1FFF]++;
		PIDs->type[(packet[5] << 8 | packet[6]) & 0x1FFF] = packet[11];
	}
	fwrite(outBuf + 4, 1, TS_PACKET_SIZE - 4, outFile);
}

void convertSTR2TS_internal(char *inFilename, char *outFilename, int notOverwrite) {
	MFILE *inFile = mopen(inFilename, O_RDONLY);
	if (inFile == NULL) {
		printf("Can't open file %s\n", inFilename);
		return;
	}

	struct tables PIDs;
	memset(&PIDs, 0, sizeof(PIDs));

	do {
		FILE *outFile;
		if (notOverwrite){
			outFile = fopen(outFilename, "a+b");
		} else {
			outFile = fopen(outFilename, "wb");
		}

		if (outFile == NULL) {
			fprintf(stderr, "Can't open file %s\n", outFilename);
			break;
		}

		do {
			uint8_t *packet = findTsPacket(inFile, 0);
			if(packet == NULL){
				fprintf(stderr, "Could not find sync\n");
				break;
			}

			writeHeaders(outFile);

			long offset;
			for(;(offset=moff(inFile, packet)) < msize(inFile);
				packet += TS_PACKET_SIZE
			){
				if(packet[4] != 0x47){
					fprintf(stderr, "\nLost sync at offset %" PRIx64 "\n", offset);
					packet = findTsPacket(inFile, offset);
				}
				processTsPacket(packet, &PIDs, outFile);
			}
		} while(0);

		writePMT(&PIDs, outFile);
		fclose(outFile);
	} while(0);
	mclose(inFile);
}

void convertSTR2TS(char *inFilename, int notOverwrite) {
	char *baseDir = my_dirname(inFilename);
	char *keyPath;
	
	asprintf(&keyPath, "%s/dvr", baseDir);
	if (0 != setKey(keyPath)){
		free(keyPath);
		err_exit("Load DVR Key-file failed for %s/dvr\n", baseDir);
	}
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

	if (0 != setKey(keyPath)){
		free(keyPath);
		err_exit("Load DVR Key-file failed for %s/dvr\n", baseDir);
	}
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
