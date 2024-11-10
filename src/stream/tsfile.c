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
#include <string.h>
#include <inttypes.h>
#include <openssl/aes.h>

#include <sys/stat.h>
#include <unistd.h>

#include "util.h"
#include "stream/crc32.h"
#include "stream/tsfile.h"


#define TS_PACKET_SIZE 192
static AES_KEY AESkey;

static bool do_unwrap_func(const uint8_t unwrap_key[], const uint8_t aes_key[], uint8_t unwrapped_key[]) {
	puts("Wrapped key: ");
	for (unsigned int i = 0; i < 24; i++){
		printf("%02" PRIX8, aes_key[i]);
	}

	// 8 bytes of 0xB7 (B7B7B7B7B7B7B7B7)
	const uint8_t wrap_iv[8] = {0xB7, 0xB7, 0xB7, 0xB7, 0xB7, 0xB7, 0xB7, 0xB7};

	// TODO: replace these deprecated functions
	// unwrap 'aes_key' with 'unwrap_key' into 'unwrapped_key'
	AES_set_decrypt_key(unwrap_key, 128, &AESkey);
	AES_unwrap_key(&AESkey, wrap_iv, unwrapped_key, aes_key, 24);

	uint8_t accum = 0;

	puts("\nUnwrapped key: ");
	for (unsigned int i = 0; i < 16; i++){
		printf("%02" PRIX8, unwrapped_key[i]);

		// Record any bits that are set
		accum |= unwrapped_key[i];
	}
	putchar('\n');

	// If all bits were zero, return false
	return (accum != 0);
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
			fprintf(stderr, "Unknown or invalid key found (key size=%jd)\n", (intmax_t) statBuf.st_size);
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
			//printf("%02" PRIx8, unwrap_key[i]);
		}
		putchar('\n');

		if (!do_unwrap_func(unwrap_key, aes_key, unwrapped_key)) {
			// If unwrapping failed, try alternative KEK from ww#8543
			puts("Failed to unwrap key; trying again with alternative key encryption key...\n");
			const uint8_t unwrap_key2[16] = {0xb1, 0x52, 0x73, 0x3f, 0x68, 0x61, 0x3b, 0x6a, 0x40, 0x6c, 0x7a, 0xa4, 0xbe, 0x28, 0xb8, 0xb6};
			if (!do_unwrap_func(unwrap_key2, aes_key, unwrapped_key)) {
				puts("Failed to unwrap key\n");
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
		// abort in case no valid sync is found in the first bytes of the file
		if(offset >= (TS_PACKET_SIZE * 2)){
			return NULL;
		}

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

		// increase offset to be able to find the correct sync in case a "garbage" sync was found
		offset = moff(tsFile, head) + 1;
	} while(syncPackets<MIN_TS_PACKETS);

	if(syncPackets < MIN_TS_PACKETS){
		return NULL;
	}

	return head;
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

#define AUDIO_TYPE_MPEG2 0x04
#define VIDEO_TYPE_H264 0x1B

static inline uint32_t pack_pid(int pid){
	return (0
		// reserved bits
		| 0x07 << 29
		// PID
		| ((pid & 0x1FFF) << 16)
		// reserved bits
		| 0x0F << 12
	) & 0xFFFFF;
}

void writePMT(struct tables *PIDs, FILE *outFile, struct tsfile_options *opts){
	int audio_stream_type = (opts->audio_stream_type == -1) ? AUDIO_TYPE_MPEG2 : opts->audio_stream_type;
	int video_stream_type = (opts->video_stream_type == -1) ? VIDEO_TYPE_H264 : opts->video_stream_type;

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
	memset(outBuf, 0xFF, TS_PACKET_SIZE);

	// Fill PMT
	uint8_t PMT[TS_PACKET_SIZE - 4];
	memset(PMT, 0xFF, TS_PACKET_SIZE - 4);

	const uint8_t PMT_header[17] = {
		/** 0x0: Transport header (TS) **/
		0x47, // sync byte
		0x40, // PUSI flag
		0xB1, 0x10,
		/** 0x4: PSI **/
		0x00, // pointer field
		/** 0x5: table header **/
		0x02, // program_map_section
		0xB0,
		0x00,				// section length in bytes including crc
		/** 0x8: table syntax data **/
		0x00, 0x01,			// program number
		0xC1, 0x00, 0x00,
		/** 0xD: PMT data **/
		0xE4, 0x7E,			// PCR PID
		0xF0, 0x00			// Program info length
		/** 0x11 **/
	};
	memcpy(PMT, PMT_header, sizeof(PMT_header));
	PMT[7] = 13 + stream_count * 5;

	uint32_t pmt_data;

	stream_count = 0;
	for (unsigned int i = 0; i < 8192; i++){
		uint32_t packed_pid = pack_pid(i);
		if (PIDs->number[i] > 0) {
			printf("PID %X : %d Type: %hhX PCRs: %X\n", i, PIDs->number[i], PIDs->type[i], (unsigned int) PIDs->pcr_count[i]);
			if (PIDs->pcr_count[i] > 0) {	// Set PCR PID
				pmt_data = (0
					| (packed_pid << 12)
					// program info length (0 for now)
					| 0 & 0xFFF
				);

				PMT[13] = (pmt_data >> 24) & 0xFF;
				PMT[14] = (pmt_data >> 16) & 0xFF;
				PMT[15] = (pmt_data >>  8) & 0xFF;
				PMT[16] = (pmt_data >>  0) & 0xFF;
			}

			uint32_t es_data = (0
				| (packed_pid << 12)
				// ES info length (0 for now)
				| 0 & 0xFFF
			);

			//Set video stream data in PMT
			if (PIDs->type[i] >= 0xE0 && PIDs->type[i] <= 0xEF) {
				PMT[17 + stream_count * 5] = video_stream_type; // stream type
				PMT[18 + stream_count * 5] = (es_data >> 24) & 0xFF;
				PMT[19 + stream_count * 5] = (es_data >> 16) & 0xFF;
				PMT[20 + stream_count * 5] = (es_data >>  8) & 0xFF;
				PMT[21 + stream_count * 5] = (es_data >>  0) & 0xF;
				stream_count++;
			}
			//Set audio stream data in PMT
			else if (PIDs->type[i] >= 0xC0 && PIDs->type[i] <= 0xDF) {
				PMT[17 + stream_count * 5] = audio_stream_type; // stream type
				PMT[18 + stream_count * 5] = (es_data >> 24) & 0xFF;
				PMT[19 + stream_count * 5] = (es_data >> 16) & 0xFF;
				PMT[20 + stream_count * 5] = (es_data >>  8) & 0xFF;
				PMT[21 + stream_count * 5] = (es_data >>  0) & 0xF;
				stream_count++;
			}
		}
	}
	// Set CRC32
	// A checksum of the entire table
	// excluding the pointer field, pointer filler bytes (aka none)
	// and the trailing CRC32.
	uint32_t crc = str_crc32(&PMT[5], PMT[7] - 1);
	PMT[PMT_size - 4] = (crc >> 24) & 0xFF;
	PMT[PMT_size - 3] = (crc >> 16) & 0xFF;
	PMT[PMT_size - 2] = (crc >> 8) & 0xFF;
	PMT[PMT_size - 1] = crc & 0xFF;
	memcpy(outBuf, PMT, sizeof(PMT));

	fseek(outFile, 0xBC, SEEK_SET);
	fwrite(outBuf, 1, TS_PACKET_SIZE, outFile);
}

void processTsPacket(uint8_t *packet, struct tables *PIDs, FILE *outFile){
	uint8_t outBuf[TS_PACKET_SIZE];

	// data offset
	int offset = 4;

	// Transport scrambling control
	int tsc = packet[3] & 0xC0;
	// either 0x20 or 0x30
	int have_adapt_field = (packet[3] & 0x30) > 0x10;
	// either 0x10 or 0x30
	int have_payload_field = (packet[3] & 0x30) != 0x20;
	int pid = (0
		| ((packet[1] & 0x1F) << 8)
		| packet[2]
	);

	if(!have_payload_field){
		return;
	}

	if (
		// LG Netcast writes even/odd DVB-CSA flag, even tho the key is fixed
		tsc == 0x80 || tsc == 0xC0
		// WebOS uses the "reserved" flag instead
		|| tsc == 0x40
	) {
		// packet is encrypted, so we copy the original (readonly) for modifications
		memcpy(outBuf, packet, TS_PACKET_SIZE);
		// now set the pointer to the copy
		packet = &outBuf[0];

		if(have_adapt_field){
			offset += (packet[4] + 1);	// adaption field length + sizeof length field
		}

		packet[3] &= ~0xC0;	// remove scrambling bits
		if (offset > TS_PACKET_SIZE){
			//application will crash without this check when file is corrupted
			offset = TS_PACKET_SIZE;
		}

		// NOTE: 4 seems to be custom LG padding, excluded from AES
		int data_length = TS_PACKET_SIZE - offset - 4;
		unsigned blocks = data_length / AES_BLOCK_SIZE;
		for (unsigned int i = 0; i < blocks; i++){
			// in-place decrypt (ECB)
			AES_decrypt(
				&packet[offset + i * AES_BLOCK_SIZE],
				&packet[offset + i * AES_BLOCK_SIZE],
				&AESkey);
		}
	};

	// Search PCR
	if (have_adapt_field){
		if (packet[5] & 0x10){	// check if PCR exists
			PIDs->pcr_count[pid]++;
		}
	}
	// Count PES packets only
	// check PES start code prefix
	if(packet[offset + 0] == 0
	&& packet[offset + 1] == 0
	&& packet[offset + 2] == 1
	){
		PIDs->number[pid]++;
		// stream ID. Examples: Audio streams (0xC0-0xDF), Video streams (0xE0-0xEF)
		PIDs->type[pid] = packet[offset + 3];
	}
	fwrite(packet, 1, TS_PACKET_SIZE, outFile);
}

void convertSTR2TS_internal(char *inFilename, char *outFilename, struct tsfile_options *opts) {
	MFILE *inFile = mopen(inFilename, O_RDONLY);
	if (inFile == NULL) {
		printf("Can't open file %s\n", inFilename);
		return;
	}

	struct tables PIDs;
	memset(&PIDs, 0, sizeof(PIDs));

	do {
		const char *mode = (opts->append) ? "a+b" : "wb";
		FILE *outFile = fopen(outFilename, mode);;

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
			for(;
				(offset=moff(inFile, packet)) < msize(inFile)
				&& offset + TS_PACKET_SIZE < msize(inFile)
				;
				packet += TS_PACKET_SIZE
			){
				if(packet[0] != 0x47){
					fprintf(stderr, "\nLost sync at offset %" PRIx64 "\n", offset);
					packet = findTsPacket(inFile, offset);
				}
				if(packet == NULL){
					fprintf(stderr, "error: lost sync\n");
					break;
				}
				processTsPacket(packet, &PIDs, outFile);
			}
		} while(0);

		writePMT(&PIDs, outFile, opts);
		fclose(outFile);
	} while(0);
	mclose(inFile);
}

void convertSTR2TS(char *inFilename, struct tsfile_options *opts) {
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
	convertSTR2TS_internal(inFilename, outFilename, opts);

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

				struct tsfile_options opts = {
					// $TODO: add a way to specify these
					.video_stream_type = -1,
					.audio_stream_type = -1,
					.append = append
				};

				convertSTR2TS_internal(filePath, dest_file, &opts);
				free(filePath);

				append = 1;
			}
		}
	}
	fclose(file);
	free(buffer);

	free(baseDir);
}
