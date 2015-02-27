#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <openssl/aes.h>

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
	for (i = 0; i < sizeof(wKey); i++)
		printf("%02X", wKey[i]);

	unsigned char drm_key[0x10];
	printf("\nUnwrap key: ");
	for (i = 0; i < sizeof(drm_key); i++)
		printf("%02X", drm_key[i] = i);

	static const unsigned char iv[] = { 0xB7, 0xB7, 0xB7, 0xB7, 0xB7, 0xB7, 0xB7, 0xB7 };

	AES_set_decrypt_key(drm_key, 128, &AESkey);
	AES_unwrap_key(&AESkey, iv, drm_key, wKey, 24);
	printf("\nUnwrapped key: ");
	for (i = 0; i < sizeof(drm_key); i++)
		printf("%02X", drm_key[i]);
	AES_set_decrypt_key(drm_key, 128, &AESkey);
}

static const unsigned int crc_table[256] = {
	0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9, 0x130476dc, 0x17c56b6b,
	0x1a864db2, 0x1e475005, 0x2608edb8, 0x22c9f00f, 0x2f8ad6d6, 0x2b4bcb61,
	0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd, 0x4c11db70, 0x48d0c6c7,
	0x4593e01e, 0x4152fda9, 0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75,
	0x6a1936c8, 0x6ed82b7f, 0x639b0da6, 0x675a1011, 0x791d4014, 0x7ddc5da3,
	0x709f7b7a, 0x745e66cd, 0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039,
	0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5, 0xbe2b5b58, 0xbaea46ef,
	0xb7a96036, 0xb3687d81, 0xad2f2d84, 0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d,
	0xd4326d90, 0xd0f37027, 0xddb056fe, 0xd9714b49, 0xc7361b4c, 0xc3f706fb,
	0xceb42022, 0xca753d95, 0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1,
	0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d, 0x34867077, 0x30476dc0,
	0x3d044b19, 0x39c556ae, 0x278206ab, 0x23431b1c, 0x2e003dc5, 0x2ac12072,
	0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16, 0x018aeb13, 0x054bf6a4,
	0x0808d07d, 0x0cc9cdca, 0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde,
	0x6b93dddb, 0x6f52c06c, 0x6211e6b5, 0x66d0fb02, 0x5e9f46bf, 0x5a5e5b08,
	0x571d7dd1, 0x53dc6066, 0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba,
	0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e, 0xbfa1b04b, 0xbb60adfc,
	0xb6238b25, 0xb2e29692, 0x8aad2b2f, 0x8e6c3698, 0x832f1041, 0x87ee0df6,
	0x99a95df3, 0x9d684044, 0x902b669d, 0x94ea7b2a, 0xe0b41de7, 0xe4750050,
	0xe9362689, 0xedf73b3e, 0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2,
	0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686, 0xd5b88683, 0xd1799b34,
	0xdc3abded, 0xd8fba05a, 0x690ce0ee, 0x6dcdfd59, 0x608edb80, 0x644fc637,
	0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb, 0x4f040d56, 0x4bc510e1,
	0x46863638, 0x42472b8f, 0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53,
	0x251d3b9e, 0x21dc2629, 0x2c9f00f0, 0x285e1d47, 0x36194d42, 0x32d850f5,
	0x3f9b762c, 0x3b5a6b9b, 0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff,
	0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623, 0xf12f560e, 0xf5ee4bb9,
	0xf8ad6d60, 0xfc6c70d7, 0xe22b20d2, 0xe6ea3d65, 0xeba91bbc, 0xef68060b,
	0xd727bbb6, 0xd3e6a601, 0xdea580d8, 0xda649d6f, 0xc423cd6a, 0xc0e2d0dd,
	0xcda1f604, 0xc960ebb3, 0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7,
	0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b, 0x9b3660c6, 0x9ff77d71,
	0x92b45ba8, 0x9675461f, 0x8832161a, 0x8cf30bad, 0x81b02d74, 0x857130c3,
	0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640, 0x4e8ee645, 0x4a4ffbf2,
	0x470cdd2b, 0x43cdc09c, 0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8,
	0x68860bfd, 0x6c47164a, 0x61043093, 0x65c52d24, 0x119b4be9, 0x155a565e,
	0x18197087, 0x1cd86d30, 0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec,
	0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088, 0x2497d08d, 0x2056cd3a,
	0x2d15ebe3, 0x29d4f654, 0xc5a92679, 0xc1683bce, 0xcc2b1d17, 0xc8ea00a0,
	0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb, 0xdbee767c, 0xe3a1cbc1, 0xe760d676,
	0xea23f0af, 0xeee2ed18, 0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4,
	0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0, 0x9abc8bd5, 0x9e7d9662,
	0x933eb0bb, 0x97ffad0c, 0xafb010b1, 0xab710d06, 0xa6322bdf, 0xa2f33668,
	0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4
};

uint32_t str_crc32(const unsigned char *data, int len) {
	uint32_t crc = 0xffffffff;
	uint32_t i;
	for (i = 0; i < len; i++)
		crc = (crc << 8) ^ crc_table[((crc >> 24) ^ *data++) & 0xff];
	return crc;
}

void convertSTR2TS(char *inFilename, char *outFilename, int notOverwrite) {
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

void processPIF(const char *filename, char *dest_file) {
	FILE *file = fopen(filename, "r");
	if (file == NULL) {
		printf("Can't open file %s\n", filename);
		exit(1);
	}
	fseek(file, 0, SEEK_END);
	int filesize = ftell(file);
	rewind(file);

	int append = 0;
	char *buffer = malloc(filesize);
	int read = fread(buffer, 1, filesize, file);
	if (read == filesize) {
		int i;
		for (i = 0; i < (filesize - 5); i++) {
			if (!memcmp(&buffer[i], "/mnt/", 5) && !memcmp(&buffer[i + strlen(&buffer[i]) - 3], "STR", 3)) {
				printf("Converting file: %s\n", strrchr(&buffer[i], '/') + 1);
				convertSTR2TS(strrchr(&buffer[i], '/') + 1, dest_file, append);
				append = 1;
			}
		}
	}
	fclose(file);
	free(buffer);
}
