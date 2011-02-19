/*
 ============================================================================
 Name        : main.c
 Author      : sirius
 Copyright   : published under GPL
 Description : EPK2 firmware extractor for LG electronic digital tv's
 ============================================================================
 */



#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>

#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <epk2.h>

pak_type_t convertToPakType(unsigned char type[4]) {

	uint32_t byte1 = type[0];
	uint32_t byte2 = type[1];
	uint32_t byte3 = type[2];
	uint32_t byte4 = type[3];

	byte1 = byte1 << 24;
	byte4 = byte4 | byte1;
	byte2 = byte2 << 16;
	byte4 = byte4 | byte2;
	byte3 = byte3 << 8;

	uint32_t result = byte4 | byte3;

	switch (result) {
	case 0x6C67666F:
		return LGFO;
	case 0x63726333:
		return CRC3;
	case 0x626F6F74:
		return BOOT;
	case 0x61736967:
		return ASIG;
	case 0x61757468:
		return AUTH;
	case 0x6164646F:
		return ADDO;
	case 0x62726F77:
		return BROW;
	case 0x63655F66:
		return CE_F;
	case 0x67616D65:
		return GAME;
	case 0x6B65726E:
		return KERN;
	case 0x6B696473:
		return KIDS;
	case 0x6C676170:
		return LGAP;
	case 0x69646669:
		return IDFI;
	case 0x65737472:
		return ESTR;
	case 0x657A6361:
		return ECZA;
	case 0x6570616B:
		return EPAK;
	case 0x6F70656E:
		return OPEN;
		// for backward compatibility with older fw ('opsr' -> 'open')
	case 0x6F707372:
		return OPEN;
	case 0x6D69636F:
		return MICO;
	case 0x6C677265:
		return LGRE;
	case 0x6C6F676F:
		return LOGO;
	case 0x6C67696E:
		return LGIN;
	case 0x6D746469:
		return MTDI;
	case 0x6E657466:
		return NETF;
	case 0x6E767261:
		return NVRA;
	case 0x6D6F6465:
		return MODE;
	case 0x73706962:
		return SPIB;
	case 0x72656364:
		return RECD;
	case 0x72657365:
		return RESE;
	case 0x726F6F74:
		return ROOT;
	case 0x7072656C:
		return PREL;
	case 0x73797374:
		return SYST;
	case 0x75736572:
		return USER;
	case 0x79776564:
		return YWED;
	case 0x73746F72:
		return STOR;
	case 0x63657274:
		return CERT;
	default:
		return UNKNOWN;
	}

}





int SSU_OadFileScan(const char* buffer) {

	int32_t byte0 = buffer[0];
	int32_t byte1 = buffer[1];
	int32_t byte2 = buffer[2];
	int32_t byte3 = buffer[3];

	byte0 = byte0 << 24;
	byte1 = byte1 << 16;
	byte2 = byte2 << 8;

	byte1 = byte1 | byte3;
	byte1 = byte1 | byte0;
	byte1 = byte1 | byte2;

	if (byte1 == 0x42494F50) {
		return 1;
	} else {
		return -1;
	}
}

uint32_t get_big_endian(const unsigned char* buffer) {

	uint32_t byte0 = buffer[0];
	uint32_t byte1 = buffer[1];
	uint32_t byte2 = buffer[2];
	uint32_t byte3 = buffer[3];

	byte3 = byte3 << 24;
	byte0 = byte0 | byte3;
	byte2 = byte2 << 16;
	byte0 = byte0 | byte2;
	byte1 = byte1 << 8;

	return byte0 | byte1;
}


char *appendFilenameToDir(const char *directory, const char *filename) {
	int len = sizeof(directory) + sizeof("/") + sizeof(filename) + 10;
	char *result = malloc(len);
	memset(result, 0, len);
	strcat(result, "./");
	strcat(result, directory);
	strcat(result, "/");
	strcat(result, filename);

	return result;
}

char* getExtractionDir(struct epk2_header_t *epak_header) {
	char *fw_version = malloc(0x50);

	sprintf(fw_version, "%02x.%02x.%02x.%02x-%s", epak_header->_05_fw_version[3],
			epak_header->_05_fw_version[2], epak_header->_05_fw_version[1],
			epak_header->_05_fw_version[0], epak_header->_06_fw_type);

	return fw_version;
}

void createDirIfNotExist(const char *directory) {
	struct stat st;
	if (stat(directory, &st) != 0) {
		if (mkdir((const char*) directory, 0744) != 0) {
			printf("Can't create directory %s within current directory",
					directory);
			exit(1);
		}
	}
}

void writePakChunks(struct pak_t *pak, const char *filename) {
	FILE *outfile = fopen(((const char*) filename), "w");

	int pak_chunk_index;
	for (pak_chunk_index = 0; pak_chunk_index < pak->chunk_count; pak_chunk_index++) {
		struct pak_chunk_t *pak_chunk = pak->chunks[pak_chunk_index];

		int content_len = pak_chunk->content_len;
		unsigned char* decrypted = malloc(content_len);
		memset(decrypted, 0xFF, content_len);
		decryptImage(pak_chunk->content, content_len, decrypted);
		fwrite(decrypted, 1, content_len, outfile);

		free(decrypted);
	}

	fclose(outfile);
}


int main(int argc, char *argv[]) {

	printf("LG electronics digital tv firmware EPK2 extractor\n");
	printf("Version 0.6 by sirius (openlgtv.org.ru) 08.02.2011\n\n");

	SWU_CryptoInit();

	char *current_dir = getcwd(NULL, 0);

	printf("current directory: %s\n\n", current_dir);

	if (argc < 2) {

		printf("\n");
		printf("usage: %s FILENAME\n", argv[0]);
		exit(1);
	}

	char *epk_file = argv[1];

	printf("firmware info\n");
	printf("-------------\n");
	printf("firmware file: %s\n", epk_file);

	FILE *file = fopen(epk_file, "r");

	if (file == NULL) {
		printf("Can't open file %s", epk_file);
		exit(1);
	}

	fseek(file, 0, SEEK_END);

	int fileLength;

	fileLength = ftell(file);

	rewind(file);

	unsigned char* buffer = (unsigned char*) malloc(sizeof(char) * fileLength);

	int read = fread(buffer, 1, fileLength, file);

	if (read != fileLength) {
		printf("error reading file. read %d bytes from %d.\n", read, fileLength);
		exit(1);
	}

	fclose(file);

	struct epk2_header_t *epak_header = getEPakHeader(buffer);

	printEPakHeader(epak_header);

	int verified = API_SWU_VerifyImage(buffer, epak_header->_07_header_length
			+ SIGNATURE_SIZE);

	if (verified != 1) {
		printf(
				"firmware package can't be verified by it's digital signature. aborting.\n");
		exit(1);
	}

	struct pak_t **pak_array = malloc((epak_header->_03_pak_count)
			* sizeof(struct pak_t*));

	scanPAKs(epak_header, pak_array);

	char *target_dir = getExtractionDir(epak_header);

	createDirIfNotExist(target_dir);

	int pak_index;
	for (pak_index = 0; pak_index < epak_header->_03_pak_count; pak_index++) {
		struct pak_t *pak = pak_array[pak_index];

		if (pak->type == UNKNOWN) {
			printf(
					"WARNING!! firmware file contains unknown pak type '%.*s'. ignoring it!\n",
					4, pak->header->_00_type_code);
			continue;
		}

		printPakInfo(pak);

		const char *pak_type_name = getPakName(pak->type);

		char filename[100] = "";
		sprintf(filename, "./%s/%s.image", target_dir, pak_type_name);

		printf("saving content of pak #%u/%u (%s) to file %s\n", pak_index + 1,
				epak_header->_03_pak_count, pak_type_name, filename);

		writePakChunks(pak, filename);

		if (is_squashfs(filename)) {
			char unsquashed[100] = "";
			sprintf(unsquashed, "./%s/%s", target_dir, pak_type_name);
			printf("unsquashfs %s to directory %s\n", filename, unsquashed);
			rmrf(unsquashed);
			unsquashfs(filename, unsquashed);
		}

		if (check_lzo_header(filename) == 0) {
			char unpacked[100] = "";

			sprintf(unpacked, "./%s/%s.unpacked", target_dir, pak_type_name);

			printf("decompressing %s with modified LZO algorithm to %s\n",
					filename, unpacked);

			if (lzo_unpack((const char*) filename, (const char*) unpacked) != 0) {
				printf("sorry. decompression failed. aborting now.\n");
				exit(1);
			}

			if (is_cramfs_image(unpacked)) {
				char uncram[100] = "";
				sprintf(uncram, "./%s/%s", target_dir, pak_type_name);
				printf("uncramfs %s to directory %s\n", unpacked, uncram);
				rmrf(uncram);
				uncramfs(uncram, unpacked);

//				if ((pak->type == LGAP)) {
//
//					char release[100] = "";
//					sprintf(release, "%s/RELEASE", uncram, uncram);
//
//					extractRELEASE(unpacked, release);
//				}

			}
		}
	}

	printf("extraction succeeded\n");

	return EXIT_SUCCESS;
}
