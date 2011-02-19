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

int main(int argc, char *argv[]) {

	printf("LG electronics digital tv firmware EPK2 extractor\n");
	printf("Version 0.7dev by sirius (openlgtv.org.ru)\n\n");

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
			}
		}
	}

	printf("extraction succeeded\n");

	return EXIT_SUCCESS;
}
