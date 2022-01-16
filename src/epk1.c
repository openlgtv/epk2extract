/**
 * EPK v1 handling
 * Copyright 2016 Smx <smxdev4@gmail.com>
 * Copyright 2016 lprot
 * Copyright 20?? sirius
 * All right reserved
 */
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>

#include "main.h" //for handle_file
#include "epk1.h"
#include "os_byteswap.h"
#include "util.h"

int isFileEPK1(const char *epk_file) {
	FILE *file = fopen(epk_file, "rb");
	if (file == NULL) {
		err_exit("Can't open file %s\n\n", epk_file);
	}
	char magic[4];
	if (fread(&magic, 1, 4, file) != 4)
		return 0;
	fclose(file);
	return !memcmp(&magic, "epak", 4);
}

void printHeaderInfo(struct epk1Header_t *epakHeader) {
	printf("\nFirmware otaID: %s\n", epakHeader->otaID);
	printf("Firmware version: " EPK_VERSION_FORMAT "\n", epakHeader->fwVer[3], epakHeader->fwVer[2], epakHeader->fwVer[1], epakHeader->fwVer[0]);
	printf("PAK count: %d\n", epakHeader->pakCount);
	printf("PAKs total size: %d\n", epakHeader->fileSize);
}

void printNewHeaderInfo(struct epk1NewHeader_t *epakHeader) {
	printf("\nFirmware otaID: %s\n", epakHeader->otaID);
	printf("Firmware version: " EPK_VERSION_FORMAT "\n", epakHeader->fwVer[3], epakHeader->fwVer[2], epakHeader->fwVer[1], epakHeader->fwVer[0]);
	printf("PAK count: %d\n", epakHeader->pakCount);
	printf("PAKs total size: %d\n", epakHeader->fileSize);
}

void constructVerString(char *fw_version, struct epk1Header_t *epakHeader) {
	sprintf(fw_version, EPK_VERSION_FORMAT "-%s", epakHeader->fwVer[2], epakHeader->fwVer[1], epakHeader->fwVer[0], epakHeader->otaID);
}

void constructNewVerString(char *fw_version, struct epk1NewHeader_t *epakHeader) {
	sprintf(fw_version, EPK_VERSION_FORMAT "-%s", epakHeader->fwVer[2], epakHeader->fwVer[1], epakHeader->fwVer[0], epakHeader->otaID);
}

void extract_epk1_file(const char *epk_file, config_opts_t *config_opts) {
	int file;
	if (!(file = open(epk_file, O_RDONLY))) {
		err_exit("\nCan't open file %s\n\n", epk_file);
	}
	struct stat statbuf;
	if (fstat(file, &statbuf) < 0) {
		err_exit("\nfstat error\n\n");
	}
	int fileLength = statbuf.st_size;
	printf("File size: %d bytes\n", fileLength);
	void *buffer;
	if ((buffer = mmap(0, fileLength, PROT_READ, MAP_SHARED, file, 0)) == MAP_FAILED) {
		err_exit("\nCannot mmap input file (%s). Aborting\n\n", strerror(errno));
	}
	char verString[12];
	int index;
	uint32_t pakcount = ((struct epk1Header_t *)buffer)->pakCount;
	if (pakcount >> 8 != 0) {
		SWAP(pakcount);
		printf("\nFirmware type is EPK1 Big Endian...\n");
		unsigned char *header = malloc(sizeof(struct epk1BEHeader_t));	//allocate space for header
		memcpy(header, buffer, sizeof(struct epk1BEHeader_t));	//copy header to buffer
		struct epk1BEHeader_t *epakHeader = (struct epk1BEHeader_t *)header;	//make struct from buffer
		SWAP(epakHeader->fileSize);
		SWAP(epakHeader->pakCount);
		SWAP(epakHeader->offset);

		uint32_t *fwVer = buffer + epakHeader->offset - 4;
		printf("\nFirmware otaID: %s\n", (char *)(buffer + epakHeader->offset + 8));
		printf("Firmware version: " EPK_VERSION_FORMAT "\n",
			(fwVer[0] >> (8 * 0)) & 0xff,
			(fwVer[0] >> (8 * 1)) & 0xff,
			(fwVer[0] >> (8 * 2)) & 0xff,
			(fwVer[0] >> (8 * 3)) & 0xff);
		printf("PAK count: %d\n", epakHeader->pakCount);
		printf("PAKs total size: %d\n", epakHeader->fileSize);

		sprintf(verString, EPK_VERSION_FORMAT,
			(fwVer[0] >> (8 * 0)) & 0xff,
			(fwVer[0] >> (8 * 1)) & 0xff,
			(fwVer[0] >> (8 * 2)) & 0xff,
			(fwVer[0] >> (8 * 3)) & 0xff);
		asprintf_inplace(&config_opts->dest_dir, "%s/%s", config_opts->dest_dir, verString);
		createFolder(config_opts->dest_dir);

		unsigned long int offset = 0xC;
		for (index = 0; index < epakHeader->pakCount; index++) {
			struct pakRec_t *pakRecord = malloc(sizeof(struct pakRec_t));	//allocate space for header
			memcpy(pakRecord, buffer + offset, sizeof(struct pakRec_t));	//copy pakRecord to buffer

			if (pakRecord->offset == 0) {
				offset += 8;
				index--;
				continue;
			}

			SWAP(pakRecord->offset);
			SWAP(pakRecord->size);
			unsigned char *pheader = malloc(sizeof(struct pakHeader_t));
			memcpy(pheader, (buffer + pakRecord->offset), sizeof(struct pakHeader_t));
			struct pakHeader_t *pakHeader = (struct pakHeader_t *)pheader;
			SWAP(pakHeader->pakSize);
			pakHeader = (struct pakHeader_t *)(buffer + pakRecord->offset);
			char pakName[5] = "";
			sprintf(pakName, "%.*s", 4, pakHeader->pakName);
			char filename[255] = "";
			sprintf(filename, "%s/%s.pak", config_opts->dest_dir, pakName);
			printf("\n#%u/%u saving PAK (name='%s', platform='%s', offset=0x%x, size='%d') to file %s\n", index + 1, epakHeader->pakCount, pakName, pakHeader->platform, pakRecord->offset, pakRecord->size, filename);
			FILE *outfile = fopen(((const char *)filename), "wb");
			fwrite(pakHeader->pakName + sizeof(struct pakHeader_t), 1, pakRecord->size - 132, outfile);
			fclose(outfile);
			handle_file(filename, config_opts);
			free(pakRecord);
			free(pheader);
			offset += 8;
		}
		free(header);
	} else if (pakcount < 21) {	// old EPK1 header
		printf("\nFirmware type is EPK1...\n");
		struct epk1Header_t *epakHeader = (struct epk1Header_t *)buffer;
		printHeaderInfo(epakHeader);
		constructVerString(verString, epakHeader);
		asprintf_inplace(&config_opts->dest_dir, "%s/%s", config_opts->dest_dir, verString);
		createFolder(config_opts->dest_dir);
		for (index = 0; index < epakHeader->pakCount; index++) {
			struct pakRec_t pakRecord = epakHeader->pakRecs[index];
			struct pakHeader_t *pakHeader;
			pakHeader = (struct pakHeader_t *)(buffer + pakRecord.offset);
			char pakName[5] = "";
			sprintf(pakName, "%.*s", 4, pakHeader->pakName);
			char filename[255] = "";
			sprintf(filename, "%s/%s.pak", config_opts->dest_dir, pakName);
			printf("\n#%u/%u saving PAK (name='%s', platform='%s', offset=0x%x, size='%d') to file %s\n", index + 1, epakHeader->pakCount, pakName, pakHeader->platform, pakRecord.offset, pakRecord.size, filename);
			FILE *outfile = fopen(((const char *)filename), "wb");
			fwrite(pakHeader->pakName + sizeof(struct pakHeader_t), 1, pakRecord.size - 132, outfile);
			fclose(outfile);
			handle_file(filename, config_opts);
		}
	} else {					// new EPK1 header
		printf("\nFirmware type is EPK1(new)...\n");
		struct epk1NewHeader_t *epakHeader = (struct epk1NewHeader_t *)(buffer);
		printNewHeaderInfo(epakHeader);
		constructNewVerString(verString, epakHeader);
		asprintf_inplace(&config_opts->dest_dir, "%s/%s", config_opts->dest_dir, verString);
		createFolder(config_opts->dest_dir);
		for (index = 0; index < epakHeader->pakCount; index++) {
			struct pakRec_t pakRecord = epakHeader->pakRecs[index];
			struct pakHeader_t *pakHeader = (struct pakHeader_t *)(buffer + pakRecord.offset);
			char pakName[5] = "";
			sprintf(pakName, "%.*s", 4, pakHeader->pakName);
			char filename[255] = "";
			sprintf(filename, "%s/%s.pak", config_opts->dest_dir, pakName);
			printf("\n#%u/%u saving PAK (name='%s', platform='%s', offset=0x%x, size='%d') to file %s\n", index + 1, epakHeader->pakCount, pakName, pakHeader->platform, pakRecord.offset, pakRecord.size, filename);
			FILE *outfile = fopen(((const char *)filename), "wb");
			fwrite(pakHeader->pakName + sizeof(struct pakHeader_t), 1, pakHeader->pakSize + 4, outfile);
			fclose(outfile);
			handle_file(filename, config_opts);
		}
	}
	if (munmap(buffer, fileLength) == -1)
		printf("Error un-mmapping the file");
	close(file);
}
