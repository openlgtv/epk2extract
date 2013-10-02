#include <sys/mman.h>
#include <fcntl.h>
#include <epk1.h>

const char EPK1_MAGIC[] = "epak";

int isFileEPK1(const char *epk_file) {
	FILE *file = fopen(epk_file, "r");
	if (file == NULL) {
		printf("Can't open file %s", epk_file);
		exit(1);
	}
	size_t header_size = sizeof(struct epk1Header_t);
	unsigned char* buffer = (unsigned char*) malloc(sizeof(char) * header_size);
	int read = fread(buffer, 1, header_size, file);
	if (read != header_size) return 0;
	fclose(file);
	int result = !memcmp(((struct epk1Header_t*)(buffer))->epakMagic, EPK1_MAGIC, 4);
	free(buffer);
	return result;
}

void printHeaderInfo(struct epk1Header_t *epakHeader) {
	printf("\nFirmware otaID: %s\n", epakHeader->otaID);
	printf("Firmware version: %02x.%02x.%02x.%02x\n", epakHeader->fwVer[3], epakHeader->fwVer[2], epakHeader->fwVer[1], epakHeader->fwVer[0]);
	printf("PAK count: %d\n", epakHeader->pakCount);
	printf("PAKs total size: %d\n\n", epakHeader->fileSize);
}

void printNewHeaderInfo(struct epk1NewHeader_t *epakHeader) {
	printf("\nFirmware otaID: %s\n", epakHeader->otaID);
	printf("Firmware version: %02x.%02x.%02x.%02x\n", epakHeader->fwVer[3], epakHeader->fwVer[2], epakHeader->fwVer[1], epakHeader->fwVer[0]);
	printf("PAK count: %d\n", epakHeader->pakCount);
	printf("PAKs total size: %d\n\n", epakHeader->fileSize);
}

void constructVerString(char *fw_version, struct epk1Header_t *epakHeader) {
	sprintf(fw_version, "%02x.%02x.%02x-%s", epakHeader->fwVer[2],	epakHeader->fwVer[1], epakHeader->fwVer[0], epakHeader->otaID);
}

void constructNewVerString(char *fw_version, struct epk1NewHeader_t *epakHeader) {
	sprintf(fw_version, "%02x.%02x.%02x-%s", epakHeader->fwVer[2],	epakHeader->fwVer[1], epakHeader->fwVer[0], epakHeader->otaID);
}

void extract_epk1_file(const char *epk_file, struct config_opts_t *config_opts) {
	int file;
	if (!(file = open(epk_file, O_RDONLY))) {
		printf("\nCan't open file %s\n", epk_file);
		exit(1);
	}
	struct stat statbuf;
	if (fstat(file, &statbuf) < 0) {
		printf("\nfstat error\n"); 
		exit(1);
	}
	int fileLength = statbuf.st_size;
	printf("File size: %d bytes\n", fileLength);
	void *buffer;
	if ( (buffer = mmap(0, fileLength, PROT_READ, MAP_SHARED, file, 0)) == MAP_FAILED ) {
		printf("\nCannot mmap input file. Aborting\n"); 
		exit(1);
	}
	char verString[1024];
	char targetFolder[1024]="";
	int index;
	if (((struct epk1Header_t*)(buffer))->pakCount < 21) { // old EPK1 header
		printf("\nFirmware type is EPK1...\n");
		struct epk1Header_t *epakHeader = (struct epk1Header_t*) (buffer);
		printHeaderInfo(epakHeader);
		constructVerString(verString, epakHeader);
		constructPath(targetFolder, config_opts->dest_dir, verString, NULL);
		createFolder(targetFolder);
		for (index = 0; index < epakHeader->pakCount; index++) {
			struct pakRec_t pakRecord = epakHeader->pakRecs[index];
			struct pakHeader_t *pakHeader = (struct pakHeader_t *)(buffer + pakRecord.offset);
			char pakName[5] = "";
			sprintf(pakName, "%.*s", 4, pakHeader->pakName);
			char filename[255] = "";
			constructPath(filename, targetFolder, pakName, ".pak");
			printf("#%u/%u saving PAK  (%s) to file %s\n", index + 1, epakHeader->pakCount, pakName, filename);
			FILE *outfile = fopen(((const char*) filename), "w");
			fwrite(pakHeader->pakName + sizeof(struct pakHeader_t), 1, pakRecord.size, outfile);
			fclose(outfile);
			processExtractedFile(filename, targetFolder, pakName);
		}
	} else { // new EPK1 header
		printf("\nFirmware type is EPK1(new)...\n");
		struct epk1NewHeader_t *epakHeader = (struct epk1NewHeader_t*) (buffer);
		printNewHeaderInfo(epakHeader);
		constructNewVerString(verString, epakHeader);
		constructPath(targetFolder, config_opts->dest_dir, verString, NULL);
		createFolder(targetFolder);
		for (index = 0; index < epakHeader->pakCount; index++) {
			struct pakRec_t pakRecord = epakHeader->pakRecs[index];
			struct pakHeader_t *pakHeader = (struct pakHeader_t *)(buffer + pakRecord.offset);
			char pakName[5] = "";
			sprintf(pakName, "%.*s", 4, pakHeader->pakName);
			char filename[255] = "";
			constructPath(filename, targetFolder, pakName, ".pak");
			printf("#%u/%u saving PAK (%s) to file %s\n", index + 1, epakHeader->pakCount, pakName, filename);
			FILE *outfile = fopen(((const char*) filename), "w");
			fwrite(pakHeader->pakName + sizeof(struct pakHeader_t), 1, pakHeader->pakSize+4, outfile);
			fclose(outfile);
			processExtractedFile(filename, targetFolder, pakName);
		}
	}
	if (munmap(buffer, fileLength) == -1) printf("Error un-mmapping the file");
	close(file);
}

