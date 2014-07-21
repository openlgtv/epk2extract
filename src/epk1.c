#include <sys/mman.h>
#include <fcntl.h>
#include <epk1.h>
#include <errno.h>
#include <formats.h>


const char EPK1_MAGIC[] = "epak";
int endianswap;

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
		printf("\nCannot mmap input file (%s). Aborting\n", strerror(errno));
		exit(1);
	}
	char verString[1024];
	char targetFolder[1024]="";
	int index;
	endianswap=0;
	uint32_t pakcount = ((struct epk1Header_t*)buffer)->pakCount;
	if (pakcount >> 8 != 0) {
	    endianswap = 1;
	    SWAP(pakcount);
	    printf("\nFirmware type is EPK1 Big Endian...\n");
	    unsigned char *header = malloc(sizeof(struct epk1BEHeader_t)); //allocate space for header
	    memcpy(header, buffer, sizeof(struct epk1BEHeader_t)); //copy header to buffer
	    struct epk1BEHeader_t *epakHeader = (struct epk1BEHeader_t*)header; //make struct from buffer
	    SWAP(epakHeader->fileSize);
	    SWAP(epakHeader->pakCount);
        SWAP(epakHeader->offset);
        
        uint32_t *fwVer = buffer + epakHeader->offset - 4;
        printf("\nFirmware otaID: %s\n", (char*)(buffer + epakHeader->offset + 8));
        printf("Firmware version: %02x.%02x.%02x.%02x\n", (fwVer[0] >> (8*0)) & 0xff, (fwVer[0] >> (8*1)) & 0xff, 
            (fwVer[0] >> (8*2)) & 0xff, (fwVer[0] >> (8*3)) & 0xff);
        printf("PAK count: %d\n", epakHeader->pakCount);
        printf("PAKs total size: %d\n\n", epakHeader->fileSize);

        sprintf(verString, "%02x.%02x.%02x", (fwVer[0] >> (8*1)) & 0xff, (fwVer[0] >> (8*2)) & 0xff, (fwVer[0] >> (8*3)) & 0xff);
	    constructPath(targetFolder, config_opts->dest_dir, verString, NULL);
	    createFolder(targetFolder);
        
        unsigned long int offset = 0xC;
        for (index = 0; index < epakHeader->pakCount; index++) {
            struct pakRec_t *pakRecord = malloc(sizeof(struct pakRec_t)); //allocate space for header
	        memcpy(pakRecord, buffer + offset, sizeof(struct pakRec_t)); //copy pakRecord to buffer

            if (pakRecord->offset == 0) {
                offset += 8;
                index--;
                continue;
            }

            SWAP(pakRecord->offset);
            SWAP(pakRecord->size);
            unsigned char *pheader = malloc(sizeof(struct pakHeader_t));
            memcpy(pheader, (buffer+pakRecord->offset), sizeof(struct pakHeader_t));
            struct pakHeader_t *pakHeader = (struct pakHeader_t*)pheader;
            SWAP(pakHeader->pakSize);
            pakHeader = (struct pakHeader_t *)(buffer + pakRecord->offset);
            char pakName[5] = "";
            sprintf(pakName, "%.*s", 4, pakHeader->pakName);
            char filename[255] = "";
            constructPath(filename, targetFolder, pakName, ".pak");
            printf("#%u/%u saving PAK (name='%s', platform='%s', offset=0x%x, size='%d') to file %s\n", index + 1, epakHeader->pakCount, pakName, 
                pakHeader->platform, pakRecord->offset, pakRecord->size, filename);
            FILE *outfile = fopen(((const char*) filename), "w");
            fwrite(pakHeader->pakName + sizeof(struct pakHeader_t), 1, pakRecord->size - 132, outfile);
            fclose(outfile);
            processExtractedFile(filename, targetFolder, pakName);
            free(pakRecord);
            free(pheader);            
            offset += 8;
        }
        free(header);
    } else if (pakcount < 21) { // old EPK1 header
	    printf("\nFirmware type is EPK1...\n");
	    struct epk1Header_t *epakHeader = (struct epk1Header_t*)buffer;
	    printHeaderInfo(epakHeader);
	    constructVerString(verString, epakHeader);
	    constructPath(targetFolder, config_opts->dest_dir, verString, NULL);
	    createFolder(targetFolder);
	    for (index = 0; index < epakHeader->pakCount; index++) {
		struct pakRec_t pakRecord = epakHeader->pakRecs[index];
		struct pakHeader_t *pakHeader;
		pakHeader = (struct pakHeader_t *)(buffer + pakRecord.offset);
		char pakName[5] = "";
		sprintf(pakName, "%.*s", 4, pakHeader->pakName);
		char filename[255] = "";
		constructPath(filename, targetFolder, pakName, ".pak");
        printf("#%u/%u saving PAK (name='%s', platform='%s', offset=0x%x, size='%d') to file %s\n", index + 1, epakHeader->pakCount, pakName, 
            pakHeader->platform, pakRecord.offset, pakRecord.size, filename);
		FILE *outfile = fopen(((const char*) filename), "w");
		fwrite(pakHeader->pakName + sizeof(struct pakHeader_t), 1, pakRecord.size - 132, outfile);
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
            printf("#%u/%u saving PAK (name='%s', platform='%s', offset=0x%x, size='%d') to file %s\n", index + 1, epakHeader->pakCount, pakName, 
                pakHeader->platform, pakRecord.offset, pakRecord.size, filename);
			FILE *outfile = fopen(((const char*) filename), "w");
			fwrite(pakHeader->pakName + sizeof(struct pakHeader_t), 1, pakHeader->pakSize + 4, outfile);
			fclose(outfile);
			processExtractedFile(filename, targetFolder, pakName);
		}
	}
	if (munmap(buffer, fileLength) == -1) printf("Error un-mmapping the file");
	close(file);
}