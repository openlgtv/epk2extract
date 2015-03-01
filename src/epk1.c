#include <sys/mman.h>
#include <fcntl.h>
#include <epk1.h>
#include <errno.h>
#include <os_byteswap.h>

int isFileEPK1(file_t *file) {
	return !memcmp(file->data, "epak", 4);
}

void printHeaderInfo(struct epk1Header_t *epakHeader) {
	printf("\nFirmware otaID: %s\n", epakHeader->otaID);
	printf("Firmware version: %02x.%02x.%02x.%02x\n", epakHeader->fwVer[3], epakHeader->fwVer[2], epakHeader->fwVer[1], epakHeader->fwVer[0]);
	printf("PAK count: %d\n", epakHeader->pakCount);
	printf("PAKs total size: %d\n", epakHeader->fileSize);
}

void printNewHeaderInfo(struct epk1NewHeader_t *epakHeader) {
	printf("\nFirmware otaID: %s\n", epakHeader->otaID);
	printf("Firmware version: %02x.%02x.%02x.%02x\n", epakHeader->fwVer[3], epakHeader->fwVer[2], epakHeader->fwVer[1], epakHeader->fwVer[0]);
	printf("PAK count: %d\n", epakHeader->pakCount);
	printf("PAKs total size: %d\n", epakHeader->fileSize);
}

void constructVerString(char *fw_version, struct epk1Header_t *epakHeader) {
	sprintf(fw_version, "%02x.%02x.%02x-%s", epakHeader->fwVer[2], epakHeader->fwVer[1], epakHeader->fwVer[0], epakHeader->otaID);
}

void constructNewVerString(char *fw_version, struct epk1NewHeader_t *epakHeader) {
	sprintf(fw_version, "%02x.%02x.%02x-%s", epakHeader->fwVer[2], epakHeader->fwVer[1], epakHeader->fwVer[0], epakHeader->otaID);
}

#define BUILD_VERSTRING(dest, src) \
	sprintf(dest, "%02x.%02x.%02x.%02x", \
		src >> (8 * 0) & 0xff, \
		src >> (8 * 1) & 0xff, \
		src >> (8 * 2) & 0xff, \
		src >> (8 * 3) & 0xff);

void extract_EPK1_BE(file_t *file){
	uint8_t *data = file->data;
	char verString[12];
	int index;

	printf("\nFirmware type is EPK1 Big Endian...\n");
	struct epk1BEHeader_t *epakHeader = (struct epk1BEHeader_t *)data;	//make struct from buffer
	SWAP(epakHeader->fileSize);
	SWAP(epakHeader->pakCount);

	pakRec_t *first_pak = (pakRec_t *)(data + sizeof(struct epk1BEHeader_t));
	uint32_t first_off = be32toh(first_pak->offset);

	uint32_t *fwVer = (uint32_t *)(data + first_off - 4);
	printf("\nFirmware otaID: %s\n", ((struct pakHeader_t *)(data + first_off))->platform);

	BUILD_VERSTRING(verString, *fwVer);

	printf("Firmware version: %s\n", verString);
	printf("PAK count: %d\n", epakHeader->pakCount);
	printf("PAKs total size: %d\n", epakHeader->fileSize);

	char *outdir = calloc(1, strlen(file->out_dir)+strlen(verString));
	sprintf(outdir, "%s/%s", file->out_dir, verString);
	createFolder(outdir);

	uint32_t offset = 0xC;
	for (index = 0; index < epakHeader->pakCount; index++) {
		pakRec_t *pakRecord = (pakRec_t *)(data + offset);
		if (pakRecord->offset == 0) {
			offset += 8;
			index--;
			continue;
		}

		SWAP(pakRecord->offset);
		SWAP(pakRecord->size);
		struct pakHeader_t *pakHeader = (struct pakHeader_t *)(data + pakRecord->offset);
		SWAP(pakHeader->pakSize);
		char pakName[5] = "";
		sprintf(pakName, "%.*s", 4, pakHeader->pakName);
		file->out_path = calloc(1, strlen(outdir) + strlen(pakName) + 5 + 1);
		sprintf(file->out_path, "%s/%s.pak", outdir, pakName);
		printf("\n#%u/%u saving PAK (name='%s', platform='%s', offset=0x%x, size='%d') to file %s\n", index + 1, epakHeader->pakCount, pakName, pakHeader->platform, pakRecord->offset, pakRecord->size, file->out_path);

		FILE *outfile = fopen(file->out_path, "wb");
		fwrite(pakHeader->pakName + sizeof(struct pakHeader_t), 1, pakRecord->size - 132, outfile);
		fclose(outfile);
		//handle_file(file->out_path, file->out_dir);
		offset += 8;
	}
	free(outdir);
}

void extract_EPK1_OLD(file_t *file){
}

void extract_EPK1_NEW(file_t *file){
}

void extractEPK1file(file_t *file) {
	uint32_t *pakcount = &( ((struct epk1Header_t *)file->data)->pakCount );
	if (IS_BE(*pakcount)) {
		return extract_EPK1_BE(file);
	} else if (pakcount < 21) {	// old EPK1 header
		return extract_EPK1_OLD(file);
	} else { // new EPK1 header
		return extract_EPK1_NEW(file);
	}
}
