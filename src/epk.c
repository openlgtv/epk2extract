#include <epk.h>
#include <u-boot/image.h>
#include <arpa/inet.h>

int is_kernel(const char *image_file) {
	FILE *file = fopen(image_file, "r");
	if (file == NULL) {
		printf("Can't open file %s", image_file);
		exit(1);
	}
	size_t header_size = sizeof(struct image_header);
	unsigned char* buffer = (unsigned char*) malloc(sizeof(char) * header_size);
	int read = fread(buffer, 1, header_size, file);
	if (read != header_size) return 0;
	fclose(file);
	struct image_header *image_header = (struct image_header *) buffer;
	int result = image_header->ih_magic == ntohl(IH_MAGIC);
	free(buffer);
	return result;
}

void extract_kernel(const char *image_file, const char *destination_file) {
	FILE *file = fopen(image_file, "r");
	if (file == NULL) {
		printf("Can't open file %s", image_file);
		exit(1);
	}
	fseek(file, 0, SEEK_END);
	int fileLength = ftell(file);
	rewind(file);
	unsigned char* buffer = (unsigned char*) malloc(sizeof(char) * fileLength);
	int read = fread(buffer, 1, fileLength, file);
	if (read != fileLength) {
		printf("Error reading file. read %d bytes from %d.\n", read, fileLength);
		exit(1);
	}
	fclose(file);

	struct image_header *image_header = (struct image_header *) buffer;
	FILE *out = fopen(destination_file, "w");
	int header_size = sizeof(struct image_header);
	fwrite(buffer + header_size, 1, read - header_size, out);
	fclose(out);
	free(buffer);
}

void processExtractedFile(char *filename, char *target_dir, const char *pak_type_name) {
	if (strcmp(pak_type_name, "patc") != 0 && strcmp(pak_type_name, "extr") != 0) {
		if (is_squashfs(filename)) {
			char unsquashed[255] = "";
			constructPath(unsquashed, target_dir, pak_type_name, NULL);
			printf("Unsquashfs %s to folder %s\n", filename, unsquashed);
			rmrf(unsquashed);
			unsquashfs(filename, unsquashed);
		}
	} else {
		printf("!!!Skipping unsquashfs (%s) as it doesn't know how to handle it...\n", pak_type_name);
	}
	if (is_lz4(filename)) {
		char unpacked[255] = "";
		constructPath(unpacked, target_dir, pak_type_name, ".unLZ4");
		char lz4pack[255] = "";
		sprintf(lz4pack, "./lz4pack -d %s %s", filename, unpacked);
		system(lz4pack);
		processExtractedFile(unpacked, target_dir, pak_type_name);	
	}
	if (check_lzo_header(filename)) {
		char unpacked[255] = "";
		constructPath(unpacked, target_dir, pak_type_name, ".unpacked");
		printf("LZOunpack %s to folder %s\n", filename, unpacked);
		if (lzo_unpack((const char*) filename, (const char*) unpacked) != 0) {
			printf("Decompression failed. Aborting now.\n");
			exit(1);
		}
		processExtractedFile(unpacked, target_dir, pak_type_name);
	}
	if (is_cramfs_image(filename)) {
		char uncram[255] = "";
		constructPath(uncram, target_dir, pak_type_name, NULL);
		printf("Uncramfs %s to folder %s\n", filename, uncram);
		rmrf(uncram);
		uncramfs(uncram, filename);
	}
	if (is_kernel(filename)) {
		char deimaged[255] = "";
		constructPath(deimaged, target_dir, pak_type_name, ".unPAKed");
		printf("Extracting kernel %s to %s\n", filename, deimaged);
		extract_kernel(filename, deimaged);
		processExtractedFile(deimaged, target_dir, pak_type_name);
	}
}																																																																																																																																																																																																																																																			
