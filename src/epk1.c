#include <epk1.h>

const char EPK1_MAGIC[] = "epak";

struct epk1_header_t *get_epk1_header(unsigned char *buffer) {
	return (struct epk1_header_t*) (buffer);
}

int is_epk1(char *buffer) {
	struct epk1_header_t *epak_header = get_epk1_header(buffer);
	return !memcmp(epak_header->_01_epak_magic, EPK1_MAGIC, 4);
}

int is_epk1_file(const char *epk_file) {
	FILE *file = fopen(epk_file, "r");
	if (file == NULL) {
		printf("Can't open file %s", epk_file);
		exit(1);
	}
	size_t header_size = sizeof(struct epk1_header_t);
	unsigned char* buffer = (unsigned char*) malloc(sizeof(char) * header_size);
	int read = fread(buffer, 1, header_size, file);
	if (read != header_size) return 0;
	fclose(file);
	int result = is_epk1(buffer);
	free(buffer);
	return result;
}

void print_epk1_header(struct epk1_header_t *epakHeader) {
	printf("firmware type: %s\n", epakHeader->_06_fw_type);
	printf("firmware version: %02x.%02x.%02x.%02x\n", epakHeader->_05_fw_version[3], epakHeader->_05_fw_version[2], epakHeader->_05_fw_version[1], epakHeader->_05_fw_version[0]);
	printf("contains %d mtd images\n", epakHeader->_03_pak_count);
	printf("total size of the images: %d\n\n", epakHeader->_02_file_size);
}

void print_epk1new_header(struct epk1new_header_t *epakHeader) {
	printf("firmware type: %s\n", epakHeader->_06_fw_type);
	printf("firmware version: %02x.%02x.%02x.%02x\n", epakHeader->_05_fw_version[3], epakHeader->_05_fw_version[2], epakHeader->_05_fw_version[1], epakHeader->_05_fw_version[0]);
	printf("contains %d mtd images\n", epakHeader->_03_pak_count);
	printf("total size of the images: %d\n\n", epakHeader->_02_file_size);
}

void get_epk1_version_string(char *fw_version, struct epk1_header_t *epak_header) {
	sprintf(fw_version, "%02x.%02x.%02x-%s", epak_header->_05_fw_version[2],
			epak_header->_05_fw_version[1], epak_header->_05_fw_version[0],
			epak_header->_06_fw_type);
}

void get_epk1new_version_string(char *fw_version, struct epk1new_header_t *epak_header) {
	sprintf(fw_version, "%02x.%02x.%02x-%s", epak_header->_05_fw_version[2],
			epak_header->_05_fw_version[1], epak_header->_05_fw_version[0],
			epak_header->_06_fw_type);
}

void extract_epk1_file(const char *epk_file, struct config_opts_t *config_opts) {
	FILE *file = fopen(epk_file, "r");
	if (file == NULL) {
		printf("Can't open file %s", epk_file);
		exit(1);
	}
	fseek(file, 0, SEEK_END);
	int fileLength = ftell(file);
	rewind(file);
	unsigned char* buffer = (unsigned char*) malloc(sizeof(char) * fileLength);
	int read = fread(buffer, 1, fileLength, file);
	if (read != fileLength) {
		printf("error reading file. read %d bytes from %d.\n", read, fileLength);
		exit(1);
	}
	fclose(file);

	if (!is_epk1(buffer)) {
		printf("unsupported file type. aborting.\n");
		exit(1);
	}

	char version_string[1024];
	char target_dir[1024];
	int pak_index;
	if (buffer[8] < 21) { //
		struct epk1_header_t *epak_header = (struct epk1_header_t*) (buffer);
		print_epk1_header(epak_header);
		get_epk1_version_string(version_string, epak_header);
		construct_path(target_dir, config_opts->dest_dir, version_string, NULL);
		create_dir_if_not_exist(target_dir);
		for (pak_index = 0; pak_index < epak_header->_03_pak_count; pak_index++) {
			struct pak1_info_t pak_info = epak_header->_04_pak_infos[pak_index];
			struct pak1_header_t *pak_header = (struct pak1_header_t *)(buffer + pak_info._01_file_offset);
			pak_type_t pak_type = get_pak_type(pak_header->_01_type_code);
			if (pak_type == UNKNOWN) {
				printf("WARNING!! firmware file contains unknown PAK type '%.*s'. ignoring it!\n", 4, pak_header->_01_type_code);
				continue;
			}
			char pak_type_name[5] = "";
			sprintf(pak_type_name, "%.*s", 4, pak_header->_01_type_code);
			char filename[100] = "";
			construct_path(filename, target_dir, pak_type_name, ".image");
			printf("Saving PAK #%u/%u (%s) to file %s\n", pak_index + 1, epak_header->_03_pak_count, pak_type_name, filename);
			FILE *outfile = fopen(((const char*) filename), "w");
			fwrite(pak_header->_01_type_code + sizeof(struct pak1_header_t), 1, pak_info._02_size, outfile);
			fclose(outfile);
			handle_extracted_image_file(filename, target_dir, pak_type_name);
		}
	} else {
		struct epk1new_header_t *epak_header = (struct epk1new_header_t*) (buffer);
		print_epk1new_header(epak_header);
		get_epk1new_version_string(version_string, epak_header);
		construct_path(target_dir, config_opts->dest_dir, version_string, NULL);
		create_dir_if_not_exist(target_dir);
		for (pak_index = 0; pak_index < epak_header->_03_pak_count; pak_index++) {
			struct pak1_info_t pak_info = epak_header->_04_pak_infos[pak_index];
			struct pak1_header_t *pak_header = (struct pak1_header_t *)(buffer + pak_info._01_file_offset);
			pak_type_t pak_type = get_pak_type(pak_header->_01_type_code);
			if (pak_type == UNKNOWN) {
				printf("WARNING!! firmware file contains unknown pak type '%.*s'. ignoring it!\n", 4, pak_header->_01_type_code);
				continue;
			}
			char pak_type_name[5] = "";
			sprintf(pak_type_name, "%.*s", 4, pak_header->_01_type_code);
			char filename[100] = "";
			construct_path(filename, target_dir, pak_type_name, ".image");
			printf("Saving PAK #%u/%u (%s) to file %s\n", pak_index + 1, epak_header->_03_pak_count, pak_type_name, filename);
			FILE *outfile = fopen(((const char*) filename), "w");
			fwrite(pak_header->_01_type_code + sizeof(struct pak1_header_t), 1, pak_header->_02_unknown1+4, outfile);
			fclose(outfile);
			handle_extracted_image_file(filename, target_dir, pak_type_name);
		}
	}
	free(buffer);
}

