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

int handle_file(const char *file, char *destination) {
	if (check_lzo_header(file)) {
		if (destination == NULL) {
			destination = "./lzounpack.out";
		}
		printf("extracting lzo compressed file to: %s\n", destination);
		if (lzo_unpack(file, destination) == 0) {
			handle_file(destination, NULL);
			return EXIT_SUCCESS;
		}
	} else if (is_squashfs(file)) {
		if (destination == NULL) {
			destination = "./unsquashfs.out";
		}
		printf("unsquashfs compressed file system to: %s\n", destination);
		rmrf(destination);
		unsquashfs(file, destination);
		return EXIT_SUCCESS;
	} else if (is_cramfs_image(file)) {
		if (destination == NULL) {
			destination = "./uncramfs.out";
		}
		printf("uncramfs compressed file system to: %s\n", destination);
		rmrf(destination);
		uncramfs(destination, file);
		return EXIT_SUCCESS;
	} else if (is_epk2_file(file)) {
		printf("extracting firmware file...\n\n");
		extract_epk2_file(file);
		return EXIT_SUCCESS;
	}

	printf("\n");
	printf("unsupported file format:\n", file);
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {

	printf("LG electronics digital tv firmware EPK2 extractor\n");
	printf("Version 0.8dev by sirius (openlgtv.org.ru)\n\n");

	char *current_dir = getcwd(NULL, 0);

	printf("current directory: %s\n\n", current_dir);

	if (argc < 2) {
		printf("\n");
		printf("usage: %s FILENAME\n", argv[0]);
		exit(1);
	}

	char *input_file = argv[1];

	printf("input file: %s\n\n", input_file);

	int exit_code =  handle_file(input_file, NULL);

	printf("finished\n");

	return exit_code;
}
