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

#include <libgen.h>

#include <getopt.h>

#include <epk1.h>
#include <epk2.h>
#include <symfile.h>

char exe_dir[1024];

struct config_opts_t config_opts;



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



int handle_file(const char *file, struct config_opts_t *config_opts) {
	const char *dest_dir = config_opts->dest_dir;
	const char *file_name = basename(strdup(file));

	char dest_file[1024] = "";

	if (check_lzo_header(file)) {
		construct_path(dest_file, dest_dir, file_name, ".lzounpack");
		printf("extracting lzo compressed file to: %s\n", dest_file);
		if (lzo_unpack(file, dest_file) == 0) {
			handle_file(dest_file, config_opts);
			return EXIT_SUCCESS;
		}
	} else if (is_squashfs(file)) {
		construct_path(dest_file, dest_dir, file_name, ".unsquashfs");
		printf("unsquashfs compressed file system to: %s\n", dest_file);
		rmrf(dest_file);
		unsquashfs(file, dest_file);
		return EXIT_SUCCESS;
	} else if (is_cramfs_image(file)) {
		construct_path(dest_file, dest_dir, file_name, ".uncramfs");
		printf("uncramfs compressed file system to: %s\n", dest_file);
		rmrf(dest_file);
		uncramfs(dest_file, file);
		return EXIT_SUCCESS;
	} else if (is_epk2_file(file)) {
		printf("extracting firmware file...\n\n");
		extract_epk2_file(file, config_opts);
		return EXIT_SUCCESS;
	} else if (is_epk1_file(file)) {
		printf("extracting epk1 firmware file...\n\n");
		extract_epk1_file(file, config_opts);
		return EXIT_SUCCESS;
	} else if (is_uboot_image(file)) {
		construct_path(dest_file, dest_dir, file_name, ".deimaged");
		printf("extracting u-boot image file to: %s.\n\n", dest_file);
		extract_uboot_image(file, dest_file);
		handle_file(dest_file, config_opts);
		return EXIT_SUCCESS;
	} else if(symfile_load(file) == 0) {
		printf("converting symbol file to IDA script...\n\n");
		construct_path(dest_file, dest_dir, file_name, ".idc");
		printf("Writing to file: %s\n", dest_file);
		symfile_write_idc(dest_file);
		return EXIT_SUCCESS;
	}

	return EXIT_FAILURE;
}

int main(int argc, char *argv[]) {

	printf("LG electronics digital tv firmware package (EPK) extractor\n");
	printf("Version 1.8dev by sirius (openlgtv.org.ru)\n\n");

	if (argc < 2) {
		printf(
				"Thanks to xeros, tbage, jenya, Arno1, rtokarev, cronix and all other guys from openlgtv project for their kind assistance.\n\n");
		printf("usage: epk2extract [-options] FILENAME\n\n");
		printf("options:\n");
		printf(
				"  -c : extract to current directory instead of source file directory\n");
		exit(1);
	}

	char *current_dir = getcwd(NULL, 0);

	printf("current directory: %s\n\n", current_dir);

	readlink("/proc/self/exe", exe_dir, 1024);

	config_opts.config_dir = dirname(exe_dir);

	config_opts.dest_dir = NULL;

	int opt;
	while ((opt = getopt(argc, argv, "c")) != -1) {
		switch (opt) {
		case 'c': {
			config_opts.dest_dir = current_dir;
			break;
		}
		case ':': {
			fprintf(stderr, "option `%c' needs a value\n\n", optopt);
			exit(1);
			break;
		}
		case '?': {
			fprintf(stderr, "unknown option: `%c'\n\n", optopt);
			exit(1);
		}
		}
	}

	char *input_file = argv[optind];

	printf("input file: %s\n\n", input_file);

	if (config_opts.dest_dir == NULL)
		config_opts.dest_dir = dirname(strdup(input_file));

	printf("destination directory: %s\n\n", config_opts.dest_dir);

	int exit_code = handle_file(input_file, &config_opts);

	if(exit_code == EXIT_FAILURE) {
		printf("\n");
		printf("unsupported input file format:\n", input_file);
		return exit_code;
	}

	printf("\nfinished\n");

	return exit_code;

}
