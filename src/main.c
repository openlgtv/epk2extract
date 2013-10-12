/*
 ============================================================================
 Name        : main.c
 Author      : sirius
 Copyright   : published under GPL
 Description : EPK2 firmware extractor for LG Electronic digital TVs
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
#ifdef __CYGWIN__
#include <sys/cygwin.h>
#endif
#include <epk1.h>
#include <epk2.h>
#include <symfile.h>

char exe_dir[1024];
char *current_dir;

struct config_opts_t config_opts;

int is_lz4(const char *lz4file) {
	FILE *file = fopen(lz4file, "r");
	if (file == NULL) {
		printf("Can't open file %s", lz4file);
		exit(1);
	}
	size_t headerSize = 4;
	unsigned char* buffer = (unsigned char*) malloc(sizeof(char) * headerSize);
	int read = fread(buffer, 1, headerSize, file);
	if (read != headerSize) return 0;
	fclose(file);
	int result = !memcmp(&buffer[0], "LZ4P", 4); 
	free(buffer);
	return result;
}

int handle_file(const char *file, struct config_opts_t *config_opts) {
	const char *dest_dir = config_opts->dest_dir;
	const char *file_name = basename(strdup(file));

	char dest_file[1024] = "";
	char lz4pack[1024] = "";

	if (check_lzo_header(file)) {
		constructPath(dest_file, dest_dir, file_name, ".lzounpack");
		printf("Extracting LZO file to: %s\n", dest_file);
		if (lzo_unpack(file, dest_file) == 0) {
			handle_file(dest_file, config_opts);
			return EXIT_SUCCESS;
		}
	} else if (is_nfsb(file)) {
		constructPath(dest_file, dest_dir, file_name, ".unnfsb");
		printf("Extracting nfsb image to: %s.\n\n", dest_file);
		unnfsb(file, dest_file);
		handle_file(dest_file, config_opts);
		return EXIT_SUCCESS;
	} else if (is_lz4(file)) {
		constructPath(dest_file, dest_dir, file_name, ".unlz4");
		printf("UnLZ4 file to: %s\n", dest_file);
		decode_file(file, dest_file);
		return EXIT_SUCCESS;			
	} else if (is_squashfs(file)) {
		constructPath(dest_file, dest_dir, file_name, ".unsquashfs");
		printf("Unsquashfs file to: %s\n", dest_file);
		rmrf(dest_file);
		unsquashfs(file, dest_file);
		return EXIT_SUCCESS;
	} else if (is_cramfs_image(file)) {
		constructPath(dest_file, dest_dir, file_name, ".uncramfs");
		printf("Uncramfs file to: %s\n", dest_file);
		rmrf(dest_file);
		uncramfs(dest_file, file);
		return EXIT_SUCCESS;
	} else if (isFileEPK2(file)) { 
		extractEPK2file(file, config_opts);
		return EXIT_SUCCESS;
	} else if (isFileEPK1(file)) {
		extract_epk1_file(file, config_opts);
		return EXIT_SUCCESS;
	} else if (is_kernel(file)) {
		constructPath(dest_file, dest_dir, file_name, ".unpaked");
		printf("Extracting boot image to: %s.\n\n", dest_file);
		extract_kernel(file, dest_file);
		handle_file(dest_file, config_opts);
		return EXIT_SUCCESS;
	} else if(isSTRfile(file)) {
		constructPath(dest_file, dest_dir, file_name, ".m2ts");
		setKey();
		printf("\nConverting %s file to M2TS: %s\n", file, dest_file);
		convertSTR2TS(file, dest_file, 0);
		return EXIT_SUCCESS;
	} else if(!memcmp(&file[strlen(file)-3], "PIF", 3)) {
		constructPath(dest_file, dest_dir, file_name, ".m2ts");
		setKey();
		printf("\nProcessing PIF file: %s\n", file);
		processPIF(file, dest_file);
		return EXIT_SUCCESS;
	} else if(symfile_load(file) == 0) {
		constructPath(dest_file, dest_dir, file_name, ".idc");
		printf("Converting SYM file to IDC script: %s\n", dest_file);
		symfile_write_idc(dest_file);
		return EXIT_SUCCESS;
	}
	return EXIT_FAILURE;
}

int main(int argc, char *argv[]) {
	printf("\nLG Electronics digital TV firmware package (EPK) extractor 3.3 by sirius (http://openlgtv.org.ru)\n\n");

	if (argc < 2) {
		printf("Thanks to xeros, tbage, jenya, Arno1, rtokarev, cronix, lprot and all other guys from openlgtv project for their kind assistance.\n\n");
		printf("Usage: epk2extract [-options] FILENAME\n\n");
		printf("Options:\n");
		printf("  -c : extract to current directory instead of source file directory\n");
		exit(1);
	}

	current_dir = getcwd(NULL, 0);
	printf("Current directory: %s\n", current_dir);
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
			printf("Option `%c' needs a value\n\n", optopt);
			exit(1);
			break;
		}
		case '?': {
			printf("Unknown option: `%c'\n\n", optopt);
			exit(1);
		}
		}
	}

	#ifdef __CYGWIN__
		char posix[PATH_MAX];
		cygwin_conv_path(CCP_WIN_A_TO_POSIX, argv[optind], posix, PATH_MAX);
		char *input_file = posix;
	#else
		char *input_file = argv[optind];
	#endif
	printf("Input file: %s\n", input_file);
	if (config_opts.dest_dir == NULL) config_opts.dest_dir = dirname(strdup(input_file));
	printf("Destination directory: %s\n", config_opts.dest_dir);
	int exit_code = handle_file(input_file, &config_opts);
	if(exit_code == EXIT_FAILURE) {
		printf("Unsupported input file format: %s\n\n", input_file);
		#ifdef __CYGWIN__
			puts("Press any key to continue...");
			getch();
		#endif
		return exit_code;
	}
	printf("\nExtraction is finished.\n\n");
	#ifdef __CYGWIN__
		puts("Press any key to continue...");
		getch();
	#endif
	return exit_code;
}

