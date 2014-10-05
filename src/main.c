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
#include <minigzip.h>

char *remove_ext(const char* mystr) {
    char *retstr, *lastdot;
    if (mystr == NULL) return NULL;
    if ((retstr = (char *)malloc(strlen(mystr) + 1)) == NULL) return NULL;
    strcpy(retstr, mystr);
    lastdot = strrchr (retstr, '.');
    if (lastdot != NULL) *lastdot = '\0';
    return retstr;
}

char *get_ext(const char* mystr) {
    char *retstr, *lastdot;
    if (mystr == NULL) return NULL;
    if ((retstr = (char *)malloc(strlen(mystr) + 1)) == NULL) return NULL;
    lastdot = strrchr (mystr, '.');
	if (lastdot != NULL){
		sprintf(retstr, "%s", lastdot+1);
		int i;
		for(i = 0; retstr[i]; i++) retstr[i] = tolower(retstr[i]);
	}
    return retstr;
}

struct config_opts_t config_opts;

int handle_file(const char *file, struct config_opts_t *config_opts) {
	char *dest_dir = config_opts->dest_dir;
	char *file_name = basename(strdup(file));
	char *file_base = remove_ext(strdup(file_name));
	//char *file_ext = get_ext(strdup(file_name));
	char *dest_file = malloc(strlen(file) + 50);
	
	memset(dest_file, 0, sizeof(dest_file));
	if (isFileEPK1(file)) {
		extract_epk1_file(file, config_opts);
	} else if (isFileEPK2(file)) {
		extractEPK2file(file, config_opts);
	} else if (isFileEPK3(file)) {
		extractEPK3file(file, config_opts);
	} else if (is_lz4(file)) {
		sprintf(dest_file, "%s/%s.unlz4", dest_dir, file_name);
		printf("UnLZ4 file to: %s\n", dest_file);
		if (!decode_file(file, dest_file)) handle_file(dest_file, config_opts);
	} else if (check_lzo_header(file)) {
		if(!strcmp(file_name, "logo.pak"))
			sprintf(dest_file, "%s/%s.bmp", dest_dir, file_name);
		else
			sprintf(dest_file, "%s/%s.unlzo", dest_dir, file_name);
		printf("UnLZO file to: %s\n", dest_file);
		if (!lzo_unpack(file, dest_file)) handle_file(dest_file, config_opts);
	} else if (is_nfsb(file)) {
		sprintf(dest_file, "%s/%s.unnfsb", dest_dir, file_name);
		printf("UnNFSB file to: %s\n", dest_file);
		unnfsb(file, dest_file);
		handle_file(dest_file, config_opts);
	} else if (is_squashfs(file)) {
		sprintf(dest_file, "%s/%s.unsquashfs", dest_dir, file_name);
		printf("UnSQUASHFS file to: %s\n", dest_file);
		rmrf(dest_file);
		unsquashfs(file, dest_file);
	} else if (is_gzip(file)) {
		sprintf(dest_file, "%s/", dest_dir);
		printf("UnGZIP %s to folder %s\n", file, dest_file);
		strcpy(dest_file, file_uncompress_origname((char *)file, dest_file));
		handle_file(dest_file, config_opts);
	} else if (is_mtk_boot(file)) {
		sprintf(dest_file, "%s/mtk_pbl.bin", dest_dir);
		printf("Extracting primary bootloader to mtk_pbl.bin...\n");
		extract_mtk_boot(file, dest_file);
		printf("Extracting embedded LZHS files...\n");
		extract_lzhs(file);
	} else if(is_cramfs_image(file, "be")) {
		sprintf(dest_file, "%s/%s.cramswap", dest_dir, file_name);
		printf("Swapping cramfs endian for file %s\n", file);
		cramswap(file, dest_file);
		handle_file(dest_file, config_opts);
	} else if(is_cramfs_image(file, "le")) {
		sprintf(dest_file, "%s/%s.uncramfs", dest_dir, file_name);
		printf("UnCRAMFS %s to folder %s\n", file, dest_file);
		rmrf(dest_file);
		uncramfs(dest_file, file);
	} else if (is_kernel(file)) {
		sprintf(dest_file, "%s/%s.unpaked", dest_dir, file_name);
		printf("Extracting boot image to: %s\n", dest_file);
		extract_kernel(file, dest_file);
		handle_file(dest_file, config_opts);
	} else if(isPartPakfile(file)) {
		sprintf(dest_file, "%s/%s.txt", dest_dir, file_base);
		printf("Saving partition info to: %s\n", dest_file);
		dump_partinfo(file, dest_file);
	} else if(is_jffs2(file)) {
		sprintf(dest_file, "%s/%s.unjffs2", dest_dir, file_name);
		printf("UnJFFS2 file %s to folder %s\n", file, dest_file);
		rmrf(dest_file);
		jffs2extract(file, dest_file, "1234");
	} else if(isSTRfile(file)) {
		sprintf(dest_file, "%s/%s.ts", dest_dir, file_name);
		setKey();
		printf("\nConverting %s file to TS: %s\n", file, dest_file);
		convertSTR2TS(file, dest_file, 0);
	} else if(!memcmp(&file[strlen(file)-3], "PIF", 3)) {
		sprintf(dest_file, "%s/%s.ts", dest_dir, file_name);
		setKey();
		printf("\nProcessing PIF file: %s\n", file);
		processPIF(file, dest_file);
	} else if(symfile_load(file) == 0) {
		sprintf(dest_file, "%s/%s.idc", dest_dir, file_name);
		printf("Converting SYM file to IDC script: %s\n", dest_file);
		symfile_write_idc(dest_file);
	} else if (is_lzhs(file)) {
		sprintf(dest_file, "%s/%s.unlzhs", dest_dir, file_name);
		printf("UnLZHS %s to %s\n", file, dest_file);
		lzhs_decode(file, dest_file);
	} else if (!strcmp(file_name, "tzfw.pak") && is_elf(file)) {
		printf("Splitting mtk tzfw...\n");
		split_mtk_tz(file, dest_dir);
	} else 
        return EXIT_FAILURE;
	return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
    printf("\nLG Electronics digital TV firmware package (EPK) extractor 4.2 by sirius (http://openlgtv.org.ru)\n\n");
    if (argc < 2) {
        printf("Thanks to xeros, tbage, jenya, Arno1, rtokarev, cronix, lprot, Smx and all other guys from openlgtv project for their kind assistance.\n\n");
        printf("Usage: epk2extract [-options] FILENAME\n\n");
        printf("Options:\n");
        printf("  -c : extract to current directory instead of source file directory\n\n");
        #ifdef __CYGWIN__
        puts("Press any key to continue...");
        getch();
        #endif
        return 1;
    }

    char exe_dir[PATH_MAX];
    char *current_dir = malloc(PATH_MAX);
    getcwd(current_dir, PATH_MAX);
    printf("Current directory: %s\n", current_dir);
    readlink("/proc/self/exe", exe_dir, PATH_MAX);
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
                return 1;
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
    if (exit_code == EXIT_FAILURE) {
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
