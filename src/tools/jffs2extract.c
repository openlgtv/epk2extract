/**
 * Copyright 2018 Smx <smxdev4@gmail.com>
 * All right reserved
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#include "jffs2/jffs2.h"
#include "util.h"

int main(int argc, char *argv[]){
	if(argc < 2){
		usage:
		fprintf(stderr,
			"Usage: %s [file.jffs2]\n"
			"    -e [erase block size]\n"
			"       if a value is specified, it will be used as erase block size\n"
			"       if no value is specified, it will be guessed (EXPERIMENTAL)\n"
			"    -v\n"
			"       be verbose\n"
			"    -k\n"
			"       keep a copy of detected unlinked files\n",
		argv[0]);
		return 1;
	}
	
	int erase_size = -1;
	int verbose = 0;
	bool keep_unlinked = false;
	
	int c;
	while ((c = getopt (argc, argv, "e:vk")) != -1){
		switch(c){
			case 'e':
				erase_size = strtoul(optarg, NULL, 16);
				break;
			case 'v':
				verbose++;
				break;
			case 'k':
				keep_unlinked = true;
				break;
			case '?':
				break;
		}
	}
	
	char *filename;
	if(optind < argc){
		filename = argv[optind];
	} else {
		goto usage;
	}
	
	char *dir_name = my_dirname(filename);
	char *base_name = my_basename(filename);
	
	char *outpath;
	asprintf(&outpath, "%s/%s.unjffs2", dir_name, base_name);
	
	free(dir_name); free(base_name);
	
	struct jffs2_main_args args = {
		.erase_size = erase_size,
		.keep_unlinked = keep_unlinked,
		.verbose = verbose
	};
	
	printf("Extracting %s to %s\n", filename, outpath);
	int ret = jffs2extract(filename, outpath, args);
	
	free(outpath);
	return ret;
}