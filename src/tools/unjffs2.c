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
		fprintf(stderr, "Usage: %s [[erase_size]] [file.jffs2]\n", argv[0]);
		return 1;
	}
	
	char *filename = argv[1];
	if(argc > 2){
		uint32_t erase_size = strtoull(argv[1], NULL, 16);
		init_eraseblock_size(erase_size);
		
		filename = argv[2];
	}
	
	char pwd[PATH_MAX];
	getcwd(pwd, PATH_MAX);
	
	printf("Extracting %s to %s\n", filename, (char *)&pwd);
	return jffs2extract(filename, (char *)&pwd, "1234");
}