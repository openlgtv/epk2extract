/**
 * LZHS Encoding tool
 * Copyright 2016 Smx <smxdev4@gmail.com>
 * All right reserved
 */
#include <stdio.h>
#include "lzhs/lzhs.h"

int main(int argc, char *argv[]) {
	if (argc < 3) {
		printf("Usage: %s [in] [out.lzhs]\n", argv[0]);
		return 1;
	}
	printf("LZHS Encoding %s => %s...\n", argv[1], argv[2]);
	lzhs_encode(argv[1], argv[2]);
	return 0;
}
