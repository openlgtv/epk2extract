/**
 * Copyright 2016 Smx <smxdev4@gmail.com>
 * Copyright 2016 lprot
 * Copyright 20?? sirius
 * All right reserved
 */

#ifndef EPK1_H_
#    define EPK1_H_

#    include <stdint.h>
#    include <sys/stat.h>
#    include <sys/types.h>
#    include <stdio.h>
#    include <epk.h>
#    include <string.h>

struct pakRec_t {
	uint32_t offset;
	uint32_t size;
};

struct epk1BEHeader_t {
	unsigned char epakMagic[4];
	uint32_t fileSize;
	uint32_t pakCount;
	uint32_t offset;
	uint32_t size;
};

struct epk1Header_t {
	unsigned char epakMagic[4];
	uint32_t fileSize;
	uint32_t pakCount;
	struct pakRec_t pakRecs[20];
	unsigned char fwVer[4];
	unsigned char otaID[32];
};

struct epk1NewHeader_t {
	unsigned char epakMagic[4];
	uint32_t fileSize;
	uint32_t pakCount;
	unsigned char fwVer[4];
	unsigned char otaID[32];
	struct pakRec_t pakRecs[26];
};

struct pakHeader_t {
	unsigned char pakName[4];
	uint32_t pakSize;
	unsigned char platform[15];
	unsigned char unknown[105];
};

void extract_epk1_file(const char *epk_file, config_opts_t *config_opts);
int isFileEPK1(const char *epk_file);

#endif /* EPK1_H_ */
