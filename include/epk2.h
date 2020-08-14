/**
 * Copyright 2016 Smx <smxdev4@gmail.com>
 * All right reserved
 */
#ifndef _EPK2_H_
#define _EPK2_H_

#include <stdint.h>
#include "mfile.h"
#include "epk.h"

#define EPK2_MAGIC "EPK2"
#define PAK_MAGIC "MPAK"

int compare_pak2_header(uint8_t *header, size_t headerSize);
int compare_epk2_header(uint8_t *header, size_t headerSize);
MFILE *isFileEPK2(const char *epk_file);
void extractEPK2(MFILE *epk, config_opts_t *config_opts); 

typedef struct {
	char imageType[4];
	uint32_t imageSize; //excluded headers and signatures
	char modelName[64];
	uint32_t swVersion;
	uint32_t swDate;
	BUILD_TYPE_T devMode;
	uint32_t segmentCount;
	uint32_t segmentSize;
	uint32_t segmentIndex;
	char pakMagic[4];
	unsigned char reserved[24];
	uint32_t segmentCrc32;
} PAK_V2_HEADER_T;

typedef struct {
	uint32_t imageOffset;
	uint32_t imageSize; //containing headers (excluded signatures)
	char imageType[4];
	uint32_t imageVersion;
	uint32_t segmentSize;
} PAK_V2_LOCATION_T;

/**
 * NOTE: the number of partitions is hardcoded in the structure
 * 16 - GP2
 * 32 - (not sure if some sets use 32)
 * 64 - NC4
 **/
typedef struct {
	char fileType[4];
	uint32_t fileSize;
	uint32_t fileNum;
	char epkMagic[4];
	uint8_t epakVersion[4];
	char otaId[32];
	PAK_V2_LOCATION_T imageLocation[64];
} EPK_V2_HEADER_T;

struct epk2_structure {
	signature_t signature;
	EPK_V2_HEADER_T epkHeader;
	uint32_t crc32Info[64];
	uint32_t reserved;
	char platformVersion[16];
	char sdkVersion[16];
};

struct pak2_structure {
	signature_t signature;
	PAK_V2_HEADER_T pakHeader;
	unsigned char pData[];
};
#endif
