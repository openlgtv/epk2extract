/**
 * Copyright 2016 Smx <smxdev4@gmail.com>
 * All right reserved
 */

#ifndef __EPK3_H
#define __EPK3_H
#include "mfile.h"
#include "epk.h"

#define EPK3_MAGIC "EPK3"

int compare_epk3_header(uint8_t *header, size_t headerSize);
MFILE *isFileEPK3(const char *epk_file);
void extractEPK3(MFILE *epk, config_opts_t *config_opts);

typedef struct __attribute__((packed)) {
	char epkMagic[4];
	char epkVersion[4];
	char otaId[32];
	uint32_t packageInfoSize;
	uint32_t bChunked;
} EPK_V3_HEADER_T;

typedef struct __attribute__((packed)) {
	// SegmentInfo
	uint32_t isSegmented;
	uint32_t segmentIndex;
	uint32_t segmentCount;
	uint32_t segmentSize;
} PACKAGE_SEGMENT_INFO_T;

typedef struct __attribute__((packed)) {
	// PackageData
	//void * pData;
	uint32_t reserved;
} PACKAGE_INFO_DATA_T;

typedef struct __attribute__((packed)) {
	// PackageInfo
	uint32_t packageType;
	uint32_t packageInfoSize;
	char packageName[128];
	char packageVersion[96];
	char packageArchitecture[32];
	unsigned char checkSum[32];
	uint32_t packageSize;
	uint32_t dipk;
	PACKAGE_SEGMENT_INFO_T segmentInfo;
	PACKAGE_INFO_DATA_T infoData;
} PAK_V3_HEADER_T;

typedef struct __attribute__((packed)) {
	// ListHeader
	uint32_t packageInfoListSize;
	uint32_t packageInfoCount;
	PAK_V3_HEADER_T packages[];
} PAK_V3_LISTHEADER_T;

struct  __attribute__((packed)) epk3_structure {
	signature_t signature;
	EPK_V3_HEADER_T epkHeader;
	uint32_t crc32Info[384];
	char platformVersion[16];
	char sdkVersion[16];
    uint32_t reserved; //or unknown
    signature_t packageInfo_signature;
	PAK_V3_LISTHEADER_T packageInfo;
};

struct __attribute__((packed)) pak3_structure {
	signature_t signature;
	PAK_V3_HEADER_T header;
};
#endif