/*
 * epk1.h
 *
 *  Created on: 24.02.2011
 *      Author: sirius
 */

#ifndef EPK1_H_
#define EPK1_H_

#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <epk.h>
#include <string.h>

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

#endif /* EPK1_H_ */