/*
 * epk2.h
 *
 *  Created on: 16.02.2011
 *      Author: sirius
 */

#ifndef EPK2_H_
#define EPK2_H_

#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <epk.h>
#include <stdbool.h>

enum { SIGNATURE_SIZE = 0x80 };

typedef enum {
	RELEASE = 0,
	DEBUG,
	TEST,
	UNKNOWN,
} build_type_t;

struct epk3header_t {
	unsigned char signature[SIGNATURE_SIZE];
	unsigned char EPK3magic[4];
	unsigned char fwVersion[4];
	unsigned char otaID[32];
	uint32_t packageInfoSize;
	uint32_t bChunked;
}; 

struct pak3segmentHeader_t {
	unsigned char unknown1[4]; // 0x01 00 00 00
	uint32_t infoRecordSize; // 0x144
	unsigned char name[128];
	unsigned char address1[128];
	unsigned char address2[32];
	uint32_t pakSize;
	uint32_t unknown2; // 0x00 00 00 00
	uint32_t unknown3; // 0x01 00 00 00
	uint32_t segmentNumber;
	uint32_t totalSegments;
	uint32_t segmentSize;
	uint32_t unknown4; // 0x00 00 00 00
}; 

struct pak3_t {
	uint32_t packageInfoSize;
	uint32_t numOfSegments;
	struct pak3segmentHeader_t segment;
}; 

/* main epk2 header */
struct epk2header_t {
	unsigned char signature[SIGNATURE_SIZE];
	unsigned char epakMagic[4]; //epak
	uint32_t fileSize;
	uint32_t pakCount;
	unsigned char EPK2magic[4]; //EPK2
	unsigned char fwVersion[4];
	unsigned char otaID[32];
	uint32_t headerLength;
	uint32_t unknown;
};

/* package info header */
struct pak2header_t {
	unsigned char name[4];
	uint32_t version;
	uint32_t maxPAKsegmentSize;
	uint32_t nextPAKfileOffset;
	uint32_t nextPAKlength;
};

/* package chunk header */
struct pak2segmentHeader_t {
	unsigned char signature[SIGNATURE_SIZE];
	unsigned char name[4];
	unsigned int size;
	unsigned char platform[15];
	unsigned char unknown2[49];
	unsigned char version[4];
	unsigned char date[4];
	unsigned int devmode;
	uint32_t segmentCount;
	uint32_t segmentLength;
	uint32_t segmentIndex;
	char pakMagic[4];
	unsigned char reserved[24];
	unsigned int segmentCrc32;
};

/* main segment header */
struct pak2segment_t {
	struct pak2segmentHeader_t *header;
	unsigned char *content;
	int content_file_offset;
	int content_len;
};

/* main package header */
struct pak2_t {
	struct pak2header_t *header;
	unsigned int segment_count;
	struct pak2segment_t **segments;
};

#endif /* EPK2_H_ */