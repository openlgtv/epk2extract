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

typedef int bool;
#define TRUE   (1)
#define FALSE  (0)

enum { SIGNATURE_SIZE = 0x80 };

struct epk2header_t {
	unsigned char signature[SIGNATURE_SIZE];
	unsigned char epakMagic[4];
	uint32_t fileSize;
	uint32_t pakCount;
	unsigned char EPK2magic[4];
	unsigned char fwVersion[4];
	unsigned char otaID[32];
	uint32_t headerLength;
	uint32_t unknown;
}; 

struct epk3header_t {
	unsigned char signature[SIGNATURE_SIZE];
	unsigned char EPK3magic[4];
	unsigned char fwVersion[4];
	unsigned char otaID[32];
	uint32_t packageInfoSize;
	uint32_t bChunked;
}; 

struct pak2header_t {
	unsigned char name[4];
	uint32_t version;
	uint32_t maxPAKsegmentSize;
	uint32_t nextPAKfileOffset;
	uint32_t nextPAKlength;
};

struct pak2segmentHeader_t {
	unsigned char signature[SIGNATURE_SIZE];
	unsigned char name[4];
	unsigned char unknown1[4];
	unsigned char platform[15];
	unsigned char unknown2[49];
	unsigned char version[4];
	unsigned char date[4];
	unsigned char unknown3[4];
	uint32_t segmentCount;
	uint32_t segmentLength;
	uint32_t segmentIndex;
	unsigned char unknown4[32];
};

struct pak2segment_t {
	struct pak2segmentHeader_t *header;
	unsigned char *content;
	int content_file_offset;
	int content_len;
};

struct pak2_t {
	struct pak2header_t *header;
	unsigned int segment_count;
	struct pak2segment_t **segments;
};

#endif /* EPK2_H_ */
