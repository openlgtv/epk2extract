/*
 * epk1.h
 *
 *  Created on: 24.02.2011
 *      Author: sirius
 */

#ifndef EPK1_H_
#    define EPK1_H_

#    include <stdint.h>
#    include <sys/stat.h>
#    include <sys/types.h>
#    include <stdio.h>
#    include <epk.h>
#    include <string.h>

typedef struct {
	uint32_t offset;
	uint32_t size;
} pakRec_t __attribute__((packed));

/*
The big endian header has a non-fixed size, so we have to get some members at runtime
fwVer is -4 bytes from first pak location
For otaID we use the PAK platform, since this header lacks a proper one
*/
struct epk1BEHeader_t {
	char epakMagic[4];
	uint32_t fileSize;
	uint32_t pakCount;
} __attribute__((packed));

struct epk1Header_t {
	char epakMagic[4];
	uint32_t fileSize;
	uint32_t pakCount;
	pakRec_t pakRecs[20];
	uint32_t fwVer[4];
	unsigned char otaID[32];
};

struct epk1NewHeader_t {
	char epakMagic[4];
	uint32_t fileSize;
	uint32_t pakCount;
	unsigned char fwVer[4];
	unsigned char otaID[32];
	pakRec_t pakRecs[26];
};

struct pakHeader_t {
	char pakName[4];
	uint32_t pakSize;
	char platform[15];
	unsigned char unknown[105];
};

#endif /* EPK1_H_ */
