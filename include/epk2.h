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

typedef int bool;
#define TRUE   (1)
#define FALSE  (0)

enum {
	MAX_PAK_CHUNKS = 0x10
};
enum {
	SIGNATURE_SIZE = 0x80
};

#define stringify( name ) # name

typedef enum {
	BOOT = 0x0,
	MTDI = 0x1,
	CRC3 = 0x2,
	ROOT = 0x3,
	LGIN = 0x4,
	MODE = 0x5,
	KERN = 0x6,
	LGAP = 0x7,
	LGRE = 0x8,
	LGFO = 0x9,
	ADDO = 0xA,
	ECZA = 0xB,
	RECD = 0xC,
	MICO = 0xD,
	SPIB = 0xE,
	SYST = 0xF,
	USER = 0x10,
	NETF = 0x11,
	IDFI = 0x12,
	LOGO = 0x13,
	OPEN = 0x14,
	YWED = 0x15,
	CMND = 0x16,
	NVRA = 0x17,
	PREL = 0x18,
	KIDS = 0x19,
	STOR = 0x1A,
	CERT = 0x1B,
	AUTH = 0x1C,
	ESTR = 0x1D,
	GAME = 0x1E,
	BROW = 0x1F,
	CE_F = 0x20,
	ASIG = 0x21,
	RESE = 0x22,
	EPAK = 0x23,
	UNKNOWN = 0x42,
} pak_type_t;


struct epk2_header_t {
	unsigned char _00_signature[SIGNATURE_SIZE];
	unsigned char _01_type_code[4];
	uint32_t _02_file_size;
	uint32_t _03_pak_count;
	unsigned char _04_fw_format[4];
	unsigned char _05_fw_version[4];
	unsigned char _06_fw_type[32];
	uint32_t _07_header_length;
	uint32_t _08_unknown;
};

struct pak2_header_t {
	unsigned char _00_type_code[4];
	uint32_t _01_unknown1;
	uint32_t _02_unknown2;
	uint32_t _03_next_pak_file_offset;
	uint32_t _04_next_pak_length;
};

struct pak2_chunk_header_t {
	unsigned char _00_signature[SIGNATURE_SIZE];
	unsigned char _01_type_code[4];
	unsigned char _02_unknown1[4];
	unsigned char _03_platform[15];
	unsigned char _04_unknown3[105];
};

struct pak2_chunk_t {
	struct pak2_chunk_header_t *header;
	unsigned char *content;
	int content_len;
};

struct pak2_t {
	pak_type_t type;
	struct pak2_header_t *header;
	unsigned int chunk_count;
	struct pak2_chunk_t **chunks;
};


#endif /* EPK2_H_ */
