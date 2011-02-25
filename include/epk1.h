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

struct pak1_info_t {
	uint32_t _01_file_offset;
	uint32_t _02_size;
};

struct epk1_header_t {
	unsigned char _01_epak_magic[4];
	uint32_t _02_file_size;
	uint32_t _03_pak_count;
	struct pak1_info_t _04_pak_infos[20];
	unsigned char _05_fw_version[4];
	unsigned char _06_fw_type[32];
};

struct pak1_header_t {
	unsigned char _01_type_code[4];
	unsigned char _02_unknown1[4];
	unsigned char _03_platform[15];
	unsigned char _04_unknown3[105];
};

#endif /* EPK1_H_ */
