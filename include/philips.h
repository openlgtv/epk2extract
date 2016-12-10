/**
 * Copyright 2016 Smx <smxdev4@gmail.com>
 * All right reserved
 */
#ifndef __PHILIPS_H
#define __PHILIPS_H

#include <stdint.h>
#include "config.h"

#define PHILIPS_FUSION1_MAGIC "NFWB"

//partition table start = headerSize

struct philips_fusion1_part {
	uint32_t unk0;
	uint32_t unk1;
	uint32_t unk2;
	uint32_t unk3;
	uint32_t index;
	uint32_t size;
	uint32_t offset;
};

struct philips_fusion1_upg {
	uint32_t magic;
	uint32_t flags;
	uint32_t headerSize;
	uint32_t padding[5];
	uint8_t unk[16]; //crc or hash?
	uint32_t unk0; //part of unk?

	uint32_t numPartitions;
	uint32_t firstPartition; //offset of first part
};

void extract_philips_fusion1(MFILE *mf, config_opts_t *config_opts);
MFILE *is_philips_fusion1(const char *filename);
#endif