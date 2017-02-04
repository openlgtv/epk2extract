/**
 * Mediatek bootloader handling
 * Copyright 2016 Smx <smxdev4@gmail.com>
 * All right reserved
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "mfile.h"
#include "mediatek.h"
#include "util.h"

//lzhs
//#include "lzhs/lzhs.h"

//boot and tzfw
#include <elf.h>

void extract_mtk_1bl(MFILE *in, const char *outname) {
	MFILE *out = mfopen(outname, "w+");
	if (out == NULL){
		err_exit("Can't open file %s for writing (%s)\n", outname, strerror(errno));
	}

	size_t pbl_size = 0;
	
	uint8_t *data = mdata(in, uint8_t);
	if(memcmp(data + 0x100, MTK_PBL_MAGIC, strlen(MTK_PBL_MAGIC)) == 0)
		pbl_size = MTK_PBL_SIZE;
	else if(memcmp(data + 0x100, MTK_ROM_MAGIC, strlen(MTK_ROM_MAGIC)) == 0)
		pbl_size = MTK_ROM_SIZE;
	else
		err_exit("Cannot detect PBL size\n");

	printf("[MTK] PBL Size: 0x%08X\n", pbl_size);

	mfile_map(out, pbl_size);
	memcpy(
		mdata(out, uint8_t),
		mdata(in, uint8_t),
		pbl_size
	);

	mclose(out);
}

void split_mtk_tz(MFILE *tz, const char *destdir) {
	size_t tz_size;

	char *dest;
	asprintf(&dest, "%s/env.o", destdir);

	MFILE *out = mfopen(dest, "w+");
	if (out == NULL)
		err_exit("Can't open file %s for writing\n", dest);

	tz_size = msize(tz) - MTK_ENV_SIZE;
	printf("Extracting env.o... (%d bytes)\n", MTK_ENV_SIZE);

	uint8_t *data = mdata(tz, uint8_t);


	mfile_map(out, MTK_ENV_SIZE);
	memcpy(mdata(out, void), data, MTK_ENV_SIZE);

	free(dest);
	mclose(out);

	asprintf(&dest, "%s/tz.bin", destdir);

	out = mfopen(dest, "w+");
	if (out == NULL)
		err_exit("Can't open file %s for writing\n", dest);

	mfile_map(out, tz_size);

	printf("Extracting tz.bin... (%zu bytes)\n", tz_size);
	memcpy(mdata(out, void), data + MTK_ENV_SIZE, tz_size);

	free(dest);
	mclose(out);
}

MFILE *is_mtk_boot(const char *filename) {
	MFILE *file = mopen(filename, O_RDONLY);
	uint8_t *data = mdata(file, uint8_t);
	if (file == NULL) {
		err_exit("Can't open file %s\n", filename);
	}
	if (
		(msize(file) >= MTK_PBL_SIZE) &&
		(memcmp(data + 0x100, MTK_PBL_MAGIC, strlen(MTK_PBL_MAGIC)) == 0)
	){
		printf("Found valid PBL magic: "MTK_PBL_MAGIC"\n");
	} else if (
		(msize(file) >= MTK_ROM_SIZE) &&
		(memcmp(data + 0x100, MTK_ROM_MAGIC, strlen(MTK_ROM_MAGIC)) == 0)
	){
		printf("Found valid PBL/ROM magic: "MTK_ROM_MAGIC"\n");
	} else {
		mclose(file);
		return NULL;
	}
	
	return file;
}

int is_elf_mem(Elf32_Ehdr * header) {
	if (!memcmp(&header->e_ident, ELFMAG, 4))
		return 1;
	return 0;
}

MFILE *is_elf(const char *filename) {
	MFILE *file = mopen(filename, O_RDONLY);
	if (file == NULL) {
		err_exit("Can't open file %s\n", filename);
	}
	
	Elf32_Ehdr *elfHdr = mdata(file, Elf32_Ehdr);
	if (!memcmp(&(elfHdr->e_ident), ELFMAG, 4))
		return file;
	
	mclose(file);
	return NULL;
}
