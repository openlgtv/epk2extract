/**
 * Copyright 2016 Smx <smxdev4@gmail.com>
 * All right reserved
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "mfile.h"
#include "util.h"
#include "philips.h"
#include "main.h"

#define PHILIPS_DEBUG

MFILE *is_philips_fusion1(const char *filename){
		MFILE *mf = mopen(filename, O_RDONLY);
		if(!mf){
			err_exit("mfopen failed for %s\n", filename);
		}
		uint8_t *data = mdata(mf, uint8_t);
		if(!memcmp(data, PHILIPS_FUSION1_MAGIC, strlen(PHILIPS_FUSION1_MAGIC))){
			return mf;
		}
		mclose(mf);
		return NULL;
}

void extract_philips_fusion1(MFILE *mf, config_opts_t *config_opts){
	char *basename = my_basename(mf->path);
	char *name = remove_ext(basename);
	asprintf_inplace(&config_opts->dest_dir, "%s/%s", config_opts->dest_dir, name);
	createFolder(config_opts->dest_dir);

	uint8_t *data = mdata(mf, uint8_t);
	struct philips_fusion1_upg *upg = mdata(mf, struct philips_fusion1_upg);
	struct philips_fusion1_part *part_table = (struct philips_fusion1_part *)&data[0xB0];

	printf("Fusion1 firmware contains %u partitions (first at 0x%08X)\n",
		upg->numPartitions, upg->firstPartition
	);

	uint i;
	for(i=0; i<upg->numPartitions; i++){
		struct philips_fusion1_part *part = &part_table[i];
		printf("[Part %u] Index: %02u - 0x%08X (0x%08X bytes)\n",
			i, part->index, part->offset, part->size
		);

		#ifdef PHILIPS_DEBUG
		printf("UNK0: 0x%08X\n", part->unk0);
		printf("UNK1: 0x%08X\n", part->unk1);
		printf("UNK2: 0x%08X\n", part->unk2);
		printf("UNK3: 0x%08X\n\n", part->unk3);
		#endif

		char *path;
		asprintf(&path, "%s/part_%d.pak", config_opts->dest_dir, i);
		printf("  Writing partition to %s\n", path);

		MFILE *out = mfopen(path, "w+");
		mfile_map(out, part->size);
		memcpy(
			mdata(out, void),
			&data[part->offset],
			part->size
		);
		mclose(out);
		
		handle_file(path, config_opts);

		free(path);
	}

	free(name);
	free(basename);
}
