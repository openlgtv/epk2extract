/**
 * Image Database dumper
 * Copyright 2016 Smx <smxdev4@gmail.com>
 * All right reserved
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "mfile.h"
#include "util.h"

#define IDB_VERSION "IDB_VERSION="
#define IDB_NUM_IMG "IDB_NUM_IMG="
#define IDB_HDR_ENDMARK "IDB_HDR_ENDMARK"
#define IDB_V1 "1.1"

char *READ_TO(MFILE *mfile, char *ptr, char ch){
	while(*ptr != ch){
		ptr++;
		if(moff(mfile, ptr) >= msize(mfile)){
			fprintf(stderr, "Unexpected EOF!\n");
			return NULL;
		}
	}
	return ptr;
}

char *READ_AFTER(MFILE *mfile, char *ptr, char ch){
	ptr = READ_TO(mfile, ptr, ch);
	if(ptr == NULL)
		return ptr;
	return ++ptr;
}

struct idb_file {
	uint major;
	uint minor;
	unsigned long num_img;
};

struct __attribute__((packed)) idb_entry {
	uint32_t unk1;
	uint32_t unk2;
	uint32_t size;
	uint32_t offset;
};

int process_idb(MFILE *mf){
	uint8_t *data = mdata(mf, uint8_t);
	uint8_t *p = data;

	struct idb_file idb;

	if(strncmp(p, IDB_VERSION, strlen(IDB_VERSION))){
		fprintf(stderr, "Not an IDB file (no version TAG)\n");
		return -1;
	}

	p += strlen(IDB_VERSION);
	if(strncmp(p, IDB_V1, strlen(IDB_V1))){
		fprintf(stderr, "Unsupported version %.*s\n", READ_TO(mf, p, '\n') - (char *)p, p);
		return -1;
	}

	idb.major = 1;
	idb.minor = 1;

	p += strlen(IDB_V1);

	if((p=READ_AFTER(mf, p, '\n')) == NULL)
		return -1;

	if(strncmp(p, IDB_NUM_IMG, strlen(IDB_NUM_IMG))){
		fprintf(stderr, "Cannot find number of pictures TAG\n");
		return -1;
	}

	p += strlen(IDB_NUM_IMG);

	idb.num_img = strtoul((char *)p, (char **)&p, 10);
	if(idb.num_img == 0){
		fprintf(stderr, "Invalid number of pictures (%zu)\n", idb.num_img);
		return -1;
	}

	do {
		p = READ_AFTER(mf, p, '\n');
		if(p == NULL){
			fprintf(stderr, "Cannot find header end TAG\n");
			return -1;
		}
	} while(strncmp(p, IDB_HDR_ENDMARK, strlen(IDB_HDR_ENDMARK)));
	
	p = READ_AFTER(mf, p, '\n');
	if(p == NULL){
		return -1;
	}

	/* Smx: this is either wrong or we're not extracting all of the pictures */
	printf("[IDB] Extracting %lu pictures\n", idb.num_img);

	struct idb_entry *entry = (struct idb_entry *)p;
	off_t hdr_end = entry->offset;

	char *file_dir = my_dirname(mf->path);
	char *file_base = my_basename(mf->path);
	char *file_name = remove_ext(file_base);
	
	char *dest_dir;
	asprintf(&dest_dir, "%s/%s", file_dir, file_name);
	createFolder(dest_dir);

	free(file_dir); free(file_base); free(file_name);

	uint i = 0;
	for(i=0; moff(mf, entry) < hdr_end; entry++){
		/* Smx: I don't know why there are many dupes with size 0 */
		if(entry->size == 0)
			continue;
		i++;
		printf("[IDB:0x%08X] Picture %u (%u bytes)\n", entry->offset, i, entry->size);

		char *out_file;
		asprintf(&out_file, "%s/%d.png", dest_dir, i);
		
		MFILE *out = mfopen(out_file, "w+");
		if(!out){
			fprintf(stderr, "Cannot open '%s' for writing\n", out_file);
			free(out_file);
			return -1;
		}
		mfile_map(out, entry->size);
		memcpy(
			mdata(out, void),
			&data[entry->offset],
			entry->size
		);
		mclose(out);
		free(out_file);
	}

	free(dest_dir);
	return 0;
}

int main(int argc, char *argv[]){
	int ret = EXIT_FAILURE;
	if(argc < 2){
		fprintf(stderr, "Usage: %s [IDB_<revision>_<region>.lr]\n", argv[0]);
		goto exit_e0;
	}

	MFILE *mf = mopen(argv[1], O_RDONLY);
	if(!mf){
		fprintf(stderr, "mopen failed!\n");
		return -1;
	}

	if(!process_idb(mf))
		ret = EXIT_SUCCESS;

	mclose(mf);

	exit_e0:
		return ret;
}