/**
 * LZHS Scanner tool
 * Copyright 2016 Smx <smxdev4@gmail.com>
 * All right reserved
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "mfile.h"
#include "lzhs/lzhs.h"
#include "mediatek.h"
#include "util.h"

void scan_lzhs(const char *filename, int extract) {
	struct lzhs_header *header = NULL;
	char *outname, *outdecode;

	MFILE *file = mopen(filename, O_RDONLY);
	if (file == NULL) {
		printf("Can't open file %s\n", filename);
		exit(1);
	}

	int i, count = 0;
	for (i = 0; i<msize(file); i += sizeof(*header)) {
		header = (struct lzhs_header *)(mdata(file, uint8_t) + i);
		if (_is_lzhs_mem(header)) {

			if(moff(file, header) + header->compressedSize >= msize(file)){
				continue;
			}

			count++;
			off_t fileOff = moff(file, header);
			char *fstring;
			if(!(fileOff % MTK_LOADER_OFF)){
				fstring="mtk loader";
			} else if(!(fileOff % MTK_UBOOT_OFF)){
				fstring="mtk uboot";
			} else {
				fstring="LZHS header";
			}

			printf("Found possible %-12s at offset @0x%08X (Checksum: 0x%02X, compressedSize: 0x%08X, uncompressedSize: 0x%08X)\n",
				fstring, fileOff, header->checksum, header->compressedSize, header->uncompressedSize
			);

			if (extract) {
				char *dirn = my_dirname(filename);
				char *filen = my_basename(filename);
				asprintf(&outname, "%s/%s_file%d.lzhs", dirn, filen, count);
								
				printf("Extracting to %s\n", outname);
				
				MFILE *out = mfopen(outname, "w+");
				if (out == NULL) {
					err_exit("Cannot open file %s for writing\n", outname);
				}
				
				mfile_map(out, sizeof(*header) + header->compressedSize);

				memcpy(
					mdata(out, void),
					(uint8_t *)header,
					sizeof(*header) + header->compressedSize
				);
				
				uint8_t out_checksum;
				asprintf(&outdecode, "%s/%s_file%d.unlzhs", dirn, filen, count);
				lzhs_decode(out, 0, outdecode, &out_checksum);
				if(extract == 2 && out_checksum != header->checksum){
					printf("Checksum Mismatch, Skipping\n");
					unlink(outname);
					unlink(outdecode);
				}
				printf("\n");
				
				mclose(out);
				free(outname); free(outdecode);
				free(dirn); free(filen);
			}
		}
	}
	mclose(file);
}

int main(int argc, char *argv[]) {
	if (argc < 3) {
		printf("Usage: \n");
		printf("'%s [in] 0' scan\n", argv[0]);
		printf("'%s [in] 1' scan and extract\n", argv[0]);
		printf("'%s [in] 2' scan and extract chunks with valid checksum only\n", argv[0]);
		return 1;
	}
	scan_lzhs(argv[1], atoi(argv[2]));
	return 0;
}
