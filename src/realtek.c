#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "mfile.h"
#include "realtek/rtsplit.h"
#include "util.h"

MFILE *is_rtk_bspfw(const char *filename){
	MFILE *mf = mopen(filename, O_RDONLY);
	if(mf == NULL){
		err_exit("Can't open file %s\n", filename);
	}

	kernel_image_header *hdr = mdata(mf, kernel_image_header);

	int zero_size = member_size(kernel_image_header, reserved);
	uint8_t reserved[zero_size];
	memset(&reserved, 0x00, zero_size);

	int matches = 0;

	for(; moff(mf, hdr) < msize(mf); hdr++){
		int stop = 0;
		switch(hdr->magic){
			case HEADER_AUDIO1_IMAGE:
			case HEADER_AUDIO2_IMAGE:
			case HEADER_VIDEO1_IMAGE:
			case HEADER_VIDEO2_IMAGE:
				if(memcmp(&hdr->reserved, &reserved, zero_size) != 0){
					break;
				}
				if(hdr->offset > msize(mf) || (hdr->offset + hdr->size) > msize(mf)){
					break;
				}

				matches++;
				break;
			default:
				stop = 1;
				break;
		}

		if(stop){
			break;
		}
	}

	if(matches < 1){
		mclose(mf);
		return NULL;
	}

	return mf;
}

void split_rtk_bspfw(MFILE *mf, const char *destdir) {
	char *innerDirectory;
	asprintf(&innerDirectory, "%s/bspfw.pak.split", destdir);
	createFolder(innerDirectory);

	kernel_image_header *hdr = mdata(mf, kernel_image_header);
	for(; moff(mf, hdr) < msize(mf); hdr++){
		char *filepath = NULL;
		
		switch(hdr->magic){
			case HEADER_AUDIO1_IMAGE:
			case HEADER_AUDIO2_IMAGE:
			case HEADER_VIDEO1_IMAGE:
			case HEADER_VIDEO2_IMAGE: {
				char *filename = (hdr->magic == HEADER_AUDIO1_IMAGE) ? "ACPU1" : (
					(hdr->magic == HEADER_AUDIO2_IMAGE) ? "ACPU2" : (
						(hdr->magic == HEADER_VIDEO1_IMAGE) ? "VCPU1" : "VCPU2"
					)
				);

				printf("Found %s firmware (offset='0x%x', size='0x%x')\n", filename, hdr->offset, hdr->size);

				asprintf(&filepath, "%s/%s.bin", innerDirectory, filename);
				printf(" == Saving to %s\n", filepath);

				MFILE *out = mfopen(filepath, "w+");
				if(out == NULL){
					err_exit("Cannot open '%s' for writing\n", filepath);
				}

				mfile_map(out, hdr->size);
				memcpy(
					mdata(out, void),
					mdata(mf, uint8_t) + hdr->offset,
					hdr->size
				);
				mclose(out);

				break;
			}
		}

		if(filepath != NULL){
			free(filepath);
		}
	}
	free(innerDirectory);
}