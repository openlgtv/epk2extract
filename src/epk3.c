/**
 * Copyright 2016 Smx <smxdev4@gmail.com>
 * All right reserved
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "main.h"
#include "config.h"
#include "mfile.h"
#include "epk3.h"
#include "util.h"
#include "util_crypto.h"

/*
 * Check for epk3 files with an additional heading signature (whole file signature?)
 */
int compare_epk3_new_header(uint8_t *header, size_t headerSize){
	EPK_V3_HEADER_T *hdr = (EPK_V3_HEADER_T *)(header + SIGNATURE_SIZE);
	return memcmp(hdr->epkMagic, EPK3_MAGIC, sizeof(hdr->epkMagic)) == 0;
}

/*
 * Checks if the given data is an EPK3 header
 */
int compare_epk3_header(uint8_t *header, size_t headerSize){
	EPK_V3_HEADER_T *hdr = (EPK_V3_HEADER_T *)header;

	return memcmp(hdr->epkMagic, EPK3_MAGIC, sizeof(hdr->epkMagic)) == 0;
}

MFILE *isFileEPK3(const char *epk_file) {
	setKeyFile_LG();
	MFILE *file = mopen(epk_file, O_RDONLY);
	if (!file) {
		err_exit("Can't open file %s\n\n", epk_file);
	}

	struct epk3_structure *epk3 = mdata(file, struct epk3_structure);
	struct epk3_head_structure *head = &(epk3->head);

	if(msize(file) < sizeof(*epk3)){
		goto checkFail;
	}
	
	// check if the epk magic is present (decrypted)
	if(compare_epk3_header((uint8_t *)&(head->epkHeader), sizeof(EPK_V3_HEADER_T))){
		goto checkOk;
	}

	if(isEpkVersionString(head->platformVersion) && isEpkVersionString(head->sdkVersion))
		goto checkOk;


	checkFail:
		mclose(file);
		return NULL;

	checkOk:
		printf("[EPK3] Platform Version: %.*s\n", sizeof(head->platformVersion), head->platformVersion);
		printf("[EPK3] SDK Version: %.*s\n", sizeof(head->sdkVersion), head->sdkVersion);
		return file;
}

void extractEPK3(MFILE *epk, FILE_TYPE_T epkType, config_opts_t *config_opts){
	struct epk3_head_structure *head;
	
	struct epk3_structure *epk3 = mdata(epk, struct epk3_structure);
	struct epk3_new_structure *epk3_new = mdata(epk, struct epk3_new_structure);
	{
		uint8_t *data = mdata(epk, uint8_t);
		switch(epkType){
			case EPK_V3:
				head = &((struct epk3_structure *)data)->head;
				break;
			case EPK_V3_NEW:
				head = &((struct epk3_new_structure *)data)->head;
				break;
			default:
				err_exit("Unsupported EPK3 variant\n");
		}
	}
	
	EPK_V3_HEADER_T *epkHeader = &(head->epkHeader);
	EPK_V3_NEW_HEADER_T *epkHeaderNew = (EPK_V3_NEW_HEADER_T *)epkHeader;
	if(config_opts->enableSignatureChecking)
	{	
		size_t signed_size = (
				sizeof(head->epkHeader) +
				sizeof(head->crc32Info) +
				sizeof(head->reserved)
		);
		
		wrap_verifyimage(
			head->signature,
			epkHeader,
			signed_size,
			config_opts->config_dir
		);
	}

	size_t headerSize;
	switch(epkType){
		case EPK_V3:
			headerSize = sizeof(EPK_V3_HEADER_T);
			break;
		case EPK_V3_NEW:
			headerSize = sizeof(EPK_V3_NEW_HEADER_T);
			break;
	}
	
	int result = wrap_decryptimage(
		epkHeader,
		headerSize,
		epkHeader,
		config_opts->dest_dir,
		EPK_V3,
		NULL
	);

	if(result < 0){
		return;
	}

	if(config_opts->enableSignatureChecking){
		size_t signed_size = epkHeader->packageInfoSize;

		wrap_verifyimage(
			epk3->packageInfo_signature,
			(void *)&(epk3->packageInfo),
			signed_size,
			config_opts->config_dir
		);
	}

	printf("\nFirmware info\n");
	printf("-------------\n");
	printf("Firmware magic: %.*s\n", 4, epkHeader->epkMagic);
	printf("Firmware otaID: %s\n", epkHeader->otaId);
	printf("Firmware version: " EPK_VERSION_FORMAT "\n",
		epkHeader->epkVersion[3],
		epkHeader->epkVersion[2],
		epkHeader->epkVersion[1],
		epkHeader->epkVersion[0]
	);
	printf("packageInfoSize: %d\n", epkHeader->packageInfoSize);
	printf("bChunked: %d\n", epkHeader->bChunked);
	
	if(epkType == EPK_V3_NEW){	
		printf("EncryptType: %.*s\n",
			sizeof(epkHeaderNew->encryptType),
			epkHeaderNew->encryptType
		);
		printf("UpdateType:  %.*s\n",
			sizeof(epkHeaderNew->updateType),
			epkHeaderNew->updateType
		);
	}

	char *fwVersion;
	asprintf(&fwVersion, EPK_VERSION_FORMAT "-%s",
		epkHeader->epkVersion[3],
		epkHeader->epkVersion[2],
		epkHeader->epkVersion[1],
		epkHeader->epkVersion[0],
		epkHeader->otaId
	);

	asprintf_inplace(&config_opts->dest_dir, "%s/%s", config_opts->dest_dir, fwVersion);

	createFolder(config_opts->dest_dir);
	free(fwVersion);

	printf("---- begin ----\n");

	PAK_V3_LISTHEADER_T *packageInfo;
	PAK_V3_NEW_LISTHEADER_T *packageInfoNew;
	
	uint i = 0;
	PAK_V3_HEADER_T *pak;

	uintptr_t dataPtr;

	switch(epkType){
		case EPK_V3:
			packageInfo = &(epk3->packageInfo);
			pak = &(packageInfo->packages[i]);
			dataPtr = (uintptr_t)packageInfo;
			break;
		case EPK_V3_NEW:
			packageInfoNew = &(epk3_new->packageInfo);
			pak = &(packageInfoNew->packages[i]);
			dataPtr = (uintptr_t)packageInfoNew;
			break;
	}
	
	/* Decrypt packageInfo */
	result = wrap_decryptimage(
		(void *)dataPtr,
		epkHeader->packageInfoSize,
		(void *)dataPtr,
		config_opts->dest_dir,
		RAW,
		NULL
	);
	
	if(result < 0){
		return;
	}
	
	if(epkType == EPK_V3_NEW){
		if(packageInfoNew->pakInfoMagic != epkHeaderNew->pakInfoMagic){
			printf("pakInfoMagic mismatch! (expected: %04X, actual: %04X)\n", 
					epkHeaderNew->pakInfoMagic,
					packageInfoNew->pakInfoMagic
			);
			return;
		}
	}
		
	dataPtr += epkHeader->packageInfoSize;
	
	int packageInfoCount;
	
	switch(epkType){
		case EPK_V3:
			packageInfoCount = packageInfo->packageInfoCount;
			break;
		case EPK_V3_NEW:
			packageInfoCount = packageInfoNew->packageInfoCount;
			break;
	}
	
	for(; i<packageInfoCount;){
		if(pak->packageInfoSize != sizeof(*pak)){
			printf("Warning: Unexpected packageInfoSize '%d', expected '%d'\n",
					pak->packageInfoSize, sizeof(*pak)
			);
		}

		printf("\nPAK '%s' contains %d segment(s), size %d bytes:\n",
			pak->packageName,
			pak->segmentInfo.segmentCount,
			pak->packageSize
		);
		
		char *pakFileName;
		asprintf(&pakFileName, "%s/%s.pak", config_opts->dest_dir, pak->packageName);

		MFILE *pakFile = mfopen(pakFileName, "w+");
		if(!pakFile){
			err_exit("Cannot open '%s' for writing\n", pakFileName);
		}
		mfile_map(pakFile, pak->packageSize);
		printf("Saving partition (%s) to file %s\n", pak->packageName, pakFileName);


		PACKAGE_SEGMENT_INFO_T segmentInfo = pak->segmentInfo;
		uint segNo;
		for(segNo = segmentInfo.segmentIndex;
			segNo < segmentInfo.segmentCount;
			segNo++, pak++, i++
		){
			dataPtr += SIGNATURE_SIZE; //skip segment signature
		
			if(epkType == EPK_V3_NEW){
				dataPtr += SIGNATURE_SIZE;
			}
			
			printf("  segment #%u (name='%s', version='%s', offset='0x%lx', size='%u bytes')\n",
				segNo + 1,
				pak->packageName,
				pak->packageVersion,
				moff(epk, dataPtr),
				pak->segmentInfo.segmentSize
			);

			result = wrap_decryptimage(
				(void *)dataPtr,
				pak->segmentInfo.segmentSize,
				(void *)dataPtr,
				config_opts->dest_dir,
				RAW,
				NULL
			);
					
			if(result < 0){
				return;	
			}
			
			if(epkType == EPK_V3_NEW){
				uint32_t decryptedSegmentIndex = *(uint32_t *)dataPtr;
				if(decryptedSegmentIndex != i){
					printf("Warning: Decrypted segment doesn't match expected index! (index: %d, expected: %d)\n",
							decryptedSegmentIndex, i
					);
				}
				mwrite(dataPtr + 4, pak->segmentInfo.segmentSize, 1, pakFile);
			} else {
				mwrite(dataPtr, pak->segmentInfo.segmentSize, 1, pakFile);
			}

			dataPtr += pak->segmentInfo.segmentSize;
			
			if(epkType == EPK_V3_NEW){
				dataPtr += sizeof(uint32_t);
			}
		}

		mclose(pakFile);
		handle_file(pakFileName, config_opts);
		free(pakFileName);
	}
}

