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

	if(msize(file) < sizeof(*epk3)){
		goto checkFail;
	}
	
	// check if the epk magic is present (decrypted)
	if(compare_epk3_header((uint8_t *)&(epk3->epkHeader), sizeof(EPK_V3_HEADER_T))){
		goto checkOk;
	}

	if(isEpkVersionString(epk3->platformVersion) && isEpkVersionString(epk3->sdkVersion))
		goto checkOk;


	checkFail:
		mclose(file);
		return NULL;

	checkOk:
		printf("[EPK] Platform Version: %.*s\n", sizeof(epk3->platformVersion), epk3->platformVersion);
		printf("[EPK] SDK Version: %.*s\n", sizeof(epk3->sdkVersion), epk3->sdkVersion);
		return file;
}

void extractEPK3(MFILE *epk, config_opts_t *config_opts){
	struct epk3_structure *epk3 = mdata(epk, struct epk3_structure);
	EPK_V3_HEADER_T *epkHeader = &(epk3->epkHeader);

	{
		size_t signed_size = (
			member_size(struct epk3_structure, epkHeader) +
			member_size(struct epk3_structure, crc32Info) + 
			member_size(struct epk3_structure, reserved)
		);

		wrap_verifyimage(
			epk3->signature,
			epkHeader,
			signed_size,
			config_opts->config_dir
		);
	}

	int result = wrap_decryptimage(
		epkHeader,
		sizeof(EPK_V3_HEADER_T),
		epkHeader,
		config_opts->dest_dir,
		EPK_V3,
		NULL
	);

	if(result < 0){
		return;
	}

	{
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
	printf("Firmware version: %02x.%02x.%02x.%02x\n",
		epkHeader->epkVersion[3],
		epkHeader->epkVersion[2],
		epkHeader->epkVersion[1],
		epkHeader->epkVersion[0]
	);
	printf("packageInfoSize: %d\n", epkHeader->packageInfoSize);
	printf("bChunked: %d\n", epkHeader->bChunked);

	char *fwVersion;
	asprintf(&fwVersion, "%02x.%02x.%02x.%02x-%s",
		epkHeader->epkVersion[3],
		epkHeader->epkVersion[2],
		epkHeader->epkVersion[1],
		epkHeader->epkVersion[0],
		epkHeader->otaId
	);
	sprintf(config_opts->dest_dir, "%s/%s", config_opts->dest_dir, fwVersion);
	createFolder(config_opts->dest_dir);
	free(fwVersion);

	/* Decrypt packageInfo */
	result = wrap_decryptimage(
		&(epk3->packageInfo),
		epkHeader->packageInfoSize,
		&(epk3->packageInfo),
		config_opts->dest_dir,
		RAW,
		NULL
	);
	if(result < 0){
		return;
	}

	//hexdump(&(epk3->packageInfo), epkHeader->packageInfoSize);
	PAK_V3_LISTHEADER_T *packageInfo = &(epk3->packageInfo);
	
	printf("---- begin ----\n");
	uint i = 0;
	PAK_V3_HEADER_T *pak = &(packageInfo->packages[i]);
	
	uintptr_t dataPtr = (uintptr_t)packageInfo + epkHeader->packageInfoSize;

	for(; i<packageInfo->packageInfoCount;){
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
			mwrite(dataPtr, pak->segmentInfo.segmentSize, 1, pakFile);

			dataPtr += pak->segmentInfo.segmentSize;
		}

		mclose(pakFile);
		handle_file(pakFileName, config_opts);
		free(pakFileName);
	}
}

