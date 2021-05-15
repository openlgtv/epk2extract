/**
 * Copyright 2016 Smx <smxdev4@gmail.com>
 * All right reserved
 */
#include <sys/mman.h>
#include <fcntl.h>
#include <crc.h>
#include <dirent.h>
#include <ctype.h>

#include "config.h"
#include "common.h"
#include "main.h" /* handle_file */

#include "epk.h"
#include "epk2.h"

#include "mfile.h"
#include "util.h"
#include "util_crypto.h"

/*
 * Checks if the given data is a PAK2 header
 */
int compare_pak2_header(uint8_t *header, size_t headerSize){
	PAK_V2_HEADER_T *hdr = (PAK_V2_HEADER_T *)header;
	return memcmp(hdr->pakMagic, PAK_MAGIC, sizeof(hdr->pakMagic)) == 0;
}

/*
 * Checks if the given data is an EPK2 header 
 */ 
int compare_epk2_header(uint8_t *header, size_t headerSize){
	EPK_V2_HEADER_T *hdr = (EPK_V2_HEADER_T *)header;
	return memcmp(hdr->epkMagic, EPK2_MAGIC, sizeof(hdr->epkMagic)) == 0;
}

MFILE *isFileEPK2(const char *epk_file) {
	setKeyFile_LG();
	MFILE *file = mopen(epk_file, O_RDONLY);
	if (!file) {
		err_exit("Can't open file %s\n\n", epk_file);
	}

	struct epk2_structure *epk2 = mdata(file, struct epk2_structure);

	if(msize(file) < sizeof(*epk2)){
		goto checkFail;
	}
	
	// check if the epk magic is present (decrypted)
	if(compare_epk2_header((uint8_t *)&(epk2->epkHeader), sizeof(EPK_V2_HEADER_T))){
		goto checkOk;
	}

	bool has_versions = false;
	if(isEpkVersionString(epk2->platformVersion) && isEpkVersionString(epk2->sdkVersion)){
		has_versions = true;
		goto checkOk;
	}

	checkFail:
		mclose(file);
		return NULL;

	checkOk:
		if(has_versions){
			printf("[EPK2] Platform Version: %.*s\n", sizeof(epk2->platformVersion), epk2->platformVersion);
			printf("[EPK2] SDK Version: %.*s\n", sizeof(epk2->sdkVersion), epk2->sdkVersion);
		}
		return file;

}

void extractEPK2(MFILE *epk, config_opts_t *config_opts) {
	struct epk2_structure *epk2 = mdata(epk, struct epk2_structure);
	EPK_V2_HEADER_T *epkHeader = &(epk2->epkHeader);
	int result;
	
	if(config_opts->enableSignatureChecking){
		size_t signed_size = (
			member_size(struct epk2_structure, epkHeader) +
			member_size(struct epk2_structure, crc32Info)
		);
		
		/**
		 * Note: 
		 * The signature check is not strict but tries the given size and
		 * tries with smaller sizes if unsuccesful.
		 * This allows us to work with EPK2 headers of different size by using
		 * the biggest header as base (64 partitions)
		 */
		printf("\nVerifying digital signature of EPK2 firmware header...\n");
		result = wrap_verifyimage(
			// Signature to check against
			epk2->signature,
			// Header to verify
			epkHeader,
			signed_size,
			// Folder containing keys
			config_opts->config_dir
		);
	}

	result = wrap_decryptimage(
		epkHeader,
		sizeof(EPK_V2_HEADER_T),
		epkHeader,
		config_opts->dest_dir,
		EPK_V2,
		NULL
	);

	if(result < 0){
		return;
	}
	
	PAK_V2_LOCATION_T *pakLocs = epkHeader->imageLocation;
	
	printf("\nFirmware info\n");
	printf("-------------\n");
	printf("Firmware magic: %.*s\n", 4, epkHeader->fileType);
	printf("Firmware type: %.*s\n", 4, epkHeader->epkMagic);
	printf("Firmware otaID: %s\n", epkHeader->otaId);
	printf("Firmware version: " EPK_VERSION_FORMAT "\n",
		epkHeader->epakVersion[3],
		epkHeader->epakVersion[2],
		epkHeader->epakVersion[1],
		epkHeader->epakVersion[0]);

	printf("PAK count: %d\n", epkHeader->fileNum);
	printf("PAKs total size: %d\n", epkHeader->fileSize);	
	printf("Header length: %d\n\n", pakLocs[0].imageOffset); //first image after header
	
	char *fwVersion;
	asprintf(&fwVersion, EPK_VERSION_FORMAT "-%s",
		epkHeader->epakVersion[3],
		epkHeader->epakVersion[2],
		epkHeader->epakVersion[1],
		epkHeader->epakVersion[0],
		epkHeader->otaId
	);
	
	asprintf_inplace(&config_opts->dest_dir, "%s/%s", config_opts->dest_dir, fwVersion);
	createFolder(config_opts->dest_dir);
	
	unsigned int curPak=0, signatureCount=0;
	uintptr_t pakLoc;
	
	struct pak2_structure *pak;
	/* Process every pak in a loop */
	for(curPak=0; curPak < epkHeader->fileNum; curPak++){
		pakLoc = (uintptr_t)(epkHeader) + pakLocs[curPak].imageOffset + (sizeof(signature_t) * signatureCount);
		pak = (struct pak2_structure *)pakLoc;
		
		unsigned int curSeg, segCount;
		char *filename;
		char *pakPartitionShortName;
		MFILE *outFile;

		/* Process every segment in a loop. We don't know the segment count yet */
		for (curSeg=0; ;){
			++signatureCount;

			size_t signed_size = pakLocs[curPak].imageSize;

			/* if the package is splitted, fallback to the segment size */
			if(signed_size > pakLocs[curPak].segmentSize){
				signed_size = pakLocs[curPak].segmentSize + sizeof(PAK_V2_HEADER_T);

				/*
				* We now need to check if the segment is trailing. If it is, we'd overflow into the next
				* package. Calculate the distance between us and the next package. If less than the segment size, truncate
				*/
				size_t distance;
				struct pak2_structure *nextPak = (struct pak2_structure *)(
					(uintptr_t)(epkHeader) + pakLocs[curPak + 1].imageOffset + (sizeof(signature_t) * signatureCount)
				);
				
				// No need to subtract signature, as it's included in both (so it cancels out)
				distance = (size_t)(
					(uintptr_t)&(nextPak->pakHeader) - (uintptr_t)&(pak->pakHeader)
				);

				// Last pak will have a distance < than the segment size
				// Because the data contained is less
				if(distance < pakLocs[curPak].segmentSize){
					signed_size = distance - sizeof(signature_t);
				}
			}
			
			if(config_opts->enableSignatureChecking){
				wrap_verifyimage(
					pak->signature,
					&(pak->pakHeader),
					signed_size,
					config_opts->config_dir
				);
			}


			//printf("Decrypting PAK Header @0x%x\n", (uintptr_t)&(pak->pakHeader)-(uintptr_t)epk2);
			//decrypt the pak header
			int result = wrap_decryptimage(
					&(pak->pakHeader),
					sizeof(PAK_V2_HEADER_T),
					&(pak->pakHeader),
					config_opts->config_dir,
					(FILE_TYPE_T)PAK_V2,
					NULL
			);
			
			if(result < 0){
				return;
			}
										
			curSeg = pak->pakHeader.segmentIndex;
			segCount = pak->pakHeader.segmentCount;
			if(curSeg == 0){ //first pak, print segment count and open output file			
				printf("\nPAK '%.4s' contains %d segment(s):\n", pak->pakHeader.imageType, pak->pakHeader.segmentCount);
				pakPartitionShortName = pak->pakHeader.imageType;
				asprintf(&filename, "%s/%.4s.pak", config_opts->dest_dir, pak->pakHeader.imageType);
				
				outFile = mfopen(filename, "w+");
				if(!outFile){
					PERROR_SE("Cannot open %s for writing", filename);
					return;
				}
				mfile_map(outFile, pak->pakHeader.imageSize);
			}
		
			size_t pakContentSize = pak->pakHeader.segmentSize;	

			//printf("Decrypting PAK DATA @0x%x\n", (uintptr_t)pak-(uintptr_t)epk2);
			//decrypt the pak data
			wrap_decryptimage(
				&(pak->pData),
				pak->pakHeader.segmentSize,
				&(pak->pData),
				config_opts->config_dir,
				(FILE_TYPE_T)RAW,
				NULL
			);
			
			mwrite(&(pak->pData), pakContentSize, 1, outFile); //write the decrypted data

			
			printf("  segment #%u (name='%.4s',", curSeg + 1, pak->pakHeader.imageType);
			printf(" version='%02x.%02x.%02x.%02x',",
				(pak->pakHeader.swVersion >> 24) & 0xff,
				(pak->pakHeader.swVersion >> 16) & 0xff,
				(pak->pakHeader.swVersion >> 8 ) & 0xff,
				(pak->pakHeader.swVersion      ) & 0xff);
			printf(" platform='%s', offset='0x%x', size='%u bytes', ",
				pak->pakHeader.modelName,
				moff(epk, pak),
				pakContentSize);
					
			switch ((BUILD_TYPE_T) pak->pakHeader.devMode) {
				case RELEASE:
					printf("build=RELEASE");
					break;
				case DEBUG:
					printf("build=DEBUG");
					break;
				case TEST:
					printf("build=TEST");
					break;
				default:
					printf("build=UNKNOWN 0x%x\n", pak->pakHeader.devMode);
					break;
			}
			printf(")\n");
			
			if(curSeg + 1 == segCount){
				printf("#%u/%u saved PAK (%.4s) to file %s\n",
					curPak + 1, epkHeader->fileNum,
					pakPartitionShortName, filename);
				mclose(outFile);
				handle_file(filename, config_opts);
				free(filename);
				break;
			}

			mfile_flush(&(pak->pData), pak->pakHeader.segmentSize);

			pakLoc += sizeof(*pak) + pakContentSize;
			pak = (struct pak2_structure *)pakLoc;
		}
	}
}
