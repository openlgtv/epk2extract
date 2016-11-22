/**
 * Mediatek PKG Handling
 * Copyright 2016 Smx <smxdev4@gmail.com>
 * All right reserved
 */
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <pthread.h>
#include "main.h" //for handle_file
#include "mfile.h"
#include "mediatek_pkg.h"
#include "lzhs/lzhs.h"
#include "util.h"
#include "util_crypto.h"
#include "thpool.h"

static int is_philips_pkg = 0;

int compare_pkg_header(uint8_t *header, size_t headerSize){
	struct mtkupg_header *hdr = (struct mtkupg_header *)header;
	
	if( !strncmp(hdr->vendor_magic, HISENSE_PKG_MAGIC, strlen(HISENSE_PKG_MAGIC)) ){
		printf("[+] Found HISENSE Package\n");
		return 1;
	}
	if( !strncmp(hdr->vendor_magic, SHARP_PKG_MAGIC, strlen(SHARP_PKG_MAGIC)) ){
		printf("[+] Found SHARP Package\n");
		return 1;
	}
	if( !strncmp(hdr->vendor_magic, PHILIPS_PKG_MAGIC, strlen(PHILIPS_PKG_MAGIC)) ){
		printf("[+] Found PHILIPS Package\n");
		return 1;
	}

	if( !strncmp(hdr->mtk_magic, MTK_FIRMWARE_MAGIC, strlen(MTK_FIRMWARE_MAGIC)) ){
		printf("[+] Found UNKNOWN Package (Magic: '%.*s')\n",
			member_size(struct mtkupg_header, vendor_magic),
			hdr->vendor_magic
		);
		return 1;
	}

	return 0;
}

MFILE *is_mtk_pkg(const char *pkgfile){
	MFILE *mf = mopen(pkgfile, O_RDONLY);
	if(!mf){
		err_exit("Cannot open file %s\n", pkgfile);
	}
	
	uint8_t *data = mdata(mf, uint8_t);

	if(find_AES_key(data, UPG_HEADER_SIZE, compare_pkg_header, 0) != NULL){
		return mf;
	}

	/* It failed, but we want to check for Philips.
 	 * Philips has an additional 0x80 header before the normal PKG one
 	 */
	if(find_AES_key(data + PHILIPS_HEADER_SIZE, UPG_HEADER_SIZE, compare_pkg_header, 0) != NULL){
		is_philips_pkg = 1;
		return mf;
	}

	/* No AES key found to decrypt the header. Try to check if it's a MTK PKG anyways
	 * This method can return false for valid packages as the order of partitions isn't fixed
	 */
	data = &data[sizeof(struct mtkupg_header) + UPG_HMAC_SIZE];

	/* First pak doesn't have OTA ID fields */
	struct mtkpkg *cfig = (struct mtkpkg *)data;
	if(
		(	/* Hisense and Sharp first partition */
			!strcmp(cfig->pakName, "cfig") &&
			!strncmp(cfig->data, "START", 5)
		) || (
			!strcmp(cfig->pakName, "ixml") //Philips first partition
		)
	){
		/* Checking for END may be desirable */
		return mf;
	}
	mclose(mf);
	return NULL;
}

MFILE *is_lzhs_fs(const char *pkg){
	MFILE *mf = mopen(pkg, O_RDONLY);
	if(!mf){
		err_exit("Cannot open file %s\n", pkg);
	}

	uint8_t *data = mdata(mf, uint8_t);

	if(
		msize(mf) > (MTK_EXT_LZHS_OFFSET + sizeof(struct lzhs_header)) &&
		is_lzhs_mem(mf, MTK_EXT_LZHS_OFFSET) &&
		is_lzhs_mem(mf, MTK_EXT_LZHS_OFFSET + sizeof(struct lzhs_header)) &&
		// First LZHS header contains number of segment in checksum. Make sure that it is the first segment
		((struct lzhs_header *)&data[MTK_EXT_LZHS_OFFSET])->checksum == 1
	){
		return mf;
	}

	mclose(mf);
	return NULL;
}

/* Arguments passed to the thread function */
struct thread_arg {
	MFILE *mf;
	off_t offset;
	char *filename;
	uint blockNo;
};

void process_block(struct thread_arg *arg){
	printf("[+] Extracting %u...\n", arg->blockNo);
	uint8_t out_checksum = 0x00;
	cursor_t *out_cur = lzhs_decode(arg->mf, arg->offset, NULL, &out_checksum);
	if(out_cur == NULL || (intptr_t)out_cur < 0){
		err_exit("LZHS decode failed\n");
	}

	MFILE *out = mfopen(arg->filename, "w+");
	if(!out){
		err_exit("mfopen failed for file '%s'\n", arg->filename);
	}
	mfile_map(out, out_cur->size);
	memcpy(
		mdata(out, void),
		out_cur->ptr,
		out_cur->size
	);
	mclose(out);
	free(out_cur);

	free(arg->filename);
	free(arg);
}

/*
 * Hisense (or Mediatek?) uses an ext4 filesystem splitted in chunks, compressed with LZHS
 * They use 2 LZHS header for each chunk
 * The first header contains the chunk number, and the compressed size includes the outer lzhs header (+16)
 * The second header contains the actual data
 */
void extract_lzhs_fs(MFILE *mf, const char *dest_file){
	uint8_t *data = mdata(mf, uint8_t) + MTK_EXT_LZHS_OFFSET;
	
	FILE *out_file = fopen(dest_file, "w+");
	if(!out_file){
		err_exit("Cannot open %s for writing\n", dest_file);
	}

	char *dir = my_dirname(dest_file);
	char *file = my_basename(dest_file);
	char *base = remove_ext(file);

	char *tmpdir;
	asprintf(&tmpdir, "%s/tmp", dir);
	createFolder(tmpdir);

	printf("Copying 0x%08X bytes\n", MTK_EXT_LZHS_OFFSET);
	/* Copy first MB as-is (uncompressed) */
	fwrite (
		mdata(mf, uint8_t),
		MTK_EXT_LZHS_OFFSET,
		1,
		out_file
	);

	int nThreads = sysconf(_SC_NPROCESSORS_ONLN);
	printf("[+] Max threads: %d\n", nThreads);
	threadpool thpool = thpool_init(nThreads);

	uint segNo = 0;
	while(moff(mf, data) < msize(mf)){
		struct lzhs_header *main_hdr = (struct lzhs_header *)data; 
		struct lzhs_header *seg_hdr = (struct lzhs_header *)(data + sizeof(*main_hdr));

		printf("\n[0x%08X] segment #%u (compressed='%u bytes', uncompressed='%u bytes')\n",
			moff(mf, main_hdr),
			main_hdr->checksum,
			seg_hdr->compressedSize, seg_hdr->uncompressedSize);

		char *outSeg;
		asprintf(&outSeg, "%s/%s.%d", tmpdir, base, (segNo++) + 1);
		struct thread_arg *arg = calloc(1, sizeof(struct thread_arg));
		arg->mf = mf;
		arg->offset = moff(mf, seg_hdr);
		arg->filename = outSeg;
		arg->blockNo = main_hdr->checksum;
		
		thpool_add_work(thpool, (void *)process_block, arg);

		uint pad;
		pad = (pad = (seg_hdr->compressedSize % 16)) == 0 ? 0 : (16 - pad);

		data += (
			sizeof(*main_hdr) + sizeof(*seg_hdr) +
			seg_hdr->compressedSize +
			pad
		);
	}
	
	thpool_wait(thpool);
	thpool_destroy(thpool);

	int i;
	for(i=1; i<=segNo; i++){
		printf("[+] Joining Segment %d\n", i);
		char *outSeg;
		asprintf(&outSeg, "%s/%s.%d", tmpdir, base, i);
		
		MFILE *seg = mopen(outSeg, O_RDONLY);
		fwrite(mdata(seg, void), msize(seg), 1, out_file);
		mclose(seg);
		
		unlink(outSeg);
		free(outSeg);
	}

	rmrf(tmpdir);
	free(tmpdir);

	fclose(out_file);

	free(dir);
	free(file);
	free(base);
}

struct mtkupg_header *process_pkg_header(MFILE *mf){
	uint8_t *header = mdata(mf, uint8_t);
	if(is_philips_pkg)
		header += PHILIPS_HEADER_SIZE;

	AES_KEY *headerKey = find_AES_key(header, UPG_HEADER_SIZE, compare_pkg_header, 1);
	if(!headerKey){
		fprintf(stderr, "[!] Cannot find proper AES key for header, ignoring\n");
		return NULL;
	}

	struct mtkupg_header *hdr = calloc(1, sizeof(struct mtkupg_header));

	uint8_t ivec[16] = {0x00};
	AES_cbc_encrypt(header, (uint8_t *)hdr, sizeof(*hdr), headerKey, (uint8_t *)&ivec, AES_DECRYPT);
	hexdump(hdr, sizeof(*hdr));

	printf("======== Firmware Info ========\n");
	printf("| Product Name: %s\n", hdr->product_name);
	printf("| Firmware ID : %.*s\n",
		member_size(struct mtkupg_header, vendor_magic) + 
		member_size(struct mtkupg_header, mtk_magic) + 
		member_size(struct mtkupg_header, vendor_info),
		hdr->vendor_magic
	);
	printf("| File Size: %u bytes\n", hdr->fileSize);
	printf("| Platform Type: 0x%02X\n", hdr->platform);
	printf("======== Firmware Info ========\n");

	free(headerKey);
	return hdr;
}

void extract_mtk_pkg(MFILE *mf, struct config_opts_t *config_opts){
	off_t i = sizeof(struct mtkupg_header) + UPG_HMAC_SIZE;
	if(is_philips_pkg)
		i += PHILIPS_HEADER_SIZE;

	uint8_t *data = mdata(mf, uint8_t) + i;

	char *file_name = my_basename(mf->path);
	char *file_base = remove_ext(file_name);

	struct mtkupg_header *hdr = process_pkg_header(mf);
	if(hdr != NULL){
		// Use product name for now (version would be better)
		sprintf(config_opts->dest_dir, "%s/%s", config_opts->dest_dir, hdr->product_name);
		createFolder(config_opts->dest_dir);
	}
	
	int pakNo;
	for(pakNo=0; moff(mf, data) < msize(mf); pakNo++){
		struct mtkpkg *pak = (struct mtkpkg *)data;
		/* End of package */
		if(pak->size == 0){
			break;
		}

		if(is_philips_pkg && moff(mf, data) + PHILIPS_SIGNATURE_SIZE == msize(mf)){
			//Philips RSA-2048 signature
			break;
		}

		printf("PAK #%u (name='%s', offset='0x%lx', size='%u bytes'",
			pakNo + 1, pak->pakName, moff(mf, data), pak->size
		);

		data += sizeof(*pak);

		uint8_t *pkgData = pak->data;
		size_t pkgSize = pak->size;

		char *dest_path;
		struct mtkpkg_plat *ext = (struct mtkpkg_plat *)pkgData;
		if(!strncmp(ext->platform, MTK_PAK_MAGIC, strlen(MTK_PAK_MAGIC))){
			/* If otaID is missing, compensate for the otaID_len field that would normally be there */
			uint8_t *extData = (uint8_t *)&(ext->otaID_len);
			int has_otaID = strncmp(extData, MTK_PAD_MAGIC, strlen(MTK_PAD_MAGIC)) != 0;
			if(has_otaID){
				printf(", platform='%s', otaid='%s')\n", ext->platform, ext->otaID);
				if(pakNo == 1 && hdr == NULL){
					sprintf(config_opts->dest_dir, "%s/%s", config_opts->dest_dir, ext->otaID);
					createFolder(config_opts->dest_dir);
				}
			} else if(pakNo == 1 && hdr == NULL){
				sprintf(config_opts->dest_dir, "%s/%s", config_opts->dest_dir, file_base);
				createFolder(config_opts->dest_dir);
			}

			uint skip = sizeof(*ext);
			if(has_otaID){
				skip += ext->otaID_len;
			}
			if(skip < MTK_EXTHDR_SIZE){
				skip += (MTK_EXTHDR_SIZE - skip);
			}

			pkgData += skip;
			pkgSize -= skip;
		} else {
			printf(")\n");
		}

		asprintf(&dest_path, "%s/%.*s.pak",
			config_opts->dest_dir,
			member_size(struct mtkpkg, pakName), pak->pakName
		);

		MFILE *out = mfopen(dest_path, "w+");
		if(!out){
			err_exit("Cannot open %s for writing\n", dest_path);
		}

		printf("Saving partition (%s) to file %s\n\n", pak->pakName, dest_path);

		mfile_map(out, pkgSize);

		memcpy(
			mdata(out, void),
			pkgData,
			pkgSize
		);

		mclose(out);

		if(pak->flags != PAK_FLAG_ENCRYPTED){
			handle_file(dest_path, config_opts);
		}

		free(dest_path);

		data += pak->size;
	}

	if(hdr != NULL){
		free(hdr);
	}

	free(file_name);
	free(file_base);
}
