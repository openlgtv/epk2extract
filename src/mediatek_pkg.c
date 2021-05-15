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

enum mtkpkg_variant {
	OLD = 1 << 0,
	NEW = 1 << 1,
	THOMPSON = 1 << 2,
	PHILIPS = 1 << 3,
	SHARP = 1 << 4
};

#define SIZEOF_THOMPSON_HEADER 0x170
#define SIZEOF_OLD_HEADER 0x98

static int mtkpkg_variant_flags = NEW;

static struct mtkupg_header packageHeader;
static bool was_decrypted = false;

int compare_pkg_header(uint8_t *header, size_t headerSize){
	struct mtkupg_header *hdr = (struct mtkupg_header *)header;

	if( !strncmp(hdr->vendor_magic, HISENSE_PKG_MAGIC, strlen(HISENSE_PKG_MAGIC)) ){
		printf("[+] Found HISENSE Package\n");
		return 1;
	}
	if( !strncmp(hdr->vendor_magic, SHARP_PKG_MAGIC, strlen(SHARP_PKG_MAGIC)) ){
		printf("[+] Found SHARP Package\n");
		mtkpkg_variant_flags |= SHARP;
		return 1;
	}
	if( !strncmp(hdr->vendor_magic, TPV_PKG_MAGIC, strlen(TPV_PKG_MAGIC)) ||
		!strncmp(hdr->vendor_magic, TPV_PKG_MAGIC2,strlen(TPV_PKG_MAGIC2))
	){
		printf("[+] Found PHILIPS(TPV) Package\n");
		return 1;
	}
	
	if( !strncmp(hdr->vendor_magic, PHILIPS_PKG_MAGIC, strlen(PHILIPS_PKG_MAGIC)) 
	 || !strncmp(hdr->vendor_magic, PHILIPS_PKG_MAGIC2, strlen(PHILIPS_PKG_MAGIC2))
	){
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

int compare_content_header(uint8_t *header, size_t headerSize){
	struct mtkpkg_data *data = (struct mtkpkg_data *)header;
	if ( !strncmp(data->header.mtk_reserved, MTK_RESERVED_MAGIC, strlen(MTK_RESERVED_MAGIC)) ){
		return 1;
	}
	return 0;
}

bool is_known_partition(struct mtkpkg *pak){
	const char *likelyPartitionNames[] = {
		"cfig",
		"ixml",
		"tzbp",
		NULL
	};
	
	char **curPartName = likelyPartitionNames;
	for(int nameIndex=0; *curPartName != NULL; nameIndex++){
		if(!strncmp(pak->header.pakName, *curPartName, sizeof(pak->header.pakName))){
			return true;
		}
		curPartName++;
	}
	return false;
}

MFILE *is_mtk_pkg(const char *pkgfile){
	setKeyFile_MTK();
	
	MFILE *mf = mopen(pkgfile, O_RDONLY);
	if(!mf){
		err_exit("Cannot open file %s\n", pkgfile);
	}
	
	uint8_t *data = mdata(mf, uint8_t);
	void *decryptedHeader = NULL;
	KeyPair *headerKey = NULL;

	do {
		if((headerKey = find_AES_key(data, UPG_HEADER_SIZE, compare_pkg_header, KEY_CBC, (void **)&decryptedHeader, 0)) != NULL){
			break;
		}

		/* It failed, but we want to check for Philips.
		 * Philips has an additional 0x80 header before the normal PKG one
		 */
		if((headerKey = find_AES_key(data + PHILIPS_HEADER_SIZE, UPG_HEADER_SIZE, compare_pkg_header, KEY_CBC, (void **)&decryptedHeader, 0)) != NULL){
			mtkpkg_variant_flags |= PHILIPS;
		}
	} while(0);

	if(headerKey != NULL){
		was_decrypted = true;
		memcpy(&packageHeader, decryptedHeader, sizeof(packageHeader));
		free(headerKey);
		return mf;
	}

	/* No AES key found to decrypt the header. Try to check if it's a MTK PKG anyways
	 * This method can return false for valid packages as the order of partitions isn't fixed
	 */

	/* First pak doesn't have extended fields */
	struct mtkpkg *firstPak = (struct mtkpkg *)(data + sizeof(struct mtkupg_header));
	if(is_known_partition(firstPak))
		return mf;
	
	firstPak = (struct mtkpkg *)(data + SIZEOF_OLD_HEADER);
	if(is_known_partition(firstPak)){
		mtkpkg_variant_flags = OLD;
		return mf;
	}

	firstPak = (struct mtkpkg *)(data + SIZEOF_OLD_HEADER + PHILIPS_HEADER_SIZE);
	if(is_known_partition(firstPak)){
		mtkpkg_variant_flags = OLD | PHILIPS;
		return mf;
	}

	firstPak = (struct mtkpkg *)(data + SIZEOF_THOMPSON_HEADER);
	if(is_known_partition(firstPak)){
		mtkpkg_variant_flags = NEW | THOMPSON;
		return mf;
	}

	mclose(mf);
	return NULL;
}

#define SIZEOF_FIRM_HEADERS 0x90

MFILE *is_firm_image(const char *pkg){
	MFILE *mf = mopen(pkg, O_RDONLY);
	if(!mf){
		err_exit("Cannot open file %s\n", pkg);
	}

	if(msize(mf) < (SIZEOF_FIRM_HEADERS + 16)){
		mclose(mf);
		return NULL;
	}

	if(is_lzhs_mem(mf, SIZEOF_FIRM_HEADERS)){
		return mf;
	}
	mclose(mf);
	return NULL;
}

int extract_firm_image(MFILE *mf){
	return process_segment(mf, SIZEOF_FIRM_HEADERS, "firm");
}

MFILE *is_lzhs_fs(const char *pkg){
	MFILE *mf = mopen(pkg, O_RDONLY);
	if(!mf){
		err_exit("Cannot open file %s\n", pkg);
	}

	uint8_t *data = mdata(mf, uint8_t);

	off_t start = MTK_EXT_LZHS_OFFSET;
	if(is_nfsb_mem(mf, SHARP_PKG_HEADER_SIZE)){
		start += SHARP_PKG_HEADER_SIZE;
	}

	if(msize(mf) < (start + sizeof(struct lzhs_header))){
		goto fail;
	}

	if(
		is_lzhs_mem(mf, start) &&
		is_lzhs_mem(mf, start + sizeof(struct lzhs_header)) &&
		// First LZHS header contains number of segment in checksum. Make sure that it is the first segment
		((struct lzhs_header *)&data[start])->checksum == 1
	){
		return mf;
	}

	fail:
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
	munmap(out_cur->ptr, out_cur->size);
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
void extract_lzhs_fs(MFILE *mf, const char *dest_file, config_opts_t *config_opts){
	int is_sharp = 0;
	uint8_t *data = mdata(mf, uint8_t);
	if(is_nfsb_mem(mf, SHARP_PKG_HEADER_SIZE)){
		data += SHARP_PKG_HEADER_SIZE;
		is_sharp = 1;
	}

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
		data,
		MTK_EXT_LZHS_OFFSET,
		1,
		out_file
	);

	data += MTK_EXT_LZHS_OFFSET;

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

	if(is_sharp){
		handle_file(dest_file, config_opts);
	}
}

void print_pkg_header(struct mtkupg_header *hdr){
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
}

static off_t get_mtkpkg_offset(){
	if((mtkpkg_variant_flags & THOMPSON) == THOMPSON){
		return SIZEOF_THOMPSON_HEADER;
	}

	off_t offset = 0;
	if((mtkpkg_variant_flags & NEW) == NEW){
		offset += sizeof(struct mtkupg_header);
	} else if((mtkpkg_variant_flags & OLD) == OLD){
		offset += SIZEOF_OLD_HEADER;
	}
	
	if((mtkpkg_variant_flags & PHILIPS) == PHILIPS){
		offset += PHILIPS_HEADER_SIZE;
	}

	return offset;
}

void extract_mtk_pkg(const char *pkgFile, config_opts_t *config_opts){
	MFILE *mf = mopen_private(pkgFile, O_RDONLY);
	mprotect(mf->pMem, msize(mf), PROT_READ | PROT_WRITE);

	off_t offset = get_mtkpkg_offset();
	uint8_t *data = mdata(mf, uint8_t) + offset;

	char *file_name = my_basename(mf->path);
	char *file_base = remove_ext(file_name);

	struct mtkupg_header *hdr = (was_decrypted) ? &packageHeader : NULL;
	if(hdr != NULL)
		print_pkg_header(hdr);
	
	if(hdr != NULL){
		// Use product name for now (version would be better)
		asprintf_inplace(&config_opts->dest_dir, "%s/%s", config_opts->dest_dir, hdr->product_name);
	} else {
		asprintf_inplace(&config_opts->dest_dir, "%s/%s", config_opts->dest_dir, file_base);
	}
	createFolder(config_opts->dest_dir);
	
	KeyPair *dataKey = NULL;
	
	int pakNo;
	for(pakNo=0; moff(mf, data) < msize(mf); pakNo++){
		struct mtkpkg *pak = (struct mtkpkg *)data;
		if((mtkpkg_variant_flags & PHILIPS) == PHILIPS && moff(mf, data) + PHILIPS_SIGNATURE_SIZE == msize(mf)){
			printf("-- RSA 2048 Signature --\n");
			hexdump(data, PHILIPS_SIGNATURE_SIZE);
			//Philips RSA-2048 signature
			break;
		}

		size_t cryptedHeaderSize = ((mtkpkg_variant_flags & NEW) == NEW) ? sizeof(pak->content.header) : 0;
		
		/* Skip pak header and crypted header */
		data += sizeof(pak->header) + cryptedHeaderSize;

		uint8_t *pkgData = (uint8_t *)&(pak->content.header);
		size_t dataSize = sizeof(pak->content.header);
		size_t pkgSize = pak->header.pakSize;
		if(pkgSize == 0){
			goto save_file;
		}
		
		if((pak->header.flags & PAK_FLAG_ENCRYPTED) == PAK_FLAG_ENCRYPTED){
			dataSize += pak->header.pakSize;
		}

#pragma region FindAesKey
		uint8_t *decryptedPkgData = NULL;
		
		if(was_decrypted){
			if(dataKey == NULL){
				dataKey = find_AES_key(
					pkgData,
					dataSize,
					compare_content_header,
					KEY_CBC,
					(void **)&decryptedPkgData,
					1
				);
				int success = dataKey != NULL;
				if(success){
					/* Copy decrypted data */
					memcpy(pkgData, decryptedPkgData, dataSize);
					free(decryptedPkgData);
				} else if(was_decrypted) {
					/* Try to decrypt by using vendorMagic repeated 4 times, ivec 0 */
					do {
						AES_KEY aesKey;
						uint8_t keybuf[16];				
						uint i;
						for(i=0; i<4; i++){
							memcpy(&keybuf[4 * i], hdr->vendor_magic, sizeof(uint32_t));
						}

						AES_set_decrypt_key((uint8_t *)&keybuf, 128, &aesKey);

						dataKey = calloc(1, sizeof(KeyPair)); //also fills ivec with zeros
						memcpy(&(dataKey->key), &aesKey, sizeof(aesKey));

						uint8_t iv_tmp[16];
						memcpy(&iv_tmp, &(dataKey->ivec), sizeof(iv_tmp));
						AES_cbc_encrypt(
							pkgData, pkgData,
							dataSize, &(dataKey->key),
							(void *)&iv_tmp, AES_DECRYPT
						);

						success = compare_content_header(pkgData, sizeof(struct mtkpkg_data));
					} while(0);
				}
				if(!success){
					if((pak->header.flags & PAK_FLAG_ENCRYPTED) == PAK_FLAG_ENCRYPTED){
						printf("[-] Couldn't decrypt data!\n");
					} else {
						printf("[-] Couldn't decrypt header!\n");
					}
				}
			} else {
	#pragma endregion
				uint8_t iv_tmp[16];
				memcpy(&iv_tmp, &(dataKey->ivec), sizeof(iv_tmp));
				AES_cbc_encrypt(
					pkgData, pkgData,
					dataSize, &(dataKey->key),
					(void *)&iv_tmp, AES_DECRYPT
				);
				int success = compare_content_header(pkgData, sizeof(struct mtkpkg_data));
				if(!success){
					fprintf(stderr, "[!] WARNING: MTK Crypted header not found, continuing anyways...\n");
				}
			}
		}
		
		if((mtkpkg_variant_flags & NEW) == NEW){
			// Skip the mtk header (reserved inc)
			pkgData += sizeof(struct mtkpkg_crypted_header);
		}
		
		printf("\nPAK #%u %s (name='%s', offset='0x%lx', size='%u bytes'",
			pakNo + 1,
			((pak->header.flags & PAK_FLAG_ENCRYPTED) == PAK_FLAG_ENCRYPTED) ? "[ENCRYPTED]" : "",
			pak->header.pakName,
			moff(mf, data),
			pak->header.pakSize
		);

		struct mtkpkg_plat *ext = (struct mtkpkg_plat *)pkgData;

		/* Parse the fields at the start of pkgData, and skip them */
		if(!strncmp(ext->platform, MTK_PAK_MAGIC, strlen(MTK_PAK_MAGIC))){
			uint8_t *extData = (uint8_t *)&(ext->otaID_len);
			/* otaID is optional. if we have it, it's preceded by its length. If we don't have it, we have the iPAD magic instead */
			int has_otaID = strncmp(extData, MTK_PAD_MAGIC, strlen(MTK_PAD_MAGIC)) != 0;
			if(has_otaID){
				printf(", platform='%s', otaid='%s'", ext->platform, ext->otaID);
				if(pakNo == 1 && hdr == NULL){
					asprintf_inplace(&config_opts->dest_dir, "%s/%s", config_opts->dest_dir, ext->otaID);
					createFolder(config_opts->dest_dir);
				}
			} else if(pakNo == 1 && hdr == NULL){
				asprintf_inplace(&config_opts->dest_dir, "%s/%s", config_opts->dest_dir, file_base);
				createFolder(config_opts->dest_dir);
			}

			/* Skip the headers to get to the data */
			uint skip = sizeof(*ext);
			if(has_otaID){
				skip += ext->otaID_len;
			}
			if(skip < MTK_EXTHDR_SIZE){
				skip += (MTK_EXTHDR_SIZE - skip);
			}

			pkgData += skip;
			pkgSize -= skip;
		}

		save_file:
		printf(")\n");
		
		char *dest_path = NULL;
		asprintf(&dest_path, "%s/%.*s.pak",
			config_opts->dest_dir,
			member_size(struct mtkpkg_header, pakName), pak->header.pakName
		);

		MFILE *out = mfopen(dest_path, "w+");
		if(!out){
			err_exit("Cannot open %s for writing\n", dest_path);
		}

		printf("Saving partition (%s) to file %s\n\n", pak->header.pakName, dest_path);

		if(pkgSize == 0)
			goto saved_file;

		mfile_map(out, pkgSize);
		mwrite(pkgData, pkgSize, 1, out);

		saved_file:
		mclose(out);

		if(dest_path != NULL && pkgSize != 0){
			handle_file(dest_path, config_opts);
		}
		if(dest_path != NULL){
			free(dest_path);
		}

		data += pak->header.pakSize;
	}

	if(dataKey != NULL){
		free(dataKey);
	}

	free(file_name);
	free(file_base);
	mclose(mf);
}
