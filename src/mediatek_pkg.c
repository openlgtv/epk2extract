#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include "main.h" //for handle_file
#include "mfile.h"
#include "mediatek_pkg.h"
#include "lzhs/lzhs.h"
#include "util.h"
#include "util_crypto.h"

MFILE *is_mtk_pkg(const char *pkgfile){
	MFILE *mf = mopen(pkgfile, O_RDONLY);
	if(!mf){
		err_exit("Cannot open file %s\n", pkgfile);
	}
	
	uint8_t *data = mdata(mf, uint8_t);
	data = &data[sizeof(struct mtkupg_header) + UPG_HMAC_SIZE];

	/* First pak doesn't have OTA ID fields */
	struct mtkpkg *cfig = (struct mtkpkg *)data;
	if(
		(!strcmp(cfig->pakName, "cfig")) &&
		(!strncmp(cfig->data, "START", 5))
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

	#ifdef LZHSFS_EXTRACT_CHUNKS
	char *dir = my_dirname(dest_file);
	char *file = my_basename(dest_file);
	char *base = remove_ext(file);
	#endif


	printf("Copying 0x%08X bytes\n", MTK_EXT_LZHS_OFFSET);
	/* Copy first MB as-is (uncompressed) */
	fwrite (
		mdata(mf, uint8_t),
		MTK_EXT_LZHS_OFFSET,
		1,
		out_file
	);

	while(moff(mf, data) < msize(mf)){
		struct lzhs_header *main_hdr = (struct lzhs_header *)data; 
		struct lzhs_header *seg_hdr = (struct lzhs_header *)(data + sizeof(*main_hdr));

		printf("\n[0x%08X] segment #%u (compressed='%u bytes', uncompressed='%u bytes')\n",
			moff(mf, main_hdr),
			main_hdr->checksum,
			seg_hdr->compressedSize, seg_hdr->uncompressedSize);

		uint8_t out_checksum = 0x00;

		#ifdef LZHSFS_EXTRACT_CHUNKS
		char *out;

		asprintf(&out, "%s/%s.%d", dir, base, main_hdr->checksum);
		lzhs_decode(mf, moff(mf, seg_hdr), out, &out_checksum);
		free(out);
		#else
		cursor_t *out_cur = lzhs_decode(mf, moff(mf, seg_hdr), NULL, &out_checksum);
		if(out_cur == NULL || (intptr_t)out_cur < 0){
			err_exit("LZHS decode failed\n");
		}

		fwrite(out_cur->ptr, out_cur->size, 1, out_file);
		free(out_cur);
		#endif

		uint pad;
		pad = (pad = (seg_hdr->compressedSize % 16)) == 0 ? 0 : (16 - pad);

		data += (
			sizeof(*main_hdr) + sizeof(*seg_hdr) +
			seg_hdr->compressedSize +
			pad
		);
	}

	fclose(out_file);

	#ifdef LZHSFS_EXTRACT_CHUNKS
	free(dir); free(file); free(base);
	#endif
}

int compare_pkg_header(uint8_t *header, size_t headerSize){
	if( !strncmp(header, HISENSE_PKG_MAGIC, strlen(HISENSE_PKG_MAGIC)) ){
		printf("[+] Found HISENSE Package\n");
		return 1;
	}
	if( !strncmp(header, SHARP_PKG_MAGIC, strlen(SHARP_PKG_MAGIC)) ){
		printf("[+] Found SHARP Package\n");
		return 1;
	}
	if( !strncmp(header, PHILIPS_PKG_MAGIC, strlen(PHILIPS_PKG_MAGIC)) ){
		printf("[+] Found PHILIPS Package\n");
		return 1;
	}
	return 0;
}

void process_pkg_header(MFILE *mf){
	uint8_t *header = mdata(mf, uint8_t);
	AES_KEY *headerKey = find_AES_key(header, UPG_HEADER_SIZE, compare_pkg_header);
	if(!headerKey){
		fprintf(stderr, "[!] Cannot find proper AES key for header, ignoring\n");
		return;
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
}

void extract_mtk_pkg(MFILE *mf, struct config_opts_t *config_opts){
	off_t i = sizeof(struct mtkupg_header) + UPG_HMAC_SIZE;
	uint8_t *data = mdata(mf, uint8_t) + i;

	char *file_name = my_basename(mf->path);
	char *file_base = remove_ext(file_name);

	process_pkg_header(mf);
	
	int pakNo;
	for(pakNo=0; i < msize(mf); pakNo++){
		struct mtkpkg *pak = (struct mtkpkg *)data;
		/* End of package */
		if(pak->size == 0){
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
			printf(", platform='%s', otaid='%s')\n", ext->platform, ext->otaID);
			if(pakNo == 1){
				sprintf(config_opts->dest_dir, "%s/%s", config_opts->dest_dir, ext->otaID);
				createFolder(config_opts->dest_dir);
			}
			pkgData += sizeof(*ext) + ext->otaID_len;
			pkgSize -= sizeof(*ext) + ext->otaID_len;
		} else {
			printf(")\n");
		}

		struct mtkpkg_pad *pad = (struct mtkpkg_pad *)pkgData;
		if(!strncmp(pad->magic, MTK_PAD_MAGIC, strlen(MTK_PAD_MAGIC))){
			pkgData += sizeof(*pad);
			pkgSize -= sizeof(*pad);
		}

		asprintf(&dest_path, "%s/%s.pak", config_opts->dest_dir, pak->pakName);

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
		handle_file(dest_path, config_opts);
		free(dest_path);

		data += pak->size;
	}

	mclose(mf);
	mf = NULL;

	free(file_name);
	free(file_base);
}
