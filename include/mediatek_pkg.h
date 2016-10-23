#ifndef __MTKPKG_H
#define __MTKPKG_H
#include "config.h"

#define UPG_HEADER_SIZE 0x70
#define UPG_HMAC_SIZE 0x20 //HMAC-SHA-256
#define PKG_HMAC_SIZE 0x30 //HMAC-SHA-384

/* Vendor Magics (all 4 bytes) */ 
#define HISENSE_PKG_MAGIC "hise"
#define SHARP_PKG_MAGIC "Shar"
#define PHILIPS_PKG_MAGIC "TPV_"

#define MTK_FIRMWARE_MAGIC "#DH@FiRm" //after vendor magic

#define MTK_PAK_MAGIC "iMtK8"
#define MTK_PAD_MAGIC "iPAd"

#define MTK_EXT_LZHS_OFFSET 0x100000

struct mtkupg_header {
	int8_t vendor_magic[4];
	int8_t mtk_magic[8];
	int8_t vendor_info[60]; //version and other stuff
	uint32_t fileSize;
	uint32_t platform; //0x50 on sharp. Platform type? (unsure)
	int8_t product_name[32];
};

struct mtkpkg {
	char pakName[8];
	uint32_t size; //including any extra header, if present
	uint8_t signature[PKG_HMAC_SIZE];
	char data[];
};

struct mtkpkg_plat {
	char platform[8];
	uint32_t otaID_len;
	char otaID[];
};

struct mtkpkg_pad {
	char magic[8];
	uint8_t padding[28];
};

MFILE *is_mtk_pkg(const char *pkgfile);
MFILE *is_lzhs_fs(const char *pkg);
void extract_mtk_pkg(MFILE *pkg, struct config_opts_t *config_opts);
void extract_lzhs_fs(MFILE *mf, const char *dest_file);
#endif