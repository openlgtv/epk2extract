/**
 * Copyright 2016 Smx <smxdev4@gmail.com>
 * All right reserved
 */

#ifndef __EPK_H
#define __EPK_H
#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>

#define SIGNATURE_SIZE 0x80  //RSA-1024
#define SIGNATURE_SIZE_NEW 0x100 //RSA-2048
typedef unsigned char signature_t[SIGNATURE_SIZE];
typedef unsigned char signature_new_t[SIGNATURE_SIZE_NEW];

typedef enum {
	RELEASE = 0,
	DEBUG,
	TEST,
	UNKNOWN,
} BUILD_TYPE_T;

typedef enum {
    EPK,
	EPK_V2,
	EPK_V3,
	EPK_V3_NEW,
    PAK_V2,
    RAW
} FILE_TYPE_T;

typedef enum {
	SIG_SHA1,
	SIG_SHA256
} SIG_TYPE_T;

#define EPK_VERSION_FORMAT "%02" PRIx8 ".%02" PRIx8 ".%02" PRIx8 ".%02" PRIx8
#define EPKV1_VERSION_FORMAT "%02" PRIx8 ".%02" PRIx8 ".%02" PRIx8

bool isEpkVersionString(const char *str);
bool wrap_verifyimage(const void *signature, const void *data, size_t signSize, const char *config_dir, SIG_TYPE_T sigType);
bool wrap_decryptimage(const void *src, size_t datalen, void *dest, const char *config_dir, FILE_TYPE_T type, FILE_TYPE_T *outType);
void extractEPKfile(const char *epk_file, config_opts_t *config_opts);
#endif
