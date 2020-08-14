/**
 * Copyright 2016 Smx <smxdev4@gmail.com>
 * All right reserved
 */

#ifndef __EPK_H
#define __EPK_H
#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>

#define SIGNATURE_SIZE 0x80 //RSA-1024
typedef unsigned char signature_t[SIGNATURE_SIZE];

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

#define EPK_VERSION_FORMAT "%02" PRIx8 ".%02" PRIx8 ".%02" PRIx8 ".%02" PRIx8

bool isEpkVersionString(const char *str);
int wrap_verifyimage(void *signature, void *data, size_t signSize, char *config_dir);
int wrap_decryptimage(void *src, size_t datalen, void *dest, char *config_dir, FILE_TYPE_T type, FILE_TYPE_T *outType);
void extractEPKfile(const char *epk_file, config_opts_t *config_opts);
#endif
