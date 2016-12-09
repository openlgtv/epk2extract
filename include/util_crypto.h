/**
 * Copyright 2016 Smx <smxdev4@gmail.com>
 * All right reserved
 */
#ifndef __UTIL_CRYPTO_H
#define __UTIL_CRYPTO_H
#include <stdint.h>
#include <openssl/aes.h>

#define KEY_ECB (1 << 0)
#define KEY_CBC (1 << 1)

typedef int (*CompareFunc)(uint8_t *data, size_t size);

AES_KEY *find_AES_key(uint8_t *in_data, size_t in_data_size, CompareFunc fCompare, int key_type, int verbose);

#endif
