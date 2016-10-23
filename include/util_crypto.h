#ifndef __UTIL_CRYPTO_H
#define __UTIL_CRYPTO_H
#include <stdint.h>
#include <openssl/aes.h>

typedef int (*CompareFunc)(uint8_t *data, size_t size);

void decryptImage(AES_KEY *aesKey, unsigned char *dstaddr, unsigned char *srcaddr, size_t len);
AES_KEY *find_AES_key(uint8_t *in_data, size_t in_data_size, CompareFunc fCompare);

#endif
