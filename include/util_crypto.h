/**
 * Copyright 2016 Smx <smxdev4@gmail.com>
 * All right reserved
 */
#ifndef __UTIL_CRYPTO_H
#define __UTIL_CRYPTO_H
#include <stdint.h>
#include <openssl/aes.h>

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined (LIBRESSL_VERSION_NUMBER)
#define EVP_MD_CTX_new EVP_MD_CTX_create
#define EVP_MD_CTX_free EVP_MD_CTX_destroy
#endif

#define KEY_ECB (1 << 0)
#define KEY_CBC (1 << 1)

typedef int (*CompareFunc)(uint8_t *data, size_t size);

void setKeyFile(const char *keyFile);
void setKeyFile_LG();
void setKeyFile_MTK();

uint8_t *getLastKey();
uint8_t *getLastIV();

#define MAX_KEY_SIZE (AES_BLOCK_SIZE * 2) // AES-256

typedef struct {
    AES_KEY key;
    uint8_t keybuf[MAX_KEY_SIZE];
    uint8_t ivec[MAX_KEY_SIZE];
} KeyPair;

KeyPair *find_AES_key(
    uint8_t *in_data, size_t in_data_size, CompareFunc fCompare,
    int key_type, void **dataOut, int verbose
);

#endif
