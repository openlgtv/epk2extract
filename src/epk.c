/**
 * Copyright 2016 Smx <smxdev4@gmail.com>
 * All right reserved
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "config.h"
#include "epk.h"
#include "epk2.h"
#include "epk3.h"
#include "util.h"
#include "util_crypto.h"

static EVP_PKEY *_gpPubKey;
static AES_KEY *aesKey;
static int keyFound = 0;
static int sigCheckAvailable = 0;
static int firstAttempt = 1;

/*
 * Checks if the given data is an EPK2 or EPK3 header
 */
int compare_epak_header(uint8_t *header, size_t headerSize){
	if(compare_epk2_header(header, headerSize)){
		return EPK_V2;
	} else if(compare_epk3_header(header, headerSize)){
		return EPK_V3;
	} else if(compare_epk3_new_header(header, headerSize)){
		return EPK_V3_NEW;
	}

	return 0;
}

/*
 * Loads the specified Public Key for Signature verification
 */
int SWU_CryptoInit_PEM(char *configuration_dir, char *pem_file) {
	OpenSSL_add_all_digests();
	ERR_load_CRYPTO_strings();
	char *pem_file_name;
	asprintf(&pem_file_name, "%s/%s", configuration_dir, pem_file);
	FILE *pubKeyFile = fopen(pem_file_name, "r");
	if (pubKeyFile == NULL) {
		printf("Error: Can't open PEM file %s\n\n", pem_file);
		return 1;
	}
	EVP_PKEY *gpPubKey = PEM_read_PUBKEY(pubKeyFile, NULL, NULL, NULL);
	_gpPubKey = gpPubKey;
	if (_gpPubKey == NULL) {
		printf("Error: Can't read PEM signature from file %s\n\n", pem_file);
		fclose(pubKeyFile);
		return 1;
	}
	fclose(pubKeyFile);
	ERR_clear_error();
	return 0;
}

/*
 * Verifies the signature of the given data against the loaded public key
 */
int API_SWU_VerifyImage(void *signature, void* data, size_t imageSize, SIG_TYPE_T sigType) {
	size_t hashSize;
	unsigned int sigSize;
	const EVP_MD *algo;

	switch(sigType) {
		case SIG_SHA1:
			hashSize = 0x40;
			sigSize = SIGNATURE_SIZE;
			algo = EVP_sha1();
			break;
		case SIG_SHA256:
			hashSize = 0x80;
			sigSize = SIGNATURE_SIZE_NEW;
			algo = EVP_sha256();
			break;
		default:
			printf("Invalid sigType: %d\n", sigType);
			return 0;
	}

	unsigned char md_value[hashSize];
	unsigned int md_len = 0;
	int result = 0;

	EVP_MD_CTX *ctx1, *ctx2;
	if ((ctx1 = EVP_MD_CTX_new()) == NULL)
		return 0;

	if ((ctx2 = EVP_MD_CTX_new()) == NULL) {
		EVP_MD_CTX_free(ctx1);
		return 0;
	}

	EVP_DigestInit(ctx1, algo);
	EVP_DigestUpdate(ctx1, data, imageSize);
	EVP_DigestFinal(ctx1, md_value, &md_len);
	EVP_DigestInit(ctx2, algo);
	EVP_DigestUpdate(ctx2, md_value, md_len);

	result = EVP_VerifyFinal(ctx2, signature, sigSize, _gpPubKey);

	EVP_MD_CTX_free(ctx2);
	EVP_MD_CTX_free(ctx1);

	return result;
}

/*
 * Wrapper for signature verification. Retries by decrementing size if it fails
 */
int wrap_SWU_VerifyImage(
	void *signature, void* data,
	size_t signedSize, size_t *effectiveSignedSize, SIG_TYPE_T sigType
){
	size_t curSize = signedSize;
	int verified;
	//int skipped = 0;
	while (curSize > 0) {
		verified = API_SWU_VerifyImage(signature, data, curSize, sigType);
		if (verified) {
			if(effectiveSignedSize != NULL){
				*effectiveSignedSize = curSize;
			}
			//printf("Success!\nDigital signature is OK. Signed bytes: %d\n", curSize);
			//printf("Subtracted: %d\n", skipped);
			return 0;
		} else {
			//skipped++;
		}
		curSize--;
	}
	//printf("Failed\n");
	return -1;
}

/*
 * High level wrapper for signature verification
 */
int wrap_verifyimage(void *signature, void *data, size_t signSize, char *config_dir, SIG_TYPE_T sigType){
	size_t effectiveSignedSize;
	int result = -1;
	if(!sigCheckAvailable){
		// No key available, fail early
		if(!firstAttempt){
			return -1;
		}
		firstAttempt = 0;
		printf("Verifying %zu bytes\n", signSize);

		DIR* dirFile = opendir(config_dir);
		if (dirFile == NULL){
			fprintf(stderr, "Failed to open dir '%s'\n", config_dir);
		} else {
			struct dirent* hFile;
			while ((hFile = readdir(dirFile)) != NULL) {
				if (!strcmp(hFile->d_name, ".") || !strcmp(hFile->d_name, "..") || hFile->d_name[0] == '.') continue;
				if (strstr(hFile->d_name, ".pem") || strstr(hFile->d_name, ".PEM")) {
					printf("Trying RSA key: %s...\n", hFile->d_name);
					SWU_CryptoInit_PEM(config_dir, hFile->d_name);
					result = wrap_SWU_VerifyImage(signature, data, signSize, &effectiveSignedSize, sigType);
					if(result > -1){
						sigCheckAvailable = 1;
						break;
					}
				}
			}
			closedir(dirFile);
		}
	} else {
		result = wrap_SWU_VerifyImage(signature, data, signSize, &effectiveSignedSize, sigType);
	}

	if (result < 0) {
		fprintf(stderr, "WARNING: Cannot verify digital signature (maybe you don't have proper PEM file)\n\n");
	} else {
		printf("Succesfully verified 0x%zx out of 0x%zx bytes\n", effectiveSignedSize, signSize);
	}
	return result;
}

/*
 * Decrypts the given data against the loaded AES key, with ECB mode
 */
void decryptImage(void *srcaddr, size_t len, void *dstaddr) {
	unsigned int remaining = len;

	while (remaining >= AES_BLOCK_SIZE) {
		AES_decrypt(srcaddr, dstaddr, aesKey);
		srcaddr += AES_BLOCK_SIZE;
		dstaddr += AES_BLOCK_SIZE;
		remaining -= AES_BLOCK_SIZE;
	}
	if (remaining != 0) {
		memcpy(dstaddr, srcaddr, remaining);
	}
}

/*
 * Identifies correct key for decryption (if not previously identified) and decrypts data
 * The comparison function is selected from the passed file type
 * For EPK comparison, outType is used to store the detected type (EPK v2 or EPK v3)
 */
int wrap_decryptimage(void *src, size_t datalen, void *dest, char *config_dir, FILE_TYPE_T type, FILE_TYPE_T *outType){
	CompareFunc compareFunc = NULL;
	switch(type){
		case EPK:
			compareFunc = compare_epak_header;
			break;
		case EPK_V2:
			compareFunc = compare_epk2_header;
			break;
		case PAK_V2:
			compareFunc = compare_pak2_header;
			break;
		case EPK_V3:
			compareFunc = compare_epk3_header;
			break;
		case RAW: /* special case below */
			break;
		default:
			err_exit("Error in %s: file type %d not handled\n", __func__, type);
	}

	int decrypted = 0;
	uint8_t *decryptedData = NULL;

	// Check if we need decryption
	if(type != RAW && compareFunc(src, datalen)){
		decrypted = 1;
		return decrypted;
	}

	if(!keyFound){
		printf("Trying known AES keys...\n");
		KeyPair *keyPair = find_AES_key(src, datalen, compareFunc, KEY_ECB, (void **)&decryptedData, true);
		decrypted = keyFound = (keyPair != NULL);
		if(decrypted){
			aesKey = &(keyPair->key);
		}
		if(decrypted && type != EPK){
			memcpy(dest, decryptedData, datalen);
			free(decryptedData);
		}
	} else {
		decryptImage(src, datalen, dest);
		if(type == RAW)
			decrypted = 1;
		else
			decrypted = compareFunc(dest, datalen);
	}
	if (!decrypted){
		PERROR("Cannot decrypt EPK content (proper AES key is missing).\n");
		return -1;
	} else if(type == EPK){
		if(outType != NULL){
			*outType = compare_epak_header(decryptedData, datalen);
		}
	}

	return decrypted;
}

/*
 * Verifies if a string contains 2 dots and numbers (x.y.z)
 */
bool isEpkVersionString(const char *str){
	// Size of string is the same across EPK2 and EPK3, for both Platform and SDK versions
	return count_tokens(str, '.', member_size(struct epk2_structure, platformVersion)) == 2;
}

/*
 * Detects if the EPK file is v2 or v3, and extracts it
 */
void extractEPKfile(const char *epk_file, config_opts_t *config_opts){
	do {
		MFILE *epk = mopen_private(epk_file, O_RDONLY);
		if(!epk){
			err_exit("\nCan't open file %s\n\n", epk_file);
		}
		//Make it R/W
		mprotect(epk->pMem, msize(epk), PROT_READ | PROT_WRITE);

		printf("File size: %jd bytes\n", (intmax_t) msize(epk));

		struct epk2_structure *epk2 = mdata(epk, struct epk2_structure);
		EPK_V2_HEADER_T *epkHeader = &(epk2->epkHeader);

		int result;
		FILE_TYPE_T epkType;
		if(compare_epk2_header((uint8_t *)epkHeader, sizeof(*epkHeader))){
			epkType = EPK_V2;
		} else {
			printf("\nTrying to decrypt EPK header...\n");
			/* Detect if the file is EPK v2 or EPK v3 */
			result = wrap_decryptimage(
				epkHeader,
				sizeof(EPK_V2_HEADER_T),
				epkHeader,
				config_opts->config_dir,
				EPK,
				&epkType
			);
			if(result < 0){
				break;
			}
		}

		switch(epkType){
			case EPK_V2:
				printf("[+] EPK v2 Detected\n");
				extractEPK2(epk, config_opts);
				break;
			case EPK_V3:
			case EPK_V3_NEW:
				printf("[+] EPK v3 Detected\n");
				extractEPK3(epk, epkType, config_opts);
				break;
			default:
				err_exit("Error in %s: file type not handled\n", __func__);
		}
	} while(0);
}
