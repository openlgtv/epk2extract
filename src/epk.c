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

/*
 * Determines the format of an EPK header
 */
static FILE_TYPE_T get_epak_header_type(const uint8_t *header, size_t headerSize) {
	if (compare_epk2_header(header, headerSize)){
		return EPK_V2;
	} else if(compare_epk3_header(header, headerSize)){
		return EPK_V3;
	} else if(compare_epk3_new_header(header, headerSize)){
		return EPK_V3_NEW;
	}

	return INVALID;
}

/*
 * Checks if the given data is an EPK2 or EPK3 header
 */
static bool compare_epak_header(const uint8_t *header, size_t headerSize) {
	return (get_epak_header_type(header, headerSize) != INVALID);
}

/*
 * Loads the specified Public Key for Signature verification
 */
static EVP_PKEY *SWU_CryptoInit_PEM(const char *configuration_dir, const char *pem_file) {
	OpenSSL_add_all_digests();
	ERR_load_CRYPTO_strings();

	char *pem_file_name = NULL;
	asprintf(&pem_file_name, "%s/%s", configuration_dir, pem_file);

	FILE *pubKeyFile = fopen(pem_file_name, "r");
	if (pubKeyFile == NULL) {
		printf("Error: Can't open PEM file %s\n\n", pem_file);
		return NULL;
	}

	EVP_PKEY *pPubKey = PEM_read_PUBKEY(pubKeyFile, NULL, NULL, NULL);
	if (pPubKey == NULL) {
		printf("Error: Can't read PEM signature from file %s\n\n", pem_file);
	} else {
		ERR_clear_error();
	}

	fclose(pubKeyFile);

	return pPubKey;
}

/*
 * Verifies the signature of the given data against the loaded public key
 */
static bool API_SWU_VerifyImage(const void *signature, const void *data, size_t imageSize, SIG_TYPE_T sigType) {
	size_t hashSize;
	unsigned int sigSize;
	const EVP_MD *algo;

	switch (sigType) {
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
			return false;
	}

	unsigned char md_value[hashSize];
	unsigned int md_len = 0;

	EVP_MD_CTX *ctx;
	if ((ctx = EVP_MD_CTX_new()) == NULL) {
		return false;
	}

	EVP_DigestInit(ctx, algo);
	EVP_DigestUpdate(ctx, data, imageSize);
	EVP_DigestFinal(ctx, md_value, &md_len);

	EVP_MD_CTX_reset(ctx);

	EVP_VerifyInit(ctx, algo);
	EVP_VerifyUpdate(ctx, md_value, md_len);

	int result = EVP_VerifyFinal(ctx, signature, sigSize, _gpPubKey);

	/* I hope this can't affect OpenSSL's error queue. */
	EVP_MD_CTX_free(ctx);

	if (result == 1) {
		return true;
	} else if (result != 0) {
		fprintf(stderr, "Error: EVP_VerifyFinal failed in %s:\n", __func__);
		ERR_print_errors_fp(stderr);
	}

	return false;
}

/*
 * Wrapper for signature verification. Retries by decrementing size if it fails
 */
static bool wrap_SWU_VerifyImage(
	const void *signature, const void *data,
	size_t signedSize, size_t *effectiveSignedSize, SIG_TYPE_T sigType
){
	size_t curSize = signedSize;
	bool verified;
	//int skipped = 0;
	while (curSize > 0) {
		verified = API_SWU_VerifyImage(signature, data, curSize, sigType);
		if (verified) {
			if(effectiveSignedSize != NULL){
				*effectiveSignedSize = curSize;
			}
			//printf("Success!\nDigital signature is OK. Signed bytes: %d\n", curSize);
			//printf("Subtracted: %d\n", skipped);
			return true;
		} else {
			//skipped++;
		}
		curSize--;
	}
	//printf("Failed\n");
	return false;
}

/*
 * High level wrapper for signature verification
 */
bool wrap_verifyimage(const void *signature, const void *data, size_t signSize, const char *config_dir, SIG_TYPE_T sigType){
	static bool firstAttempt = true;
	static bool sigCheckAvailable = false;
	size_t effectiveSignedSize;
	bool result = false;

	if(!sigCheckAvailable){
		// No key available, fail early
		if(!firstAttempt){
			return false;
		}
		firstAttempt = false;

		printf("Verifying %zu bytes\n", signSize);

		DIR* dirFile = opendir(config_dir);
		if (dirFile == NULL){
			fprintf(stderr, "Failed to open dir '%s'\n", config_dir);
		} else {
			struct dirent* hFile;
			while ((hFile = readdir(dirFile)) != NULL) {
				if (hFile->d_name[0] == '.') continue;
				if ((hFile->d_type != DT_REG) && (hFile->d_type == DT_LNK) && (hFile->d_type == DT_UNKNOWN)) continue;
				if (strstr(hFile->d_name, ".pem") || strstr(hFile->d_name, ".PEM")) {
					printf("Trying RSA key: %s...\n", hFile->d_name);
					EVP_PKEY *key = SWU_CryptoInit_PEM(config_dir, hFile->d_name);
					if (key == NULL) continue;
					_gpPubKey = key; /* TODO: this doesn't need to be global */
					result = wrap_SWU_VerifyImage(signature, data, signSize, &effectiveSignedSize, sigType);
					if(result){
						sigCheckAvailable = true;
						break;
					}
				}
			}
			closedir(dirFile);
		}
	} else {
		result = wrap_SWU_VerifyImage(signature, data, signSize, &effectiveSignedSize, sigType);
	}

	if (!result) {
		fprintf(stderr, "WARNING: Cannot verify digital signature (maybe you don't have proper PEM file)\n\n");
	} else {
		printf("Succesfully verified 0x%zx out of 0x%zx bytes\n", effectiveSignedSize, signSize);
	}
	return result;
}

/*
 * Decrypts the given data against the loaded AES key, with ECB mode
 */
static void decryptImage(const void *srcaddr, size_t len, void *dstaddr, const AES_KEY *aesKey) {
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
 *
 * Returns true on successful decryption.
 */
bool wrap_decryptimage(const void *src, size_t datalen, void *dest, const char *config_dir, FILE_TYPE_T type, FILE_TYPE_T *outType){
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

	// Check if it's not encrypted
	if(type != RAW && compareFunc(src, datalen)){
		return true;
	}

	bool decrypted = false;
	uint8_t *decryptedData = NULL;
	static bool keyFound = false;
	static AES_KEY *aesKey = NULL;

	if (!keyFound){
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
		decryptImage(src, datalen, dest, aesKey);
		if(type == RAW)
			decrypted = true;
		else
			decrypted = compareFunc(dest, datalen);
	}

	if (!decrypted){
		PERROR("Cannot decrypt EPK content (proper AES key is missing).\n");
		return false;
	} else if(type == EPK){
		if(outType != NULL){
			*outType = get_epak_header_type(decryptedData, datalen);
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
	MFILE *epk = mopen_private(epk_file, O_RDONLY, true);
	if(!epk){
		err_exit("\nCan't open file %s\n\n", epk_file);
	}

	printf("File size: %jd bytes\n", (intmax_t) msize(epk));

	struct epk2_structure *epk2 = mdata(epk, struct epk2_structure);
	EPK_V2_HEADER_T *epkHeader = &(epk2->epkHeader);

	FILE_TYPE_T epkType;

	if(compare_epk2_header((const uint8_t *) epkHeader, sizeof(*epkHeader))){
		epkType = EPK_V2;
	} else {
		printf("\nTrying to decrypt EPK header...\n");
		/* Detect if the file is EPK v2 or EPK v3 */
		bool result = wrap_decryptimage(
			epkHeader,
			sizeof(EPK_V2_HEADER_T),
			epkHeader,
			config_opts->config_dir,
			EPK,
			&epkType
		);

		if(!result){
			return;
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
}
