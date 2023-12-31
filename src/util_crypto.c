/**
 * Miscellaneous utilities
 * Copyright 2016 Smx <smxdev4@gmail.com>
 * All right reserved
 */
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include "config.h"
#include "util.h"
#include "util_crypto.h"

static char *keyFileName = NULL;

static void setKeyFile(char *keyFile){
	if(keyFileName != NULL)
		free(keyFileName);
	keyFileName = keyFile;
}

void setKeyFile_LG(void){
	char *path = NULL;
	if (asprintf(&path, "%s/AES.key", config_opts.config_dir) == -1) {
		fprintf(stderr, "error: failed to allocate string in %s\n", __func__);
		return;
	}
	setKeyFile(path);
}

void setKeyFile_MTK(void){
	char *path = NULL;
	if (asprintf(&path, "%s/MTK.key", config_opts.config_dir) == -1) {
		fprintf(stderr, "error: failed to allocate string in %s\n", __func__);
		return;
	}
	setKeyFile(path);
}

KeyPair *find_AES_key(uint8_t *in_data, size_t in_data_size, CompareFunc fCompare, int key_type, void **dataOut, bool verbose){
	AES_KEY aesKey;
	int found = 0;

	if(keyFileName == NULL){
		err_exit("No key file selected!\n");
	}

	FILE *fp = fopen(keyFileName, "r");
	if (fp == NULL) {
		fprintf(stderr, "Error: Cannot open key file.\n");
		return NULL;
	}

	uint8_t key_buf[MAX_KEY_SIZE] = {0};
	uint8_t iv_buf[MAX_KEY_SIZE] = {0};

	ssize_t read;
	size_t len = 0;
	char *line = NULL;

	while (getline(&line, &len, fp) != -1) {
		if ((line[0] == '#') || (line[0] == '\0') ||
		    (line[0] == '\n') || (line[0] == '\r')) {
			/* skip commented or empty line */
			continue;
		}

		char *pos = line;
		uint8_t *buf = key_buf;

		size_t count;
		if(verbose){
			printf("[+] Trying AES Key ");
		}

		read_key:
		for (count = 0; count < MAX_KEY_SIZE; count++) {
			if(!isprint(*pos) || *pos == ','){
				break;
			}
			if(!sscanf(pos, "%2hhx", &buf[count])){
				break;
			}
			if(verbose){
				printf("%02hhX", buf[count]);
			}
			pos += 2;
		}
		if(key_type == KEY_CBC && *pos == ','){ //repeat for IV
			buf = iv_buf;
			pos++;
			if(verbose)
				printf(", IV: ");
			goto read_key;
		}

		int key_bits = count * 8;
		if(verbose){
			printf(" (aes %d) %s\n", key_bits, pos);
		}
		AES_set_decrypt_key(key_buf, key_bits, &aesKey);

		uint8_t *tmp_data = calloc(1, in_data_size);

		switch(key_type){
			case KEY_CBC: {
				uint8_t iv_tmp[16];
				memcpy(iv_tmp, iv_buf, sizeof(iv_tmp));
				AES_cbc_encrypt(in_data, tmp_data, in_data_size, &aesKey, iv_tmp, AES_DECRYPT);
				break;
			}
			case KEY_ECB: {
				size_t blocks = in_data_size / AES_BLOCK_SIZE;
				size_t i;
				for(i=0; i<blocks; i++){
					AES_ecb_encrypt(&in_data[AES_BLOCK_SIZE * i], &tmp_data[AES_BLOCK_SIZE * i], &aesKey, AES_DECRYPT);
				}
				break;
			}
			default:
				err_exit("Unsupported key type %d\n", key_type);
				break;
		}

		found = fCompare(tmp_data, in_data_size) > 0;

		if(found && dataOut != NULL){
			*dataOut = tmp_data;
		} else {
			free(tmp_data);
		}

		if(found){
			KeyPair *key = calloc(1, sizeof(KeyPair));
			memcpy(&(key->key), &aesKey, sizeof(key->key));
			if(key_type == KEY_CBC){
				memcpy(&(key->ivec), iv_buf, sizeof(key->ivec));
			}
			free(line);
			fclose(fp);
			return key;
		}
	}

	if(line != NULL){
		free(line);
	}

	fclose(fp);

	return NULL;
}
