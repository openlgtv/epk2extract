/**
 * Miscellaneous utilities
 * Copyright 2016 Smx <smxdev4@gmail.com>
 * All right reserved
 */
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include "config.h"
#include "util.h"
#include "util_crypto.h"

static char *keyFileName = NULL;

void setKeyFile(const char *keyFile){
	if(keyFileName != NULL)
		free(keyFileName);
	keyFileName = (char *)keyFile;
}

void setKeyFile_LG(){
	char *path;
	asprintf(&path, "%s/AES.key", config_opts.config_dir);
	setKeyFile(path);
}

void setKeyFile_MTK(){
	char *path;
	asprintf(&path, "%s/MTK.key", config_opts.config_dir);
	setKeyFile(path);
}

KeyPair *find_AES_key(uint8_t *in_data, size_t in_data_size, CompareFunc fCompare, int key_type, void **dataOut, int verbose){
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

	uint8_t key_buf[MAX_KEY_SIZE];
	uint8_t iv_buf[MAX_KEY_SIZE];
	memset(&key_buf, 0x00, sizeof(key_buf));
	memset(&iv_buf, 0x00, sizeof(iv_buf));
	
	ssize_t read;
	size_t len = 0;
	char *line = NULL;

	while ((read = getline(&line, &len, fp)) != -1) {
		char *pos = line;
		uint8_t *buf = (uint8_t *)&key_buf;

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
				printf("%02X", buf[count]);
			}
			pos += 2;
		}
		if(key_type == KEY_CBC && *pos == ','){ //repeat for IV
			buf = (uint8_t *)&iv_buf;
			pos++;
			if(verbose)
				printf(", IV: ");
			goto read_key;
		}

		int key_bits = count * 8;
		if(verbose){
			printf(" (aes %d) %s\n", key_bits, pos);
		}
		AES_set_decrypt_key((uint8_t *)&key_buf, key_bits, &aesKey);

		uint8_t *tmp_data = calloc(1, in_data_size);

		switch(key_type){
			case KEY_CBC:;
				uint8_t iv_tmp[16];
				memcpy(&iv_tmp, &iv_buf, sizeof(iv_tmp));
				AES_cbc_encrypt(in_data, tmp_data, in_data_size, &aesKey, (uint8_t *)&iv_tmp, AES_DECRYPT);
				break;
			case KEY_ECB:;
				size_t blocks = in_data_size / AES_BLOCK_SIZE;
				size_t i;
				for(i=0; i<blocks; i++)
					AES_ecb_encrypt(&in_data[AES_BLOCK_SIZE * i], &tmp_data[AES_BLOCK_SIZE * i], &aesKey, AES_DECRYPT);
				break;
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
			memcpy(&(key->key), &aesKey, sizeof(aesKey));
			if(key_type == KEY_CBC){
				memcpy(&(key->ivec), &iv_buf, sizeof(iv_buf));
			}
			free(line);
			return key;
		}
	}

	if(line != NULL){
		free(line);
	}

	return NULL;
}
