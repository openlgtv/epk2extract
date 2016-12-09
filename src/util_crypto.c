/**
 * Miscellaneous utilities
 * Copyright 2016 Smx <smxdev4@gmail.com>
 * All right reserved
 */
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include "config.h"
#include "util.h"
#include "util_crypto.h"

AES_KEY *find_AES_key(uint8_t *in_data, size_t in_data_size, CompareFunc fCompare, int key_type, int verbose){
	AES_KEY *aesKey = calloc(1, sizeof(AES_KEY));
	int found = 0;
	char *key_file_name;
	asprintf(&key_file_name, "%s/AES.key", config_opts.config_dir);

	FILE *fp = fopen(key_file_name, "r");
	if (fp == NULL) {
		fprintf(stderr, "\nError: Cannot open AES.key file.\n\n");
		goto exit_e0;
	}

	uint8_t key_buf[AES_BLOCK_SIZE];
	uint8_t iv_buf[AES_BLOCK_SIZE];
	uint8_t *buf = (uint8_t *)&key_buf;
	
	ssize_t read;
	size_t len = 0;
	char *line = NULL;

	while ((read = getline(&line, &len, fp)) != -1) {
		char *pos = line;

		size_t count;
		if(verbose){
			printf("[+] Trying AES Key ");
		}

		read_key:
		for (count = 0; count < AES_BLOCK_SIZE; count++) {
			sscanf(pos, "%2hhx", &buf[count]);
			if(verbose){
				printf("%02X", buf[count]);
			}
			pos += 2;
		}
		if(key_type == KEY_CBC && *pos == ','){ //repeat for IV
			buf = (uint8_t *)&iv_buf;
			pos++;
			goto read_key;
		}
		if(verbose){
			printf("\n");
		}

		AES_set_decrypt_key((uint8_t *)&key_buf, 128, aesKey);

		uint8_t *tmp_data = calloc(1, in_data_size);

		switch(key_type){
			case KEY_CBC:
				AES_cbc_encrypt(in_data, tmp_data, in_data_size, aesKey, (uint8_t *)&iv_buf, AES_DECRYPT);
				break;
			case KEY_ECB:
				;
				size_t blocks = in_data_size / AES_BLOCK_SIZE;
				size_t i;
				for(i=0; i<blocks; i++)
					AES_ecb_encrypt(&in_data[AES_BLOCK_SIZE * i], &tmp_data[AES_BLOCK_SIZE * i], aesKey, AES_DECRYPT);
				found = fCompare(tmp_data, in_data_size);
				break;
			default:
				err_exit("Unsupported key type %d\n", key_type);
				break;
		}		

		found = fCompare(tmp_data, in_data_size);

		free(tmp_data);

		if(found)
			break;
	}

	if(line != NULL){
		free(line);
	}

	exit_e0:
	free(key_file_name);
	if(!found){
		free(aesKey);
		return NULL;
	}

	return aesKey;
}