#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include "config.h"
#include "util_crypto.h"

AES_KEY *find_AES_key(uint8_t *in_data, size_t in_data_size, CompareFunc fCompare){
	AES_KEY *aesKey = calloc(1, sizeof(AES_KEY));
	int found = 0;
	char *key_file_name;
	asprintf(&key_file_name, "%s/AES.key", config_opts.config_dir);

	FILE *fp = fopen(key_file_name, "r");
	if (fp == NULL) {
		fprintf(stderr, "\nError: Cannot open AES.key file.\n\n");
		goto exit_e0;
	}

	uint8_t key_buf[AES_BLOCK_SIZE] = {0};
	ssize_t read;
	size_t len = 0;
	char *line = NULL;

	while ((read = getline(&line, &len, fp)) != -1) {
		char *pos = line;

		size_t count;
		printf("[+] Trying AES Key ");
		for (count = 0; count < AES_BLOCK_SIZE; count++) {
			sscanf(pos, "%2hhx", &key_buf[count]);
			printf("%02X", key_buf[count]);
			pos += 2;
		}
		printf("\n");

		AES_set_decrypt_key((uint8_t *)&key_buf, 128, aesKey);

		void *tmp_data = calloc(1, in_data_size);
		memcpy(tmp_data, in_data, in_data_size);
		
		uint8_t ivec[16] = {0x00};
		AES_cbc_encrypt(tmp_data, tmp_data, in_data_size, aesKey, (uint8_t *)&ivec, AES_DECRYPT);

		if(fCompare(tmp_data, in_data_size)){
			found = 1;
		}

		free(tmp_data);

		if(found)
			break;
	}

	exit_e0:
	free(key_file_name);
	if(!found){
		free(aesKey);
		return NULL;
	}
	return aesKey;
}