#include <epk2.h>
#include <crc.h>

EVP_PKEY *_gpPubKey;
AES_KEY _gdKeyImage, _geKeyImage;
const int MAX_PAK_CHUNK_SIZE = 0x400000;
const char PEM_FILE[] = "general_pub.pem";
const char EPK2_MAGIC[] = "EPK2";

enum {
	NO_OF_PEM_FILES = 2
};

enum {
	NO_OF_AES_KEYS = 5
};

struct pem_file_t PEM_FILES_SET[NO_OF_PEM_FILES] = { { "general_pub.pem" }, {
		"netflix_pub.pem" } };

struct aes_key_t AES_KEYS_SET[NO_OF_AES_KEYS] = {
		{ 0x2F, 0x2E, 0x2D, 0x2C, 0x2B, 0x2A, 0x29, 0x28, 0x17, 0x16, 0x15,
				0x14, 0x13, 0x12, 0x11, 0x10 }, { 0x21, 0x4B, 0xF3, 0xC1, 0x29,
				0x54, 0x7A, 0xF3, 0x1D, 0x32, 0xA5, 0xEC, 0xB4, 0x74, 0x21,
				0x92 }, { 0x1F, 0x1E, 0x1D, 0x1C, 0x1B, 0x1A, 0x19, 0x18, 0x07,
				0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 }, { 0x68, 0x56, 0xa0,
				0x48, 0x24, 0x75, 0xa8, 0xb4, 0x17, 0x28, 0xa3, 0x54, 0x74,
				0x81, 0x02, 0x03 }, { 0x4E, 0xE6, 0x62, 0xC7, 0xA2, 0xC0, 0x91,
				0x7F, 0x73, 0x28, 0xDE, 0x73, 0xA0, 0x83, 0x6C, 0x6B } };

struct pak2_header_t* getPakHeader(unsigned char *buff) {
	return (struct pak2_header_t *) buff;
}

struct epk2_header_t *get_epk2_header(unsigned char *buffer) {
	return (struct epk2_header_t*) (buffer);
}

void SWU_CryptoInit_PEM(char *configuration_dir, struct pem_file_t *pem_file) {
	OpenSSL_add_all_digests();

	ERR_load_CRYPTO_strings();

	char pem_file_name[1024] = "";

	strcat(pem_file_name, configuration_dir);
	strcat(pem_file_name, "/");
	strcat(pem_file_name, pem_file->PEM_FILE);

	//printf("pem file: %s\n", pem_file);

	FILE *pubKeyFile = fopen(pem_file->PEM_FILE, "r");

	if (pubKeyFile == NULL) {

		pubKeyFile = fopen(pem_file_name, "r");

		if (pubKeyFile == NULL) {
			printf("error: can't find PEM file %s\n", pem_file->PEM_FILE);
			exit(1);
		}
	}

	EVP_PKEY *gpPubKey = PEM_read_PUBKEY(pubKeyFile, NULL, NULL, NULL);

	_gpPubKey = gpPubKey;

	if (_gpPubKey == NULL) {
		printf("error: can't read PEM signature from file %s\n",
				pem_file->PEM_FILE);
		exit(1);
	}

	fclose(pubKeyFile);

	ERR_clear_error();

}

void SWU_CryptoInit_AES(struct aes_key_t *aes_key) {

	int size = 0x80;

	AES_set_decrypt_key(aes_key->AES_KEY, size, &_gdKeyImage);

	AES_set_encrypt_key(aes_key->AES_KEY, size, &_geKeyImage);

}

int _verifyImage(unsigned char *signature, unsigned int sig_len,
		unsigned char *image, unsigned int image_len) {

	return verifyImage(_gpPubKey, signature, sig_len, image, image_len);
}

/**
 * returns 1 on success and 0 otherwise
 */
int API_SWU_VerifyImage(unsigned char* buffer, unsigned int buflen) {

	return verifyImage(_gpPubKey, buffer, SIGNATURE_SIZE, buffer
			+ SIGNATURE_SIZE, buflen - SIGNATURE_SIZE);
}

void decryptImage(unsigned char* srcaddr, unsigned int len,
		unsigned char* dstaddr) {

	unsigned int remaining = len;

	unsigned int decrypted = 0;
	while (remaining >= AES_BLOCK_SIZE) {
		AES_decrypt(srcaddr, dstaddr, &_gdKeyImage);
		srcaddr += AES_BLOCK_SIZE;
		dstaddr += AES_BLOCK_SIZE;
		remaining -= AES_BLOCK_SIZE;
		decrypted++;
	}

	if (remaining != 0) {
		decrypted = decrypted * AES_BLOCK_SIZE;
		memcpy(dstaddr, srcaddr, remaining);
	}
}

void encryptImage(unsigned char* srcaddr, unsigned int len,
		unsigned char* dstaddr) {

	unsigned int remaining = len;

	while (remaining >= AES_BLOCK_SIZE) {

		AES_encrypt(srcaddr, dstaddr, &_gdKeyImage);
		srcaddr += AES_BLOCK_SIZE;
		dstaddr += AES_BLOCK_SIZE;
		remaining -= AES_BLOCK_SIZE;
	}
}

void API_SWU_DecryptImage(unsigned char* source, unsigned int len,
		unsigned char* destination) {

	unsigned char *srcaddr = source + SIGNATURE_SIZE;

	unsigned char *dstaddr = destination;

	unsigned int remaining = len - SIGNATURE_SIZE;

	decryptImage(srcaddr, remaining, dstaddr);
}

int verifyImage(EVP_PKEY *key, unsigned char *signature, unsigned int sig_len,
		unsigned char *image, unsigned int image_len) {

	unsigned char *md_value;
	unsigned int md_len = 0;

	const EVP_MD *sha1Digest = EVP_get_digestbyname("sha1");

	md_value = malloc(0x40);

	EVP_MD_CTX ctx1, ctx2;

	EVP_DigestInit(&ctx1, sha1Digest);

	EVP_DigestUpdate(&ctx1, image, image_len);

	EVP_DigestFinal(&ctx1, md_value, &md_len);

	EVP_DigestInit(&ctx2, EVP_sha1());

	EVP_DigestUpdate(&ctx2, md_value, md_len);

	int result = EVP_VerifyFinal(&ctx2, signature, sig_len, key);

	EVP_MD_CTX_cleanup(&ctx1);

	EVP_MD_CTX_cleanup(&ctx2);

	free(md_value);

	return result;

}

pak_type_t SWU_UTIL_GetPakType(unsigned char* buffer) {

	return get_pak_type(buffer);
}

int SWU_Util_GetFileType(unsigned char* buffer) {
	int pakType = SWU_UTIL_GetPakType(buffer);

	pakType = pakType ^ 0x42;

	return pakType;
}

void print_epk2_header(struct epk2_header_t *epakHeader) {
	printf("firmware format: %.*s\n", 4, epakHeader->_04_fw_format);
	printf("firmware type: %s\n", epakHeader->_06_fw_type);
	printf("firmware version: %02x.%02x.%02x.%02x\n",
			epakHeader->_05_fw_version[3], epakHeader->_05_fw_version[2],
			epakHeader->_05_fw_version[1], epakHeader->_05_fw_version[0]);
	printf("contained mtd images: %d\n", epakHeader->_03_pak_count);
	printf("images size: %d\n", epakHeader->_02_file_size);
	printf("header length: %d\n\n", epakHeader->_07_header_length);
}

void print_pak2_info(struct pak2_t* pak) {
	printf("pak '%s' contains %d chunk(s).\n", get_pak_type_name(pak->type),
			pak->chunk_count);

	int pak_chunk_index = 0;
	for (pak_chunk_index = 0; pak_chunk_index < pak->chunk_count; pak_chunk_index++) {
		struct pak2_chunk_t *pak_chunk = pak->chunks[pak_chunk_index];

		int header_size = sizeof(struct pak2_chunk_header_t);

		unsigned char *decrypted = malloc(header_size);

		decryptImage(pak_chunk->header->_00_signature, header_size, decrypted);

		//hexdump(decrypted, header_size);

		struct pak2_chunk_header_t* decrypted_chunk_header =
				(struct pak2_chunk_header_t*) decrypted;

		pak_type_t pak_type = get_pak_type(
				decrypted_chunk_header->_01_type_code);

		if (pak_type == UNKNOWN) {
			printf(
					"FATAL: can't decrypt pak chunk. probably it's decrypted with an unknown key. aborting now. sorry.\n");
			exit(EXIT_FAILURE);
		}

		char chunk_version[20];

		get_pak2_version_string(chunk_version,
				decrypted_chunk_header->_05_version);

		printf("  chunk #%u (type='%.*s', version='%s') contains %u bytes\n",
				pak_chunk_index + 1, 4, get_pak_type_name(pak_type),
				chunk_version, pak_chunk->content_len);

		free(decrypted);
	}
}

void AES_key_lookup(struct pak2_t* pak) {

	int header_size = sizeof(struct pak2_chunk_header_t);

	unsigned char *decrypted = malloc(header_size);

	int aes_key_index = 0;

	for (aes_key_index = 0; aes_key_index < NO_OF_AES_KEYS; aes_key_index++) {

		struct aes_key_t *aes_key = &AES_KEYS_SET[aes_key_index];

		SWU_CryptoInit_AES(aes_key);

		printf("trying known AES key #%d / %d for pak chunk decryption...",
				aes_key_index + 1, NO_OF_AES_KEYS);

		struct pak2_chunk_t *pak_chunk = pak->chunks[0];

		decryptImage(pak_chunk->header->_00_signature, header_size, decrypted);

		struct pak2_chunk_header_t* decrypted_chunk_header =
				(struct pak2_chunk_header_t*) decrypted;

		//hexdump(decrypted, 16);

		pak_type_t pak_type = get_pak_type(
				decrypted_chunk_header->_01_type_code);

		if (pak_type != UNKNOWN) {

			free(decrypted);

			printf("success!\n");

			return;
		} else {

			printf("failed\n");

		}
	}

	free(decrypted);

	printf(
			"\nFATAL: can't decrypt pak. probably it's decrypted with an unknown key. aborting now. sorry.\n");
	exit(EXIT_FAILURE);

}

void scan_pak_chunks(struct epk2_header_t *epak_header,
		struct pak2_t **pak_array) {

	unsigned char *epak_offset = epak_header->_00_signature;

	unsigned char *pak_header_offset = epak_offset
			+ sizeof(struct epk2_header_t);

	struct pak2_chunk_header_t *pak_chunk_header =
			(struct pak2_chunk_header_t*) ((epak_header->_01_epak_magic)
					+ (epak_header->_07_header_length));

	// it contains the added lengths of signature data
	unsigned int signature_sum = sizeof(epak_header->_00_signature)
			+ sizeof(pak_chunk_header->_00_signature);

	unsigned int pak_chunk_signature_length =
			sizeof(pak_chunk_header->_00_signature);

	int count = 0;

	int next_pak_length = epak_header->_02_file_size;
	while (count < epak_header->_03_pak_count) {
		struct pak2_header_t *pak_header = getPakHeader(pak_header_offset);

		pak_type_t pak_type = get_pak_type(pak_header->_01_type_code);

		struct pak2_t *pak = malloc(sizeof(struct pak2_t));

		pak_array[count] = pak;

		pak->type = pak_type;
		pak->header = pak_header;
		pak->chunk_count = 0;
		pak->chunks = NULL;

		int verified = 0;

		struct pak2_chunk_header_t *next_pak_offset =
				(struct pak2_chunk_header_t*) (epak_offset
						+ pak_header->_04_next_pak_file_offset + signature_sum);

		unsigned int distance_between_paks =
				((int) next_pak_offset->_01_type_code)
						- ((int) pak_chunk_header->_01_type_code);

		// last contained pak...
		if ((count == (epak_header->_03_pak_count - 1))) {
			distance_between_paks = next_pak_length
					+ pak_chunk_signature_length;
		}

		unsigned int max_distance = MAX_PAK_CHUNK_SIZE
				+ sizeof(struct pak2_chunk_header_t);

		while (verified != 1) {

			unsigned int pak_chunk_length = distance_between_paks;

			bool is_next_chunk_needed = FALSE;

			if (pak_chunk_length > max_distance) {
				pak_chunk_length = max_distance;
				is_next_chunk_needed = TRUE;
			}

			unsigned int signed_length = next_pak_length;

			if (signed_length > max_distance) {
				signed_length = max_distance;
			}

			if (count == 0) {
				signed_length = pak_chunk_length;
			}

			if (verified != 1 && (verified = API_SWU_VerifyImage(
					pak_chunk_header->_00_signature, signed_length)) != 1) {
				printf(
						"verify pak chunk #%u of %s failed (size=0x%x). trying fallback...\n",
						pak->chunk_count + 1, get_pak_type_name(pak->type),
						signed_length);

				//hexdump(pak_chunk_header->_01_type_code, 0x80);

				while (((verified = API_SWU_VerifyImage(
						pak_chunk_header->_00_signature, signed_length)) != 1)
						&& (signed_length > 0)) {
					signed_length--;
					//printf(	"probe with size: 0x%x\n", signed_length);
				}

				if (verified) {
					printf("successfull verified with size: 0x%x\n",
							signed_length);
				} else {
					printf("fallback failed. sorry, aborting now.\n");
					exit(1);
				}
			}

			// sum signature lengths
			signature_sum += pak_chunk_signature_length;

			unsigned int pak_chunk_content_length = (pak_chunk_length
					- pak_chunk_signature_length);

			if (is_next_chunk_needed) {
				distance_between_paks -= pak_chunk_content_length;
				next_pak_length -= pak_chunk_content_length;
				verified = 0;

			} else {
				next_pak_length = pak_header->_05_next_pak_length
						+ pak_chunk_signature_length;
			}

			pak->chunk_count++;

			pak->chunks = realloc(pak->chunks, pak->chunk_count
					* sizeof(struct pak2_chunk_t*));

			struct pak2_chunk_t *pak_chunk =
					malloc(sizeof(struct pak2_chunk_t));

			pak_chunk->header = pak_chunk_header;
			pak_chunk->content = pak_chunk_header->_11_unknown4
					+ (sizeof(pak_chunk_header->_11_unknown4));

			pak_chunk->content_file_offset = pak_chunk->content - epak_offset;

			pak_chunk->content_len = signed_length
					- sizeof(struct pak2_chunk_header_t);

			pak->chunks[pak->chunk_count - 1] = pak_chunk;

			// move pointer to the next pak chunk offset
			pak_chunk_header
					= (struct pak2_chunk_header_t *) (pak_chunk_header->_00_signature
							+ pak_chunk_length);
		}

		pak_header_offset += sizeof(struct pak2_header_t);

		count++;
	}
}

int write_pak_chunks(struct pak2_t *pak, const char *filename) {
	int length = 0;

	FILE *outfile = fopen(((const char*) filename), "w");

	int pak_chunk_index;
	for (pak_chunk_index = 0; pak_chunk_index < pak->chunk_count; pak_chunk_index++) {
		struct pak2_chunk_t *pak_chunk = pak->chunks[pak_chunk_index];

		int content_len = pak_chunk->content_len;
		unsigned char* decrypted = malloc(content_len);
		memset(decrypted, 0xFF, content_len);
		decryptImage(pak_chunk->content, content_len, decrypted);
		fwrite(decrypted, 1, content_len, outfile);

		free(decrypted);

		length += content_len;
	}

	fclose(outfile);

	return length;
}

int is_epk2(char *buffer) {
	struct epk2_header_t *epak_header = get_epk2_header(buffer);

	return !memcmp(epak_header->_04_fw_format, EPK2_MAGIC, 4);
}

int is_epk2_file(const char *epk_file) {

	FILE *file = fopen(epk_file, "r");

	if (file == NULL) {
		printf("Can't open file %s", epk_file);
		exit(1);
	}

	size_t header_size = sizeof(struct epk2_header_t);

	unsigned char* buffer = (unsigned char*) malloc(sizeof(char) * header_size);

	int read = fread(buffer, 1, header_size, file);

	if (read != header_size) {
		return 0;
	}

	fclose(file);

	int result = is_epk2(buffer);

	free(buffer);

	return result;
}

void get_pak_version_string(char *fw_version, unsigned char version[4]) {
	sprintf(fw_version, "%02x.%02x.%02x.%02x", version[3], version[2],
			version[1], version[0]);
}

void get_version_string(char *fw_version, struct epk2_header_t *epak_header) {
	sprintf(fw_version, "%02x.%02x.%02x.%02x-%s",
			epak_header->_05_fw_version[3], epak_header->_05_fw_version[2],
			epak_header->_05_fw_version[1], epak_header->_05_fw_version[0],
			epak_header->_06_fw_type);
}

void get_pak2_version_string(char *fw_version, char *ptr) {
	sprintf(fw_version, "%02x.%02x.%02x.%02x", ptr[3], ptr[2], ptr[1], ptr[0]);
}

void extract_epk2_file(const char *epk_file, struct config_opts_t *config_opts) {

	FILE *file = fopen(epk_file, "r");

	if (file == NULL) {
		printf("Can't open file %s", epk_file);
		exit(1);
	}

	fseek(file, 0, SEEK_END);

	int fileLength;

	fileLength = ftell(file);

	rewind(file);

	unsigned char* buffer = (unsigned char*) malloc(sizeof(char) * fileLength);

	int read = fread(buffer, 1, fileLength, file);

	if (read != fileLength) {
		printf("error reading file. read %d bytes from %d.\n", read, fileLength);
		exit(1);
	}

	fclose(file);

	if (!is_epk2(buffer)) {
		printf("unsupported file type. aborting.\n");
		exit(1);
	}

	struct epk2_header_t *epak_header = get_epk2_header(buffer);

	printf("firmware info\n");
	printf("-------------\n");
	printf("file size: %d bytes\n", read);
	print_epk2_header(epak_header);

	int verified = 0;
	int pem_file_index = 0;
	for (pem_file_index = 0; pem_file_index < NO_OF_PEM_FILES; pem_file_index++) {
		if (verified == 1)
			break;
		struct pem_file_t *pem_file = &PEM_FILES_SET[pem_file_index];

		SWU_CryptoInit_PEM(config_opts->config_dir, pem_file);

		printf("probing signature file: %s ...\n", pem_file->PEM_FILE);

		verified = API_SWU_VerifyImage(buffer, epak_header->_07_header_length
				+ SIGNATURE_SIZE);

		if (verified == 1) {

			printf(
					"firmware was successfully verified by it's digital signature.\n");
		} else {
			int size = epak_header->_07_header_length;

			while (size > 0) {
				size -= 1;

				verified = API_SWU_VerifyImage(buffer, size + SIGNATURE_SIZE);
				if (verified == 1) {

					printf(
							"firmware was successfully verified by it's digital signature. signed bytes: %d\n\n",
							size);
					break;
				}
			}

		}
	}

	if (verified != 1) {
		printf(
				"firmware package can't be verified by it's digital signature. aborting.\n");
		exit(1);
	}

	struct pak2_t **pak_array = malloc((epak_header->_03_pak_count)
			* sizeof(struct pak2_t*));

	scan_pak_chunks(epak_header, pak_array);

	int last_pak_index = epak_header->_03_pak_count - 1;

	struct pak2_t *last_pak = pak_array[last_pak_index];

	int pak_chunk_index = last_pak->chunk_count - 1;
	struct pak2_chunk_t *last_pak_chunk = last_pak->chunks[pak_chunk_index];

	int last_extracted_file_offset = (last_pak_chunk->content_file_offset
			+ last_pak_chunk->content_len);

	printf("last extracted file offset: %d\n\n", last_extracted_file_offset);
	char version_string[1024];
	get_version_string(version_string, epak_header);

	char target_dir[1024];
	memset(target_dir, 0, 1024);

	construct_path(target_dir, config_opts->dest_dir, version_string, NULL);
	create_dir_if_not_exist(target_dir);

	AES_key_lookup(pak_array[0]);

	int pak_index;
	for (pak_index = 0; pak_index < epak_header->_03_pak_count; pak_index++) {
		struct pak2_t *pak = pak_array[pak_index];

		if (pak->type == UNKNOWN) {
			printf(
					"WARNING!! firmware file contains unknown pak type '%.*s'. ignoring it!\n",
					4, pak->header->_01_type_code);
			continue;
		}

		print_pak2_info(pak);

		const char *pak_type_name = get_pak_type_name(pak->type);

		char filename[1024] = "";
		construct_path(filename, target_dir, pak_type_name, ".image");

		printf("saving content of pak #%u/%u (%s) to file %s\n", pak_index + 1,
				epak_header->_03_pak_count, pak_type_name, filename);

		int length = write_pak_chunks(pak, filename);

		handle_extracted_image_file(filename, target_dir, pak_type_name);
	}

	printf("extraction succeeded\n");

}

