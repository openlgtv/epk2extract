#include <epk2.h>
#include <crc.h>

EVP_PKEY *_gpPubKey;
AES_KEY _gdKeyImage, _geKeyImage;
const int MAX_PAK_CHUNK_SIZE = 0x400000;
const char PEM_FILE[] = "general_pub.pem";
const char EPK2_MAGIC[] = "EPK2";

const int key_count = 2;

enum {
	KEYSET_COUNT = 2
};
struct keyset_t KEY_SETS[KEYSET_COUNT] = { { "general_pub.pem", { 0x2f, 0x2e,
		0x2d, 0x2c, 0x2b, 0x2a, 0x29, 0x28, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12,
		0x11, 0x10 } }, { "netflix_pub.pem", { 0x1F, 0x1E, 0x1D, 0x1C, 0x1B,
		0x1A, 0x19, 0x18, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 } } };

struct pak2_header_t* getPakHeader(unsigned char *buff) {
	return (struct pak2_header_t *) buff;
}

struct epk2_header_t *get_epk2_header(unsigned char *buffer) {
	return (struct epk2_header_t*) (buffer);
}

void SWU_CryptoInit(char *configuration_dir, struct keyset_t *keyset) {
	OpenSSL_add_all_digests();

	ERR_load_CRYPTO_strings();

	char pem_file[1024] = "";

	strcat(pem_file, configuration_dir);
	strcat(pem_file, "/");
	strcat(pem_file, keyset->PEM_FILE);

	//printf("pem file: %s\n", pem_file);

	FILE *pubKeyFile = fopen(keyset->PEM_FILE, "r");

	if (pubKeyFile == NULL) {

		pubKeyFile = fopen(pem_file, "r");

		if (pubKeyFile == NULL) {
			printf("error: can't find PEM file %s\n",
					keyset->PEM_FILE);
			exit(1);
		}
	}

	EVP_PKEY *gpPubKey = PEM_read_PUBKEY(pubKeyFile, NULL, NULL, NULL);

	_gpPubKey = gpPubKey;

	if(_gpPubKey == NULL) {
		printf("error: can't read PEM file %s\n",
							keyset->PEM_FILE);
		exit(1);
	}

	fclose(pubKeyFile);

	ERR_clear_error();

	int size = 0x80;

	AES_set_decrypt_key(keyset->AES_KEY, size, &_gdKeyImage);

	AES_set_encrypt_key(keyset->AES_KEY, size, &_geKeyImage);
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
	printf("images size: %d\n\n", epakHeader->_02_file_size);
}

void print_pak2_info(struct pak2_t* pak) {
	printf("pak '%s' contains %d chunk(s).\n", get_pak_type_name(pak->type),
			pak->chunk_count);

	int pak_chunk_index = 0;
	for (pak_chunk_index = 0; pak_chunk_index < pak->chunk_count; pak_chunk_index++) {
		struct pak2_chunk_t *pak_chunk = pak->chunks[pak_chunk_index];

		int header_size = sizeof(struct pak2_chunk_header_t)
				- sizeof(pak_chunk->header->_00_signature);

		unsigned char *decrypted = malloc(header_size);

		decryptImage(pak_chunk->header->_01_type_code, header_size, decrypted);

//		char version_string[1024];
//		get_pak_version_string(version_string, decrypted);
//
//		printf(	"version: %s\n", version_string);
//
		//hexdump(decrypted, header_size);

		pak_type_t pak_type = get_pak_type(decrypted);

		if (pak_type == UNKNOWN) {
			printf(
					"FATAL: can't decrypt pak chunk. probably it's decrypted with an unknown key. aborting now. sorry.\n");
			exit(EXIT_FAILURE);
		}

		printf("  chunk #%u ('%.*s') contains %u bytes\n", pak_chunk_index + 1,
				4, get_pak_type_name(pak_type), pak_chunk->content_len);

		free(decrypted);
	}
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

			if ((verified = API_SWU_VerifyImage(
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
			pak_chunk->content = pak_chunk_header + sizeof(pak_chunk_header);

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
	sprintf(fw_version, "%02x.%02x.%02x.%02x",
			version[3], version[2],
			version[1], version[0]);
}

void get_version_string(char *fw_version, struct epk2_header_t *epak_header) {
	sprintf(fw_version, "%02x.%02x.%02x.%02x-%s",
			epak_header->_05_fw_version[3], epak_header->_05_fw_version[2],
			epak_header->_05_fw_version[1], epak_header->_05_fw_version[0],
			epak_header->_06_fw_type);
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
	print_epk2_header(epak_header);

	int verified = 0;
	int keyset_index = 0;
	for (keyset_index = 0; keyset_index < KEYSET_COUNT; keyset_index++) {
		if (verified == 1)
			break;
		SWU_CryptoInit(config_opts->config_dir, &KEY_SETS[keyset_index]);

		verified = API_SWU_VerifyImage(buffer, epak_header->_07_header_length
				+ SIGNATURE_SIZE);

	}

	if (verified != 1) {
		printf(
				"firmware package can't be verified by it's digital signature. aborting.\n");
		exit(1);
	}

	struct pak2_t **pak_array = malloc((epak_header->_03_pak_count)
			* sizeof(struct pak2_t*));

	scan_pak_chunks(epak_header, pak_array);

	char version_string[1024];
	get_version_string(version_string, epak_header);

	char target_dir[1024];
	construct_path(target_dir, config_opts->dest_dir, version_string, NULL);

	create_dir_if_not_exist(target_dir);

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

