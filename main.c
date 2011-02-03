/*
 ============================================================================
 Name        : main.c
 Author      : sirius
 Copyright   : published under GPL
 Description : EPK2 firmware extractor for LG electronic digital tv's
 ============================================================================
 */

#define stringify( name ) # name

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

typedef int bool;
#define TRUE   (1)
#define FALSE  (0)
// signature verification  may be disabled while development
bool verify = TRUE;

const int PAK_ID_LENGTH = 5;

const int MAX_PAK_CHUNK_SIZE = 0x400000;
const char PEM_FILE[] = "general_pub.pem";

enum {
	MAX_PAK_CHUNKS = 0x10
};
enum {
	SIGNATURE_SIZE = 0x80
};

EVP_PKEY *_gpPubKey;
AES_KEY _gdKeyImage, _geKeyImage;

typedef enum {
	BOOT = 0x0,
	MTDI = 0x1,
	CRC3 = 0x2,
	ROOT = 0x3,
	LGIN = 0x4,
	MODE = 0x5,
	KERN = 0x6,
	LGAP = 0x7,
	LGRE = 0x8,
	LGFO = 0x9,
	ADDO = 0xA,
	ECZA = 0xB,
	RECD = 0xC,
	MICO = 0xD,
	SPIB = 0xE,
	SYST = 0xF,
	USER = 0x10,
	NETF = 0x11,
	IDFI = 0x12,
	LOGO = 0x13,
	OPEN = 0x14,
	YWED = 0x15,
	CMND = 0x16,
	NVRA = 0x17,
	PREL = 0x18,
	KIDS = 0x19,
	STOR = 0x1A,
	CERT = 0x1B,
	AUTH = 0x1C,
	ESTR = 0x1D,
	GAME = 0x1E,
	BROW = 0x1F,
	CE_F = 0x20,
	ASIG = 0x21,
	RESE = 0x22,
	EPAK = 0x23,
	UNKNOWN = 0x42,
} pak_type_t;

const char* pak_type_names[] = { stringify( BOOT ), stringify( MTDI ),
		stringify( CRC3 ), stringify( ROOT ), stringify( LGIN ),
		stringify( MODE ), stringify( KERN ), stringify( LGAP ),
		stringify( LGRE ), stringify( LGFO ), stringify( ADDO ),
		stringify( ECZA ), stringify( RECD ), stringify( MICO ),
		stringify( SPIB ), stringify( SYST ), stringify( USER ),
		stringify( NETF ), stringify( IDFI ), stringify( LOGO ),
		stringify( OPEN ), stringify( YWED ), stringify( CMND ),
		stringify( NVRA ), stringify( PREL ), stringify( KIDS ),
		stringify( STOR ), stringify( CERT ), stringify( AUTH ),
		stringify( ESTR ), stringify( GAME ), stringify( BROW ),
		stringify( CE_F ), stringify( ASIG ), stringify( RESE ),
		stringify( EPAK ), stringify( UNKNOWN ) };

struct epak_header_t {
	unsigned char _00_signature[SIGNATURE_SIZE];
	unsigned char _01_type_code[4];
	uint32_t _02_file_size;
	uint32_t _03_pak_count;
	unsigned char _04_fw_format[4];
	unsigned char _05_fw_version[4];
	unsigned char _06_fw_type[32];
	uint32_t _07_header_length;
	uint32_t _08_unknown;
};

struct pak_header_t {
	unsigned char _00_type_code[4];
	uint32_t _01_unknown1;
	uint32_t _02_unknown2;
	uint32_t _03_next_pak_file_offset;
	uint32_t _04_next_pak_length;
};

struct pak_chunk_header_t {
	unsigned char _00_signature[SIGNATURE_SIZE];
	unsigned char _01_type_code[4];
	unsigned char _02_unknown1[4];
	unsigned char _03_platform[15];
	unsigned char _04_unknown3[105];
};

struct pak_chunk_t {
	struct pak_chunk_header_t *header;
	unsigned char *content;
	int content_len;
};

struct pak_t {
	pak_type_t type;
	struct pak_header_t *header;
	unsigned int chunk_count;
	struct pak_chunk_t **chunks;
};

struct cramfs_header_t {
	unsigned char _00_unknown1[0x50];
	uint32_t _01_file_size;
};

struct pak_header_t* getPakHeader(unsigned char *buff) {
	return (struct pak_header_t *) buff;
}
;

pak_type_t convertToPakType(unsigned char type[4]) {

	uint32_t byte1 = type[0];
	uint32_t byte2 = type[1];
	uint32_t byte3 = type[2];
	uint32_t byte4 = type[3];

	byte1 = byte1 << 24;
	byte4 = byte4 | byte1;
	byte2 = byte2 << 16;
	byte4 = byte4 | byte2;
	byte3 = byte3 << 8;

	uint32_t result = byte4 | byte3;

	switch (result) {
	case 0x6C67666F:
		return LGFO;
	case 0x63726333:
		return CRC3;
	case 0x626F6F74:
		return BOOT;
	case 0x61736967:
		return ASIG;
	case 0x61757468:
		return AUTH;
	case 0x6164646F:
		return ADDO;
	case 0x62726F77:
		return BROW;
	case 0x63655F66:
		return CE_F;
	case 0x67616D65:
		return GAME;
	case 0x6B65726E:
		return KERN;
	case 0x6B696473:
		return KIDS;
	case 0x6C676170:
		return LGAP;
	case 0x69646669:
		return IDFI;
	case 0x65737472:
		return ESTR;
	case 0x657A6361:
		return ECZA;
	case 0x6570616B:
		return EPAK;
	case 0x6F70656E:
		return OPEN;
		// for backward compatibility with older fw ('opsr' -> 'open')
	case 0x6F707372:
		return OPEN;
	case 0x6D69636F:
		return MICO;
	case 0x6C677265:
		return LGRE;
	case 0x6C6F676F:
		return LOGO;
	case 0x6C67696E:
		return LGIN;
	case 0x6D746469:
		return MTDI;
	case 0x6E657466:
		return NETF;
	case 0x6E767261:
		return NVRA;
	case 0x6D6F6465:
		return MODE;
	case 0x73706962:
		return SPIB;
	case 0x72656364:
		return RECD;
	case 0x72657365:
		return RESE;
	case 0x726F6F74:
		return ROOT;
	case 0x7072656C:
		return PREL;
	case 0x73797374:
		return SYST;
	case 0x75736572:
		return USER;
	case 0x79776564:
		return YWED;
	case 0x73746F72:
		return STOR;
	case 0x63657274:
		return CERT;
	default:
		return UNKNOWN;
	}

}

const char* getPakName(unsigned int pakType) {
	const char *pak_type_name = pak_type_names[pakType];

	char *result = malloc(PAK_ID_LENGTH);

	result[0] = tolower(pak_type_name[0]);
	result[1] = tolower(pak_type_name[1]);
	result[2] = tolower(pak_type_name[2]);
	result[3] = tolower(pak_type_name[3]);
	result[4] = 0;

	return result;
}

void SWU_CryptoInit() {
	OpenSSL_add_all_digests();

	ERR_load_CRYPTO_strings();

	FILE *pubKeyFile = fopen(PEM_FILE, "r");

	if (pubKeyFile == NULL) {
		printf("error: can't open PEM file %s from current directory.\n",
				PEM_FILE);
		exit(1);
	}

	_gpPubKey = PEM_read_PUBKEY(pubKeyFile, NULL, NULL, NULL);

	fclose(pubKeyFile);

	ERR_clear_error();

	unsigned char AES_KEY[16] = { 0x2f, 0x2e, 0x2d, 0x2c, 0x2b, 0x2a, 0x29,
			0x28, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10 };

	int size = 0x80;

	AES_set_decrypt_key(AES_KEY, size, &_gdKeyImage);

	AES_set_encrypt_key(AES_KEY, size, &_geKeyImage);
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

int SSU_OadFileScan(const char* buffer) {

	int32_t byte0 = buffer[0];
	int32_t byte1 = buffer[1];
	int32_t byte2 = buffer[2];
	int32_t byte3 = buffer[3];

	byte0 = byte0 << 24;
	byte1 = byte1 << 16;
	byte2 = byte2 << 8;

	byte1 = byte1 | byte3;
	byte1 = byte1 | byte0;
	byte1 = byte1 | byte2;

	if (byte1 == 0x42494F50) {
		return 1;
	} else {
		return -1;
	}
}

uint32_t get_big_endian(const unsigned char* buffer) {

	uint32_t byte0 = buffer[0];
	uint32_t byte1 = buffer[1];
	uint32_t byte2 = buffer[2];
	uint32_t byte3 = buffer[3];

	byte3 = byte3 << 24;
	byte0 = byte0 | byte3;
	byte2 = byte2 << 16;
	byte0 = byte0 | byte2;
	byte1 = byte1 << 8;

	return byte0 | byte1;
}

pak_type_t SWU_UTIL_GetPakType(unsigned char* buffer) {

	return convertToPakType(buffer);
}

int SWU_Util_GetFileType(unsigned char* buffer) {
	int pakType = SWU_UTIL_GetPakType(buffer);

	pakType = pakType ^ 0x42;

	return pakType;
}

void scanPAKs(struct epak_header_t *epak_header, struct pak_t **pak_array) {

	unsigned char *epak_offset = epak_header->_00_signature;

	unsigned char *pak_header_offset = epak_offset
			+ sizeof(struct epak_header_t);

	struct pak_chunk_header_t *pak_chunk_header =
			(struct pak_chunk_header_t*) ((epak_header->_01_type_code)
					+ (epak_header->_07_header_length));

	// it contains the added lengths of signature data
	unsigned int signature_sum = sizeof(epak_header->_00_signature)
			+ sizeof(pak_chunk_header->_00_signature);

	unsigned int pak_chunk_signature_length =
			sizeof(pak_chunk_header->_00_signature);

	int count = 0;

	int current_pak_length = -1;
	while (count < epak_header->_03_pak_count) {
		struct pak_header_t *pak_header = getPakHeader(pak_header_offset);

		pak_type_t pak_type = convertToPakType(pak_header->_00_type_code);

		struct pak_t *pak = malloc(sizeof(struct pak_t));

		pak_array[count] = pak;

		pak->type = pak_type;
		pak->header = pak_header;
		pak->chunk_count = 0;
		pak->chunks = NULL;

		int verified = 0;

		struct pak_chunk_header_t *next_pak_offset =
				(struct pak_chunk_header_t*) (epak_offset
						+ pak_header->_03_next_pak_file_offset + signature_sum);

		unsigned int distance_between_paks =
				((int) next_pak_offset->_01_type_code)
						- ((int) pak_chunk_header->_01_type_code);

		// last contained pak...
		if ((count == (epak_header->_03_pak_count - 1))) {
			distance_between_paks = current_pak_length
					+ pak_chunk_signature_length;
		}

		unsigned int max_distance = MAX_PAK_CHUNK_SIZE
				+ sizeof(struct pak_chunk_header_t);

		while (verified != 1) {

			unsigned int pak_chunk_length = distance_between_paks;

			bool is_next_chunk_needed = FALSE;

			if (pak_chunk_length > max_distance) {
				pak_chunk_length = max_distance;
				is_next_chunk_needed = TRUE;
			}

			unsigned int signed_length = current_pak_length;

			if (signed_length > max_distance) {
				signed_length = max_distance;
			}

			if (current_pak_length < 0) {
				signed_length = pak_chunk_length;
			}

			if (verify) {
				if ((verified = API_SWU_VerifyImage(
						pak_chunk_header->_00_signature, signed_length)) != 1) {
					printf(
							"verify pak chunk #%u of %s failed (size=0x%x). trying fallback...\n",
							pak->chunk_count + 1, getPakName(pak->type),
							signed_length);

					//hexdump(pak_chunk_header->_01_type_code, 0x80);

					while (((verified = API_SWU_VerifyImage(
							pak_chunk_header->_00_signature, signed_length))
							!= 1) && (signed_length > 0)) {
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
			} else {
				verified = 1;
			}

			// sum signature lengths
			signature_sum += pak_chunk_signature_length;

			unsigned int pak_chunk_content_length = (pak_chunk_length
					- pak_chunk_signature_length);

			if (is_next_chunk_needed) {
				distance_between_paks -= pak_chunk_content_length;
				current_pak_length -= pak_chunk_content_length;
				verified = 0;

			} else {
				current_pak_length = pak_header->_04_next_pak_length
						+ pak_chunk_signature_length;
			}

			pak->chunk_count++;

			pak->chunks = realloc(pak->chunks, pak->chunk_count
					* sizeof(struct pak_chunk_t*));

			struct pak_chunk_t *pak_chunk = malloc(sizeof(struct pak_chunk_t));

			pak_chunk->header = pak_chunk_header;
			pak_chunk->content = pak_chunk_header->_04_unknown3
					+ sizeof(pak_chunk_header->_04_unknown3);

			pak_chunk->content_len = signed_length
					- sizeof(struct pak_chunk_header_t);

			pak->chunks[pak->chunk_count - 1] = pak_chunk;

			// move pointer to the next pak chunk offset
			pak_chunk_header
					= (struct pak_chunk_header_t *) (pak_chunk_header->_00_signature
							+ pak_chunk_length);
		}

		pak_header_offset += sizeof(struct pak_header_t);

		count++;
	}
}

struct epak_header_t *getEPakHeader(unsigned char *buffer) {
	return (struct epak_header_t*) (buffer);
}

void printEPakHeader(struct epak_header_t *epakHeader) {
	printf("firmware format: %.*s\n", 4, epakHeader->_04_fw_format);
	printf("firmware type: %s\n", epakHeader->_06_fw_type);
	printf("firmware version: %02x.%02x.%02x.%02x\n",
			epakHeader->_05_fw_version[3], epakHeader->_05_fw_version[2],
			epakHeader->_05_fw_version[1], epakHeader->_05_fw_version[0]);
	printf("contained mtd images: %d\n", epakHeader->_03_pak_count);
	printf("images size: %d\n", epakHeader->_02_file_size);
}

void printPakInfo(struct pak_t* pak) {
	printf("pak '%s' contains %d chunk(s).\n", getPakName(pak->type),
			pak->chunk_count);

	int pak_chunk_index = 0;
	for (pak_chunk_index = 0; pak_chunk_index < pak->chunk_count; pak_chunk_index++) {
		struct pak_chunk_t *pak_chunk = pak->chunks[pak_chunk_index];

		unsigned char *decrypted = malloc(AES_BLOCK_SIZE);

		decryptImage(pak_chunk->header->_01_type_code, AES_BLOCK_SIZE,
				decrypted);

		pak_type_t pak_type = convertToPakType(decrypted);

		printf("  chunk #%u ('%.*s') contains %u bytes\n", pak_chunk_index + 1,
				4, getPakName(pak_type), pak_chunk->content_len);

		free(decrypted);
	}
}

char *appendFilenameToDir(const char *directory, const char *filename) {
	int len = sizeof(directory) + sizeof("/") + sizeof(filename) + 10;
	char *result = malloc(len);
	memset(result, 0, len);
	strcat(result, "./");
	strcat(result, directory);
	strcat(result, "/");
	strcat(result, filename);

	return result;
}

char* getFwVersionString(struct epak_header_t *epak_header) {
	char *fw_version = malloc(0x10);

	sprintf(fw_version, "%02x.%02x.%02x.%02x", epak_header->_05_fw_version[3],
			epak_header->_05_fw_version[2], epak_header->_05_fw_version[1],
			epak_header->_05_fw_version[0]);

	return fw_version;
}

void createDirIfNotExist(const char *directory) {
	struct stat st;
	if (stat(directory, &st) != 0) {
		if (mkdir((const char*) directory, 0744) != 0) {
			printf("Can't create directory %s within current directory",
					directory);
			exit(1);
		}
	}
}

void writePakChunks(struct pak_t *pak, const char *filename) {
	FILE *outfile = fopen(((const char*) filename), "w");

	int pak_chunk_index;
	for (pak_chunk_index = 0; pak_chunk_index < pak->chunk_count; pak_chunk_index++) {
		struct pak_chunk_t *pak_chunk = pak->chunks[pak_chunk_index];

		int content_len = pak_chunk->content_len;
		unsigned char* decrypted = malloc(content_len);
		memset(decrypted, 0xFF, content_len);
		decryptImage(pak_chunk->content, content_len, decrypted);
		fwrite(decrypted, 1, content_len, outfile);

		free(decrypted);
	}

	fclose(outfile);
}

void extractRELEASE(const char *cramfs_image, const char *destination) {
	FILE *cramfs = fopen(cramfs_image, "rb");

	if (cramfs == NULL) {
		printf("Can't open file %s\n", cramfs_image);
		exit(1);
	}

	FILE *release = fopen(destination, "wb");

	if (release == NULL) {
		printf("Can't open file RELEASE\n");
		exit(1);
	}

	chmod(destination, 00744);

	int buf_len = 0x1000;
	char buffer[buf_len];

	fread(buffer, 1, buf_len, cramfs);

	struct cramfs_header_t *cramfs_header =
			(struct cramfs_header_t *) buffer;

	uint32_t release_size = cramfs_header->_01_file_size;

	// correct the size by changing most significant byte from 0xc9 to 0x1
	release_size -= 0xc8000000;

	printf(
			"extracting XIPed RELEASE executable from cramfs image to %s\n",
			destination);

	int end_pos = release_size;
	int count = 0;
	while (count < end_pos) {
		int diff = end_pos - count;
		if (diff < buf_len)
			buf_len = diff;
		size_t read = fread(buffer, 1, buf_len, cramfs);
		size_t written = fwrite(buffer, 1, read, release);
		count += written;
	}

	fclose(cramfs);
	fclose(release);
}

int main(int argc, char *argv[]) {

	printf("LG electronics digital tv firmware EPK2 extractor\n");
	printf("Version 0.6dev by sirius (openlgtv.org.ru) 31/01/2011\n\n");

	SWU_CryptoInit();

	char *current_dir = getcwd(NULL, 0);

	printf("current directory: %s\n\n", current_dir);

	if (argc < 2) {

		printf("\n");
		printf("usage: %s FILENAME\n", argv[0]);
		exit(1);
	}

	char *epk_file = argv[1];

	printf("firmware info\n");
	printf("-------------\n");
	printf("firmware file: %s\n", epk_file);

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

	printf("read %d bytes from %d.\n", read, fileLength);

	fclose(file);

	struct epak_header_t *epak_header = getEPakHeader(buffer);

	printEPakHeader(epak_header);

	int verified = API_SWU_VerifyImage(buffer, epak_header->_07_header_length
			+ SIGNATURE_SIZE);

	if (verify && verified != 1) {
		printf(
				"firmware package can't be verified by it's digital signature.\n");
		exit(1);
	}

	struct pak_t **pak_array = malloc((epak_header->_03_pak_count)
			* sizeof(struct pak_t*));

	scanPAKs(epak_header, pak_array);

	char *fw_version = getFwVersionString(epak_header);

	createDirIfNotExist(fw_version);

	int pak_index;
	for (pak_index = 0; pak_index < epak_header->_03_pak_count; pak_index++) {
		struct pak_t *pak = pak_array[pak_index];

		if (pak->type == UNKNOWN) {
			printf(
					"WARNING!! firmware file contains unknown pak type '%.*s'. ignoring it!\n",
					4, pak->header->_00_type_code);
			continue;
		}

		printPakInfo(pak);

		const char *pak_type_name = getPakName(pak->type);

		char filename[100] = "";

		sprintf(filename, "./%s/%s.image", fw_version, pak_type_name);

		printf("saving content of pak #%u/%u (%s) to file %s\n", pak_index + 1,
				epak_header->_03_pak_count, pak_type_name, filename);

		writePakChunks(pak, filename);

		if(check_lzo_header(filename) == 0) {
			char unpacked[100] = "";

			sprintf(unpacked, "./%s/%s.cramfs", fw_version, pak_type_name);

			printf("decompressing %s with modified LZO algorithm to %s\n",
								filename, unpacked);

			if (lzo_unpack((const char*) filename,	(const char*) unpacked) != 0) {
				printf("sorry. decompression failed. aborting now.\n");
				exit(1);
			}

			if ((pak->type == LGAP)) {

				char release[100] = "";
				sprintf(release, "./%s/RELEASE", fw_version);

				extractRELEASE(unpacked, release);
			}
		}
	}

	printf("extraction succeeded\n");

	return EXIT_SUCCESS;
}
