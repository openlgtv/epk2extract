#include <epk2.h>
#include <crc.h>
#include <dirent.h>

EVP_PKEY *_gpPubKey;
AES_KEY _gdKeyImage, _geKeyImage;
const char EPK2_MAGIC[] = "EPK2";

unsigned char aes_key[16];

struct pak2header_t* getPakHeader(unsigned char *buff) {
	return (struct pak2header_t *) buff;
}

struct epk2header_t *get_epk2header(unsigned char *buffer) {
	return (struct epk2header_t*) (buffer);
}

void SWU_CryptoInit_PEM(char *configuration_dir, char *pem_file) {
	OpenSSL_add_all_digests();
	ERR_load_CRYPTO_strings();
	char pem_file_name[1024] = "";
	strcat(pem_file_name, configuration_dir);
	strcat(pem_file_name, "/");
	strcat(pem_file_name, pem_file);
	FILE *pubKeyFile = fopen(pem_file_name, "r");
	if (pubKeyFile == NULL) {
		printf("Error: Can't open PEM file %s\n", pem_file);
		exit(1);
	}
	EVP_PKEY *gpPubKey = PEM_read_PUBKEY(pubKeyFile, NULL, NULL, NULL);
	_gpPubKey = gpPubKey;
	if (_gpPubKey == NULL) {
		printf("Error: Can't read PEM signature from file %s\n", pem_file);
		exit(1);
	}
	fclose(pubKeyFile);
	ERR_clear_error();
}

void SWU_CryptoInit_AES(const unsigned char* AES_KEY) {
	int size = 0x80;
	AES_set_decrypt_key(AES_KEY, size, &_gdKeyImage);
	AES_set_encrypt_key(AES_KEY, size, &_geKeyImage);
}

int _verifyImage(unsigned char *signature, unsigned int sig_len, unsigned char *image, unsigned int image_len) {
	return verifyImage(_gpPubKey, signature, sig_len, image, image_len);
}

int verifyImage(EVP_PKEY *key, unsigned char *signature, unsigned int sig_len, unsigned char *image, unsigned int image_len) {
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

int API_SWU_VerifyImage(unsigned char* buffer, unsigned int buflen) { // returns 1 on success and 0 otherwise
	return verifyImage(_gpPubKey, buffer, SIGNATURE_SIZE, buffer + SIGNATURE_SIZE, buflen);
}

void decryptImage(unsigned char* srcaddr, unsigned int len, unsigned char* dstaddr) {
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

void encryptImage(unsigned char* srcaddr, unsigned int len, unsigned char* dstaddr) {
	unsigned int remaining = len;
	while (remaining >= AES_BLOCK_SIZE) {
		AES_encrypt(srcaddr, dstaddr, &_gdKeyImage);
		srcaddr += AES_BLOCK_SIZE;
		dstaddr += AES_BLOCK_SIZE;
		remaining -= AES_BLOCK_SIZE;
	}
}

void API_SWU_DecryptImage(unsigned char* source, unsigned int len, unsigned char* destination) {
	unsigned char *srcaddr = source + SIGNATURE_SIZE;
	unsigned char *dstaddr = destination;
	unsigned int remaining = len - SIGNATURE_SIZE;
	decryptImage(srcaddr, remaining, dstaddr);
}

void printEPK2header(struct epk2header_t *epakHeader) {
	printf("Firmware magic: %.*s\n", 4, epakHeader->EPK2magic);
	printf("Firmware otaID: %s\n", epakHeader->otaID);
	printf("Firmware version: %02x.%02x.%02x.%02x\n", epakHeader->fwVersion[3], epakHeader->fwVersion[2], epakHeader->fwVersion[1], epakHeader->fwVersion[0]);
	printf("PAK count: %d\n", epakHeader->pakCount);
	printf("PAKs total size: %d\n", epakHeader->fileSize);
	printf("Header length: %d\n\n", epakHeader->headerLength);
}

void printPAKinfo(struct pak2_t* pak) {
	printf("\nPAK '%.4s' contains %d segment(s):\n", pak->header->name, pak->segment_count);
	int index = 0;
	for (index = 0; index < pak->segment_count; index++) {
		struct pak2segment_t *PAKsegment = pak->segments[index];
		int headerSize = sizeof(struct pak2segmentHeader_t);
		unsigned char *decrypted = malloc(headerSize);
		decryptImage(PAKsegment->header->signature, headerSize, decrypted);
		//hexdump(decrypted, headerSize);
		struct pak2segmentHeader_t* decryptedSegmentHeader = (struct pak2segmentHeader_t*) decrypted;
		char segment_version[20];
		printf("  segment #%u (name='%.4s', version='%02x.%02x.%02x.%02x', platform='%s', size='%u bytes')\n",
			index + 1, pak->header->name, decryptedSegmentHeader->version[3],
			decryptedSegmentHeader->version[2], decryptedSegmentHeader->version[1],
			decryptedSegmentHeader->version[0], decryptedSegmentHeader->platform, PAKsegment->content_len);
		free(decrypted);
	}
}

void SelectAESkey(struct pak2_t* pak) {
	int headerSize = sizeof(struct pak2segmentHeader_t);
	unsigned char *decrypted = malloc(headerSize);

	FILE *fp = fopen("AES.key", "r");
	if (fp == NULL) {
		printf("\nError: Cannot open AES.key file.\n");
		exit(1);
	}
	char* line = NULL;
	size_t len = 0;
	ssize_t read;
	size_t count = 0;

	while ((read = getline(&line, &len, fp)) != -1) {
		char* pos = line;
		for(count = 0; count < sizeof(aes_key)/sizeof(aes_key[0]); count++) {
			sscanf(pos, "%2hhx", &aes_key[count]);
			pos += 2 * sizeof(char);
		}
		SWU_CryptoInit_AES(aes_key);
		printf("Trying AES key (");
		int i;
		for (i = 0; i < 16; i++) printf("%02X", aes_key[i]);
		printf(") for PAK segment decryption...");
		struct pak2segment_t *PAKsegment = pak->segments[0];
		decryptImage(PAKsegment->header->signature, headerSize, decrypted);
		struct pak2segmentHeader_t* decryptedSegmentHeader = (struct pak2segmentHeader_t*) decrypted;
		if (!memcmp(decryptedSegmentHeader->unknown4, "MPAK", 4)) {
			printf("Success!\n");
			fclose(fp);
			if (line) free(line);
			return;
		} else {
			printf("Failed\n");
		}
	}
	fclose(fp);
	if (line) free(line);
	printf("\nFATAL: Can't decrypt PAK. Probably it's decrypted with an unknown key. Aborting now. Sorry.\n");
	exit(EXIT_FAILURE);
}

void scanPAKsegments(struct epk2header_t *epakHeader, struct pak2_t **pakArray) {
	unsigned char *epak_offset = epakHeader->signature;
	unsigned char *pakHeader_offset = epak_offset + sizeof(struct epk2header_t);
	struct pak2segmentHeader_t *PAKsegment_header = (struct pak2segmentHeader_t*) 
			((epakHeader->epakMagic) + (epakHeader->headerLength));

	// Contains added lengths of signature data
	unsigned int signature_sum = sizeof(epakHeader->signature)	+ sizeof(PAKsegment_header->signature);
	unsigned int PAKsegment_signature_length = sizeof(PAKsegment_header->signature);
	int count = 0;
	int next_pak_length = epakHeader->fileSize;
	while (count < epakHeader->pakCount) {
		struct pak2header_t *pakHeader = getPakHeader(pakHeader_offset);
		struct pak2_t *pak = malloc(sizeof(struct pak2_t));
		pakArray[count] = pak;
		pak->header = pakHeader;
		pak->segment_count = 0;
		pak->segments = NULL;
		int verified = 0;
		struct pak2segmentHeader_t *next_pak_offset = (struct pak2segmentHeader_t*) 
			(epak_offset + pakHeader->nextPAKfileOffset + signature_sum);
		unsigned int distance_between_paks = (next_pak_offset->name) - (PAKsegment_header->name);

		// last contained pak...
		if ((count == (epakHeader->pakCount - 1))) distance_between_paks = next_pak_length + PAKsegment_signature_length;
		unsigned int max_distance = pakHeader->maxPAKsegmentSize + sizeof(struct pak2segmentHeader_t);
		while (!verified) {
			unsigned int PAKsegment_length = distance_between_paks;
			bool is_next_segment_needed = FALSE;
			if (PAKsegment_length > max_distance) {
				PAKsegment_length = max_distance;
				is_next_segment_needed = TRUE;
			}
			unsigned int signed_length = next_pak_length;
			if (signed_length > max_distance) {
				signed_length = max_distance;
			}
			if (count == 0) signed_length = PAKsegment_length;
			if (!verified && (verified = API_SWU_VerifyImage(PAKsegment_header->signature, signed_length - SIGNATURE_SIZE)) != 1) {
				printf("Verify PAK segment #%u of %.4s failed (size=0x%x). Trying to fallback...\n", pak->segment_count + 1, PAKsegment_header->name, signed_length);
				//hexdump(PAKsegment_header->name, 0x80);
				while (((verified = API_SWU_VerifyImage(PAKsegment_header->signature,
						 signed_length - SIGNATURE_SIZE)) != 1)&& (signed_length > 0)) {
					signed_length--;
					//printf(	"probe with size: 0x%x\n", signed_length);
				}
				if (verified) {
					printf("Successfully verified with size: 0x%x\n", signed_length);
				} else {
					printf("Fallback failed. Sorry, aborting now.\n");
					exit(1);
				}
			}

			// sum signature lengths
			signature_sum += PAKsegment_signature_length;
			unsigned int PAKsegment_content_length = (PAKsegment_length - PAKsegment_signature_length);
			if (is_next_segment_needed) {
				distance_between_paks -= PAKsegment_content_length;
				next_pak_length -= PAKsegment_content_length;
				verified = 0;
			} else {
				next_pak_length = pakHeader->nextPAKlength + PAKsegment_signature_length;
			}
			pak->segment_count++;
			pak->segments = realloc(pak->segments, pak->segment_count * sizeof(struct pak2segment_t*));
			struct pak2segment_t *PAKsegment = malloc(sizeof(struct pak2segment_t));
			PAKsegment->header = PAKsegment_header;
			PAKsegment->content = PAKsegment_header->unknown4 + (sizeof(PAKsegment_header->unknown4));
			PAKsegment->content_file_offset = PAKsegment->content - epak_offset;
			PAKsegment->content_len = signed_length - sizeof(struct pak2segmentHeader_t);
			pak->segments[pak->segment_count - 1] = PAKsegment;

			// move pointer to the next pak segment offset
			PAKsegment_header = (struct pak2segmentHeader_t *) (PAKsegment_header->signature + PAKsegment_length);
		}
		pakHeader_offset += sizeof(struct pak2header_t);
		count++;
	}
}

int write_PAKsegments(struct pak2_t *pak, const char *filename) {
	int length = 0;
	FILE *outfile = fopen(((const char*) filename), "w");
	int PAKsegment_index;
	for (PAKsegment_index = 0; PAKsegment_index < pak->segment_count; PAKsegment_index++) {
		struct pak2segment_t *PAKsegment = pak->segments[PAKsegment_index];
		int content_len = PAKsegment->content_len;
		unsigned char* decrypted = malloc(content_len);
		memset(decrypted, 0xFF, content_len);
		decryptImage(PAKsegment->content, content_len, decrypted);
		fwrite(decrypted, 1, content_len, outfile);
		free(decrypted);
		length += content_len;
	}
	fclose(outfile);
	return length;
}

int isFileEPK2(const char *epk2file) {
	FILE *file = fopen(epk2file, "r");
	if (file == NULL) {
		printf("Can't open file %s", epk2file);
		exit(1);
	}
	size_t headerSize = 0x6D0;
	unsigned char* buffer = (unsigned char*) malloc(sizeof(char) * headerSize);
	int read = fread(buffer, 1, headerSize, file);
	if (read != headerSize) return 0;
	fclose(file);
	int result = !memcmp(&buffer[0x8c], EPK2_MAGIC, 4); //old EPK2
	if (!result) result = (buffer[0x6B0] == 0 && buffer[0x6B8] == 0x2E && buffer[0x6BD] == 0x2E); //new EPK2
	free(buffer);
	return result;
}

void getPAKversionStr(char *fw_version, unsigned char version[4]) {
	sprintf(fw_version, "%02x.%02x.%02x.%02x", version[3], version[2], version[1], version[0]);
}

void getEPK2versionString(char *fw_version, struct epk2header_t *epakHeader) {
	sprintf(fw_version, "%02x.%02x.%02x.%02x-%s", epakHeader->fwVersion[3], epakHeader->fwVersion[2], epakHeader->fwVersion[1], epakHeader->fwVersion[0], epakHeader->otaID);
}

void extractEPK2file(const char *epk2file, struct config_opts_t *config_opts) {
	FILE *file = fopen(epk2file, "r");
	if (file == NULL) {
		printf("\nCan't open file %s", epk2file);
		exit(1);
	}
	fseek(file, 0, SEEK_END);
	int fileLength = ftell(file);
	rewind(file);
	printf("File size: %d bytes\n", fileLength);
	printf("\nVerifying digital signature of EPK2 firmware header...\n");
	int EPK2headerSize = 0x6B4;
	unsigned char* buffer = (unsigned char*) malloc(sizeof(char) * fileLength);
	int read = fread(buffer, 1, EPK2headerSize, file);
	if (read != EPK2headerSize) {
		printf("\nError reading EPK2 header. Read %d bytes from %d.\n", read, EPK2headerSize);
		exit(1);
	}

	int verified = 0;

	DIR* dirFile = opendir(".");
	if (dirFile) {
		struct dirent* hFile;
		while ((hFile = readdir(dirFile)) != NULL) {
			if (!strcmp(hFile->d_name, ".") || !strcmp(hFile->d_name, "..") || hFile->d_name[0] == '.') continue;
			if (strstr(hFile->d_name, ".pem") || strstr(hFile->d_name, ".PEM")) {
				printf("Trying RSA key: %s... ", hFile->d_name);
				SWU_CryptoInit_PEM(config_opts->config_dir, hFile->d_name);
				int size = EPK2headerSize;
				while (size > 0) {
					verified = API_SWU_VerifyImage(buffer, size);
					if (verified) {
						printf("Success!\nDigital signature of the firmware is OK. Signed bytes: %d\n\n", size);
						break;
					}
					size -= 1;
				}
				if (!verified) printf("Failed\n");
			}
			if (verified) break;
		}
		closedir(dirFile);
   	}

	if (!verified) {
		printf("Cannot verify firmware's digital signature (maybe you don't have proper PEM file). Aborting.\n\n");
		fclose(file);
		exit(1);
	}

	struct epk2header_t *epakHeader = get_epk2header(buffer);
	if (memcmp(epakHeader->EPK2magic, EPK2_MAGIC, 4)) {
		printf("EPK2 header is encrypted. Trying to decrypt...\n");
		int headerSize = 0x634;
		unsigned char *decrypted = malloc(headerSize);
		int uncrypted = 0;
		FILE *fp = fopen("AES.key", "r");
		if (fp == NULL) {
			printf("\nError: Cannot open AES.key file.\n");
			exit(1);
		}
		char* line = NULL;
		size_t len = 0;
		ssize_t read;
		size_t count = 0;

		while ((read = getline(&line, &len, fp)) != -1) {
			char* pos = line;
			for(count = 0; count < sizeof(aes_key)/sizeof(aes_key[0]); count++) {
				sscanf(pos, "%2hhx", &aes_key[count]);
				pos += 2 * sizeof(char);
			}
			SWU_CryptoInit_AES(aes_key);
			printf("Trying AES key (");
			int i;
			for (i = 0; i < 16; i++) printf("%02X", aes_key[i]);
			printf(")...");
			decryptImage(&buffer[0x80], headerSize, decrypted);
			if (!memcmp(&decrypted[0xC], EPK2_MAGIC, 4)) {
				printf("Success!\n");
				//hexdump(decrypted, headerSize);
				memcpy(&buffer[0x80], decrypted, headerSize);
				uncrypted = 1;
				break;
			} else {
				printf("Failed\n");
			}
		}
		fclose(fp);
		if (line) free(line);
		free(decrypted);
		if (!uncrypted) {
			printf("\nFATAL: Cannot decrypt EPK2 header (proper AES key is missing). Aborting now. Sorry.\n\n");
			exit(EXIT_FAILURE);
		}
	}

	printf("\nFirmware info\n");
	printf("-------------\n");
	printEPK2header(epakHeader);

	printf("Loading EPK2 firmware file into RAM. Please wait...\n");
	read = fread(&buffer[EPK2headerSize], 1, fileLength - EPK2headerSize, file);
	if (read != fileLength - EPK2headerSize) {
		printf("\nError reading file. Read %d bytes from %d.\n", read, fileLength - EPK2headerSize);
		fclose(file);
		exit(1);
	}
	fclose(file);

	struct pak2_t **pakArray = malloc((epakHeader->pakCount) * sizeof(struct pak2_t*));
	scanPAKsegments(epakHeader, pakArray);
	int last_index = epakHeader->pakCount - 1;
	struct pak2_t *last_pak = pakArray[last_index];
	int PAKsegment_index = last_pak->segment_count - 1;
	struct pak2segment_t *last_PAKsegment = last_pak->segments[PAKsegment_index];
	int last_extracted_file_offset = (last_PAKsegment->content_file_offset + last_PAKsegment->content_len);
	printf("Last extracted file offset: %d\n\n", last_extracted_file_offset);

	char version_string[1024];
	getEPK2versionString(version_string, epakHeader);

	char targetFolder[1024];
	memset(targetFolder, 0, 1024);
	constructPath(targetFolder, config_opts->dest_dir, version_string, NULL);
	createFolder(targetFolder);

	SelectAESkey(pakArray[0]);

	int index;
	for (index = 0; index < epakHeader->pakCount; index++) {
		printPAKinfo(pakArray[index]);
		const char *pak_type_name;
		char filename[1024] = "";
		char name[4];
		sprintf(name, "%.4s", pakArray[index]->header->name);
		constructPath(filename, targetFolder, name, ".PAK");
		printf("#%u/%u saving PAK (%s) to file %s\n", index + 1, epakHeader->pakCount, name, filename);
		int length = write_PAKsegments(pakArray[index], filename);
		processExtractedFile(filename, targetFolder, name);
	}
}

