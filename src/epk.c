#include <epk.h>
#include <u-boot/image.h>
#include <arpa/inet.h>

#define stringify( name ) # name

const int PAK_ID_LENGTH = 5;

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
		stringify( BASE ), stringify( PATC ), stringify( CFGI ),
		stringify( PQLD ), stringify( TPLI ), stringify( UNKNOWN ),
		stringify( UNKNOWN ), stringify( UNKNOWN ), stringify( UNKNOWN ),
		stringify( UNKNOWN ), stringify( UNKNOWN ), stringify( UNKNOWN ) };

pak_type_t get_pak_type(unsigned char type[4]) {

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
		// for backward compatibility with older fw ('eman' -> 'estr')
	case 0x656D616E:
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
	case 0x62617365:
		return BASE;
	case 0x70617463:
		return PATC;
	case 0x63666769:
		return CFGI;
	case 0x70716C64:
		return PQLD;
	case 0x74706C69:
		return TPLI;
	default:
		return UNKNOWN;
	}
}

const char* get_pak_type_name(unsigned int pakType) {
	const char *pak_type_name = pak_type_names[pakType];

	char *result = malloc(PAK_ID_LENGTH);

	result[0] = tolower(pak_type_name[0]);
	result[1] = tolower(pak_type_name[1]);
	result[2] = tolower(pak_type_name[2]);
	result[3] = tolower(pak_type_name[3]);
	result[4] = 0;

	return result;
}

int is_uboot(char *buffer) {
	struct image_header *image_header = (struct image_header *) buffer;

	return image_header->ih_magic == ntohl(IH_MAGIC);
}

int is_uboot_image(const char *image_file) {

	FILE *file = fopen(image_file, "r");

	if (file == NULL) {
		printf("Can't open file %s", image_file);
		exit(1);
	}

	size_t header_size = sizeof(struct image_header);

	unsigned char* buffer = (unsigned char*) malloc(sizeof(char) * header_size);

	int read = fread(buffer, 1, header_size, file);

	if (read != header_size) {
		return 0;
	}

	fclose(file);

	int result = is_uboot(buffer);

	free(buffer);

	return result;
}

void extract_uboot_image(const char *image_file, const char *destination_file) {

	FILE *file = fopen(image_file, "r");

	if (file == NULL) {
		printf("Can't open file %s", image_file);
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

	if (!is_uboot(buffer)) {
		printf("unsupported file type. aborting.\n");
		exit(1);
	}

	struct image_header *image_header = (struct image_header *) buffer;

	FILE *out = fopen(destination_file, "w");

	int header_size = sizeof(struct image_header);

	fwrite(buffer + header_size, 1, read - header_size, out);

	fclose(out);

	free(buffer);

}

void handle_extracted_image_file(char *filename, char *target_dir,
		const char *pak_type_name) {
	if (is_squashfs(filename)) {
		char unsquashed[100] = "";
		construct_path(unsquashed, target_dir, pak_type_name, NULL);
		printf("unsquashfs %s to directory %s\n", filename, unsquashed);
		rmrf(unsquashed);
		unsquashfs(filename, unsquashed);
	}
	if (check_lzo_header(filename)) {
		char unpacked[100] = "";
		construct_path(unpacked, target_dir, pak_type_name, ".unpacked");
		printf("decompressing %s with modified LZO algorithm to %s\n",
				filename, unpacked);
		if (lzo_unpack((const char*) filename, (const char*) unpacked) != 0) {
			printf("sorry. decompression failed. aborting now.\n");
			exit(1);
		}
		if (is_cramfs_image(unpacked)) {
			char uncram[100] = "";
			construct_path(uncram, target_dir, pak_type_name, NULL);
			printf("uncramfs %s to directory %s\n", unpacked, uncram);
			rmrf(uncram);
			uncramfs(uncram, unpacked);
		}
	}
	if (is_uboot_image(filename)) {
		char deimaged[100] = "";
		construct_path(deimaged, target_dir, pak_type_name, ".deimaged");
		printf("extracting u-boot image %s to %s\n", filename, deimaged);
		extract_uboot_image(filename, deimaged);
		handle_extracted_image_file(deimaged, target_dir, pak_type_name);
	}

}
