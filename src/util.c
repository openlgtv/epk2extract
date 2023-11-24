/**
 * Miscellaneous utilities
 * Copyright 2016 Smx <smxdev4@gmail.com>
 * Copyright 2016 lprot
 * All right reserved
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <ftw.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <termios.h>
#include <config.h>
#include <openssl/aes.h>
#include <inttypes.h>
#include <libgen.h>
#include <errno.h>

#include "common.h"
#include "mfile.h"
#include "util.h"

//partinfo
#include <time.h>
#include "partinfo.h"
const char *modelname = NULL;
part_struct_type part_type = STRUCT_INVALID;

//jffs2
#include "jffs2/jffs2.h"

//lzhs
#include "lzhs/lzhs.h"

//kernel
#include "u-boot/image.h"
#include <arpa/inet.h>

//minigzip
#include "minigzip.h"

//boot and tzfw
#include <elf.h>

//mtk pkg
#include "mediatek_pkg.h"

char *remove_ext(const char *mystr) {
	char *retstr, *lastdot;
	if (mystr == NULL)
		return NULL;
	if ((retstr = (char *)malloc(strlen(mystr) + 1)) == NULL)
		return NULL;
	strcpy(retstr, mystr);
	lastdot = strrchr(retstr, '.');
	if (lastdot != NULL)
		*lastdot = '\0';
	return retstr;
}

char *get_ext(const char *mystr) {
	char *retstr, *lastdot;
	if (mystr == NULL)
		return NULL;
	if ((retstr = (char *)malloc(strlen(mystr) + 1)) == NULL)
		return NULL;
	lastdot = strrchr(mystr, '.');
	if (lastdot != NULL) {
		sprintf(retstr, "%s", lastdot + 1);
		int i;
		for (i = 0; retstr[i]; i++)
			retstr[i] = tolower(retstr[i]);
	}
	return retstr;
}

/**
 * basename and dirname might modify the source path.
 * they also return a pointer to static memory that might be overwritten in subsequent calls
 */
char *my_basename(const char *path){
	char *cpy = strdup(path);
	char *ret = basename(cpy);
	ret = strdup(ret);
	free(cpy);
	return ret;
}

char *my_dirname(const char *path){
	char *cpy = strdup(path);
	char *ret = dirname(cpy);
	ret = strdup(ret);
	free(cpy);
	return ret;
}

int count_tokens(const char *str, char tok, int sz){
	int no = 0;
	for(int i=0; i<sz; i++){
		if(str[i] == tok)
			no++;
	}
	return no;
}

FORMAT_PRINTF(5, 6)
void print(int verbose, int newline, const char *fn, int lineno, const char *fmt, ...) {
#if 0
#ifndef DEBUG
	if (verbose > G_VERBOSE)
		return;
#endif
#endif

	char *file = my_basename(fn);
	char *dir = my_dirname(fn);
	char *parent = my_dirname(dir);

	const char *relative = dir + strlen(parent) + 1;

	printf("[%s/%s:%d] ", relative, file, lineno);

	free(file);
	free(dir);
	free(parent);

	va_list arglist;
	va_start(arglist, fmt);
	vprintf(fmt, arglist);
	va_end(arglist);

	if (newline)
		printf("\n");

}

void SwapBytes(void *pv, size_t n) {
	unsigned char *p = pv;
	for (size_t lo = 0, hi = n - 1; hi > lo; lo++, hi--) {
		unsigned char tmp = p[lo];
		p[lo] = p[hi];
		p[hi] = tmp;
	}
}

void getch(void) {
	struct termios oldattr, newattr;
	tcgetattr(STDIN_FILENO, &oldattr);
	newattr = oldattr;
	newattr.c_lflag &= ~(ICANON | ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &newattr);
	getchar();
	tcsetattr(STDIN_FILENO, TCSANOW, &oldattr);
}

void hexdump(const void *pAddressIn, long lSize) {
	char szBuf[100];
	long lIndent = 1;
	long lOutLen, lIndex, lIndex2, lOutLen2;
	long lRelPos;
	struct {
		const char *pData;
		unsigned long lSize;
	} buf;
	unsigned char ucTmp;
	const unsigned char *pTmp, *pAddress = pAddressIn;

	buf.pData = (const char *) pAddress;
	buf.lSize = lSize;

	while (buf.lSize > 0) {
		pTmp = (unsigned char *)buf.pData;
		lOutLen = (int)buf.lSize;
		if (lOutLen > 16)
			lOutLen = 16;

		// create a 64-character formatted output line:
		sprintf(szBuf, " >                                                      %08tX", pTmp - pAddress);
		lOutLen2 = lOutLen;

		for (lIndex = 1 + lIndent, lIndex2 = 53 - 15 + lIndent, lRelPos = 0; lOutLen2; lOutLen2--, lIndex += 2, lIndex2++) {
			ucTmp = *pTmp++;
			sprintf(szBuf + lIndex, "%02hhX ", ucTmp);
			if (!isprint(ucTmp))
				ucTmp = '.';	// nonprintable char
			szBuf[lIndex2] = ucTmp;

			if (!(++lRelPos & 3)) {	// extra blank after 4 bytes
				lIndex++;
				szBuf[lIndex + 2] = ' ';
			}
		}
		if (!(lRelPos & 3))
			lIndex--;
		szBuf[lIndex] = '<';
		szBuf[lIndex + 1] = ' ';
		puts(szBuf);
		buf.pData += lOutLen;
		buf.lSize -= lOutLen;
	}
}

int unlink_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
	int rv = remove(fpath);
	if (rv != 0)
		perror(fpath);
	return rv;
}

void rmrf(const char *path) {
	struct stat status;
	if (stat(path, &status) == 0)
		nftw(path, unlink_cb, 64, FTW_DEPTH | FTW_PHYS);
}

FORMAT_PRINTF(1, 2)
int err_ret(const char *format, ...) {
	if (format != NULL) {
		va_list args;
		va_start(args, format);
		vprintf(format, args);
		va_end(args);
	}

#ifdef __CYGWIN__
	puts("Press any key to continue...");
	getch();
#endif

	return EXIT_FAILURE;
}

void createFolder(const char *directory) {
	struct stat st;
	if (stat(directory, &st) != 0) {
		if (mkdir((const char *)directory, 0744) != 0){
			err_exit("FATAL: Can't create directory '%s' (%s)\n\n", directory, strerror(errno));
		}
	}
}

MFILE *is_lz4(const char *lz4file) {
	MFILE *file = mopen(lz4file, O_RDONLY);
	if (!file){
		err_exit("Can't open file %s\n\n", lz4file);
	}
	if(!memcmp(mdata(file, uint8_t), "LZ4P", 4))
		return file;

	mclose(file);
	return NULL;
}

bool is_nfsb_mem(MFILE *file, off_t offset){
	uint8_t *data = &(mdata(file, uint8_t))[offset];

	if(memcmp(data, "NFSB", 4) != 0){
		return false;
	}

	const char algo_md5[] = "md5";
	const char algo_sha256[] = "sha256";

	const int offsets[] = { 0x0E, 0x1A };
	const char *algos[] = { algo_md5, algo_sha256 };
	const int lengths[] = { sizeof(algo_md5) - 1, sizeof(algo_sha256) - 1 };

	const int num_offsets = countof(offsets);
	const int num_algos = countof(algos);

	for(int i=0; i<num_algos; i++){
		for(int j=0; j<num_offsets; j++){
			if(memcmp(data + offsets[j], algos[i], lengths[i]) == 0){
				return true;
			}
		}
	}

	return false;
}

MFILE *is_nfsb(const char *filename) {
	MFILE *file = mopen(filename, O_RDONLY);
	if (!file){
		err_exit("Can't open file %s\n\n", filename);
	}

	if(is_nfsb_mem(file, 0))
		return file;

	mclose(file);
	return NULL;
}

void unnfsb(const char *filename, const char *extractedFile) {
	const int headerSize = 0x1000;

	MFILE *in = mopen(filename, O_RDONLY);
	if(in == NULL){
		err_exit("Cannot open file '%s' for reading\n", filename);
	}

	MFILE *out = mfopen(extractedFile, "w+");
	if(out == NULL){
		mclose(in);
		err_exit("Cannot open file '%s' for writing\n", extractedFile);
	}

	long outputSize = msize(in) - headerSize;
	mfile_map(out, outputSize);

	memcpy(
		mdata(out, void),
		mdata(in, uint8_t) + headerSize,
		outputSize
	);

	mclose(out);
	mclose(in);
}

MFILE *is_gzip(const char *filename) {
	MFILE *file = mopen(filename, O_RDONLY);
	if (file == NULL) {
		err_exit("Can't open file %s\n", filename);
		return NULL;
	}

	if(msize(file) < 16){
		mclose(file);
		return NULL;
	}

	if(memcmp(mdata(file, uint8_t *), "\x1F\x8B\x08", 3) != 0){
		mclose(file);
		return NULL;
	}

	char *gzfilename = mdata(file, char) + 10;

	int i;
	for(i=0; gzfilename[i] != 0x00 && isprint(gzfilename[i]); i++);

	if(i > 0 && gzfilename[i] == 0x00){
		return file;
	}

	mclose(file);
	return NULL;
}

int is_jffs2(const char *filename) {
	FILE *file = fopen(filename, "rb");
	if (file == NULL) {
		err_exit("Can't open file %s\n", filename);
	}
	size_t headerSize = 0x2;
	unsigned short magic = JFFS2_MAGIC_BITMASK;
	unsigned char buffer[headerSize];
	int read = fread(&buffer, 1, headerSize, file);
	int result = 0;
	if (read == headerSize) {
		result = !memcmp(&buffer[0x0], &magic, 2);
		if (!result) {
			magic = JFFS2_OLD_MAGIC_BITMASK;
			result = !memcmp(&buffer[0x0], &magic, 2);
		}
	}
	fclose(file);
	return result;
}

int isSTRfile(const char *filename) {
	FILE *file = fopen(filename, "rb");
	if (file == NULL) {
		err_exit("Can't open file %s\n", filename);
	}
	size_t headerSize = 0xC0 * 4;
	unsigned char buffer[headerSize];
	int read = fread(&buffer, 1, headerSize, file);
	int result = 0;
	if (read == headerSize && buffer[4] == 0x47 && buffer[0xC0 + 4] == 0x47 && buffer[0xC0 * 2 + 4] == 0x47 && buffer[0xC0 * 3 + 4] == 0x47)
		result = 1;
	fclose(file);
	return result;
}

int isdatetime(const char *datetime) {
	struct tm time_val;

	// datetime format is YYYYMMDD
	if (strptime(datetime, "%Y%m%d", &time_val) != 0
		&& ((time_val.tm_year+1900) > 2005)) {
		return 1;
	} else {
		return 0;
	}
}

bool is_str_printable(const char *str) {
	for (const char *p = str; *p != '\0'; p++) {
		if (isprint(*p) == 0) {
			return false;
		}
	}

	return true;
}

static const struct {
	const char *name;
	part_struct_type type;
	const char *description;
} part_type_table[] = {
	{"mstar_map0",    STRUCT_MTDINFO,    "MStar Saturn6 / Saturn7 / M1(A) / LM1"}, // ?
	{"bcm35xx_map0",  STRUCT_MTDINFO,    "BCM 2010 (BCM35XX)"}, 			// 2010
	{"bcm35230_map0", STRUCT_MTDINFO,    "BCM 2011 (BCM35230)"}, 			// 2011
	{"mtk3569-emmc",  STRUCT_PARTINFOv1, "MTK A1 (MT5369/MTK5369)"}, 		// 2012
	{"l9_emmc", 	  STRUCT_PARTINFOv1, "LX L9 (LG1152)"}, 				// 2012
	{"mtk3598-emmc",  STRUCT_PARTINFOv2, "MTK A2 (MT5398/MTK5389/M13)"},    // 2013
	{"h13_emmc", 	  STRUCT_PARTINFOv2, "LX H13 (LG1154) / M14 (LG1311)"}, // 2013/2014
	{"mstar-emmc",    STRUCT_PARTINFOv2, "MStar LM14"}, 					// 2014
};

/* detect_model - detect model and corresponding part struct */
static void detect_model(const struct p2_device_info *pid) {
	char name[STR_LEN_MAX + 1];

	strncpy(name, pid->name, STR_LEN_MAX);
	name[STR_LEN_MAX] = '\0';

	for (unsigned int i = 0; i < countof(part_type_table); i++) {
		if (strcmp(part_type_table[i].name, name) == 0) {
			modelname = part_type_table[i].description;
			part_type = part_type_table[i].type;
			return;
		}
	}

	part_type = STRUCT_INVALID;
	modelname = NULL;

	if (is_str_printable(name)) {
		fprintf(stderr, "unknown part type: '%s'\n", name);
	} else {
		fputs("unknown part type (non-printable characters)\n", stderr);
	}

	return;
}

int isPartPakfile(const char *filename) {
	FILE *file = fopen(filename, "rb");
	if (file == NULL)
		err_exit("Can't open file %s\n", filename);

	struct p2_partmap_info partinfo;

	fread(&partinfo, 1, sizeof(struct p2_partmap_info), file);

	char *cmagic = NULL;
	asprintf(&cmagic, "%x", partinfo.magic);

	int r = isdatetime(cmagic);
	free(cmagic);

	if (r == 0) {
		return 0;
	}

	printf("Found valid partpak magic 0x%x in %s\n", partinfo.magic, filename);

	detect_model(&(partinfo.dev));
	fclose(file);

	if (part_type == STRUCT_INVALID) {
		return 0;
	}

	return 1;
}

int is_kernel(const char *image_file) {
	FILE *file = fopen(image_file, "rb");
	if (file == NULL)
		err_exit("Can't open file %s", image_file);

	size_t header_size = sizeof(struct image_header);
	unsigned char buffer[header_size];
	int read = fread(&buffer, 1, header_size, file);
	if (read != header_size)
		return 0;
	fclose(file);
	struct image_header *image_header = (struct image_header *)(&buffer);
	int result = image_header->ih_magic == ntohl(IH_MAGIC);
	return result;
}

void extract_kernel(const char *image_file, const char *destination_file) {
	FILE *file = fopen(image_file, "rb");
	if (file == NULL)
		err_exit("Can't open file %s", image_file);

	fseek(file, 0, SEEK_END);
	int fileLength = ftell(file);
	rewind(file);
	unsigned char *buffer = malloc(fileLength);
	int read = fread(buffer, 1, fileLength, file);
	if (read != fileLength) {
		err_exit("Error reading file. read %d bytes from %d.\n", read, fileLength);
		free(buffer);
	}
	fclose(file);

	FILE *out = fopen(destination_file, "wb");
	int header_size = sizeof(struct image_header);
	fwrite(buffer + header_size, 1, read - header_size, out);
	free(buffer);
	fclose(out);
}

/**
 * asprintf that allows reuse of strp in variadic arguments (frees strp and replaces it with newly allocated string)
 */
FORMAT_PRINTF(2, 3)
int asprintf_inplace(char **strp, const char *fmt, ...) {
    if ((strp == NULL) || (fmt == NULL)) {
        err_exit("Error: %s called with NULL argument.\n", __func__);
    }

	va_list args;
    va_start(args, fmt);
	char *new_strp = NULL;
    int result = vasprintf(&new_strp, fmt, args);
    va_end(args);

    free(*strp);
    *strp = new_strp;

    return result;
}
