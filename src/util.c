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
char *modelname;
char *mtdname;
part_struct_type part_type;

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

void print(int verbose, int newline, char *fn, int lineno, const char *fmt, ...) {
#if 0
#ifndef DEBUG
	if (verbose > G_VERBOSE)
		return;
#endif
#endif

	char *file = my_basename(fn);
	char *dir = my_dirname(fn);
	char *parent = my_dirname(dir);
	
	char *relative = dir + strlen(parent) + 1;
	
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
	char *p = pv;
	size_t lo, hi;
	for (lo = 0, hi = n - 1; hi > lo; lo++, hi--) {
		char tmp = p[lo];
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

void hexdump(void *pAddressIn, long lSize) {
	char szBuf[100];
	long lIndent = 1;
	long lOutLen, lIndex, lIndex2, lOutLen2;
	long lRelPos;
	struct {
		char *pData;
		unsigned long lSize;
	} buf;
	unsigned char *pTmp, ucTmp;
	unsigned char *pAddress = (unsigned char *)pAddressIn;

	buf.pData = (char *)pAddress;
	buf.lSize = lSize;

	while (buf.lSize > 0) {
		pTmp = (unsigned char *)buf.pData;
		lOutLen = (int)buf.lSize;
		if (lOutLen > 16)
			lOutLen = 16;

		// create a 64-character formatted output line:
		sprintf(szBuf, " >                                                      %08zX", pTmp - pAddress);
		lOutLen2 = lOutLen;

		for (lIndex = 1 + lIndent, lIndex2 = 53 - 15 + lIndent, lRelPos = 0; lOutLen2; lOutLen2--, lIndex += 2, lIndex2++) {
			ucTmp = *pTmp++;
			sprintf(szBuf + lIndex, "%02X ", (unsigned short)ucTmp);
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
		printf("%s\n", szBuf);
		buf.pData += lOutLen;
		buf.lSize -= lOutLen;
	}
}

int unlink_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
	int rv = remove(fpath);
	if (rv)
		perror(fpath);
	return rv;
}

void rmrf(const char *path) {
	struct stat status;
	if (stat(path, &status) == 0)
		nftw(path, unlink_cb, 64, FTW_DEPTH | FTW_PHYS);
}

int err_ret(const char *format, ...) {
	va_list args;
	va_start(args, format);
	vprintf(format, args);
	va_end(args);
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

int isdatetime(char *datetime) {
	struct tm time_val;

	// datetime format is YYYYMMDD
	if (strptime(datetime, "%Y%m%d", &time_val) != 0
		&& ((time_val.tm_year+1900) > 2005)) {
		return 1;
	} else {
		return 0;
	}
}

/* detect_model - detect model and corresponding part struct */
part_struct_type detect_model(struct p2_device_info * pid) {
	char *model;
	part_type = STRUCT_INVALID;
	int ismtk1 = !strcmp("mtk3569-emmc", pid->name);  //match mtk2012
	int ismtk2 = !strcmp("mtk3598-emmc", pid->name);  //match mtk2013
	int is1152 = !strcmp("l9_emmc", pid->name);       //match 1152
	int is1154 = !strcmp("h13_emmc", pid->name);      //match 1154/lg1311
	int isbcm1 = !strcmp("bcm35xx_map0", pid->name);  //match broadcom
	int isbcm2 = !strcmp("bcm35230_map0", pid->name); //match broadcom
	int ismstar = !strcmp("mstar_map0", pid->name);   //match mstar
	int islm14 = !strcmp("mstar-emmc", pid->name);    //match lm14

	if (ismtk1)
		model = "Mtk 2012 - MTK5369 (Cortex-A9 single-core)";
	else if (ismtk2)
		model = "Mtk 2013 - MTK5398 (Cobra Cortex-A9 dual-core)";
	else if (is1152)
		model = "LG1152 (L9)";
	else if (is1154)
		model = "LG1154 (H13) / LG1311 (M14)";
	else if (isbcm1)
		model = "BCM 2010 - BCM35XX";
	else if (isbcm2)
		model = "BCM 2011 - BCM35230";
	else if (ismstar)
		model = "Mstar Saturn6 / Saturn7 / M1 / M1a / LM1";
	else if (islm14)
		model = "Mstar LM14";
	else
		return part_type;

	if (ismtk2 || is1154 || islm14) {
		part_type = STRUCT_PARTINFOv2;
	} else if (ismtk1 || is1152) {
		part_type = STRUCT_PARTINFOv1;	//partinfo v1
	} else {
		part_type = STRUCT_MTDINFO;	//mtdinfo
	}

	mtdname = pid->name;
	modelname = model;
	/*printf("\nMTD name -> %s\n",mtdname);
	   printf("%s Detected\n\n", modelname);*/

	return part_type;
}

int isPartPakfile(const char *filename) {
	FILE *file = fopen(filename, "rb");
	if (file == NULL)
		err_exit("Can't open file %s\n", filename);

	struct p2_partmap_info partinfo;

	size_t size = sizeof(struct p2_partmap_info);
	fread(&partinfo, 1, size, file);

	char *cmagic;
	asprintf(&cmagic, "%x", partinfo.magic);

	int r = isdatetime((char *)cmagic);
	free(cmagic);

	if (r) {
		printf("Found valid partpak magic 0x%x in %s\n", partinfo.magic, filename);
	} else {
		return 0;
	}

	detect_model(&(partinfo.dev));
	fclose(file);
	if (part_type == STRUCT_INVALID)
		return 0;
	else
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
int asprintf_inplace(char** strp, const char* fmt, ...) {
    va_list args;
    int result;
    char* new_strp = NULL;
    va_start(args, fmt);
    result = vasprintf(&new_strp, fmt, args);
    va_end(args);

    free(*strp);
    *strp = new_strp;

    return result;
}
