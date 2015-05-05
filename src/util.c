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

//partinfo
#include <time.h>
#include <partinfo.h>
char *modelname;
char *mtdname;
part_struct_type part_type;

//jffs2
#include <jffs2/jffs2.h>

//lzhs
#include <lzhs/lzhs.h>

//kernel
#include <u-boot/image.h>
#include <arpa/inet.h>

//minigzip
#include <minigzip.h>

//boot and tzfw
#include <elf.h>
#define MTK_PBL_SIZE 0x9FFF


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

void rmrf(char *path) {
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

void err_exit(const char *format, ...) {
	va_list args;
	va_start(args, format);
	exit(err_ret(format, args));
	va_end(args);
}

void createFolder(const char *directory) {
	struct stat st;
	if (stat(directory, &st) != 0) {
		if (mkdir((const char *)directory, 0744) != 0){
			err_exit("FATAL: Can't create directory '%s' (%s)\n\n", directory, strerror(errno));
		}
	}
}

int is_lz4(const char *lz4file) {
	FILE *file = fopen(lz4file, "rb");
	if (file == NULL)
		err_exit("Can't open file %s\n\n", lz4file);

	char magic[4];
	if (fread(&magic, 1, 4, file) != 4)
		return 0;
	return !memcmp(&magic, "LZ4P", 4);
}

int is_nfsb(const char *filename) {
	FILE *file = fopen(filename, "rb");
	if (file == NULL)
		err_exit("Can't open file %s\n\n", filename);

	char header[0x11];
	if (fread(&header, 1, sizeof(header), file) != sizeof(header))
		return 0;
	fclose(file);
	if (memcmp(&header, "NFSB", 4) == 0)
		return !memcmp(&header[0xE], "md5", 3);
	return 0;
}

void unnfsb(char *filename, char *extractedFile) {
	int fdin, fdout;
	char *src, *dst;
	struct stat statbuf;
	int headerSize = 0x1000;
	/* open the input file */
	if ((fdin = open(filename, O_RDONLY)) < 0)
		printf("Can't open file %s for reading\n", filename);

	/* open/create the output file */
	if ((fdout = open(extractedFile, O_RDWR | O_CREAT | O_TRUNC, (mode_t) 0600)) < 0)
		printf("Can't create file %s for writing\n", extractedFile);

	/* find size of input file */
	if (fstat(fdin, &statbuf) < 0)
		printf("fstat error\n");

	/* mmap the input file */
	if ((src = mmap(0, statbuf.st_size, PROT_READ, MAP_SHARED, fdin, 0)) == (caddr_t) - 1)
		printf("mmap error for input\n");

	/* go to the location corresponding to the last byte */
	if (lseek(fdout, statbuf.st_size - headerSize - 1, SEEK_SET) == -1)
		printf("lseek error\n");

	/* write a dummy byte at the last location */
	if (write(fdout, "", 1) != 1)
		printf("write error\n");

	/* mmap the output file */
	if ((dst = mmap(0, statbuf.st_size - headerSize, PROT_READ | PROT_WRITE, MAP_SHARED, fdout, 0)) == (caddr_t) - 1)
		printf("mmap error for output\n");
	/* this copies the input file to the output file */
	memcpy(dst, &src[headerSize], statbuf.st_size - headerSize);

	/* Don't forget to free the mmapped memory */
	if (munmap(src, statbuf.st_size) == -1)
		printf("Error un-mmapping the file");
	if (munmap(dst, statbuf.st_size - headerSize) == -1)
		printf("Error un-mmapping the file");

	/* Un-mmaping doesn't close the file, so we still need to do that. */
	close(fdout);
	close(fdin);
}

void extract_mtk_boot(const char *filename, const char *outname) {
	char buf[MTK_PBL_SIZE];
	int n;

	FILE *in = fopen(filename, "rb");
	if (in == NULL)
		err_exit("Can't open file %s\n", filename);

	FILE *out = fopen(outname, "wb");
	if (out == NULL)
		err_exit("Can't open file %s for writing\n", outname);

	n = fread(&buf, 1, MTK_PBL_SIZE, in);
	if (n != MTK_PBL_SIZE) {
		fclose(in);
		err_exit("Error: PBL size mismatch!\n");
	}

	fclose(in);
	fwrite(&buf, 1, MTK_PBL_SIZE, out);
	fclose(out);
}

void split_mtk_tz(const char *filename, const char *destdir) {
	unsigned int tz_off = 0x20000;
	unsigned char *buf;
	char *dest = calloc(1, strlen(destdir) + strlen(filename) + 10);
	int n;
	size_t fileSize, env_size, tz_size;
	FILE *in = fopen(filename, "rb");
	if (in == NULL) {
		err_exit("Can't open file %s\n", filename);
	}
	sprintf(dest, "%s/env.o", destdir);
	FILE *out = fopen(dest, "wb");
	if (out == NULL)
		err_exit("Can't open file %s for writing\n", dest);

	fseek(in, 0, SEEK_END);
	fileSize = ftell(in);
	rewind(in);
	env_size = tz_off;
	tz_size = fileSize - env_size;
	buf = malloc(env_size);
	n = fread(buf, 1, env_size, in);
	if (n != env_size) {
		fclose(in);
		fclose(out);
		err_exit("Error, env.o size mismatch\n");
	}
	printf("Extracting env.o... (%zu bytes)\n", env_size);
	fwrite(buf, 1, env_size, out);
	memset(dest, 0x00, strlen(dest));
	sprintf(dest, "%s/tz.bin", destdir);
	freopen(dest, "wb", out);
	if (out == NULL)
		err_exit("Can't open file %s for writing\n", dest);

	buf = realloc(buf, tz_size);
	memset(buf, 0x00, tz_size);
	fseek(in, tz_off, SEEK_SET);
	n = fread(buf, 1, tz_size, in);
	if (n != tz_size) {
		free(buf);
		fclose(in);
		fclose(out);
		err_exit("Error, tz.bin size mismatch!\n");
	}
	printf("Extracting tz.bin... (%zu bytes)\n", tz_size);
	fwrite(buf, 1, tz_size, out);
	free(buf);
}

int is_mtk_boot(const char *filename) {
	FILE *in = fopen(filename, "rb");
	if (in == NULL) {
		err_exit("Can't open file %s\n", filename);
	}
	fseek(in, 0, SEEK_END);
	int fsize = ftell(in);
	if (fsize < MTK_PBL_SIZE) {
		fclose(in);
		return 0;
	}

	fseek(in, 0x100, SEEK_SET);
	char magic[] = "MTK/DTV/ROMCODE/MSDCBOOT";
	char buf[sizeof(magic)];
	fread(&buf, 1, sizeof(magic), in);
	fclose(in);
	if (memcmp(&buf, &magic, sizeof(magic) - 1) == 0) {
		printf("Found valid PBL magic: %s\n", magic);
		return 1;
	}
	return 0;
}

int is_elf_mem(Elf32_Ehdr * header) {
	size_t headerSize = 4;
	if (!memcmp(&header->e_ident, ELFMAG, headerSize))
		return 1;
	return 0;
}

int is_elf(const char *filename) {
	FILE *file = fopen(filename, "rb");
	if (file == NULL) {
		err_exit("Can't open file %s\n", filename);
	}
	Elf32_Ehdr header;
	int read = fread(&header, 1, sizeof(header), file);
	if (read == sizeof(header)) {
		return is_elf_mem(&header);
	}
	return 0;
}

int is_lzhs(const char *filename) {
	FILE *file = fopen(filename, "rb");
	if (file == NULL) {
		err_exit("Can't open file %s\n", filename);
	}
	size_t threshold = 10;
	struct lzhs_header header;
	int read = fread(&header, 1, sizeof(header), file);
	if (read == sizeof(header)) {
		fseek(file, 0, SEEK_END);
		size_t diff = ftell(file) - sizeof(header) - header.compressedSize;
		if (diff <= threshold && (memcmp(&header.spare, "\0\0\0\0\0\0\0", sizeof(header.spare)) == 0)) {
			fclose(file);
			return 1;
		}
	}
	fclose(file);
	return 0;
}

int is_gzip(const char *filename) {
	FILE *file = fopen(filename, "rb");
	if (file == NULL) {
		err_exit("Can't open file %s\n", filename);
	}
	size_t headerSize = 0x3;
	unsigned char buffer[sizeof(char) * headerSize];
	int read = fread(buffer, 1, headerSize, file);
	int result = 0;
	if (read == headerSize) {
		result = !memcmp(&buffer[0x0], "\x1F\x8B\x08", 3);	//gzip magic check
	}
	fclose(file);
	return result;
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
	time_t rawtime = time(NULL);
	struct tm time_val;
	struct tm *systime = localtime(&rawtime);
	
	// datetime format is YYYYMMDD
	if (strptime(datetime, "%Y%m%d", &time_val) != 0
		&& (systime->tm_year >= time_val.tm_year)
		&& ((time_val.tm_year+1900) > 2005)) {
		return 1;
	} else {
		return 0;
	}
}

/* detect_model - detect model and corresponding part struct */
part_struct_type detect_model(struct p2_device_info * pid) {
	part_struct_type retval;
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
		model = "Mtk 2012 - MTK5369";
	else if (ismtk2)
		model = "Mtk 2013 - MTK5398";
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

	if (isdatetime((char *)cmagic)) {
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

	struct image_header *image_header = (struct image_header *)(&buffer);
	FILE *out = fopen(destination_file, "wb");
	int header_size = sizeof(struct image_header);
	fwrite(buffer + header_size, 1, read - header_size, out);
	free(buffer);
	fclose(out);
}
