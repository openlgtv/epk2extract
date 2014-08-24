#include <stdio.h>
#include <ctype.h>
#define __USE_XOPEN_EXTENDED
#include <ftw.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <termios.h>
#include <config.h>
#include <openssl/aes.h>
#include <inttypes.h>
#include <libgen.h>

//partinfo
#include <time.h>
#include <fnmatch.h>
#include <partinfo.h>

//jffs2
#include <jffs2/jffs2.h>

//lzhs
#include <lzhs/lzhs.h>

#include <elf.h>

//kernel
#include <u-boot/image.h>
#include <arpa/inet.h>

//minigzip
#include <minigzip.h>

int ps;
char *modelname;
char *mtdname;

void SwapBytes(void *pv, size_t n)
{
    char *p = pv;
    size_t lo, hi;
    for(lo=0, hi=n-1; hi>lo; lo++, hi--)
    {
        char tmp=p[lo];
        p[lo] = p[hi];
        p[hi] = tmp;
    }
}

void getch(void) {
	struct termios oldattr, newattr;
	int ch;
	tcgetattr(STDIN_FILENO, &oldattr );
	newattr = oldattr;
	newattr.c_lflag &= ~(ICANON | ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &newattr);
	ch = getchar();
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
	unsigned char *pAddress = (unsigned char *) pAddressIn;

	buf.pData = (char *) pAddress;
	buf.lSize = lSize;

	while (buf.lSize > 0) {
		pTmp = (unsigned char *) buf.pData;
		lOutLen = (int) buf.lSize;
		if (lOutLen > 16) lOutLen = 16;

		// create a 64-character formatted output line:
		sprintf(szBuf, " >                                                      %08zX", pTmp - pAddress);
		lOutLen2 = lOutLen;

		for (lIndex = 1 + lIndent, lIndex2 = 53 - 15 + lIndent, lRelPos = 0; lOutLen2; lOutLen2--, lIndex += 2, lIndex2++) {
			ucTmp = *pTmp++;
			sprintf(szBuf + lIndex, "%02X ", (unsigned short) ucTmp);
			if (!isprint(ucTmp))
				ucTmp = '.'; // nonprintable char
			szBuf[lIndex2] = ucTmp;

			if (!(++lRelPos & 3)) { // extra blank after 4 bytes
				lIndex++;
				szBuf[lIndex + 2] = ' ';
			}
		}
		if (!(lRelPos & 3)) lIndex--;
		szBuf[lIndex] = '<';
		szBuf[lIndex + 1] = ' ';
		printf("%s\n", szBuf);
		buf.pData += lOutLen;
		buf.lSize -= lOutLen;
	}
}

int unlink_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
	int rv = remove(fpath);
	if (rv) perror(fpath);
	return rv;
}

void rmrf(char *path) {
	struct stat status;
	if (stat(path, &status) == 0) nftw(path, unlink_cb, 64, FTW_DEPTH | FTW_PHYS);
}

void createFolder(const char *directory) {
	struct stat st;
	if (stat(directory, &st) != 0) {
		if (mkdir((const char*) directory, 0744) != 0) {
			printf("FATAL: Can't create directory '%s'\n", directory);
			exit(1);
		}
	}
}

void constructPath(char *result_path, const char *first, const char *second, const char* postfix) {
	strcat(result_path, first);
	strcat(result_path, G_DIR_SEPARATOR_S);
	strcat(result_path, second);
	if(postfix != NULL) strcat(result_path, postfix);
}

int is_lz4(const char *lz4file) {
	FILE *file = fopen(lz4file, "r");
	if (file == NULL) {
		printf("Can't open file %s", lz4file);
		exit(1);
	}
	size_t headerSize = 4;
	unsigned char* buffer = (unsigned char*) malloc(sizeof(char) * headerSize);
	int read = fread(buffer, 1, headerSize, file);
	if (read != headerSize) return 0;
	fclose(file);
	int result = !memcmp(&buffer[0], "LZ4P", 4); 
	free(buffer);
	return result;
}

int is_nfsb(const char *filename) {
	FILE *file = fopen(filename, "r");
	if (file == NULL) {
		printf("Can't open file %s", filename);
		exit(1);
	}
	size_t headerSize = 0x10;
	unsigned char* buffer = (unsigned char*) malloc(sizeof(char) * headerSize);
	int read = fread(buffer, 1, headerSize, file);
	int result = 0;
	if (read == headerSize) {
		result = !memcmp(&buffer[0x0], "NFSB", 4);
		if (!result) result = !memcmp(&buffer[0xE], "md5", 3);
	}
	fclose(file);
	free(buffer);
	return result;
}

void unnfsb(char* filename, char* extractedFile) {
	int fdin, fdout;
	char *src, *dst;
	struct stat statbuf;
	int headerSize = 0x1000;
	/* open the input file */
	if ((fdin = open (filename, O_RDONLY)) < 0) printf("Can't open file %s for reading\n", filename);

	/* open/create the output file */
	if ((fdout = open (extractedFile, O_RDWR | O_CREAT | O_TRUNC, (mode_t)0600)) < 0) 
		printf("Can't create file %s for writing\n", extractedFile);

	/* find size of input file */
	if (fstat (fdin, &statbuf) < 0) printf("fstat error\n");

	/* mmap the input file */
	if ((src = mmap (0, statbuf.st_size, PROT_READ, MAP_SHARED, fdin, 0)) == (caddr_t) -1)
		printf("mmap error for input\n");

	/* go to the location corresponding to the last byte */
	if (lseek (fdout, statbuf.st_size - headerSize - 1, SEEK_SET) == -1) printf("lseek error\n");
 
	/* write a dummy byte at the last location */
	if (write (fdout, "", 1) != 1) printf("write error\n");

	/* mmap the output file */
	if ((dst = mmap (0, statbuf.st_size - headerSize, PROT_READ | PROT_WRITE, MAP_SHARED, fdout, 0)) == (caddr_t) -1)
		printf("mmap error for output\n");
	/* this copies the input file to the output file */
		memcpy(dst, &src[headerSize], statbuf.st_size - headerSize);

	/* Don't forget to free the mmapped memory */
	if (munmap(src, statbuf.st_size) == -1) printf("Error un-mmapping the file");
	if (munmap(dst, statbuf.st_size - headerSize) == -1) printf("Error un-mmapping the file");

	/* Un-mmaping doesn't close the file, so we still need to do that. */
	close(fdout);
	close(fdin);
}	

size_t mtk_pbl_size = 0x9FFF;

void extract_mtk_boot(const char *filename, const char *outname){
	char *buf = malloc(mtk_pbl_size);
	int n;

	FILE *in = fopen(filename, "rb");
	if(in == NULL){
		printf("Can't open file %s\n", filename);
		exit(1);
	}
	FILE *out = fopen(outname, "wb");
	if(out == NULL){
		printf("Can't open file %s for writing\n", outname);
		exit(1);
	}
	n = fread(buf, 1, mtk_pbl_size, in);
	if(n != mtk_pbl_size){
		printf("Error!\n");
		fclose(in);
		exit(1);
	}
	fclose(in);
	fwrite(buf, 1, mtk_pbl_size, out);
	fclose(out);
}

void split_mtk_tz(const char *filename, const char *destdir){
	unsigned int tz_off = 0x20000;
	unsigned char *buf;
	char *dest = malloc(strlen(destdir)+strlen(filename)+10);
	int n;
	size_t fileSize, env_size, tz_size;
	FILE *in = fopen(filename, "rb");
	if(in == NULL){
		printf("Can't open file %s\n", filename);
		exit(1);
	}
	memset(dest, 0x00, sizeof(dest));
	constructPath(dest, destdir, "env.o", "");
	FILE *out = fopen(dest, "wb");
	if(out == NULL){
		printf("Can't open file %s for writing\n", dest);
		exit(1);
	}
	fseek(in, 0, SEEK_END);
	fileSize = ftell(in);
	rewind(in);
	env_size = tz_off;
	tz_size = fileSize - env_size;
	buf = malloc(env_size);
	n = fread(buf, 1, env_size, in);
	if(n != env_size){
		printf("Error, cannot read %s!\n", dest);
		fclose(in); fclose(out);
		exit(1);
	}
	printf("Extracting env.o ...\n");
	fwrite(buf, 1, env_size, out);
	memset(dest, 0x00, strlen(dest));
	constructPath(dest, destdir, "tz.bin", "");
	freopen(dest, "wb", out);
	if(out == NULL){
		printf("Can't open file %s for writing\n", dest);
		exit(1);
	}
	buf = realloc(buf, tz_size);
	memset(buf, 0x00, tz_size);
	fseek(in, tz_off, SEEK_SET);
	n = fread(buf, 1, tz_size, in);
	if(n != tz_size){
		printf("Error, cannot read %s!\n", dest);
		fclose(in); fclose(out);
		exit(1);
	}
	printf("Extracting tz.bin ...\n");
	fwrite(buf, 1, tz_size, out);
}

int is_mtk_boot(const char *filename){
	FILE *in = fopen(filename, "rb");
	if(in == NULL){
		printf("Can't open file %s\n", filename);
		return 0;
	}
	fseek(in, 0, SEEK_END);
	int fsize = ftell(in);
	if (fsize < mtk_pbl_size){
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

int is_elf_mem(Elf32_Ehdr *header){
	size_t headerSize = 4;
	if(!memcmp(&header->e_ident, ELFMAG, headerSize))
		return 1;
	return 0;
}

int is_elf(const char *filename){
	FILE *file = fopen(filename, "rb");
	if(file == NULL){
		printf("Can't open file %s\n", filename);
		exit(1);
	}
	Elf32_Ehdr header;
	int read = fread(&header, 1, sizeof(header), file);
	if(read == sizeof(header)){
		return is_elf_mem(&header);
	}
	return 0;
}

int is_lzhs_mem(struct lzhs_header *header){
    if ((header->compressedSize <= 0xFFFFFF) && (header->uncompressedSize >= 0x1FFFFFF)) return 0;
	if (header->compressedSize && header->uncompressedSize && (header->compressedSize <= header->uncompressedSize) && 
        !memcmp(&header->spare, "\x00\x00\x00\x00\x00\x00\x00", sizeof(header->spare))) return 1;
	return 0;
}

int is_lzhs(const char *filename) {
	FILE *file = fopen(filename, "rb");
	if(file == NULL){
		printf("Can't open file %s\n", filename);
		return 0;
	}
    struct lzhs_header header;
	int read  = fread(&header, 1, sizeof(header), file);
	fclose(file);
	if (read == sizeof(header))
        return is_lzhs_mem(&header);
	return 0;
}

int is_gzip(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
	printf("Can't open file %s\n", filename);
	exit(1);
    }
    size_t headerSize = 0x3;
    unsigned char* buffer = (unsigned char*) malloc(sizeof(char) * headerSize);
    int read = fread(buffer, 1, headerSize, file);
    int result = 0;
    if (read == headerSize){
	result = !memcmp(&buffer[0x0], "\x1F\x8B\x08", 3);
    }
    free(buffer);
    fclose(file);
    return result;
}
    
int is_jffs2(const char *filename) {
	FILE *file = fopen(filename, "r");
	if (file == NULL) {
		printf("Can't open file %s\n", filename);
		exit(1);
	}
	size_t headerSize = 0x2;
	unsigned short magic = JFFS2_MAGIC_BITMASK;
	unsigned char* buffer = (unsigned char*) malloc(sizeof(char) * headerSize);
	int read = fread(buffer, 1, headerSize, file);
	int result = 0;
	if (read == headerSize){
	    result = !memcmp(&buffer[0x0], &magic, 2);
	    if(!result){
		magic=JFFS2_OLD_MAGIC_BITMASK;
		result = !memcmp(&buffer[0x0], &magic, 2);
	    }
	}
	fclose(file);
	free(buffer);
	return result;
}

int isSTRfile(const char *filename) {
	FILE *file = fopen(filename, "r");
	if (file == NULL) {
		printf("Can't open file %s\n", filename);
		exit(1);
	}
	size_t headerSize = 0xC0*4;
	unsigned char* buffer = (unsigned char*) malloc(sizeof(char) * headerSize);
	int read = fread(buffer, 1, headerSize, file);
	int result = 0;
	if (read == headerSize && buffer[4] == 0x47 && buffer[0xC0+4] == 0x47 && buffer[0xC0*2+4] == 0x47 && buffer[0xC0*3+4] == 0x47) result=1;
	fclose(file);
	free(buffer);
	return result;
}

int isdatetime(char *datetime)
{
	time_t rawtime;
	struct tm time_val;
	struct tm *systime;
	systime = localtime(&rawtime);
	// datetime format is YYYYMMDD
	if(strptime(datetime,"%Y%m%d",&time_val) != 0 && (time_val.tm_year > 2005 && time_val.tm_year <= systime->tm_year))
		return 1;
	else
		return 0;
}

/* detect_model - detect model and corresponding part struct
0 --> partinfo v2 struct
1 --> partinfo v1 struct
2 --> mdtinfo struct */
int detect_model(struct p2_device_info *pid){
	int retval;
	char *model;
	retval = 0; //partinfo v2
	int ismtk1   = !fnmatch("mtk3569-emmc",pid->name,FNM_NOMATCH); //match mtk2012
	int ismtk2   = !fnmatch("mtk3598-emmc",pid->name,FNM_NOMATCH); //match mtk2013
	int is1152 = !fnmatch("l9_emmc",pid->name,FNM_NOMATCH); //match 1152
	int is1154 = !fnmatch("h13_emmc",pid->name,FNM_NOMATCH); //match 1154
	int isbcm1  = !fnmatch("bcm35xx_map0",pid->name,FNM_NOMATCH); //match broadcom
	int isbcm2  = !fnmatch("bcm35230_map0",pid->name,FNM_NOMATCH); //match broadcom
	int ismstar= !fnmatch("mstar_map0",pid->name,FNM_NOMATCH); //match mstar
	
	if(ismtk1) model="Mtk 2012 - MTK5369";
	else if(ismtk2)	model="Mtk 2012 - MTK5398";
	else if(is1152)	model="LG1152";
	else if(is1154)	model="LG1154";
	else if(isbcm1)	model="BCM 2011 - BCM35230";
	else if(isbcm2)	model="BCM 2010 - BCM35XX";
	else if(ismstar) model="Mstar Saturn/LM1";
	else return -1;
	
	if(!ismtk2 && !is1154){
		if(ismtk1 || is1152) retval=1; //partinfo v1
		else retval=2; //mtdinfo
	}
	mtdname=pid->name;
	modelname=model;
	/*printf("\nMTD name -> %s\n",mtdname);
	printf("%s Detected\n\n", modelname);*/

	return retval;
}

int isPartPakfile(const char *filename) {
   FILE *file = fopen(filename, "rb");
	if (file == NULL) {
		printf("Can't open file %s\n", filename);
		exit(1);
	}
	struct p2_partmap_info partinfo;
	
	struct p2_partmap_info *pi= (struct p2_partmap_info*)malloc(sizeof(struct p2_partmap_info));       
	
	size_t size = sizeof(struct p2_partmap_info);
	fread(pi, 1, size, file);
	
	memcpy(&partinfo, pi, sizeof(struct p2_partmap_info));
	
	int result = 0;
	char cmagic[4];
	sprintf(cmagic, "%x", pi->magic);
	
	if (isdatetime((char *)cmagic)) {
		printf("Found valid partpak magic 0x%x in %s\n", pi->magic, filename);
	}
	
	ps = detect_model(&(pi->dev));
	if (ps != -1) result = 1;
	fclose(file);
	return result;
}

int is_kernel(const char *image_file) {
	FILE *file = fopen(image_file, "r");
	if (file == NULL) {
		printf("Can't open file %s", image_file);
		exit(1);
	}
	size_t header_size = sizeof(struct image_header);
	unsigned char* buffer = (unsigned char*) malloc(sizeof(char) * header_size);
	int read = fread(buffer, 1, header_size, file);
	if (read != header_size) return 0;
	fclose(file);
	struct image_header *image_header = (struct image_header *) buffer;
	int result = image_header->ih_magic == ntohl(IH_MAGIC);
	free(buffer);
	return result;
}

void extract_kernel(const char *image_file, const char *destination_file) {
	FILE *file = fopen(image_file, "r");
	if (file == NULL) {
		printf("Can't open file %s", image_file);
		exit(1);
	}
	fseek(file, 0, SEEK_END);
	int fileLength = ftell(file);
	rewind(file);
	unsigned char* buffer = (unsigned char*) malloc(sizeof(char) * fileLength);
	int read = fread(buffer, 1, fileLength, file);
	if (read != fileLength) {
		printf("Error reading file. read %d bytes from %d.\n", read, fileLength);
		free(buffer);
		exit(1);
	}
	fclose(file);

	struct image_header *image_header = (struct image_header *) buffer;
	FILE *out = fopen(destination_file, "w");
	int header_size = sizeof(struct image_header);
	fwrite(buffer + header_size, 1, read - header_size, out);
	fclose(out);
	free(buffer);
}
