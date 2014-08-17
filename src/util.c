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
#include <time.h>

//partinfo
#include <fnmatch.h>
#include <partinfo.h>

//jffs2
#include <jffs2/jffs2.h>

#include <formats.h>

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

char *remove_ext(char* mystr) {
    char *retstr;
    char *lastdot;
    if (mystr == NULL)
         return NULL;
    if ((retstr = malloc (strlen (mystr) + 1)) == NULL)
        return NULL;
    strcpy (retstr, mystr);
    lastdot = strrchr (retstr, '.');
    if (lastdot != NULL)
        *lastdot = '\0';
    return retstr;
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

int is_lzhs(const char *filename) {
	FILE *file = fopen(filename, "rb");
	if(file == NULL){
		printf("Can't open file %s\n", filename);
		exit(1);
	}
	size_t headerSize = sizeof(struct lzhs_header);
	unsigned char *buffer = (unsigned char *)malloc(headerSize);
	int read  = fread(buffer, 1, headerSize, file);
	int result = 0;
	if (read == headerSize){
		struct lzhs_header *header = (struct lzhs_header *)buffer;
		printf("%d\t%d\t0x%1x\n", header->compressedSize, header->uncompressedSize, header->checksum);
		
		if ((header->compressedSize <= header->uncompressedSize) && !memcmp(&header->spare, "\x00\x00\x00\x00\x00\x00\x00", sizeof(header->spare))) result=1;
	}
	free(buffer);
	fclose(file);
	return result;
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
	// datetime format is YYYYMMDD
	struct tm   time_val;
	if ((strptime(datetime,"%Y%m%d",&time_val)) == 0)
		return 0;
	else
		return 1;
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
	int ismtk1_1 = !fnmatch("mtk5369-emmc",pid->name,FNM_NOMATCH); //match mtk2012

	int ismtk2   = !fnmatch("mtk3598-emmc",pid->name,FNM_NOMATCH); //match mtk2013
	int ismtk2_2 = !fnmatch("mtk5398-emmc",pid->name,FNM_NOMATCH); //match mtk2013
	
	int is1152 = !fnmatch("l9_emmc",pid->name,FNM_NOMATCH); //match 1152
	int is1154 = !fnmatch("h13_emmc",pid->name,FNM_NOMATCH); //match 1154
	int isbcm1  = !fnmatch("bcm35xx_map0",pid->name,FNM_NOMATCH); //match broadcom
	int isbcm2  = !fnmatch("bcm35230_map0",pid->name,FNM_NOMATCH); //match broadcom
	int ismstar= !fnmatch("mstar_map0",pid->name,FNM_NOMATCH); //match mstar
	
	if(ismtk1 || ismtk1_1) model="Mtk 2012 - MTK5369";
	else if(ismtk2 || ismtk2_2)	model="Mtk 2012 - MTK5398";
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
        char *cmagic=malloc(4);
	sprintf(cmagic, "%x", pi->magic);
	
	if (isdatetime((char *)cmagic)) {
		printf("Found valid partpak magic 0x%x in %s\n", pi->magic, filename);
	}
	
	ps = detect_model(&(pi->dev));
	if (ps != -1) result = 1;
	fclose(file);
	return result;
}

#define TS_PACKET_SIZE 192
AES_KEY AESkey;

void setKey() {
	FILE *keyFile = fopen("dvr", "r");
	if (keyFile == NULL) {
		printf("dvr is not found.\n");
		return;
	}
	unsigned char wKey[24];
	int read = fread(&wKey, 1, 24, keyFile);
	fclose(keyFile);

	printf("Wrapped key: ");
	int i;
	for (i = 0; i < sizeof(wKey); i++) printf("%02X", wKey[i]);
	
	unsigned char drm_key[0x10];
	printf("\nUnwrap key: ");
	for (i = 0; i < sizeof(drm_key); i++) printf("%02X", drm_key[i] = i);

	static const unsigned char iv[] = { 0xB7,0xB7,0xB7,0xB7,0xB7,0xB7,0xB7,0xB7 };

	AES_set_decrypt_key(drm_key, 128, &AESkey);
	AES_unwrap_key(&AESkey, iv, drm_key, wKey, 24);
	printf("\nUnwrapped key: ");
	for (i = 0; i < sizeof(drm_key); i++) printf("%02X", drm_key[i]);
	AES_set_decrypt_key(drm_key, 128, &AESkey);
}

static const unsigned int crc_table[256] = {
   0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9, 0x130476dc, 0x17c56b6b,
   0x1a864db2, 0x1e475005, 0x2608edb8, 0x22c9f00f, 0x2f8ad6d6, 0x2b4bcb61,
   0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd, 0x4c11db70, 0x48d0c6c7,
   0x4593e01e, 0x4152fda9, 0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75,
   0x6a1936c8, 0x6ed82b7f, 0x639b0da6, 0x675a1011, 0x791d4014, 0x7ddc5da3,
   0x709f7b7a, 0x745e66cd, 0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039,
   0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5, 0xbe2b5b58, 0xbaea46ef,
   0xb7a96036, 0xb3687d81, 0xad2f2d84, 0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d,
   0xd4326d90, 0xd0f37027, 0xddb056fe, 0xd9714b49, 0xc7361b4c, 0xc3f706fb,
   0xceb42022, 0xca753d95, 0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1,
   0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d, 0x34867077, 0x30476dc0,
   0x3d044b19, 0x39c556ae, 0x278206ab, 0x23431b1c, 0x2e003dc5, 0x2ac12072,
   0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16, 0x018aeb13, 0x054bf6a4,
   0x0808d07d, 0x0cc9cdca, 0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde,
   0x6b93dddb, 0x6f52c06c, 0x6211e6b5, 0x66d0fb02, 0x5e9f46bf, 0x5a5e5b08,
   0x571d7dd1, 0x53dc6066, 0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba,
   0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e, 0xbfa1b04b, 0xbb60adfc,
   0xb6238b25, 0xb2e29692, 0x8aad2b2f, 0x8e6c3698, 0x832f1041, 0x87ee0df6,
   0x99a95df3, 0x9d684044, 0x902b669d, 0x94ea7b2a, 0xe0b41de7, 0xe4750050,
   0xe9362689, 0xedf73b3e, 0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2,
   0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686, 0xd5b88683, 0xd1799b34,
   0xdc3abded, 0xd8fba05a, 0x690ce0ee, 0x6dcdfd59, 0x608edb80, 0x644fc637,
   0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb, 0x4f040d56, 0x4bc510e1,
   0x46863638, 0x42472b8f, 0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53,
   0x251d3b9e, 0x21dc2629, 0x2c9f00f0, 0x285e1d47, 0x36194d42, 0x32d850f5,
   0x3f9b762c, 0x3b5a6b9b, 0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff,
   0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623, 0xf12f560e, 0xf5ee4bb9,
   0xf8ad6d60, 0xfc6c70d7, 0xe22b20d2, 0xe6ea3d65, 0xeba91bbc, 0xef68060b,
   0xd727bbb6, 0xd3e6a601, 0xdea580d8, 0xda649d6f, 0xc423cd6a, 0xc0e2d0dd,
   0xcda1f604, 0xc960ebb3, 0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7,
   0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b, 0x9b3660c6, 0x9ff77d71,
   0x92b45ba8, 0x9675461f, 0x8832161a, 0x8cf30bad, 0x81b02d74, 0x857130c3,
   0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640, 0x4e8ee645, 0x4a4ffbf2,
   0x470cdd2b, 0x43cdc09c, 0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8,
   0x68860bfd, 0x6c47164a, 0x61043093, 0x65c52d24, 0x119b4be9, 0x155a565e,
   0x18197087, 0x1cd86d30, 0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec,
   0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088, 0x2497d08d, 0x2056cd3a,
   0x2d15ebe3, 0x29d4f654, 0xc5a92679, 0xc1683bce, 0xcc2b1d17, 0xc8ea00a0,
   0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb, 0xdbee767c, 0xe3a1cbc1, 0xe760d676,
   0xea23f0af, 0xeee2ed18, 0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4,
   0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0, 0x9abc8bd5, 0x9e7d9662,
   0x933eb0bb, 0x97ffad0c, 0xafb010b1, 0xab710d06, 0xa6322bdf, 0xa2f33668,
   0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4
};

uint32_t str_crc32(const unsigned char *data, int len) {
	uint32_t crc = 0xffffffff;
	uint32_t i;
	for (i = 0; i < len; i++) crc = (crc << 8) ^ crc_table[((crc >> 24) ^ *data++) & 0xff];
	return crc;
}

void convertSTR2TS(char* inFilename, char* outFilename, int notOverwrite) {
	FILE *inFile = fopen(inFilename, "rb");
	if (inFile == NULL) {
		printf("Can't open file %s\n", inFilename);
		return;
	}

	fseeko(inFile, 0, SEEK_END);
	uint64_t filesize = ftello(inFile); 
	rewind(inFile);
	
	FILE *outFile;
	if (notOverwrite) outFile = fopen(outFilename, "a+b"); 
	else outFile = fopen(outFilename, "wb");
	
	if (outFile == NULL) {
		printf("Can't open file %s\n", outFilename);
		return;
	}
	
	unsigned char inBuf[TS_PACKET_SIZE*10];
	unsigned char outBuf[TS_PACKET_SIZE];
	unsigned int k, rounds;			
	int syncFound = 0, j;
	fread(inBuf, 1, sizeof(inBuf), inFile);

	uint64_t i;
	struct tables {
		int number[8192];
		unsigned char type[8192];
		int pcr_count[8192];
	};  
	
	struct tables PIDs;
	memset(&PIDs, 0, sizeof(PIDs));
	int PATnotWritten = 0;
	for (i = 0; i < (sizeof(inBuf) - TS_PACKET_SIZE*2); i++) {
		if (inBuf[i] == 0x47 && inBuf[i+TS_PACKET_SIZE] == 0x47 && inBuf[i+TS_PACKET_SIZE*2] == 0x47) {
			fseeko(inFile, i-4, SEEK_SET); 
			for (i = 0; i < filesize; i += TS_PACKET_SIZE) {
				fread(inBuf, 1, TS_PACKET_SIZE, inFile);
				if (inBuf[4] != 0x47) {
					printf("\nLost sync at offset %" PRIx64 "\n", i);
					fseeko(inFile, i, SEEK_SET); 
					syncFound = 0;
					while (syncFound == 0) {
						if (fread(inBuf, 1, sizeof(inBuf), inFile) < sizeof(inBuf)) break; //prevent infinite loop at end of file
						for (j = 0; j < (sizeof(inBuf) - TS_PACKET_SIZE); j++) {
							if (inBuf[j] == 0x47 && inBuf[j+TS_PACKET_SIZE] == 0x47 && inBuf[j+TS_PACKET_SIZE*2] == 0x47) {
								syncFound = 1;
								fseeko(inFile, i+j, SEEK_SET); 
								break;
							}
						}
						i+=sizeof(inBuf);
					}
				} else {
					if (!notOverwrite && !PATnotWritten) {
						// Construct PAT
						memset(outBuf, 0xFF, TS_PACKET_SIZE);
						unsigned char PAT[21] = { 0x47, 0x40, 0x00, 0x10, 0x00, 0x00, 0xB0, 0x0D, 0x00, 0x06, 0xC7, 0x00, 0x00, 0x00, 0x01,
												0xE0, 0xB1, 0xA2, 0x89, 0x69, 0x78 };
						memcpy(outBuf, &PAT, sizeof(PAT));
						fwrite(outBuf, 1, TS_PACKET_SIZE-4, outFile);

						// Allocate PMT
						memset(outBuf, 0xFF, TS_PACKET_SIZE);
						fwrite(outBuf, 1, TS_PACKET_SIZE-4, outFile);
						PATnotWritten = 1;
					}
					memcpy(outBuf, inBuf, TS_PACKET_SIZE);
					int offset = 8;
					if ((inBuf[7] & 0xC0) == 0xC0 || (inBuf[7] & 0xC0) == 0x80) { // decrypt only scrambled packets
						if (inBuf[7] & 0x20) offset += (inBuf[8] + 1);	// skip adaption field
						outBuf[7] &= 0x3F;	// remove scrambling bits
						if (offset > TS_PACKET_SIZE) offset = TS_PACKET_SIZE; //application will crash without this check when file is corrupted
						rounds = (TS_PACKET_SIZE - offset) / 0x10;
						for (k = 0; k < rounds; k++) AES_decrypt(inBuf + offset + k*0x10, outBuf + offset + k*0x10, &AESkey); // AES CBC
					};

					// Search PCR
					if (inBuf[7] & 0x20) { // adaptation field exists
						if (outBuf[9] & 0x10) 	// check if PCR exists
							PIDs.pcr_count[(inBuf[5] << 8 | inBuf[6]) & 0x1FFF]++;
					}

					// Count PES packets only
					if (!notOverwrite && outBuf[8]==0 && outBuf[9]==0 && outBuf[10]==1) { 
						PIDs.number[(inBuf[5] << 8 | inBuf[6]) & 0x1FFF]++;
						PIDs.type[(inBuf[5] << 8 | inBuf[6]) & 0x1FFF] = outBuf[11];
					}
					fwrite(outBuf+4, 1, TS_PACKET_SIZE-4, outFile);
				}
			}
			break;
		}
	}
	fclose(inFile);
	if (!notOverwrite) {
		// Fill PMT
		memset(outBuf, 0xFF, TS_PACKET_SIZE);
		unsigned char PMT[31] = {	0x47, 0x40, 0xB1, 0x10,	0x00, 0x02, 0xB0, 
									0x17, // section length in bytes including crc
									0x00, 0x01, // program number
									0xC1, 0x00, 0x00,
									0xE4, 0x7E, // PCR PID
									0xF0, 0x00, // Program info length
									0x1B, // stream type ITU_T_H264
									0xE4, 0x7E, // PID
									0xF0, 0x00, // ES info length
									0x04, // stream type ISO/IEC 13818-3 Audio (MPEG-2)
									0xE4, 0x7F, // PID
									0xF0, 0x00, // ES info length
									0xFF, 0xFF, 0xFF, 0xFF // crc32
								  };
		

		for (i = 0; i < 8192; i++) if (PIDs.number[i] > 0) {
			//printf("PID %zX : %d Type: %zX PCRs: %zX\n", i, PIDs.number[i], PIDs.type[i], PIDs.pcr_count[i]);
			if (PIDs.pcr_count[i]>0) { // Set PCR PID
				PMT[13] = ((i >> 8) & 0xff) + 0xE0;
				PMT[14] = i & 0xff;
			}
			//Fill video stream PID (0xE0-0xEF)
			if (PIDs.type[i]>=0xE0 && PIDs.type[i]<=0xEF) { 
				PMT[18] = ((i >> 8) & 0xff) + 0xE0;
				PMT[19] = i & 0xff;
			}
			//Fill audio stream PID (0xC0-0xDF)
			if (PIDs.type[i]>=0xC0 && PIDs.type[i]<=0xDF) { 
				PMT[23] = ((i >> 8) & 0xff) + 0xE0;
				PMT[24] = i & 0xff;
			}
		}
		// Set CRC32
		uint32_t crc = str_crc32(&PMT[5], PMT[7]-1); 
		PMT[27] = (crc>>24) & 0xff;
		PMT[28] = (crc>>16) & 0xff;
		PMT[29] = (crc>>8)  & 0xff;
		PMT[30] = crc & 0xff;
		memcpy(outBuf, &PMT, sizeof(PMT));
		fseek(outFile, 0xBC, SEEK_SET);
		fwrite(outBuf, 1, TS_PACKET_SIZE-4, outFile);
	}
	fclose(outFile);
}

/* Transport Stream Header (or 4-byte prefix) consists of 32-bit:
	Sync byte						8bit	0x47
	Transport Error Indicator (TEI)	1bit	Set by demodulator if can't correct errors in the stream, to tell the demultiplexer that the packet
											has an uncorrectable error [11]
	Payload Unit Start Indicator	1bit	1 means start of PES data or PSI otherwise zero only.
	Transport Priority				1bit	1 means higher priority than other packets with the same PID.
	PID								13bit	Packet ID
	Scrambling control				2bit	'00' = Not scrambled. The following per DVB spec:[12]   
											'01' = Reserved for future use, '10' = Scrambled with even key, '11' = Scrambled with odd key
	Adaptation field exist			2bit	'01' = no adaptation fields, payload only, '10' = adaptation field only, '11' = adaptation field and payload
	Continuity counter				4bit	Incremented only when a payload is present (i.e., adaptation field exist is 01 or 11)[13]
*/

void processPIF(const char* filename, char* dest_file) {
	FILE *file = fopen(filename, "r");
	if (file == NULL) {
		printf("Can't open file %s\n", filename);
		exit(1);
	}
	fseek(file, 0, SEEK_END);
	int filesize = ftell(file);
	rewind(file);

	int append = 0;
	unsigned char* buffer = (unsigned char*) malloc(filesize);
	int read = fread(buffer, 1, filesize, file);
	if (read == filesize) {
		int i;
		for (i = 0; i < (filesize-5); i++) {
			if (!memcmp(&buffer[i], "/mnt/", 5) && !memcmp(&buffer[i+strlen(&buffer[i])-3], "STR", 3)) {
				printf("Converting file: %s\n", strrchr(&buffer[i], '/') + 1);
				convertSTR2TS(strrchr(&buffer[i], '/') + 1, dest_file, append);
				append = 1;
			}
		}
	}
	fclose(file);
	free(buffer);
}
