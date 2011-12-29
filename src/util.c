#include <stdio.h>
#include <ctype.h>
#include <ftw.h>
#include <unistd.h>

#include <config.h>



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
		if (lOutLen > 16)
			lOutLen = 16;

		// create a 64-character formatted output line:
		sprintf(szBuf, " >                            "
			"                      "
			"    %08lX", pTmp - pAddress);
		lOutLen2 = lOutLen;

		for (lIndex = 1 + lIndent, lIndex2 = 53 - 15 + lIndent, lRelPos = 0; lOutLen2; lOutLen2--, lIndex
				+= 2, lIndex2++) {
			ucTmp = *pTmp++;

			sprintf(szBuf + lIndex, "%02X ", (unsigned short) ucTmp);
			if (!isprint(ucTmp))
				ucTmp = '.'; // nonprintable char
			szBuf[lIndex2] = ucTmp;

			if (!(++lRelPos & 3)) // extra blank after 4 bytes
			{
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

int unlink_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
    int rv = remove(fpath);

    if (rv)
        perror(fpath);

    return rv;
}

int rmrf(char *path)
{
    return nftw(path, unlink_cb, 64, FTW_DEPTH | FTW_PHYS);
}

void create_dir_if_not_exist(const char *directory) {
	struct stat st;
	if (stat(directory, &st) != 0) {
		if (mkdir((const char*) directory, 0744) != 0) {
			printf("FATAL: Can't create directory '%s'",
					directory);
			exit(1);
		}
	}
}

void construct_path(char *result_path, const char *first, const char *second, const char* postfix) {
	strcat(result_path, first);
	strcat(result_path, G_DIR_SEPARATOR_S);
	strcat(result_path, second);
	if(postfix != NULL) {
		strcat(result_path, postfix);
	}
}

