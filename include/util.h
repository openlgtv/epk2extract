/**
 * Copyright 2016 Smx <smxdev4@gmail.com>
 * Copyright 2016 lprot
 * All right reserved
 */
#ifndef __UTIL_H
#define __UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <elf.h>
#include "mfile.h"

#define member_size(type, member) sizeof(((type *)0)->member)
#define err_exit(fmt, ...) \
	exit(err_ret(fmt, ##__VA_ARGS__))

#ifdef __APPLE__
typedef    unsigned int    uint;
#endif

char *my_basename(const char *path);
char *my_dirname(const char *path);
int count_tokens(const char *str, char token, int sz);
void getch(void);
void hexdump(void *pAddressIn, long lSize);
void rmrf(const char *path);
int err_ret(const char *format, ...);

char *remove_ext(const char *mystr);
char *get_ext(const char *mystr);
void createFolder(const char *directory);
MFILE *is_lz4(const char *lz4file);
bool is_nfsb_mem(MFILE *file, off_t offset);
MFILE *is_nfsb(const char *filename);
void unnfsb(const char *filename, const char *extractedFile);
MFILE *is_gzip(const char *filename);
int is_jffs2(const char *filename);
int isSTRfile(const char *filename);
int isdatetime(char *datetime);
int isPartPakfile(const char *filename);
int is_kernel(const char *image_file);
void extract_kernel(const char *image_file, const char *destination_file);
int asprintf_inplace(char** strp, const char* fmt, ...);


#include <errno.h>
void print(int verbose, int newline, char *fn, int lineno, const char *fmt, ...);
#define WHEREARG  __FILE__, __LINE__
#define PRINT(...) print(0, 0 , WHEREARG, __VA_ARGS__)
#define VERBOSE(N,...) print(N, 0, WHEREARG, __VA_ARGS__)
#define VERBOSE_NN(N,...) print(N, 0, WHEREARG, __VA_ARGS__)
#define PERROR_SE(fmt, ...) print(0, 0, WHEREARG, "ERROR: " fmt " (%s)", ## __VA_ARGS__, strerror(errno))
#define PERROR(...) print(0, 1, WHEREARG, "ERROR: " __VA_ARGS__)

#if __WORDSIZE == 64
#   define LX "%lx"
#   define LLX LX
#   define LU "%lu"
#else
#   define LX "%x"
#   define LLX "%llx"
#   define LU "%u"
#endif 

#ifdef __cplusplus
}
#endif

#endif
