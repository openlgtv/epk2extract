#ifndef __LZMA_H__
#define __LZMA_H__

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "jffs2/jffs2.h"
#ifndef PAGE_SIZE
	extern int page_size;
	#define PAGE_SIZE page_size
#endif
#define LZMA_MALLOC malloc
#define LZMA_FREE free
#define PRINT_ERROR(msg) fprintf(stderr, msg)
#define INIT
#define STATIC

#ifndef __APPLE__
#    include <asm/types.h>
#endif

#include "lzma/LzmaDec.h"
#include "lzma/LzmaEnc.h"

#define LZMA_BEST_LEVEL (9)
#define LZMA_BEST_LC    (0)
#define LZMA_BEST_LP    (0)
#define LZMA_BEST_PB    (0)
#define LZMA_BEST_FB  (273)

#define LZMA_BEST_DICT(n) (((int)((n) / 2)) * 2)

static void *p_lzma_malloc(void *p, size_t size)
{
        if (size == 0)
                return NULL;

        return LZMA_MALLOC(size);
}

static void p_lzma_free(void *p, void *address)
{
        if (address != NULL)
                LZMA_FREE(address);
}

static ISzAlloc lzma_alloc = {p_lzma_malloc, p_lzma_free};

#endif
