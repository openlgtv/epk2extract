/**
 * mmap file wrapper
 * Copyright 2016 Smx <smxdev4@gmail.com>
 * All right reserved
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include "mfile.h"

#include "common.h"
#include "util.h"

#define PERMS_DEFAULT (mode_t)0666

/*
 * Creates a new mfile structure
 */
inline MFILE *mfile_new(){
	MFILE *mem = calloc(1, sizeof(MFILE));
	return mem;
}

/*
 * Updates size and path to a file
 */
int _mfile_update_info(MFILE *file, const char *path){
	if(path){
		if(file->path)
			free(file->path);
		file->path = strdup(path);
	}
	if(stat(file->path, &(file->statBuf)) < 0)
		return -1;
	return 0;
}

void mfile_flush(void *mem, size_t length){
	msync(mem, length, MS_INVALIDATE);
	//madvise(mem, length, MADV_REMOVE);
}

/*
 * Wrapper to mmap
 */
void *_mfile_map(MFILE *file, size_t mapSize, int mapFlags){
	if(msize(file) < mapSize){
		lseek(file->fd, mapSize-1, SEEK_SET);
		uint8_t buf = 0x00;
		write(file->fd, &buf, 1);
		lseek(file->fd, 0, SEEK_SET);
		_mfile_update_info(file, NULL);
	}
	file->pMem = mmap(0, mapSize, file->prot, mapFlags, file->fd, 0);
	if(file->pMem == MAP_FAILED){
		err_exit("mmap failed: %s (%d)\n", strerror(errno), errno);
		return NULL;
	}

	// enable read ahead and trash previously read pages
	madvise(file->pMem, mapSize, MADV_SEQUENTIAL);
	return file->pMem;
}

inline void *mfile_map(MFILE *file, size_t mapSize){
	return _mfile_map(file, mapSize, MAP_SHARED);
}

inline void *mfile_map_private(MFILE *file, size_t mapSize){
	return _mfile_map(file, mapSize, MAP_PRIVATE);
}

/*
 * Opens and maps a file with open
 */
MFILE *_mopen(const char *path, int oflags, int mapFlags){
	MFILE *file = mfile_new();
	file->fd = open(path, oflags, PERMS_DEFAULT);
	if(file->fd < 0){
		goto e0_ret;
	}
	
	if(_mfile_update_info(file, path) < 0)
		goto e1_ret;
	
	if((oflags & O_ACCMODE) == O_RDONLY) {
		file->prot = PROT_READ;
	} else if((oflags & O_ACCMODE) == O_WRONLY) {
		file->prot = PROT_WRITE;
	} else if((oflags & O_ACCMODE) == O_RDWR) {
		file->prot = PROT_READ | PROT_WRITE;
	}

	size_t fileSz = msize(file);
	if(fileSz > 0){
		if(_mfile_map(file, fileSz, mapFlags) == MAP_FAILED){
			goto e1_ret;
		}
	}
	return file;

	e1_ret:
		close(file->fd);
	e0_ret:
		if(file->path)
			free(file->path);
		free(file);
		return NULL;
}

inline MFILE *mopen(const char *path, int oflags){
	return _mopen(path, oflags, MAP_SHARED);
}

inline MFILE *mopen_private(const char *path, int oflags){
	return _mopen(path, oflags, MAP_PRIVATE);
}

int mgetc(MFILE *stream){
	if(UNLIKELY(stream->offset >= msize(stream)))
		return EOF;
	return (unsigned int)(*(&((uint8_t *)(stream->pMem))[stream->offset++]));
}

int mputc(int c, MFILE *stream){
	if(UNLIKELY(stream->offset >= msize(stream)))
		return EOF;
	((uint8_t *)(stream->pMem))[stream->offset] = (uint8_t)c;
	stream->offset++;
	return c;
}

inline int cgetc(cursor_t *stream){
	if(UNLIKELY(stream->offset >= stream->size))
		return EOF;
	return (unsigned int)(
		*(&(
			((unsigned char *)(stream->ptr))[stream->offset++]
		))
	);
}

int cputc(int c, cursor_t *stream){
	if(UNLIKELY(stream->offset >= stream->size))
		return EOF;
	((unsigned char *)(stream->ptr))[stream->offset++] = (unsigned char)c;
	return c;
}

/*
 * Closes an opened file and frees the structure
 */
int mclose(MFILE *mfile){
	if(!mfile || mfile->fd < 0 || !mfile->pMem || mfile->statBuf.st_size <= 0)
		return -1;
	if(munmap(mfile->pMem, mfile->statBuf.st_size) < 0)
		return -2;
	free(mfile->path);
	if(mfile->fh != NULL){
		fclose(mfile->fh);
		mfile->fd = 0;
	} else {
		close(mfile->fd);
	}
	free(mfile);
	mfile = NULL;
	return 0;
}

/*
 * Opens and maps a file with fopen
 */
MFILE *_mfopen(const char *path, const char *mode, int mapFlags){
	MFILE *file = mfile_new();

	file->fh = fopen(path, mode);
	if(file->fh == NULL){
		goto e0_ret;
	}
	file->fd = fileno(file->fh);
	
	if(_mfile_update_info(file, path) < 0)
		goto e1_ret;

	if(strstr(mode, "r") != NULL || strstr(mode, "+") != NULL){
		file->prot |= PROT_READ;
	}
	if(strstr(mode, "w") != NULL){
		file->prot |= PROT_WRITE;
	}

	size_t fileSz = msize(file);
	if(fileSz > 0){
		if(_mfile_map(file, fileSz, mapFlags) == MAP_FAILED){
			goto e1_ret;
		}
	}

	return file;

	e1_ret:
		fclose(file->fh);
	e0_ret:
		free(file);
		return NULL;
}

inline MFILE *mfopen(const char *path, const char *mode){
	return _mfopen(path, mode, MAP_SHARED);
}

inline MFILE *mfopen_private(const char *path, const char *mode){
	return _mfopen(path, mode, MAP_PRIVATE);
}
