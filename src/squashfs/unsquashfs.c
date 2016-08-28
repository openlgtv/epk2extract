/*
 * Unsquash a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011,
 * 2012, 2013, 2014
 * Phillip Lougher <phillip@squashfs.org.uk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * unsquashfs.c
 */

#include "unsquashfs.h"
#include "squashfs_swap.h"
#include "squashfs_compat.h"
#include "compressor.h"
#include "xattr.h"
#include "unsquashfs_info.h"
#include "stdarg.h"

#ifdef __APPLE__
#    include <sys/sysctl.h>
#else
#    include <sys/sysinfo.h>
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <limits.h>
#include <ctype.h>

struct cache *fragment_cache, *data_cache;
struct queue *to_reader, *to_inflate, *to_writer, *from_writer;
pthread_t *thread, *inflator_thread;
pthread_mutex_t fragment_mutex;

/* user options that control parallelisation */
int processors = -1;

struct super_block sBlk;
squashfs_operations s_ops;
struct compressor *comp;

int bytes = 0, swap, file_count = 0, dir_count = 0, sym_count = 0, dev_count = 0, fifo_count = 0;
char *inode_table = NULL, *directory_table = NULL;
struct hash_table_entry *inode_table_hash[65536], *directory_table_hash[65536];
int fd;
unsigned int *uid_table, *guid_table;
unsigned int cached_frag = SQUASHFS_INVALID_FRAG;
char *fragment_data;
char *file_data;
char *data;
unsigned int block_size;
unsigned int block_log;
int lsonly = FALSE, info = FALSE, force = FALSE, short_ls = TRUE;
int use_regex = FALSE;
char **created_inode;
int root_process;
int columns;
int rotate = 0;
pthread_mutex_t screen_mutex;
int progress = TRUE, progress_enabled = FALSE;
unsigned int total_blocks = 0, total_files = 0, total_inodes = 0;
unsigned int cur_blocks = 0;
int inode_number = 1;
int no_xattrs = XATTR_DEF;
int user_xattrs = FALSE;

int lookup_type[] = {
	0,
	S_IFDIR,
	S_IFREG,
	S_IFLNK,
	S_IFBLK,
	S_IFCHR,
	S_IFIFO,
	S_IFSOCK,
	S_IFDIR,
	S_IFREG,
	S_IFLNK,
	S_IFBLK,
	S_IFCHR,
	S_IFIFO,
	S_IFSOCK
};

struct test table[] = {
	{S_IFMT, S_IFSOCK, 0, 's'},
	{S_IFMT, S_IFLNK, 0, 'l'},
	{S_IFMT, S_IFBLK, 0, 'b'},
	{S_IFMT, S_IFDIR, 0, 'd'},
	{S_IFMT, S_IFCHR, 0, 'c'},
	{S_IFMT, S_IFIFO, 0, 'p'},
	{S_IRUSR, S_IRUSR, 1, 'r'},
	{S_IWUSR, S_IWUSR, 2, 'w'},
	{S_IRGRP, S_IRGRP, 4, 'r'},
	{S_IWGRP, S_IWGRP, 5, 'w'},
	{S_IROTH, S_IROTH, 7, 'r'},
	{S_IWOTH, S_IWOTH, 8, 'w'},
	{S_IXUSR | S_ISUID, S_IXUSR | S_ISUID, 3, 's'},
	{S_IXUSR | S_ISUID, S_ISUID, 3, 'S'},
	{S_IXUSR | S_ISUID, S_IXUSR, 3, 'x'},
	{S_IXGRP | S_ISGID, S_IXGRP | S_ISGID, 6, 's'},
	{S_IXGRP | S_ISGID, S_ISGID, 6, 'S'},
	{S_IXGRP | S_ISGID, S_IXGRP, 6, 'x'},
	{S_IXOTH | S_ISVTX, S_IXOTH | S_ISVTX, 9, 't'},
	{S_IXOTH | S_ISVTX, S_ISVTX, 9, 'T'},
	{S_IXOTH | S_ISVTX, S_IXOTH, 9, 'x'},
	{0, 0, 0, 0}
};

void progress_bar(long long current, long long max, int columns);

#define MAX_LINE 16384

void prep_exit() {
}

void sigwinch_handler() {
	struct winsize winsize;

	if (ioctl(1, TIOCGWINSZ, &winsize) == -1) {
		if (isatty(STDOUT_FILENO))
			ERROR("TIOCGWINSZ ioctl failed, defaulting to 80 " "columns\n");
		columns = 80;
	} else
		columns = winsize.ws_col;
}

void sigalrm_handler() {
	rotate = (rotate + 1) % 4;
}

int add_overflow(int a, int b) {
	return (INT_MAX - a) < b;
}

int shift_overflow(int a, int shift) {
	return (INT_MAX >> shift) < a;
}

int multiply_overflow(int a, int multiplier) {
	return (INT_MAX / multiplier) < a;
}

struct queue *queue_init(int size) {
	struct queue *queue = malloc(sizeof(struct queue));

	if (queue == NULL)
		EXIT_UNSQUASH("Out of memory in queue_init\n");

	if (add_overflow(size, 1) || multiply_overflow(size + 1, sizeof(void *)))
		EXIT_UNSQUASH("Size too large in queue_init\n");

	queue->data = malloc(sizeof(void *) * (size + 1));
	if (queue->data == NULL)
		EXIT_UNSQUASH("Out of memory in queue_init\n");

	queue->size = size + 1;
	queue->readp = queue->writep = 0;
	pthread_mutex_init(&queue->mutex, NULL);
	pthread_cond_init(&queue->empty, NULL);
	pthread_cond_init(&queue->full, NULL);

	return queue;
}

void queue_put(struct queue *queue, void *data) {
	int nextp;

	pthread_mutex_lock(&queue->mutex);

	while ((nextp = (queue->writep + 1) % queue->size) == queue->readp)
		pthread_cond_wait(&queue->full, &queue->mutex);

	queue->data[queue->writep] = data;
	queue->writep = nextp;
	pthread_cond_signal(&queue->empty);
	pthread_mutex_unlock(&queue->mutex);
}

void *queue_get(struct queue *queue) {
	void *data;
	pthread_mutex_lock(&queue->mutex);

	while (queue->readp == queue->writep)
		pthread_cond_wait(&queue->empty, &queue->mutex);

	data = queue->data[queue->readp];
	queue->readp = (queue->readp + 1) % queue->size;
	pthread_cond_signal(&queue->full);
	pthread_mutex_unlock(&queue->mutex);

	return data;
}

void dump_queue(struct queue *queue) {
	pthread_mutex_lock(&queue->mutex);

	printf("Max size %d, size %d%s\n", queue->size - 1, queue->readp <= queue->writep ? queue->writep - queue->readp : queue->size - queue->readp + queue->writep, queue->readp == queue->writep ? " (EMPTY)" : ((queue->writep + 1) % queue->size) == queue->readp ? " (FULL)" : "");

	pthread_mutex_unlock(&queue->mutex);
}

/* Called with the cache mutex held */
void insert_hash_table(struct cache *cache, struct cache_entry *entry) {
	int hash = CALCULATE_HASH(entry->block);

	entry->hash_next = cache->hash_table[hash];
	cache->hash_table[hash] = entry;
	entry->hash_prev = NULL;
	if (entry->hash_next)
		entry->hash_next->hash_prev = entry;
}

/* Called with the cache mutex held */
void remove_hash_table(struct cache *cache, struct cache_entry *entry) {
	if (entry->hash_prev)
		entry->hash_prev->hash_next = entry->hash_next;
	else
		cache->hash_table[CALCULATE_HASH(entry->block)] = entry->hash_next;
	if (entry->hash_next)
		entry->hash_next->hash_prev = entry->hash_prev;

	entry->hash_prev = entry->hash_next = NULL;
}

/* Called with the cache mutex held */
void insert_free_list(struct cache *cache, struct cache_entry *entry) {
	if (cache->free_list) {
		entry->free_next = cache->free_list;
		entry->free_prev = cache->free_list->free_prev;
		cache->free_list->free_prev->free_next = entry;
		cache->free_list->free_prev = entry;
	} else {
		cache->free_list = entry;
		entry->free_prev = entry->free_next = entry;
	}
}

/* Called with the cache mutex held */
void remove_free_list(struct cache *cache, struct cache_entry *entry) {
	if (entry->free_prev == NULL || entry->free_next == NULL)
		/* not in free list */
		return;
	else if (entry->free_prev == entry && entry->free_next == entry) {
		/* only this entry in the free list */
		cache->free_list = NULL;
	} else {
		/* more than one entry in the free list */
		entry->free_next->free_prev = entry->free_prev;
		entry->free_prev->free_next = entry->free_next;
		if (cache->free_list == entry)
			cache->free_list = entry->free_next;
	}

	entry->free_prev = entry->free_next = NULL;
}

struct cache *cache_init(int buffer_size, int max_buffers) {
	struct cache *cache = malloc(sizeof(struct cache));

	if (cache == NULL)
		EXIT_UNSQUASH("Out of memory in cache_init\n");

	cache->max_buffers = max_buffers;
	cache->buffer_size = buffer_size;
	cache->count = 0;
	cache->used = 0;
	cache->free_list = NULL;
	memset(cache->hash_table, 0, sizeof(struct cache_entry *) * 65536);
	cache->wait_free = FALSE;
	cache->wait_pending = FALSE;
	pthread_mutex_init(&cache->mutex, NULL);
	pthread_cond_init(&cache->wait_for_free, NULL);
	pthread_cond_init(&cache->wait_for_pending, NULL);

	return cache;
}

struct cache_entry *cache_get(struct cache *cache, long long block, int size) {
	/*
	 * Get a block out of the cache.  If the block isn't in the cache
	 * it is added and queued to the reader() and inflate() threads for
	 * reading off disk and decompression.  The cache grows until max_blocks
	 * is reached, once this occurs existing discarded blocks on the free
	 * list are reused
	 */
	int hash = CALCULATE_HASH(block);
	struct cache_entry *entry;

	pthread_mutex_lock(&cache->mutex);

	for (entry = cache->hash_table[hash]; entry; entry = entry->hash_next)
		if (entry->block == block)
			break;

	if (entry) {
		/*
		 * found the block in the cache.  If the block is currently unused
		 * remove it from the free list and increment cache used count.
		 */
		if (entry->used == 0) {
			cache->used++;
			remove_free_list(cache, entry);
		}
		entry->used++;
		pthread_mutex_unlock(&cache->mutex);
	} else {
		/*
		 * not in the cache
		 *
		 * first try to allocate new block
		 */
		if (cache->count < cache->max_buffers) {
			entry = malloc(sizeof(struct cache_entry));
			if (entry == NULL)
				EXIT_UNSQUASH("Out of memory in cache_get\n");
			entry->data = malloc(cache->buffer_size);
			if (entry->data == NULL)
				EXIT_UNSQUASH("Out of memory in cache_get\n");
			entry->cache = cache;
			entry->free_prev = entry->free_next = NULL;
			cache->count++;
		} else {
			/*
			 * try to get from free list
			 */
			while (cache->free_list == NULL) {
				cache->wait_free = TRUE;
				pthread_cond_wait(&cache->wait_for_free, &cache->mutex);
			}
			entry = cache->free_list;
			remove_free_list(cache, entry);
			remove_hash_table(cache, entry);
		}

		/*
		 * Initialise block and insert into the hash table.
		 * Increment used which tracks how many buffers in the
		 * cache are actively in use (the other blocks, count - used,
		 * are in the cache and available for lookup, but can also be
		 * re-used).
		 */
		entry->block = block;
		entry->size = size;
		entry->used = 1;
		entry->error = FALSE;
		entry->pending = TRUE;
		insert_hash_table(cache, entry);
		cache->used++;

		/*
		 * queue to read thread to read and ultimately (via the
		 * decompress threads) decompress the buffer
		 */
		pthread_mutex_unlock(&cache->mutex);
		queue_put(to_reader, entry);
	}

	return entry;
}

void cache_block_ready(struct cache_entry *entry, int error) {
	/*
	 * mark cache entry as being complete, reading and (if necessary)
	 * decompression has taken place, and the buffer is valid for use.
	 * If an error occurs reading or decompressing, the buffer also 
	 * becomes ready but with an error...
	 */
	pthread_mutex_lock(&entry->cache->mutex);
	entry->pending = FALSE;
	entry->error = error;

	/*
	 * if the wait_pending flag is set, one or more threads may be waiting
	 * on this buffer
	 */
	if (entry->cache->wait_pending) {
		entry->cache->wait_pending = FALSE;
		pthread_cond_broadcast(&entry->cache->wait_for_pending);
	}

	pthread_mutex_unlock(&entry->cache->mutex);
}

void cache_block_wait(struct cache_entry *entry) {
	/*
	 * wait for this cache entry to become ready, when reading and (if
	 * necessary) decompression has taken place
	 */
	pthread_mutex_lock(&entry->cache->mutex);

	while (entry->pending) {
		entry->cache->wait_pending = TRUE;
		pthread_cond_wait(&entry->cache->wait_for_pending, &entry->cache->mutex);
	}

	pthread_mutex_unlock(&entry->cache->mutex);
}

void cache_block_put(struct cache_entry *entry) {
	/*
	 * finished with this cache entry, once the usage count reaches zero it
	 * can be reused and is put onto the free list.  As it remains
	 * accessible via the hash table it can be found getting a new lease of
	 * life before it is reused.
	 */
	pthread_mutex_lock(&entry->cache->mutex);

	entry->used--;
	if (entry->used == 0) {
		insert_free_list(entry->cache, entry);
		entry->cache->used--;

		/*
		 * if the wait_free flag is set, one or more threads may be
		 * waiting on this buffer
		 */
		if (entry->cache->wait_free) {
			entry->cache->wait_free = FALSE;
			pthread_cond_broadcast(&entry->cache->wait_for_free);
		}
	}

	pthread_mutex_unlock(&entry->cache->mutex);
}

void dump_cache(struct cache *cache) {
	pthread_mutex_lock(&cache->mutex);

	printf("Max buffers %d, Current size %d, Used %d,  %s\n", cache->max_buffers, cache->count, cache->used, cache->free_list ? "Free buffers" : "No free buffers");

	pthread_mutex_unlock(&cache->mutex);
}

char *modestr(char *str, int mode) {
	int i;

	strcpy(str, "----------");

	for (i = 0; table[i].mask != 0; i++) {
		if ((mode & table[i].mask) == table[i].value)
			str[table[i].position] = table[i].mode;
	}

	return str;
}

#define TOTALCHARS  25
int print_filename(char *pathname, struct inode *inode) {
	char str[11], dummy[12], dummy2[12];	/* overflow safe */
	char *userstr, *groupstr;
	int padchars;
	struct passwd *user;
	struct group *group;
	struct tm *t;

	if (short_ls) {
		printf("%s\n", pathname);
		return 1;
	}

	user = getpwuid(inode->uid);
	if (user == NULL) {
		int res = snprintf(dummy, 12, "%d", inode->uid);
		if (res < 0)
			EXIT_UNSQUASH("snprintf failed in print_filename()\n");
		else if (res >= 12)
			/* unsigned int shouldn't ever need more than 11 bytes
			 * (including terminating '\0') to print in base 10 */
			userstr = "*";
		else
			userstr = dummy;
	} else
		userstr = user->pw_name;

	group = getgrgid(inode->gid);
	if (group == NULL) {
		int res = snprintf(dummy2, 12, "%d", inode->gid);
		if (res < 0)
			EXIT_UNSQUASH("snprintf failed in print_filename()\n");
		else if (res >= 12)
			/* unsigned int shouldn't ever need more than 11 bytes
			 * (including terminating '\0') to print in base 10 */
			groupstr = "*";
		else
			groupstr = dummy2;
	} else
		groupstr = group->gr_name;

	printf("%s %s/%s ", modestr(str, inode->mode), userstr, groupstr);

	switch (inode->mode & S_IFMT) {
	case S_IFREG:
	case S_IFDIR:
	case S_IFSOCK:
	case S_IFIFO:
	case S_IFLNK:
		padchars = TOTALCHARS - strlen(userstr) - strlen(groupstr);

		printf("%*lld ", padchars > 0 ? padchars : 0, inode->data);
		break;
	case S_IFCHR:
	case S_IFBLK:
		padchars = TOTALCHARS - strlen(userstr) - strlen(groupstr) - 7;

		printf("%*s%3d,%3d ", padchars > 0 ? padchars : 0, " ", (int)inode->data >> 8, (int)inode->data & 0xff);
		break;
	}

	t = localtime(&inode->time);

	printf("%d-%02d-%02d %02d:%02d %s", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, pathname);
	if ((inode->mode & S_IFMT) == S_IFLNK)
		printf(" -> %s", inode->symlink);
	printf("\n");

	return 1;
}

void add_entry(struct hash_table_entry *hash_table[], long long start, int bytes) {
	int hash = CALCULATE_HASH(start);
	struct hash_table_entry *hash_table_entry;

	hash_table_entry = malloc(sizeof(struct hash_table_entry));
	if (hash_table_entry == NULL)
		EXIT_UNSQUASH("Out of memory in add_entry\n");

	hash_table_entry->start = start;
	hash_table_entry->bytes = bytes;
	hash_table_entry->next = hash_table[hash];
	hash_table[hash] = hash_table_entry;
}

int lookup_entry(struct hash_table_entry *hash_table[], long long start) {
	int hash = CALCULATE_HASH(start);
	struct hash_table_entry *hash_table_entry;

	for (hash_table_entry = hash_table[hash]; hash_table_entry; hash_table_entry = hash_table_entry->next)

		if (hash_table_entry->start == start)
			return hash_table_entry->bytes;

	return -1;
}

int read_fs_bytes(int fd, long long byte, int bytes, void *buff) {
	off_t off = byte;
	int res, count;

	TRACE("read_bytes: reading from position 0x%llx, bytes %d\n", byte, bytes);

	if (lseek(fd, off, SEEK_SET) == -1) {
		ERROR("Lseek failed because %s\n", strerror(errno));
		return FALSE;
	}

	for (count = 0; count < bytes; count += res) {
		res = read(fd, buff + count, bytes - count);
		if (res < 1) {
			if (res == 0) {
				ERROR("Read on filesystem failed because " "EOF\n");
				return FALSE;
			} else if (errno != EINTR) {
				ERROR("Read on filesystem failed because %s\n", strerror(errno));
				return FALSE;
			} else
				res = 0;
		}
	}

	return TRUE;
}

int read_block(int fd, long long start, long long *next, int expected, void *block) {
	unsigned short c_byte;
	int offset = 2, res, compressed;
	int outlen = expected ? expected : SQUASHFS_METADATA_SIZE;

	if (swap) {
		if (read_fs_bytes(fd, start, 2, &c_byte) == FALSE)
			goto failed;
		c_byte = (c_byte >> 8) | ((c_byte & 0xff) << 8);
	} else if (read_fs_bytes(fd, start, 2, &c_byte) == FALSE)
		goto failed;

	TRACE("read_block: block @0x%llx, %d %s bytes\n", start, SQUASHFS_COMPRESSED_SIZE(c_byte), SQUASHFS_COMPRESSED(c_byte) ? "compressed" : "uncompressed");

	if (SQUASHFS_CHECK_DATA(sBlk.s.flags))
		offset = 3;

	compressed = SQUASHFS_COMPRESSED(c_byte);
	c_byte = SQUASHFS_COMPRESSED_SIZE(c_byte);

	/*
	 * The block size should not be larger than
	 * the uncompressed size (or max uncompressed size if
	 * expected is 0)
	 */
	if (c_byte > outlen)
		return 0;

	if (compressed) {
		char buffer[c_byte];
		int error;

		res = read_fs_bytes(fd, start + offset, c_byte, buffer);
		if (res == FALSE)
			goto failed;

		res = compressor_uncompress(comp, block, buffer, c_byte, outlen, &error);

		if (res == -1) {
			ERROR("%s uncompress failed with error code %d\n", comp->name, error);
			goto failed;
		}
	} else {
		res = read_fs_bytes(fd, start + offset, c_byte, block);
		if (res == FALSE)
			goto failed;
		res = c_byte;
	}

	if (next)
		*next = start + offset + c_byte;

	/*
	 * if expected, then check the (uncompressed) return data
	 * is of the expected size
	 */
	if (expected && expected != res)
		return 0;
	else
		return res;

 failed:
	ERROR("read_block: failed to read block @0x%llx\n", start);
	return FALSE;
}

int read_data_block(long long start, unsigned int size, char *block) {
	int error, res;
	int c_byte = SQUASHFS_COMPRESSED_SIZE_BLOCK(size);

	TRACE("read_data_block: block @0x%llx, %d %s bytes\n", start, c_byte, SQUASHFS_COMPRESSED_BLOCK(size) ? "compressed" : "uncompressed");

	if (SQUASHFS_COMPRESSED_BLOCK(size)) {
		if (read_fs_bytes(fd, start, c_byte, data) == FALSE)
			goto failed;

		res = compressor_uncompress(comp, block, data, c_byte, block_size, &error);

		if (res == -1) {
			ERROR("%s uncompress failed with error code %d\n", comp->name, error);
			goto failed;
		}

		return res;
	} else {
		if (read_fs_bytes(fd, start, c_byte, block) == FALSE)
			goto failed;

		return c_byte;
	}

 failed:
	ERROR("read_data_block: failed to read block @0x%llx, size %d\n", start, c_byte);
	return FALSE;
}

int read_inode_table(long long start, long long end) {
	int size = 0, bytes = 0, res;

	TRACE("read_inode_table: start %lld, end %lld\n", start, end);

	while (start < end) {
		if (size - bytes < SQUASHFS_METADATA_SIZE) {
			inode_table = realloc(inode_table, size += SQUASHFS_METADATA_SIZE);
			if (inode_table == NULL) {
				ERROR("Out of memory in read_inode_table");
				goto failed;
			}
		}

		add_entry(inode_table_hash, start, bytes);

		res = read_block(fd, start, &start, 0, inode_table + bytes);
		if (res == 0) {
			ERROR("read_inode_table: failed to read block\n");
			goto failed;
		}
		bytes += res;

		/*
		 * If this is not the last metadata block in the inode table
		 * then it should be SQUASHFS_METADATA_SIZE in size.
		 * Note, we can't use expected in read_block() above for this
		 * because we don't know if this is the last block until
		 * after reading.
		 */
		if (start != end && res != SQUASHFS_METADATA_SIZE) {
			ERROR("read_inode_table: metadata block should be %d " "bytes in length, it is %d bytes\n", SQUASHFS_METADATA_SIZE, res);

			goto failed;
		}
	}

	return TRUE;

 failed:
	free(inode_table);
	return FALSE;
}

int set_attributes(char *pathname, int mode, uid_t uid, gid_t guid, time_t time, unsigned int xattr, unsigned int set_mode) {
	struct utimbuf times = { time, time };

	write_xattr(pathname, xattr);

	if (utime(pathname, &times) == -1) {
		ERROR("set_attributes: failed to set time on %s, because %s\n", pathname, strerror(errno));
		return FALSE;
	}

	if (root_process) {
		if (chown(pathname, uid, guid) == -1) {
			ERROR("set_attributes: failed to change uid and gids " "on %s, because %s\n", pathname, strerror(errno));
			return FALSE;
		}
	} else
		mode &= ~07000;

	if ((set_mode || (mode & 07000)) && chmod(pathname, (mode_t) mode) == -1) {
		ERROR("set_attributes: failed to change mode %s, because %s\n", pathname, strerror(errno));
		return FALSE;
	}

	return TRUE;
}

int write_bytes(int fd, char *buff, int bytes) {
	int res, count;

	for (count = 0; count < bytes; count += res) {
		res = write(fd, buff + count, bytes - count);
		if (res == -1) {
			if (errno != EINTR) {
				ERROR("Write on output file failed because " "%s\n", strerror(errno));
				return -1;
			}
			res = 0;
		}
	}

	return 0;
}

int lseek_broken = FALSE;
char *zero_data = NULL;

int write_block(int file_fd, char *buffer, int size, long long hole, int sparse) {
	off_t off = hole;

	if (hole) {
		if (sparse && lseek_broken == FALSE) {
			int error = lseek(file_fd, off, SEEK_CUR);
			if (error == -1)
				/* failed to seek beyond end of file */
				lseek_broken = TRUE;
		}

		if ((sparse == FALSE || lseek_broken) && zero_data == NULL) {
			if ((zero_data = malloc(block_size)) == NULL)
				EXIT_UNSQUASH("write_block: failed to alloc " "zero data block\n");
			memset(zero_data, 0, block_size);
		}

		if (sparse == FALSE || lseek_broken) {
			int blocks = (hole + block_size - 1) / block_size;
			int avail_bytes, i;
			for (i = 0; i < blocks; i++, hole -= avail_bytes) {
				avail_bytes = hole > block_size ? block_size : hole;
				if (write_bytes(file_fd, zero_data, avail_bytes)
					== -1)
					goto failure;
			}
		}
	}

	if (write_bytes(file_fd, buffer, size) == -1)
		goto failure;

	return TRUE;

 failure:
	return FALSE;
}

pthread_mutex_t open_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t open_empty = PTHREAD_COND_INITIALIZER;
int open_unlimited, open_count;
#define OPEN_FILE_MARGIN 10

void open_init(int count) {
	open_count = count;
	open_unlimited = count == -1;
}

int open_wait(char *pathname, int flags, mode_t mode) {
	if (!open_unlimited) {
		pthread_mutex_lock(&open_mutex);
		while (open_count == 0)
			pthread_cond_wait(&open_empty, &open_mutex);
		open_count--;
		pthread_mutex_unlock(&open_mutex);
	}

	return open(pathname, flags, mode);
}

void close_wake(int fd) {
	close(fd);

	if (!open_unlimited) {
		pthread_mutex_lock(&open_mutex);
		open_count++;
		pthread_cond_signal(&open_empty);
		pthread_mutex_unlock(&open_mutex);
	}
}

void queue_file(char *pathname, int file_fd, struct inode *inode) {
	struct squashfs_file *file = malloc(sizeof(struct squashfs_file));
	if (file == NULL)
		EXIT_UNSQUASH("queue_file: unable to malloc file\n");

	file->fd = file_fd;
	file->file_size = inode->data;
	file->mode = inode->mode;
	file->gid = inode->gid;
	file->uid = inode->uid;
	file->time = inode->time;
	file->pathname = strdup(pathname);
	file->blocks = inode->blocks + (inode->frag_bytes > 0);
	file->sparse = inode->sparse;
	file->xattr = inode->xattr;
	queue_put(to_writer, file);
}

void queue_dir(char *pathname, struct dir *dir) {
	struct squashfs_file *file = malloc(sizeof(struct squashfs_file));
	if (file == NULL)
		EXIT_UNSQUASH("queue_dir: unable to malloc file\n");

	file->fd = -1;
	file->mode = dir->mode;
	file->gid = dir->guid;
	file->uid = dir->uid;
	file->time = dir->mtime;
	file->pathname = strdup(pathname);
	file->xattr = dir->xattr;
	queue_put(to_writer, file);
}

int write_file(struct inode *inode, char *pathname) {
	unsigned int file_fd, i;
	unsigned int *block_list;
	int file_end = inode->data / block_size;
	long long start = inode->start;

	TRACE("write_file: regular file, blocks %d\n", inode->blocks);

	file_fd = open_wait(pathname, O_CREAT | O_WRONLY | (force ? O_TRUNC : 0), (mode_t) inode->mode & 0777);
	if (file_fd == -1) {
		ERROR("write_file: failed to create file %s, because %s\n", pathname, strerror(errno));
		return FALSE;
	}

	block_list = malloc(inode->blocks * sizeof(unsigned int));
	if (block_list == NULL)
		EXIT_UNSQUASH("write_file: unable to malloc block list\n");

	s_ops.read_block_list(block_list, inode->block_ptr, inode->blocks);

	/*
	 * the writer thread is queued a squashfs_file structure describing the
	 * file.  If the file has one or more blocks or a fragment they are
	 * queued separately (references to blocks in the cache).
	 */
	queue_file(pathname, file_fd, inode);

	for (i = 0; i < inode->blocks; i++) {
		int c_byte = SQUASHFS_COMPRESSED_SIZE_BLOCK(block_list[i]);
		struct file_entry *block = malloc(sizeof(struct file_entry));

		if (block == NULL)
			EXIT_UNSQUASH("write_file: unable to malloc file\n");
		block->offset = 0;
		block->size = i == file_end ? inode->data & (block_size - 1) : block_size;
		if (block_list[i] == 0)	/* sparse block */
			block->buffer = NULL;
		else {
			block->buffer = cache_get(data_cache, start, block_list[i]);
			start += c_byte;
		}
		queue_put(to_writer, block);
	}

	if (inode->frag_bytes) {
		int size;
		long long start;
		struct file_entry *block = malloc(sizeof(struct file_entry));

		if (block == NULL)
			EXIT_UNSQUASH("write_file: unable to malloc file\n");
		s_ops.read_fragment(inode->fragment, &start, &size);
		block->buffer = cache_get(fragment_cache, start, size);
		block->offset = inode->offset;
		block->size = inode->frag_bytes;
		queue_put(to_writer, block);
	}

	free(block_list);
	close(file_fd);return TRUE;
}

int create_inode(char *pathname, struct inode *i) {
	TRACE("create_inode: pathname %s\n", pathname);

	if (created_inode[i->inode_number - 1]) {
		TRACE("create_inode: hard link\n");
		if (force)
			unlink(pathname);

		if (link(created_inode[i->inode_number - 1], pathname) == -1) {
			ERROR("create_inode: failed to create hardlink, " "because %s\n", strerror(errno));
			return FALSE;
		}

		return TRUE;
	}

	switch (i->type) {
	case SQUASHFS_FILE_TYPE:
	case SQUASHFS_LREG_TYPE:
		TRACE("create_inode: regular file, file_size %lld, " "blocks %d\n", i->data, i->blocks);

		if (write_file(i, pathname))
			file_count++;
		break;
	case SQUASHFS_SYMLINK_TYPE:
	case SQUASHFS_LSYMLINK_TYPE:
		TRACE("create_inode: symlink, symlink_size %lld\n", i->data);

		if (force)
			unlink(pathname);

		if (symlink(i->symlink, pathname) == -1) {
			ERROR("create_inode: failed to create symlink " "%s, because %s\n", pathname, strerror(errno));
			break;
		}

		write_xattr(pathname, i->xattr);

		if (root_process) {
			if (lchown(pathname, i->uid, i->gid) == -1)
				ERROR("create_inode: failed to change " "uid and gids on %s, because " "%s\n", pathname, strerror(errno));
		}

		sym_count++;
		break;
	case SQUASHFS_BLKDEV_TYPE:
	case SQUASHFS_CHRDEV_TYPE:
	case SQUASHFS_LBLKDEV_TYPE:
	case SQUASHFS_LCHRDEV_TYPE:{
			int chrdev = i->type == SQUASHFS_CHRDEV_TYPE;
			TRACE("create_inode: dev, rdev 0x%llx\n", i->data);

			if (root_process) {
				if (force)
					unlink(pathname);

				if (mknod(pathname, chrdev ? S_IFCHR : S_IFBLK, makedev((i->data >> 8) & 0xff, i->data & 0xff)) == -1) {
					ERROR("create_inode: failed to create " "%s device %s, because %s\n", chrdev ? "character" : "block", pathname, strerror(errno));
					break;
				}
				set_attributes(pathname, i->mode, i->uid, i->gid, i->time, i->xattr, TRUE);
				dev_count++;
			} else
				ERROR("create_inode: could not create %s " "device %s, because you're not " "superuser!\n", chrdev ? "character" : "block", pathname);
			break;
		}
	case SQUASHFS_FIFO_TYPE:
	case SQUASHFS_LFIFO_TYPE:
		TRACE("create_inode: fifo\n");

		if (force)
			unlink(pathname);

		if (mknod(pathname, S_IFIFO, 0) == -1) {
			ERROR("create_inode: failed to create fifo %s, " "because %s\n", pathname, strerror(errno));
			break;
		}
		set_attributes(pathname, i->mode, i->uid, i->gid, i->time, i->xattr, TRUE);
		fifo_count++;
		break;
	case SQUASHFS_SOCKET_TYPE:
	case SQUASHFS_LSOCKET_TYPE:
		TRACE("create_inode: socket\n");
		ERROR("create_inode: socket %s ignored\n", pathname);
		break;
	default:
		ERROR("Unknown inode type %d in create_inode_table!\n", i->type);
		return FALSE;
	}

	created_inode[i->inode_number - 1] = strdup(pathname);

	return TRUE;
}

int read_directory_table(long long start, long long end) {
	int bytes = 0, size = 0, res;

	TRACE("read_directory_table: start %lld, end %lld\n", start, end);

	while (start < end) {
		if (size - bytes < SQUASHFS_METADATA_SIZE) {
			directory_table = realloc(directory_table, size += SQUASHFS_METADATA_SIZE);
			if (directory_table == NULL) {
				ERROR("Out of memory in " "read_directory_table\n");
				goto failed;
			}
		}

		add_entry(directory_table_hash, start, bytes);

		res = read_block(fd, start, &start, 0, directory_table + bytes);
		if (res == 0) {
			ERROR("read_directory_table: failed to read block\n");
			goto failed;
		}

		bytes += res;

		/*
		 * If this is not the last metadata block in the directory table
		 * then it should be SQUASHFS_METADATA_SIZE in size.
		 * Note, we can't use expected in read_block() above for this
		 * because we don't know if this is the last block until
		 * after reading.
		 */
		if (start != end && res != SQUASHFS_METADATA_SIZE) {
			ERROR("read_directory_table: metadata block " "should be %d bytes in length, it is %d " "bytes\n", SQUASHFS_METADATA_SIZE, res);
			goto failed;
		}
	}

	return TRUE;

 failed:
	free(directory_table);
	return FALSE;
}

int squashfs_readdir(struct dir *dir, char **name, unsigned int *start_block, unsigned int *offset, unsigned int *type) {
	if (dir->cur_entry == dir->dir_count)
		return FALSE;

	*name = dir->dirs[dir->cur_entry].name;
	*start_block = dir->dirs[dir->cur_entry].start_block;
	*offset = dir->dirs[dir->cur_entry].offset;
	*type = dir->dirs[dir->cur_entry].type;
	dir->cur_entry++;

	return TRUE;
}

void squashfs_closedir(struct dir *dir) {
	free(dir->dirs);
	free(dir);
}

char *get_component(char *target, char **targname) {
	char *start;

	while (*target == '/')
		target++;

	start = target;
	while (*target != '/' && *target != '\0')
		target++;

	*targname = strndup(start, target - start);

	while (*target == '/')
		target++;

	return target;
}

void free_path(struct pathname *paths) {
	int i;

	for (i = 0; i < paths->names; i++) {
		if (paths->name[i].paths)
			free_path(paths->name[i].paths);
		free(paths->name[i].name);
		if (paths->name[i].preg) {
			regfree(paths->name[i].preg);
			free(paths->name[i].preg);
		}
	}

	free(paths);
}

struct pathname *add_path(struct pathname *paths, char *target, char *alltarget) {
	char *targname;
	int i, error;

	TRACE("add_path: adding \"%s\" extract file\n", target);

	target = get_component(target, &targname);

	if (paths == NULL) {
		paths = malloc(sizeof(struct pathname));
		if (paths == NULL)
			EXIT_UNSQUASH("failed to allocate paths\n");

		paths->names = 0;
		paths->name = NULL;
	}

	for (i = 0; i < paths->names; i++)
		if (strcmp(paths->name[i].name, targname) == 0)
			break;

	if (i == paths->names) {
		/*
		 * allocate new name entry
		 */
		paths->names++;
		paths->name = realloc(paths->name, (i + 1) * sizeof(struct path_entry));
		if (paths->name == NULL)
			EXIT_UNSQUASH("Out of memory in add_path\n");
		paths->name[i].name = targname;
		paths->name[i].paths = NULL;
		if (use_regex) {
			paths->name[i].preg = malloc(sizeof(regex_t));
			if (paths->name[i].preg == NULL)
				EXIT_UNSQUASH("Out of memory in add_path\n");
			error = regcomp(paths->name[i].preg, targname, REG_EXTENDED | REG_NOSUB);
			if (error) {
				char str[1024];	/* overflow safe */

				regerror(error, paths->name[i].preg, str, 1024);
				EXIT_UNSQUASH("invalid regex %s in export %s, " "because %s\n", targname, alltarget, str);
			}
		} else
			paths->name[i].preg = NULL;

		if (target[0] == '\0')
			/*
			 * at leaf pathname component
			 */
			paths->name[i].paths = NULL;
		else
			/*
			 * recurse adding child components
			 */
			paths->name[i].paths = add_path(NULL, target, alltarget);
	} else {
		/*
		 * existing matching entry
		 */
		free(targname);

		if (paths->name[i].paths == NULL) {
			/*
			 * No sub-directory which means this is the leaf
			 * component of a pre-existing extract which subsumes
			 * the extract currently being added, in which case stop
			 * adding components
			 */
		} else if (target[0] == '\0') {
			/*
			 * at leaf pathname component and child components exist
			 * from more specific extracts, delete as they're
			 * subsumed by this extract
			 */
			free_path(paths->name[i].paths);
			paths->name[i].paths = NULL;
		} else
			/*
			 * recurse adding child components
			 */
			add_path(paths->name[i].paths, target, alltarget);
	}

	return paths;
}

struct pathnames *init_subdir() {
	struct pathnames *new = malloc(sizeof(struct pathnames));
	if (new == NULL)
		EXIT_UNSQUASH("Out of memory in init_subdir\n");
	new->count = 0;
	return new;
}

struct pathnames *add_subdir(struct pathnames *paths, struct pathname *path) {
	if (paths->count % PATHS_ALLOC_SIZE == 0) {
		paths = realloc(paths, sizeof(struct pathnames *) + (paths->count + PATHS_ALLOC_SIZE) * sizeof(struct pathname *));
		if (paths == NULL)
			EXIT_UNSQUASH("Out of memory in add_subdir\n");
	}

	paths->path[paths->count++] = path;
	return paths;
}

void free_subdir(struct pathnames *paths) {
	free(paths);
}

int matches(struct pathnames *paths, char *name, struct pathnames **new) {
	int i, n;

	if (paths == NULL) {
		*new = NULL;
		return TRUE;
	}

	*new = init_subdir();

	for (n = 0; n < paths->count; n++) {
		struct pathname *path = paths->path[n];
		for (i = 0; i < path->names; i++) {
			int match = use_regex ? regexec(path->name[i].preg, name, (size_t) 0,
											NULL, 0) == 0 : fnmatch(path->name[i].name,
																	name, FNM_PATHNAME | FNM_PERIOD | FNM_EXTMATCH) == 0;
			if (match && path->name[i].paths == NULL)
				/*
				 * match on a leaf component, any subdirectories
				 * will implicitly match, therefore return an
				 * empty new search set
				 */
				goto empty_set;

			if (match)
				/*
				 * match on a non-leaf component, add any
				 * subdirectories to the new set of
				 * subdirectories to scan for this name
				 */
				*new = add_subdir(*new, path->name[i].paths);
		}
	}

	if ((*new)->count == 0) {
		/*
		 * no matching names found, delete empty search set, and return
		 * FALSE
		 */
		free_subdir(*new);
		*new = NULL;
		return FALSE;
	}

	/*
	 * one or more matches with sub-directories found (no leaf matches),
	 * return new search set and return TRUE
	 */
	return TRUE;

 empty_set:
	/*
	 * found matching leaf exclude, return empty search set and return TRUE
	 */
	free_subdir(*new);
	*new = NULL;
	return TRUE;
}

void pre_scan(char *parent_name, unsigned int start_block, unsigned int offset, struct pathnames *paths) {
	unsigned int type;
	char *name;
	struct pathnames *new;
	struct inode *i;
	struct dir *dir = s_ops.squashfs_opendir(start_block, offset, &i);

	if (dir == NULL)
		return;

	while (squashfs_readdir(dir, &name, &start_block, &offset, &type)) {
		struct inode *i;
		char *pathname;
		int res;

		TRACE("pre_scan: name %s, start_block %d, offset %d, type %d\n", name, start_block, offset, type);

		if (!matches(paths, name, &new))
			continue;

		res = asprintf(&pathname, "%s/%s", parent_name, name);
		if (res == -1)
			EXIT_UNSQUASH("asprintf failed in dir_scan\n");

		if (type == SQUASHFS_DIR_TYPE)
			pre_scan(parent_name, start_block, offset, new);
		else if (new == NULL) {
			if (type == SQUASHFS_FILE_TYPE || type == SQUASHFS_LREG_TYPE) {
				i = s_ops.read_inode(start_block, offset);
				if (created_inode[i->inode_number - 1] == NULL) {
					created_inode[i->inode_number - 1] = (char *)i;
					total_blocks += (i->data + (block_size - 1)) >> block_log;
				}
				total_files++;
			}
			total_inodes++;
		}

		free_subdir(new);
		free(pathname);
	}

	squashfs_closedir(dir);
}

void dir_scan(char *parent_name, unsigned int start_block, unsigned int offset, struct pathnames *paths) {
	unsigned int type;
	char *name;
	struct pathnames *new;
	struct inode *i;
	struct dir *dir = s_ops.squashfs_opendir(start_block, offset, &i);

	if (dir == NULL) {
		ERROR("dir_scan: failed to read directory %s, skipping\n", parent_name);
		return;
	}

	if (lsonly || info)
		print_filename(parent_name, i);

	if (!lsonly) {
		/*
		 * Make directory with default User rwx permissions rather than
		 * the permissions from the filesystem, as these may not have
		 * write/execute permission.  These are fixed up later in
		 * set_attributes().
		 */
		int res = mkdir(parent_name, S_IRUSR | S_IWUSR | S_IXUSR);
		if (res == -1) {
			/*
			 * Skip directory if mkdir fails, unless we're
			 * forcing and the error is -EEXIST
			 */
			if (!force || errno != EEXIST) {
				ERROR("dir_scan: failed to make directory %s, " "because %s\n", parent_name, strerror(errno));
				squashfs_closedir(dir);
				return;
			}

			/*
			 * Try to change permissions of existing directory so
			 * that we can write to it
			 */
			res = chmod(parent_name, S_IRUSR | S_IWUSR | S_IXUSR);
			if (res == -1)
				ERROR("dir_scan: failed to change permissions " "for directory %s, because %s\n", parent_name, strerror(errno));
		}
	}

	while (squashfs_readdir(dir, &name, &start_block, &offset, &type)) {
		char *pathname;
		int res;

		TRACE("dir_scan: name %s, start_block %d, offset %d, type %d\n", name, start_block, offset, type);

		if (!matches(paths, name, &new))
			continue;

		res = asprintf(&pathname, "%s/%s", parent_name, name);
		if (res == -1)
			EXIT_UNSQUASH("asprintf failed in dir_scan\n");

		if (type == SQUASHFS_DIR_TYPE) {
			dir_scan(pathname, start_block, offset, new);
			free(pathname);
		} else if (new == NULL) {
			update_info(pathname);

			i = s_ops.read_inode(start_block, offset);

			if (lsonly || info)
				print_filename(pathname, i);

			if (!lsonly)
				create_inode(pathname, i);

			if (i->type == SQUASHFS_SYMLINK_TYPE || i->type == SQUASHFS_LSYMLINK_TYPE)
				free(i->symlink);
		} else
			free(pathname);

		free_subdir(new);
	}

	if (!lsonly)
		queue_dir(parent_name, dir);

	squashfs_closedir(dir);
	dir_count++;
}

void squashfs_stat(char *source) {
	time_t mkfs_time = (time_t) sBlk.s.mkfs_time;
	char *mkfs_str = ctime(&mkfs_time);

#if __BYTE_ORDER == __BIG_ENDIAN
	printf("Found a valid %sSQUASHFS %d:%d superblock on %s.\n", sBlk.s.s_major == 4 ? "" : swap ? "little endian " : "big endian ", sBlk.s.s_major, sBlk.s.s_minor, source);
#else
	printf("Found a valid %sSQUASHFS %d:%d superblock on %s.\n", sBlk.s.s_major == 4 ? "" : swap ? "big endian " : "little endian ", sBlk.s.s_major, sBlk.s.s_minor, source);
#endif

	printf("Creation or last append time %s", mkfs_str ? mkfs_str : "failed to get time\n");
	printf("Filesystem size %.2f Kbytes (%.2f Mbytes)\n", sBlk.s.bytes_used / 1024.0, sBlk.s.bytes_used / (1024.0 * 1024.0));

	if (sBlk.s.s_major == 4) {
		printf("Compression %s\n", comp->name);

		if (SQUASHFS_COMP_OPTS(sBlk.s.flags)) {
			char buffer[SQUASHFS_METADATA_SIZE] __attribute__ ((aligned));
			int bytes;

			bytes = read_block(fd, sizeof(sBlk.s), NULL, 0, buffer);
			if (bytes == 0) {
				ERROR("Failed to read compressor options\n");
				return;
			}

			compressor_display_options(comp, buffer, bytes);
		}
	}

	printf("Block size %d\n", sBlk.s.block_size);
	printf("Filesystem is %sexportable via NFS\n", SQUASHFS_EXPORTABLE(sBlk.s.flags) ? "" : "not ");
	printf("Inodes are %scompressed\n", SQUASHFS_UNCOMPRESSED_INODES(sBlk.s.flags) ? "un" : "");
	printf("Data is %scompressed\n", SQUASHFS_UNCOMPRESSED_DATA(sBlk.s.flags) ? "un" : "");

	if (sBlk.s.s_major > 1) {
		if (SQUASHFS_NO_FRAGMENTS(sBlk.s.flags))
			printf("Fragments are not stored\n");
		else {
			printf("Fragments are %scompressed\n", SQUASHFS_UNCOMPRESSED_FRAGMENTS(sBlk.s.flags) ? "un" : "");
			printf("Always-use-fragments option is %sspecified\n", SQUASHFS_ALWAYS_FRAGMENTS(sBlk.s.flags) ? "" : "not ");
		}
	}

	if (sBlk.s.s_major == 4) {
		if (SQUASHFS_NO_XATTRS(sBlk.s.flags))
			printf("Xattrs are not stored\n");
		else
			printf("Xattrs are %scompressed\n", SQUASHFS_UNCOMPRESSED_XATTRS(sBlk.s.flags) ? "un" : "");
	}

	if (sBlk.s.s_major < 4)
		printf("Check data is %spresent in the filesystem\n", SQUASHFS_CHECK_DATA(sBlk.s.flags) ? "" : "not ");

	if (sBlk.s.s_major > 1)
		printf("Duplicates are %sremoved\n", SQUASHFS_DUPLICATES(sBlk.s.flags) ? "" : "not ");
	else
		printf("Duplicates are removed\n");

	if (sBlk.s.s_major > 1)
		printf("Number of fragments %d\n", sBlk.s.fragments);

	printf("Number of inodes %d\n", sBlk.s.inodes);

	if (sBlk.s.s_major == 4)
		printf("Number of ids %d\n", sBlk.s.no_ids);
	else {
		printf("Number of uids %d\n", sBlk.no_uids);
		printf("Number of gids %d\n", sBlk.no_guids);
	}

	TRACE("sBlk.s.inode_table_start 0x%llx\n", sBlk.s.inode_table_start);
	TRACE("sBlk.s.directory_table_start 0x%llx\n", sBlk.s.directory_table_start);

	if (sBlk.s.s_major > 1)
		TRACE("sBlk.s.fragment_table_start 0x%llx\n\n", sBlk.s.fragment_table_start);

	if (sBlk.s.s_major > 2)
		TRACE("sBlk.s.lookup_table_start 0x%llx\n\n", sBlk.s.lookup_table_start);

	if (sBlk.s.s_major == 4) {
		TRACE("sBlk.s.id_table_start 0x%llx\n", sBlk.s.id_table_start);
		TRACE("sBlk.s.xattr_id_table_start 0x%llx\n", sBlk.s.xattr_id_table_start);
	} else {
		TRACE("sBlk.uid_start 0x%llx\n", sBlk.uid_start);
		TRACE("sBlk.guid_start 0x%llx\n", sBlk.guid_start);
	}
}

int check_compression(struct compressor *comp) {
	int res, bytes = 0;
	char buffer[SQUASHFS_METADATA_SIZE] __attribute__ ((aligned));

	if (!comp->supported) {
		ERROR("Filesystem uses %s compression, this is " "unsupported by this version\n", comp->name);
		ERROR("Decompressors available:\n");
		display_compressors("", "");
		return 0;
	}

	/*
	 * Read compression options from disk if present, and pass to
	 * the compressor to ensure we know how to decompress a filesystem
	 * compressed with these compression options.
	 *
	 * Note, even if there is no compression options we still call the
	 * compressor because some compression options may be mandatory
	 * for some compressors.
	 */
	if (SQUASHFS_COMP_OPTS(sBlk.s.flags)) {
		bytes = read_block(fd, sizeof(sBlk.s), NULL, 0, buffer);
		if (bytes == 0) {
			ERROR("Failed to read compressor options\n");
			return 0;
		}
	}

	res = compressor_check_options(comp, sBlk.s.block_size, buffer, bytes);

	return res != -1;
}

int read_super(char *source) {
	squashfs_super_block_3 sBlk_3;
	struct squashfs_super_block sBlk_4;

	/*
	 * Try to read a Squashfs 4 superblock
	 */
	read_fs_bytes(fd, SQUASHFS_START, sizeof(struct squashfs_super_block), &sBlk_4);
	swap = sBlk_4.s_magic != SQUASHFS_MAGIC;
	SQUASHFS_INSWAP_SUPER_BLOCK(&sBlk_4);

	if (sBlk_4.s_magic == SQUASHFS_MAGIC && sBlk_4.s_major == 4 && sBlk_4.s_minor == 0) {
		s_ops.squashfs_opendir = squashfs_opendir_4;
		s_ops.read_fragment = read_fragment_4;
		s_ops.read_fragment_table = read_fragment_table_4;
		s_ops.read_block_list = read_block_list_2;
		s_ops.read_inode = read_inode_4;
		s_ops.read_uids_guids = read_uids_guids_4;
		memcpy(&sBlk, &sBlk_4, sizeof(sBlk_4));

		/*
		 * Check the compression type
		 */
		comp = lookup_compressor_id(sBlk.s.compression);
		return TRUE;
	}

	/*
	 * Not a Squashfs 4 superblock, try to read a squashfs 3 superblock
	 * (compatible with 1 and 2 filesystems)
	 */
	read_fs_bytes(fd, SQUASHFS_START, sizeof(squashfs_super_block_3), &sBlk_3);

	/*
	 * Check it is a SQUASHFS superblock
	 */
	swap = 0;
	if (sBlk_3.s_magic != SQUASHFS_MAGIC) {
		if (sBlk_3.s_magic == SQUASHFS_MAGIC_SWAP) {
			squashfs_super_block_3 sblk;
			ERROR("Reading a different endian SQUASHFS filesystem " "on %s\n", source);
			SQUASHFS_SWAP_SUPER_BLOCK_3(&sblk, &sBlk_3);
			memcpy(&sBlk_3, &sblk, sizeof(squashfs_super_block_3));
			swap = 1;
		} else {
			//ERROR("Can't find a SQUASHFS superblock on %s\n", source);
			goto failed_mount;
		}
	}

	sBlk.s.s_magic = sBlk_3.s_magic;
	sBlk.s.inodes = sBlk_3.inodes;
	sBlk.s.mkfs_time = sBlk_3.mkfs_time;
	sBlk.s.block_size = sBlk_3.block_size;
	sBlk.s.fragments = sBlk_3.fragments;
	sBlk.s.block_log = sBlk_3.block_log;
	sBlk.s.flags = sBlk_3.flags;
	sBlk.s.s_major = sBlk_3.s_major;
	sBlk.s.s_minor = sBlk_3.s_minor;
	sBlk.s.root_inode = sBlk_3.root_inode;
	sBlk.s.bytes_used = sBlk_3.bytes_used;
	sBlk.s.inode_table_start = sBlk_3.inode_table_start;
	sBlk.s.directory_table_start = sBlk_3.directory_table_start;
	sBlk.s.fragment_table_start = sBlk_3.fragment_table_start;
	sBlk.s.lookup_table_start = sBlk_3.lookup_table_start;
	sBlk.no_uids = sBlk_3.no_uids;
	sBlk.no_guids = sBlk_3.no_guids;
	sBlk.uid_start = sBlk_3.uid_start;
	sBlk.guid_start = sBlk_3.guid_start;
	sBlk.s.xattr_id_table_start = SQUASHFS_INVALID_BLK;

	/* Check the MAJOR & MINOR versions */
	if (sBlk.s.s_major == 1 || sBlk.s.s_major == 2) {
		sBlk.s.bytes_used = sBlk_3.bytes_used_2;
		sBlk.uid_start = sBlk_3.uid_start_2;
		sBlk.guid_start = sBlk_3.guid_start_2;
		sBlk.s.inode_table_start = sBlk_3.inode_table_start_2;
		sBlk.s.directory_table_start = sBlk_3.directory_table_start_2;

		if (sBlk.s.s_major == 1) {
			sBlk.s.block_size = sBlk_3.block_size_1;
			sBlk.s.fragment_table_start = sBlk.uid_start;
			s_ops.squashfs_opendir = squashfs_opendir_1;
			s_ops.read_fragment_table = read_fragment_table_1;
			s_ops.read_block_list = read_block_list_1;
			s_ops.read_inode = read_inode_1;
			s_ops.read_uids_guids = read_uids_guids_1;
		} else {
			sBlk.s.fragment_table_start = sBlk_3.fragment_table_start_2;
			s_ops.squashfs_opendir = squashfs_opendir_1;
			s_ops.read_fragment = read_fragment_2;
			s_ops.read_fragment_table = read_fragment_table_2;
			s_ops.read_block_list = read_block_list_2;
			s_ops.read_inode = read_inode_2;
			s_ops.read_uids_guids = read_uids_guids_1;
		}
	} else if (sBlk.s.s_major == 3) {
		s_ops.squashfs_opendir = squashfs_opendir_3;
		s_ops.read_fragment = read_fragment_3;
		s_ops.read_fragment_table = read_fragment_table_3;
		s_ops.read_block_list = read_block_list_2;
		s_ops.read_inode = read_inode_3;
		s_ops.read_uids_guids = read_uids_guids_1;
	} else {
		ERROR("Filesystem on %s is (%d:%d), ", source, sBlk.s.s_major, sBlk.s.s_minor);
		ERROR("which is a later filesystem version than I support!\n");
		goto failed_mount;
	}

	/*
	 * 1.x, 2.x and 3.x filesystems use gzip compression.
	 */
	comp = lookup_compressor("gzip");
	return TRUE;

 failed_mount:
	return FALSE;
}

struct pathname *process_extract_files(struct pathname *path, char *filename) {
	FILE *fd;
	char buffer[MAX_LINE + 1];	/* overflow safe */
	char *name;

	fd = fopen(filename, "r");
	if (fd == NULL)
		EXIT_UNSQUASH("Failed to open extract file \"%s\" because %s\n", filename, strerror(errno));

	while (fgets(name = buffer, MAX_LINE + 1, fd) != NULL) {
		int len = strlen(name);

		if (len == MAX_LINE && name[len - 1] != '\n')
			/* line too large */
			EXIT_UNSQUASH("Line too long when reading " "extract file \"%s\", larger than %d " "bytes\n", filename, MAX_LINE);

		/*
		 * Remove '\n' terminator if it exists (the last line
		 * in the file may not be '\n' terminated)
		 */
		if (len && name[len - 1] == '\n')
			name[len - 1] = '\0';

		/* Skip any leading whitespace */
		while (isspace(*name))
			name++;

		/* if comment line, skip */
		if (*name == '#')
			continue;

		/* check for initial backslash, to accommodate
		 * filenames with leading space or leading # character
		 */
		if (*name == '\\')
			name++;

		/* if line is now empty after skipping characters, skip it */
		if (*name == '\0')
			continue;

		path = add_path(path, name, name);
	}

	if (ferror(fd))
		EXIT_UNSQUASH("Reading extract file \"%s\" failed because %s\n", filename, strerror(errno));

	fclose(fd);
	return path;
}

/*
 * reader thread.  This thread processes read requests queued by the
 * cache_get() routine.
 */
void *reader(void *arg) {
	while (1) {
		struct cache_entry *entry = queue_get(to_reader);
		int res = read_fs_bytes(fd, entry->block,
								SQUASHFS_COMPRESSED_SIZE_BLOCK(entry->size),
								entry->data);

		if (res && SQUASHFS_COMPRESSED_BLOCK(entry->size))
			/*
			 * queue successfully read block to the inflate
			 * thread(s) for further processing
			 */
			queue_put(to_inflate, entry);
		else
			/*
			 * block has either been successfully read and is
			 * uncompressed, or an error has occurred, clear pending
			 * flag, set error appropriately, and wake up any
			 * threads waiting on this buffer
			 */
			cache_block_ready(entry, !res);
	}
}

/*
 * writer thread.  This processes file write requests queued by the
 * write_file() routine.
 */
void *writer(void *arg) {
	int i;

	while (1) {
		struct squashfs_file *file = queue_get(to_writer);
		int file_fd;
		long long hole = 0;
		int failed = FALSE;
		int error;

		if (file == NULL) {
			queue_put(from_writer, NULL);
			continue;
		} else if (file->fd == -1) {
			/* write attributes for directory file->pathname */
			set_attributes(file->pathname, file->mode, file->uid, file->gid, file->time, file->xattr, TRUE);
			free(file->pathname);
			free(file);
			continue;
		}

		TRACE("writer: regular file, blocks %d\n", file->blocks);

		file_fd = file->fd;

		for (i = 0; i < file->blocks; i++, cur_blocks++) {
			struct file_entry *block = queue_get(to_writer);

			if (block->buffer == 0) {	/* sparse file */
				hole += block->size;
				free(block);
				continue;
			}

			cache_block_wait(block->buffer);

			if (block->buffer->error)
				failed = TRUE;

			if (failed)
				continue;

			error = write_block(file_fd, block->buffer->data + block->offset, block->size, hole, file->sparse);

			if (error == FALSE) {
				ERROR("writer: failed to write data block %d\n", i);
				failed = TRUE;
			}

			hole = 0;
			cache_block_put(block->buffer);
			free(block);
		}

		if (hole && failed == FALSE) {
			/*
			 * corner case for hole extending to end of file
			 */
			if (file->sparse == FALSE || lseek(file_fd, hole, SEEK_CUR) == -1) {
				/*
				 * for files which we don't want to write
				 * sparsely, or for broken lseeks which cannot
				 * seek beyond end of file, write_block will do
				 * the right thing
				 */
				hole--;
				if (write_block(file_fd, "\0", 1, hole, file->sparse) == FALSE) {
					ERROR("writer: failed to write sparse " "data block\n");
					failed = TRUE;
				}
			} else if (ftruncate(file_fd, file->file_size) == -1) {
				ERROR("writer: failed to write sparse data " "block\n");
				failed = TRUE;
			}
		}

		close_wake(file_fd);
		if (failed == FALSE)
			set_attributes(file->pathname, file->mode, file->uid, file->gid, file->time, file->xattr, force);
		else {
			ERROR("Failed to write %s, skipping\n", file->pathname);
			unlink(file->pathname);
		}
		free(file->pathname);
		free(file);

	}
}

/*
 * decompress thread.  This decompresses buffers queued by the read thread
 */
void *inflator(void *arg) {
	char tmp[block_size];

	while (1) {
		struct cache_entry *entry = queue_get(to_inflate);
		int error, res;

		res = compressor_uncompress(comp, tmp, entry->data, SQUASHFS_COMPRESSED_SIZE_BLOCK(entry->size), block_size, &error);

		if (res == -1)
			ERROR("%s uncompress failed with error code %d\n", comp->name, error);
		else
			memcpy(entry->data, tmp, res);

		/*
		 * block has been either successfully decompressed, or an error
		 * occurred, clear pending flag, set error appropriately and
		 * wake up any threads waiting on this block
		 */
		cache_block_ready(entry, res == -1);
	}
}

void *progress_thread(void *arg) {
	struct timespec requested_time, remaining;
	struct itimerval itimerval;
	struct winsize winsize;

	if (ioctl(1, TIOCGWINSZ, &winsize) == -1) {
		if (isatty(STDOUT_FILENO))
			ERROR("TIOCGWINSZ ioctl failed, defaulting to 80 " "columns\n");
		columns = 80;
	} else
		columns = winsize.ws_col;
	signal(SIGWINCH, sigwinch_handler);
	signal(SIGALRM, sigalrm_handler);

	itimerval.it_value.tv_sec = 0;
	itimerval.it_value.tv_usec = 250000;
	itimerval.it_interval.tv_sec = 0;
	itimerval.it_interval.tv_usec = 250000;
	setitimer(ITIMER_REAL, &itimerval, NULL);

	requested_time.tv_sec = 0;
	requested_time.tv_nsec = 250000000;

	while (1) {
		int res = nanosleep(&requested_time, &remaining);

		if (res == -1 && errno != EINTR)
			EXIT_UNSQUASH("nanosleep failed in progress thread\n");

		if (progress_enabled) {
			pthread_mutex_lock(&screen_mutex);
			progress_bar(sym_count + dev_count + fifo_count + cur_blocks, total_inodes - total_files + total_blocks, columns);
			pthread_mutex_unlock(&screen_mutex);
		}
	}
}

void initialise_threads(int fragment_buffer_size, int data_buffer_size) {
	struct rlimit rlim;
	int i, max_files, res;
	sigset_t sigmask, old_mask;

	/* block SIGQUIT and SIGHUP, these are handled by the info thread */
	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGQUIT);
	sigaddset(&sigmask, SIGHUP);
	if (pthread_sigmask(SIG_BLOCK, &sigmask, NULL) == -1)
		EXIT_UNSQUASH("Failed to set signal mask in initialise_threads" "\n");

	/*
	 * temporarily block these signals so the created sub-threads will
	 * ignore them, ensuring the main thread handles them
	 */
	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGINT);
	sigaddset(&sigmask, SIGTERM);
	if (pthread_sigmask(SIG_BLOCK, &sigmask, &old_mask) == -1)
		EXIT_UNSQUASH("Failed to set signal mask in initialise_threads" "\n");

	if (processors == -1) {
#if !defined(linux) && !defined(__CYGWIN__)
		int mib[2];
		size_t len = sizeof(processors);

		mib[0] = CTL_HW;
#    ifdef HW_AVAILCPU
		mib[1] = HW_AVAILCPU;
#    else
		mib[1] = HW_NCPU;
#    endif

		if (sysctl(mib, 2, &processors, &len, NULL, 0) == -1) {
			ERROR("Failed to get number of available processors.  " "Defaulting to 1\n");
			processors = 1;
		}
#else
		processors = sysconf(_SC_NPROCESSORS_ONLN);
#endif
	}

	if (add_overflow(processors, 3) || multiply_overflow(processors + 3, sizeof(pthread_t)))
		EXIT_UNSQUASH("Processors too large\n");

	thread = malloc((3 + processors) * sizeof(pthread_t));
	if (thread == NULL)
		EXIT_UNSQUASH("Out of memory allocating thread descriptors\n");
	inflator_thread = &thread[3];

	/*
	 * dimensioning the to_reader and to_inflate queues.  The size of
	 * these queues is directly related to the amount of block
	 * read-ahead possible.  To_reader queues block read requests to
	 * the reader thread and to_inflate queues block decompression
	 * requests to the inflate thread(s) (once the block has been read by
	 * the reader thread).  The amount of read-ahead is determined by
	 * the combined size of the data_block and fragment caches which
	 * determine the total number of blocks which can be "in flight"
	 * at any one time (either being read or being decompressed)
	 *
	 * The maximum file open limit, however, affects the read-ahead
	 * possible, in that for normal sizes of the fragment and data block
	 * caches, where the incoming files have few data blocks or one fragment
	 * only, the file open limit is likely to be reached before the
	 * caches are full.  This means the worst case sizing of the combined
	 * sizes of the caches is unlikely to ever be necessary.  However, is is
	 * obvious read-ahead up to the data block cache size is always possible
	 * irrespective of the file open limit, because a single file could
	 * contain that number of blocks.
	 *
	 * Choosing the size as "file open limit + data block cache size" seems
	 * to be a reasonable estimate.  We can reasonably assume the maximum
	 * likely read-ahead possible is data block cache size + one fragment
	 * per open file.
	 *
	 * dimensioning the to_writer queue.  The size of this queue is
	 * directly related to the amount of block read-ahead possible.
	 * However, unlike the to_reader and to_inflate queues, this is
	 * complicated by the fact the to_writer queue not only contains
	 * entries for fragments and data_blocks but it also contains
	 * file entries, one per open file in the read-ahead.
	 *
	 * Choosing the size as "2 * (file open limit) +
	 * data block cache size" seems to be a reasonable estimate.
	 * We can reasonably assume the maximum likely read-ahead possible
	 * is data block cache size + one fragment per open file, and then
	 * we will have a file_entry for each open file.
	 */
	res = getrlimit(RLIMIT_NOFILE, &rlim);
	if (res == -1) {
		ERROR("failed to get open file limit!  Defaulting to 1\n");
		rlim.rlim_cur = 1;
	}

	if (rlim.rlim_cur != RLIM_INFINITY) {
		/*
		 * leave OPEN_FILE_MARGIN free (rlim_cur includes fds used by
		 * stdin, stdout, stderr and filesystem fd
		 */
		if (rlim.rlim_cur <= OPEN_FILE_MARGIN)
			/* no margin, use minimum possible */
			max_files = 1;
		else
			max_files = rlim.rlim_cur - OPEN_FILE_MARGIN;
	} else
		max_files = -1;

	/* set amount of available files for use by open_wait and close_wake */
	open_init(max_files);

	/*
	 * allocate to_reader, to_inflate and to_writer queues.  Set based on
	 * open file limit and cache size, unless open file limit is unlimited,
	 * in which case set purely based on cache limits
	 *
	 * In doing so, check that the user supplied values do not overflow
	 * a signed int
	 */
	if (max_files != -1) {
		if (add_overflow(data_buffer_size, max_files) || add_overflow(data_buffer_size, max_files * 2))
			EXIT_UNSQUASH("Data queue size is too large\n");

		to_reader = queue_init(max_files + data_buffer_size);
		to_inflate = queue_init(max_files + data_buffer_size);
		to_writer = queue_init(max_files * 2 + data_buffer_size);
	} else {
		int all_buffers_size;

		if (add_overflow(fragment_buffer_size, data_buffer_size))
			EXIT_UNSQUASH("Data and fragment queues combined are" " too large\n");

		all_buffers_size = fragment_buffer_size + data_buffer_size;

		if (add_overflow(all_buffers_size, all_buffers_size))
			EXIT_UNSQUASH("Data and fragment queues combined are" " too large\n");

		to_reader = queue_init(all_buffers_size);
		to_inflate = queue_init(all_buffers_size);
		to_writer = queue_init(all_buffers_size * 2);
	}

	from_writer = queue_init(1);

	fragment_cache = cache_init(block_size, fragment_buffer_size);
	data_cache = cache_init(block_size, data_buffer_size);
	pthread_create(&thread[0], NULL, reader, NULL);
	pthread_create(&thread[1], NULL, writer, NULL);
	pthread_create(&thread[2], NULL, progress_thread, NULL);
	init_info();
	pthread_mutex_init(&fragment_mutex, NULL);

	for (i = 0; i < processors; i++) {
		if (pthread_create(&inflator_thread[i], NULL, inflator, NULL) != 0)
			EXIT_UNSQUASH("Failed to create thread\n");
	}

	printf("Parallel unsquashfs: Using %d processor%s\n", processors, processors == 1 ? "" : "s");

	if (pthread_sigmask(SIG_SETMASK, &old_mask, NULL) == -1)
		EXIT_UNSQUASH("Failed to set signal mask in initialise_threads" "\n");
}

void enable_progress_bar() {
	pthread_mutex_lock(&screen_mutex);
	progress_enabled = progress;
	pthread_mutex_unlock(&screen_mutex);
}

void disable_progress_bar() {
	pthread_mutex_lock(&screen_mutex);
	if (progress_enabled) {
		progress_bar(sym_count + dev_count + fifo_count + cur_blocks, total_inodes - total_files + total_blocks, columns);
		printf("\n");
	}
	progress_enabled = FALSE;
	pthread_mutex_unlock(&screen_mutex);
}

void progressbar_error(char *fmt, ...) {
	va_list ap;

	pthread_mutex_lock(&screen_mutex);

	if (progress_enabled)
		fprintf(stderr, "\n");

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	pthread_mutex_unlock(&screen_mutex);
}

void progressbar_info(char *fmt, ...) {
	va_list ap;

	pthread_mutex_lock(&screen_mutex);

	if (progress_enabled)
		printf("\n");

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);

	pthread_mutex_unlock(&screen_mutex);
}

void progress_bar(long long current, long long max, int columns) {
	char rotate_list[] = { '|', '/', '-', '\\' };
	int max_digits, used, hashes, spaces;
	static int tty = -1;

	if (max == 0)
		return;

	max_digits = floor(log10(max)) + 1;
	used = max_digits * 2 + 11;
	hashes = (current * (columns - used)) / max;
	spaces = columns - used - hashes;

	if ((current > max) || (columns - used < 0))
		return;

	if (tty == -1)
		tty = isatty(STDOUT_FILENO);
	if (!tty) {
		static long long previous = -1;

		/*
		 * Updating much more frequently than this results in huge
		 * log files.
		 */
		if ((current % 100) != 0 && current != max)
			return;
		/* Don't update just to rotate the spinner. */
		if (current == previous)
			return;
		previous = current;
	}

	printf("\r[");

	while (hashes--)
		putchar('=');

	putchar(rotate_list[rotate]);

	while (spaces--)
		putchar(' ');

	printf("] %*lld/%*lld", max_digits, current, max_digits, max);
	printf(" %3lld%%", current * 100 / max);
	fflush(stdout);
}

int parse_number(char *arg, int *res) {
	char *b;
	long number = strtol(arg, &b, 10);

	/* check for trailing junk after number */
	if (*b != '\0')
		return 0;

	/*
	 * check for strtol underflow or overflow in conversion.
	 * Note: strtol can validly return LONG_MIN and LONG_MAX
	 * if the user entered these values, but, additional code
	 * to distinguish this scenario is unnecessary, because for
	 * our purposes LONG_MIN and LONG_MAX are too large anyway
	 */
	if (number == LONG_MIN || number == LONG_MAX)
		return 0;

	/* reject negative numbers as invalid */
	if (number < 0)
		return 0;

	/* check if long result will overflow signed int */
	if (number > INT_MAX)
		return 0;

	*res = number;
	return 1;
}

#define VERSION() \
	printf("unsquashfs version 4.3 (2014/05/12)\n");\
	printf("copyright (C) 2014 Phillip Lougher "\
		"<phillip@squashfs.org.uk>\n\n");\
    	printf("This program is free software; you can redistribute it and/or"\
		"\n");\
	printf("modify it under the terms of the GNU General Public License"\
		"\n");\
	printf("as published by the Free Software Foundation; either version "\
		"2,\n");\
	printf("or (at your option) any later version.\n\n");\
	printf("This program is distributed in the hope that it will be "\
		"useful,\n");\
	printf("but WITHOUT ANY WARRANTY; without even the implied warranty of"\
		"\n");\
	printf("MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the"\
		"\n");\
	printf("GNU General Public License for more details.\n");

int is_squashfs(char *filename) {
	if ((fd = open(filename, O_RDONLY)) == -1) {
		ERROR("Could not open %s, because %s\n", filename, strerror(errno));
		return FALSE;
	}
	char *buffer = (char *)malloc(sizeof(char) * 0x67);
	if (buffer == NULL) {
		printf("Memory allocation error!\n");
		return FALSE;
	}
	int result = read(fd, buffer, 0x67);
	if (result != 0x67) {
		printf("File reading error!\n");
		return FALSE;
	}
	result = memcmp(&buffer[0x64], "cdx", 3);
	free(buffer);

	if (!result)
		return FALSE;

	result = read_super(filename);
	close(fd);
	return result;
}

int unsquashfs(char *squashfs, char *dest) {
	int i, stat_sys = FALSE, version = FALSE;
	int n;
	struct pathnames *paths = NULL;
	struct pathname *path = NULL;
	long long directory_table_end;
	int fragment_buffer_size = FRAGMENT_BUFFER_DEFAULT;
	int data_buffer_size = DATA_BUFFER_DEFAULT;

	pthread_mutex_init(&screen_mutex, NULL);
	root_process = geteuid() == 0;
	if (root_process)
		umask(0);

#ifdef SQUASHFS_TRACE
	/*
	 * Disable progress bar if full debug tracing is enabled.
	 * The progress bar in this case just gets in the way of the
	 * debug trace output
	 */
	progress = FALSE;
#endif

	if ((fd = open(squashfs, O_RDONLY)) == -1) {
		ERROR("Could not open %s, because %s\n", squashfs, strerror(errno));
		exit(1);
	}

	if (read_super(squashfs) == FALSE)
		exit(1);

	if (stat_sys) {
		squashfs_stat(squashfs);
		exit(0);
	}

	if (!check_compression(comp))
		exit(1);

	block_size = sBlk.s.block_size;
	block_log = sBlk.s.block_log;

	/*
	 * Sanity check block size and block log.
	 *
	 * Check they're within correct limits
	 */
	if (block_size > SQUASHFS_FILE_MAX_SIZE || block_log > SQUASHFS_FILE_MAX_LOG)
		EXIT_UNSQUASH("Block size or block_log too large." "  File system is corrupt.\n");

	/*
	 * Check block_size and block_log match
	 */
	if (block_size != (1 << block_log))
		EXIT_UNSQUASH("Block size and block_log do not match." "  File system is corrupt.\n");

	/*
	 * convert from queue size in Mbytes to queue size in
	 * blocks.
	 *
	 * In doing so, check that the user supplied values do not
	 * overflow a signed int
	 */
	if (shift_overflow(fragment_buffer_size, 20 - block_log))
		EXIT_UNSQUASH("Fragment queue size is too large\n");
	else
		fragment_buffer_size <<= 20 - block_log;

	if (shift_overflow(data_buffer_size, 20 - block_log))
		EXIT_UNSQUASH("Data queue size is too large\n");
	else
		data_buffer_size <<= 20 - block_log;

	initialise_threads(fragment_buffer_size, data_buffer_size);

	fragment_data = malloc(block_size);
	if (fragment_data == NULL)
		EXIT_UNSQUASH("failed to allocate fragment_data\n");

	file_data = malloc(block_size);
	if (file_data == NULL)
		EXIT_UNSQUASH("failed to allocate file_data");

	data = malloc(block_size);
	if (data == NULL)
		EXIT_UNSQUASH("failed to allocate data\n");

	created_inode = malloc(sBlk.s.inodes * sizeof(char *));
	if (created_inode == NULL)
		EXIT_UNSQUASH("failed to allocate created_inode\n");

	memset(created_inode, 0, sBlk.s.inodes * sizeof(char *));

	if (s_ops.read_uids_guids() == FALSE)
		EXIT_UNSQUASH("failed to uid/gid table\n");

	if (s_ops.read_fragment_table(&directory_table_end) == FALSE)
		EXIT_UNSQUASH("failed to read fragment table\n");

	if (read_inode_table(sBlk.s.inode_table_start, sBlk.s.directory_table_start) == FALSE)
		EXIT_UNSQUASH("failed to read inode table\n");

	if (read_directory_table(sBlk.s.directory_table_start, directory_table_end) == FALSE)
		EXIT_UNSQUASH("failed to read directory table\n");

	if (no_xattrs)
		sBlk.s.xattr_id_table_start = SQUASHFS_INVALID_BLK;

	if (read_xattrs_from_disk(fd, &sBlk.s) == 0)
		EXIT_UNSQUASH("failed to read the xattr table\n");

	if (path) {
		paths = init_subdir();
		paths = add_subdir(paths, path);
	}

	pre_scan(dest, SQUASHFS_INODE_BLK(sBlk.s.root_inode), SQUASHFS_INODE_OFFSET(sBlk.s.root_inode), paths);

	memset(created_inode, 0, sBlk.s.inodes * sizeof(char *));
	inode_number = 1;

	printf("%d inodes (%d blocks) to write\n\n", total_inodes, total_inodes - total_files + total_blocks);

	enable_progress_bar();

	dir_scan(dest, SQUASHFS_INODE_BLK(sBlk.s.root_inode), SQUASHFS_INODE_OFFSET(sBlk.s.root_inode), paths);

	queue_put(to_writer, NULL);
	queue_get(from_writer);

	disable_progress_bar();

	if (!lsonly) {
		printf("\n");
		printf("created %d files\n", file_count);
		printf("created %d directories\n", dir_count);
		printf("created %d symlinks\n", sym_count);
		printf("created %d devices\n", dev_count);
		printf("created %d fifos\n", fifo_count);
	}

	return 0;
}
