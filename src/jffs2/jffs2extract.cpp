/*
 * a very simple jffs2 unpacker.
 * algorithm is memory intensive but has (almost) linear complexity.
 * at first, the jffs2 is unpacked and put into a map, inode data blocks
 * sorted by version number.
 * then the data blocks are "replayed" in correct order, and memcpy'ed 
 * into a buffer.
 *
 * usage: jffs2_unpack <jffs2 file> <output directory> <endianess>
 * ...where endianess is 4321 for big endian or 1234 for little endian.
 *
 * SECURITY NOTE: as you need to run this program as root, you could 
 * easily build a fake-jffs2 file with relative pathnames, thus overwriting
 * any file on the host system! BE AWARE OF THIS!
 * (this could be easily avoided by checking directory. however, i don't
 * want to give any false sense of security. this program was NOT designed
 * with security in mind, and i know that this is no excuse.)
 *
 * License: GPL (due to the used unpack algorithms)
 *
 *                          (C) 2006 Felix Domke <tmbinc@elitedvb.net>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#ifdef __APPLE__
#    include <machine/endian.h>
#else
#    include <endian.h>
#    include <sys/sysmacros.h>
#endif

#include <map>
#include <string>
#include <list>
#include <vector>
#include <set>

#include "mfile.h"
#include "common.h"
#include "lzo/lzo1x.h"
#include "lzma.h"
#include "util.h"

#include "os_byteswap.h"
#include "jffs2/mini_inflate.h"
#include "jffs2/jffs2.h"

#define PAD_U32(x) ((x + 3) & ~3)
#define PAD_X(x, y) ((x + (y - 1) & ~(y - 1)))

#define RUBIN_REG_SIZE   16
#define UPPER_BIT_RUBIN    (((long) 1)<<(RUBIN_REG_SIZE-1))
#define LOWER_BITS_RUBIN   ((((long) 1)<<(RUBIN_REG_SIZE-1))-1)

extern unsigned long crc32_no_comp(unsigned long crc, const unsigned char *buf, int len);

static int swap_words = -1;
static int verbose = 0;
static bool guess_es = false;
static bool keep_unlinked = true;

static CLzmaEncHandle *p;
static uint8_t propsEncoded[LZMA_PROPS_SIZE];
static size_t propsSize = sizeof(propsEncoded);

unsigned short fix16(unsigned short c) {
	if (swap_words)
		return bswap_16(c);
	else
		return c;
}

unsigned long fix32(unsigned long c) {
	if (swap_words)
		return bswap_32(c);
	else
		return c;
}

typedef __u32 u32;

void lzma_free_workspace(void)
{
	LzmaEnc_Destroy(p, &lzma_alloc, &lzma_alloc);
}


int lzma_alloc_workspace(CLzmaEncProps *props)
{
	if ((p = (CLzmaEncHandle *)LzmaEnc_Create(&lzma_alloc)) == NULL)
	{
		PRINT_ERROR("Failed to allocate lzma deflate workspace\n");
		return -ENOMEM;
	}

	if (LzmaEnc_SetProps(p, props) != SZ_OK)
	{
		lzma_free_workspace();
		return -1;
	}
	
	if (LzmaEnc_WriteProperties(p, propsEncoded, &propsSize) != SZ_OK)
	{
		lzma_free_workspace();
		return -1;
	}

        return 0;
}

void rubin_do_decompress(unsigned char *bits, unsigned char *in, unsigned char *page_out, __u32 destlen) {
	register unsigned char *curr = page_out;
	unsigned char *end = page_out + destlen;
	register unsigned long temp;
	register unsigned long result;
	register unsigned long p;
	register unsigned long q;
	register unsigned long rec_q;
	register unsigned long bit;
	register long i0;
	unsigned long i;

	/* init_pushpull */
	temp = *(u32 *) in;
	bit = 16;

	/* init_rubin */
	q = 0;
	p = (long)(2 * UPPER_BIT_RUBIN);

	/* init_decode */
	rec_q = (in[0] << 8) | in[1];

	while (curr < end) {
		/* in byte */

		result = 0;
		for (i = 0; i < 8; i++) {
			/* decode */

			while ((q & UPPER_BIT_RUBIN) || ((p + q) <= UPPER_BIT_RUBIN)) {
				q &= ~UPPER_BIT_RUBIN;
				q <<= 1;
				p <<= 1;
				rec_q &= ~UPPER_BIT_RUBIN;
				rec_q <<= 1;
				rec_q |= (temp >> (bit++ ^ 7)) & 1;
				if (bit > 31) {
					bit = 0;
					temp = *(u32 *) in;
					in += 4;
				}
			}
			i0 = (bits[i] * p) >> 8;

			if (i0 <= 0)
				i0 = 1;
			/* if it fails, it fails, we have our crc
			   if (i0 >= p) i0 = p - 1; */

			result >>= 1;
			if (rec_q < q + i0) {
				/* result |= 0x00; */
				p = i0;
			} else {
				result |= 0x80;
				p -= i0;
				q += i0;
			}
		}
		*(curr++) = result;
	}
}

void dynrubin_decompress(unsigned char *data_in, unsigned char *cpage_out, unsigned long sourcelen, unsigned long dstlen) {
	unsigned char bits[8];
	int c;

	for (c = 0; c < 8; c++)
		bits[c] = (256 - data_in[c]);

	rubin_do_decompress(bits, data_in + 8, cpage_out, dstlen);
}

void rtime_decompress(unsigned char *data_in, unsigned char *cpage_out, u32 srclen, u32 destlen) {
	int positions[256];
	int outpos;
	int pos;
	int i;

	outpos = pos = 0;

	for (i = 0; i < 256; positions[i++] = 0) ;

	while (outpos < destlen) {
		unsigned char value;
		int backoffs;
		int repeat;

		value = data_in[pos++];
		cpage_out[outpos++] = value;	/* first the verbatim copied byte */
		repeat = data_in[pos++];
		backoffs = positions[value];

		positions[value] = outpos;
		if (repeat) {
			if (backoffs + repeat >= outpos) {
				while (repeat) {
					cpage_out[outpos++] = cpage_out[backoffs++];
					repeat--;
				}
			} else {
				for (i = 0; i < repeat; i++)
					*(cpage_out + outpos + i) = *(cpage_out + backoffs + i);
				outpos += repeat;
			}
		}
	}
}

long zlib_decompress(unsigned char *data_in, unsigned char *cpage_out, __u32 srclen, __u32 destlen) {
	return (decompress_block(cpage_out, data_in + 2, memcpy));
}

long lzma_decompress(unsigned char *data_in, unsigned char *cpage_out,
				 uint32_t srclen, uint32_t destlen)
{
	int ret;
	size_t dl = (size_t)destlen;
	size_t sl = (size_t)srclen;
	ELzmaStatus status;
	
	ret = LzmaDecode(cpage_out, &dl, data_in, &sl, propsEncoded,
		propsSize, LZMA_FINISH_ANY, &status, &lzma_alloc);

	if (ret != SZ_OK || status == LZMA_STATUS_NOT_FINISHED || dl != (size_t)destlen)
		return -1;

	return destlen;
}

long lzo_decompress(unsigned char *data_in, unsigned char *cpage_out,
				 uint32_t srclen, uint32_t destlen)
{
	size_t dl = destlen;
	int ret;

	ret = lzo1x_decompress_safe(data_in, srclen, cpage_out, &dl, NULL);

	if (ret != LZO_E_OK || dl != destlen)
		return -1;

	return dl;
}


int do_uncompress(void *dst, int dstlen, void *src, int srclen, int type) {
	switch (type) {
	case JFFS2_COMPR_NONE:
		memcpy(dst, src, dstlen);
		return dstlen;
	case JFFS2_COMPR_ZERO:
		memset(dst, 0, dstlen);
		return dstlen;
	case JFFS2_COMPR_RTIME:
		rtime_decompress((unsigned char *)src, (unsigned char *)dst, srclen, dstlen);
		return dstlen;
	case JFFS2_COMPR_RUBINMIPS:
		break;
	case JFFS2_COMPR_COPY:
		break;
	case JFFS2_COMPR_DYNRUBIN:
		dynrubin_decompress((unsigned char *)src, (unsigned char *)dst, srclen, dstlen);
		return dstlen;
	case JFFS2_COMPR_ZLIB:
		return zlib_decompress((unsigned char *)src, (unsigned char *)dst, srclen, dstlen);
	case JFFS2_COMPR_LZO:
		return lzo_decompress((unsigned char *)src, (unsigned char *)dst, srclen, dstlen);
	case JFFS2_COMPR_LZMA:
		return lzma_decompress((unsigned char *)src, (unsigned char *)dst, srclen, dstlen);
	}
	printf("  ** unknown compression type %d!\n", type);
	return -1;
}

std::map <int, std::string> inodes;
std::map <int, __u8> node_type;
std::map <int, std::list <int> > childs;

struct nodedata_s {
	unsigned char *data;
	int size;
	int offset;

	int isize, gid, uid, mode;

	nodedata_s(unsigned char *_data, int _size, int _offset, int _isize, int _gid, int _uid, int _mode) {
		data = (unsigned char *)malloc(_size);
		size = _size;
		offset = _offset;
		memcpy(data, _data, size);

		isize = _isize;
		gid = _gid;
		uid = _uid;
		mode = _mode;
	} nodedata_s() {
		data = 0;
		size = 0;
		offset = 0;

		isize = 0;
		gid = 0;
		uid = 0;
		mode = 0;
	}
};

std::map <int, std::map <int, struct nodedata_s>> nodedata;

int whine = 0;
std::string prefix;
FILE *devtab;

void do_list(int inode, std::string root = "") {
	std::string pathname = prefix + root + inodes[inode];

	std::map <int, struct nodedata_s> &data = nodedata[inode];
	
	//printf("inode %d -> %s\n", inode, inodes[inode].c_str());

	int max_size = 0, gid = 0, uid = 0, mode = 0755;
	if (!data.empty()) {
		std::map <int, struct nodedata_s>::iterator last = data.end();
		--last;
		max_size = last->second.isize;
		mode = last->second.mode;
		gid = last->second.gid;
		uid = last->second.uid;
	}

	if ((node_type[inode] == DT_BLK) || (node_type[inode] == DT_CHR))
		max_size = 2;

	unsigned char *merged_data = (unsigned char *)calloc(1, max_size + 1);
	int devtab_type = 0, major = 0, minor = 0;

	for (auto i : data) {
		int size = i.second.size;
		int offset = i.second.offset;
		if (offset + size > max_size)
			size = max_size - offset;
		if (size > 0)
			memcpy(merged_data + i.second.offset, i.second.data, i.second.size);
	}

	switch (node_type[inode]) {
	case DT_DIR:
		if (mkdir(pathname.c_str(), mode & 0777)){
			fprintf(stderr, "mkdir '%s' failed (%s)\n", pathname.c_str(), strerror(errno));
		}
		devtab_type = 'd';
		break;

	case DT_REG:
		{
			FILE *f = fopen(pathname.c_str(), "wb");
			if (!f){
				fprintf(stderr, "fopen '%s' failed (%s)\n", pathname.c_str(), strerror(errno));
			} else {
				fwrite(merged_data, max_size, 1, f);
				fclose(f);
			}
			devtab_type = 'f';
			break;
		}
	case DT_LNK:
		{
			symlink((char *)merged_data, pathname.c_str());
			break;
		}
	case DT_CHR:
	case DT_BLK:
		{
			major = merged_data[1];
			minor = merged_data[0];
			if (mknod(pathname.c_str(), ((node_type[inode] == DT_BLK) ? S_IFBLK : S_IFCHR) | (mode & 07777), makedev(major, minor))) {
				if (!whine++){
					fprintf(stderr, "mknod '%s' failed (%s)\n", pathname.c_str(), strerror(errno));
				}
			}

			if (node_type[inode] == DT_BLK)
				devtab_type = 'b';
			else
				devtab_type = 'c';
			break;
		}
	case DT_FIFO:
		{
			if (mkfifo(pathname.c_str(), mode) < 0)
				fprintf(stderr, "failed to create FIFO(%s) (%s)\n", pathname.c_str(), strerror(errno));
			break;
		}
	case DT_SOCK: {
		// create and close a TCP Unix Socket
		int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
		const char *cpath = pathname.c_str();
		
		if(sock_fd < 0){
			fprintf(stderr, "failed to create unix socket '%s' (%s)\n", cpath, strerror(errno));
			break;
		}
		close(sock_fd);
		break;
	}
	case DT_WHT:
		goto node_warn_uhnandled;
	case DT_UNKNOWN:
		//deletion node
		if(inode == 0){
			const char *cpath = pathname.c_str();
		
			if(keep_unlinked){
				int nidx = 0;
				std::string suffix = "";

				while(access((pathname + suffix).c_str(), F_OK ) != -1){
					suffix = std::to_string(nidx++);
				}

				std::string new_name = pathname + suffix;
				
				MFILE *f_src = mopen(cpath, O_RDONLY);
				MFILE *f_dst = mfopen(new_name.c_str(), "w+");
				if(!f_src || !f_dst){
					fprintf(stderr, "failed to copy '%s' to '%s'\n", cpath, new_name.c_str());
					if(f_src)
						mclose(f_src);
					if(f_dst)
						mclose(f_dst);
				} else {
					mfile_map(f_dst, msize(f_src));
					memcpy(
						mdata(f_dst, void),
						mdata(f_src, void),
						msize(f_src)
					);
					mclose(f_dst);
					mclose(f_src);
				}
			}
		} else {
			node_warn_uhnandled:
			printf("warning:unhandled inode type(%d) for inode %d\n", node_type[inode], inode);
		}
		break;
	}

	free(merged_data);

	if (devtab_type && devtab && (inode != 1)){
		fprintf(devtab, "%s %c %o %d %d %d %d - - -\n",
			(root + inodes[inode]).c_str(),
			devtab_type,
			mode & 07777,
			uid, gid, major, minor
		);
	}

	if (node_type[inode] != DT_LNK) {
		if (chmod(pathname.c_str(), mode))
			if (!whine++){
				fprintf(stderr, "chmod failed for '%s' (%s)\n", pathname.c_str(), strerror(errno));
			}

		if (chown(pathname.c_str(), uid, gid)) {
#ifndef __CYGWIN__
			if (!whine++)
				fprintf(stderr, "chown failed for '%s' (%s)\n", pathname.c_str(), strerror(errno));
#endif
		}
	}
//  printf("%s (%d)\n", pathname.c_str(), max_size);
	std::list < int >&child = childs[inode];
	for (auto i : child)
		do_list(i, root + inodes[inode].c_str() + "/");
}


inline int is_jffs2_magic(uint16_t val){
	if(val == KSAMTIB_CIGAM_2SFFJ){
		fputs("invalid endianess detected\n", stderr);
		return -1;
	}
	return (val == JFFS2_MAGIC_BITMASK);
}

size_t contiguos_region_size(MFILE *mf, off_t offset, uint8_t match_pattern){
	uint8_t *pStart = mdata(mf, uint8_t);
	uint8_t *cursor = pStart + offset;
	size_t fileSz = msize(mf);
	
	for(; moff(mf, cursor) < fileSz; cursor++){
		if(*cursor != match_pattern)
			break;
	}
	return (cursor - pStart) - offset;
}

uint32_t try_guess_es(MFILE *mf, bool *is_reliable){
	uint8_t *data = mdata(mf, uint8_t);
	size_t fileSz = msize(mf);
	
	*is_reliable = false;
	
	uint8_t blk16[16];
	memset(&blk16, 0xFF, sizeof(blk16));
	
	// find start of remaining data
	off_t off = 0;
	for(; off < fileSz; off += sizeof(blk16)){
		if(!memcmp(data + off, &blk16, sizeof(blk16)))
			break;
	}
	
	if(off == fileSz)
		return 0;
	
	// align to 16
	int remainder = off % 16;
	while(remainder > 0){
		if(*(data + (off++)) != 0xFF)
			return off;
	}
	
	// find end
	for(; off < fileSz; off += sizeof(blk16)){
		if(memcmp(data + off, &blk16, sizeof(blk16)) != 0)
			break;
	}
	
	// align to next JFFS2 header
	for(int i=0; i<=32; i++, off++){
		union jffs2_node_union *hdr = (union jffs2_node_union *)(data + off);
		if((is_jffs2_magic(hdr->u.magic)) &&
			crc32_no_comp(0, (uint8_t *)hdr, sizeof(hdr->u) - 4) == fix32(hdr->u.hdr_crc)
		){
			break;
		}
	}
	
	*is_reliable = true;
	return off;
}

union jffs2_node_union *find_next_node(MFILE *mf, off_t cur_off, int erase_size){
	uint8_t *data = mdata(mf, uint8_t);
	size_t fileSz = msize(mf);
	
	// find empty FS data
	{
		size_t empty_fsdata_sz = contiguos_region_size(mf, cur_off, 0x0);
		if(empty_fsdata_sz != 0){
			if(verbose)
				printf("region(0x00) = 0x%x\n", empty_fsdata_sz);
		}
	
		cur_off += empty_fsdata_sz;
	}
	
	if(erase_size > -1){
		cur_off = PAD_X(cur_off, erase_size);
		goto find_jffs2;
	}
	
	// find empty eraseblocks
	{
		size_t empty_esblks_sz = contiguos_region_size(mf, cur_off, 0xFF);
		if(empty_esblks_sz != 0){
			if(verbose)
				printf("region(0xFF) = 0x%x\n", empty_esblks_sz);
		}
		
		cur_off += empty_esblks_sz;
	}
	
	find_jffs2:
	off_t off;
	for(off = cur_off; off < fileSz;){
		union jffs2_node_union *node = (union jffs2_node_union *)(data + off);
		int r;
		if((r=is_jffs2_magic(node->u.magic)) &&
			crc32_no_comp(0, (uint8_t *)node, sizeof(node->u) - 4) == fix32(node->u.hdr_crc)
		){
			return node;
		}
		
		// if something unusual happened, stop search
		if(r < 0){
			break;
		}
		
		if(erase_size > -1){
			off += erase_size;
		} else {
			off += 4;
		}
	}
	if(off == msize(mf)){
		return NULL;
	}
}

extern "C" int jffs2extract(char *infile, char *outdir, struct jffs2_main_args args) {
	int errors = 0;

	verbose = args.verbose;
	keep_unlinked = args.keep_unlinked;
	
	MFILE *mf = mopen(infile, O_RDONLY);
	if (!mf) {
		fprintf(stderr, "Failed to open '%s'\n", infile);
		return 1;
	}
	
	union jffs2_node_union *node = mdata(mf, union jffs2_node_union);

	swap_words = (node->u.magic == KSAMTIB_CIGAM_2SFFJ);
	
	bool es_reliable = false;
	uint32_t es;
	if(args.erase_size > -1){
		es = args.erase_size;
	} else if(guess_es){
		es = try_guess_es(mf, &es_reliable);
		printf("> Guessed Erase Size: 0x%x (reliable=%d)\n", es, es_reliable);
	}

	uint8_t *data = mdata(mf, uint8_t);

	off_t off = moff(mf, node);
	while(off + sizeof(*node) < msize(mf)){
		node = (union jffs2_node_union *)&data[off];		
		if(!is_jffs2_magic(node->u.magic) || node->u.totlen == 0){
			printf("invalid node - scanning next node... (offset: %p)\n", off);
			
			int use_es = -1;
			if(es_reliable){
				use_es = es;
			}
			node = find_next_node(mf, off, use_es);
			if(node == NULL){
				// reached EOF
				break;
			}
			off_t prev_off = off;
			off = moff(mf, node);
			printf("found at %p, after 0x%x bytes\n", off, off - prev_off);
		}
		
		off += PAD_U32(node->u.totlen);
		if (verbose)
			printf("at %08x: %04x | %04x (%lu bytes): ", off, fix16(node->u.magic), fix16(node->u.nodetype), fix32(node->u.totlen));

		if (crc32_no_comp(0, (unsigned char *)node, sizeof(node->u) - 4) != fix32(node->u.hdr_crc)) {
			++errors;
			printf(" ** wrong crc **\n");
			continue;
		}
		
		switch (fix16(node->u.nodetype)) {
			case JFFS2_NODETYPE_DIRENT:
			{
				char name[node->d.nsize + 1];
				strncpy(name, (char *)node->d.name, node->d.nsize);
				name[node->d.nsize] = 0;
				
				if (verbose)
					printf("DIRENT, ino %lu (%s), parent=%lu\n", fix32(node->d.ino), name, fix32(node->d.pino));

				uint32_t ino = fix32(node->d.ino);
				uint32_t pino = fix32(node->d.pino);
				
				inodes[ino] = name;
				node_type[ino] = node->d.type;
				childs[pino].push_back(ino);
				break;
			}
			case JFFS2_NODETYPE_INODE:
			{		
				if (verbose)
					printf("\n");
				if (crc32_no_comp(0, (unsigned char *)&(node->i), sizeof(struct jffs2_raw_inode) - 8) != fix32(node->i.node_crc)) {
					errors++;
					printf("  ** wrong node crc **\n");
					continue;
				}
				if (verbose) {
					printf("  INODE, ino %lu (version %lu) at %08lx\n", fix32(node->i.ino), fix32(node->i.version), fix32(node->i.offset));
					printf("  compression: %d, user compression requested: %d\n", node->i.compr, node->i.usercompr);
				}
				int compr_size = fix32(node->i.csize);
				int uncompr_size = fix32(node->i.dsize);
				if (verbose)
					printf("  compr_size: %d, uncompr_size: %d\n", compr_size, uncompr_size);
				
				uint8_t *compr = node->i.data;
				uint8_t uncomp[uncompr_size];

				int extracted_size;
				if (crc32_no_comp(0, compr, compr_size) != fix32(node->i.data_crc)) {
					errors++;
					printf("  ** wrong data crc **\n");
					continue;
				} else {
					if (verbose)
						printf("  data crc ok\n");
					if ((extracted_size=do_uncompress(uncomp, uncompr_size, compr, compr_size, node->i.compr)) != uncompr_size) {
						errors++;
						printf("  ** data uncompress failed! (%u =! %u)\n", extracted_size, uncompr_size);
					} else {
						nodedata[fix32(node->i.ino)][fix32(node->i.version)] = nodedata_s(
							uncomp, uncompr_size, fix32(node->i.offset),
							fix32(node->i.isize), fix32(node->i.gid),
							fix32(node->i.uid), fix32(node->i.mode)
						);
#if 0
						int i;
						for (i = 0; i < ((uncompr_size + 15) & ~15); ++i) {
							if ((i & 15) == 0)
								printf("%08x: ", fix32(node.i.offset) + i);
							if (i < uncompr_size)
								printf("%02x ", uncomp[i]);
							else
								printf("   ");
							if ((i & 15) == 15)
								printf("\n");
						}
#endif
					}
				}
				break;
			}
			case JFFS2_NODETYPE_CLEANMARKER:
				if (verbose)
					printf("CLEANMARKER\n");
				break;
			case JFFS2_NODETYPE_PADDING:
				if (verbose)
					printf("PADDING\n");
				break;
			case JFFS2_NODETYPE_SUMMARY:
				if (verbose)
					printf("SUMMARY\n");
				break;
			default:
				errors++;
				printf(" ** INVALID ** - nodetype %04x (offset: %p)\n", fix16(node->u.nodetype), off);
		}
	}

	if (errors) {
		if (!inodes.empty())
			printf("there were errors, but some valid stuff was detected. continuing.\n");
		else {
			fprintf(stderr, "errors present and no valid data.\n");
			mclose(mf);
			return 2;
		}
	}
	
	node_type[1] = DT_DIR;
	prefix = outdir;
	devtab = fopen((prefix + ".devtab").c_str(), "wb");
	do_list(1);
	fclose(devtab);

	mclose(mf);
	return 0;
}
