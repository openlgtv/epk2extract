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
#include <sys/stat.h>
#include <sys/types.h>

#ifdef __APPLE__
#    include <machine/endian.h>
#else
#    include <endian.h>
#endif

#include <os_byteswap.h>
#include <mini_inflate.h>

extern unsigned long crc32_no_comp(unsigned long crc, const unsigned char *buf, int len);

#define ES 0x1ff

#include <jffs2/jffs2.h>

int swap_words;

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

#define RUBIN_REG_SIZE   16
#define UPPER_BIT_RUBIN    (((long) 1)<<(RUBIN_REG_SIZE-1))
#define LOWER_BITS_RUBIN   ((((long) 1)<<(RUBIN_REG_SIZE-1))-1)

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

int do_uncompress(void *dst, int dstlen, void *src, int srclen, int type) {
	switch (type) {
	case JFFS2_COMPR_NONE:
		memcpy(dst, src, dstlen);
		return dstlen;
		break;
	case JFFS2_COMPR_ZERO:
		memset(dst, 0, dstlen);
		return dstlen;
		break;
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
	}
	printf("  ** unknown compression type %d!\n", type);
	return -1;
}

#include <map>
#include <string>
#include <list>
#include <vector>

std::map <int, std::string> inodes;
std::map <int, int> node_type;
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

std::map <int, std::map <int, struct nodedata_s> > nodedata;

int whine = 0;
std::string prefix;
FILE *devtab;

void do_list(int inode, std::string root = "") {
	std::string pathname = prefix + root + inodes[inode];

	std::map < int, struct nodedata_s >&data = nodedata[inode];

	int max_size = 0, gid = 0, uid = 0, mode = 0755;
	if (!data.empty()) {
		std::map < int, struct nodedata_s >::iterator last = data.end();
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

	for (std::map < int, struct nodedata_s >::iterator i(data.begin()); i != data.end(); ++i) {
		int size = i->second.size;
		int offset = i->second.offset;
		if (offset + size > max_size)
			size = max_size - offset;
		if (size > 0)
			memcpy(merged_data + i->second.offset, i->second.data, i->second.size);
	}

	switch (node_type[inode]) {
	case DT_DIR:
		if (mkdir(pathname.c_str(), mode & 0777))
			perror(pathname.c_str());
		devtab_type = 'd';
		break;

	case DT_REG:
		{
			FILE *f = fopen(pathname.c_str(), "wb");
			if (!f)
				perror(pathname.c_str());
			else {
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
				if (!whine++)
					perror("mknod");
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
				printf("warnning:fail to make FIFO(%s) !\n", pathname.c_str());
			break;
		}
	case DT_SOCK:
	case DT_WHT:
	case DT_UNKNOWN:
		printf("warnning:unhandled inode type(%d) !\n", node_type[inode]);
		break;
	}

	if (devtab_type && devtab && (inode != 1))
		fprintf(devtab, "%s %c %o %d %d %d %d - - -\n", (root + inodes[inode]).c_str(), devtab_type, mode & 07777, uid, gid, major, minor);

	if (node_type[inode] != DT_LNK) {
		if (chmod(pathname.c_str(), mode))
			if (!whine++)
				perror("chmod");

		if (chown(pathname.c_str(), uid, gid)) {
#ifndef __CYGWIN__
			if (!whine++)
				perror("chown");
#endif
		}
	}
//  printf("%s (%d)\n", pathname.c_str(), max_size);
	std::list < int >&child = childs[inode];
	for (std::list < int >::iterator i(child.begin()); i != child.end(); ++i)
		do_list(*i, root + inodes[inode].c_str() + "/");
}

int do_jffs2extract(char *infile, char *outdir, char *inendian) {
	int errors = 0;
	int verbose = 0;

	/*if (argc != 4)
	   {
	   fprintf(stderr, "usage: %s <jffs2 file> <output directory> <endianess>\n", *argv);
	   fprintf(stderr, "\t\tendianess must be %d (be) or %d (le)\n", BIG_ENDIAN, LITTLE_ENDIAN);
	   return 1;
	   } */

	FILE *fd = fopen(infile, "r");
	if (!fd) {
		perror(infile);
		return 1;
	}

	int endianess = atoi(inendian);
	if ((endianess != BIG_ENDIAN) && (endianess != LITTLE_ENDIAN)) {
		fprintf(stderr, "endianess must be %d (be) or %d (le)!\n", BIG_ENDIAN, LITTLE_ENDIAN);
		return 2;
	}

	swap_words = endianess != BYTE_ORDER;

	while (1) {
		union jffs2_node_union node;
		int off = ftell(fd);
		if (fread(&node, 1, sizeof(node), fd) != sizeof(node))
			break;

		if (node.u.magic == KSAMTIB_CIGAM_2SFFJ) {
			fprintf(stderr, "ERROR: reverse endianess detected!\n");
			break;
		}
		if (node.u.magic == 0xFFFF) {
			if (verbose)
				printf("%08x: empty marker - going to next eraseblock\n", off);
			if (fseek(fd, (off + ES + 1) & ~ES, SEEK_SET) < 0)
				break;
			continue;
		}
		if (verbose)
			printf("at %08x: %04x | %04x (%lu bytes): ", off, fix16(node.u.magic), fix16(node.u.nodetype), fix32(node.u.totlen));

		if (crc32_no_comp(0, (unsigned char *)&node, sizeof(node.u) - 4) != fix32(node.u.hdr_crc)) {
			++errors;
			printf(" ** wrong crc **\n");
		}

		switch (fix16(node.u.nodetype)) {
		case JFFS2_NODETYPE_DIRENT:
			{
				fseek(fd, off + sizeof(struct jffs2_raw_dirent), SEEK_SET);
				char name[node.d.nsize + 1];
				fread(name, node.d.nsize, 1, fd);
				name[node.d.nsize] = 0;
				if (verbose)
					printf("DIRENT, ino %lu (%s), parent=%lu\n", fix32(node.d.ino), name, fix32(node.d.pino));

				inodes[fix32(node.d.ino)] = name;
				node_type[fix32(node.d.ino)] = node.d.type;
				childs[fix32(node.d.pino)].push_back(fix32(node.d.ino));
				break;
			}
		case JFFS2_NODETYPE_INODE:
			{
				if (verbose)
					printf("\n");
				if (crc32_no_comp(0, (unsigned char *)&node.i, sizeof(struct jffs2_raw_inode) - 8) != fix32(node.i.node_crc)) {
					errors++;
					printf("  ** wrong node crc **\n");
				}
				if (verbose) {
					printf("  INODE, ino %lu (version %lu) at %08lx\n", fix32(node.i.ino), fix32(node.i.version), fix32(node.i.offset));
					printf("  compression: %d, user compression requested: %d\n", node.i.compr, node.i.usercompr);
				}
				int compr_size = fix32(node.i.csize);
				int uncompr_size = fix32(node.i.dsize);
				if (verbose)
					printf("  compr_size: %d, uncompr_size: %d\n", compr_size, uncompr_size);
				unsigned char compr[compr_size], uncomp[uncompr_size];
				fread(compr, compr_size, 1, fd);
				if (crc32_no_comp(0, compr, compr_size) != fix32(node.i.data_crc)) {
					errors++;
					printf("  ** wrong data crc **\n");
				} else {
					if (verbose)
						printf("  data crc ok\n");
					if (do_uncompress(uncomp, uncompr_size, compr, compr_size, node.i.compr) != uncompr_size) {
						errors++;
						printf("  ** data uncompress failed!\n");
					} else {
						nodedata[fix32(node.i.ino)][fix32(node.i.version)] = nodedata_s(uncomp, uncompr_size, fix32(node.i.offset), fix32(node.i.isize), fix32(node.i.gid), fix32(node.i.uid), fix32(node.i.mode));
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
		default:
			errors++;
			printf(" ** INVALID ** - nodetype %04x\n", fix16(node.u.nodetype));
		}

		if (fix32(node.u.totlen))
			fseek(fd, (off + fix32(node.u.totlen) + 3) & ~3, SEEK_SET);
		else {
			errors++;
			printf(" ** INVALID NODE SIZE. skipping to next eraseblock\n");
			fseek(fd, (off + ES + 1) & ~ES, SEEK_SET);
		}
	}

	if (errors) {
		if (!inodes.empty())
			printf("there were errors, but some valid stuff was detected. continuing.\n");
		else {
			fprintf(stderr, "errors present and no valid data.\n");
			return 2;
		}
	}
	node_type[1] = DT_DIR;
	prefix = outdir;
	devtab = fopen((prefix + ".devtab").c_str(), "wb");
	do_list(1);
	fclose(devtab);

	return 0;
}

extern "C" int jffs2extract(char *infile, char *outdir, char *inendian) {
	return do_jffs2extract(infile, outdir, inendian);
}
