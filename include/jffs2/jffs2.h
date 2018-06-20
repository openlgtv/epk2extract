/*
 * JFFS2 -- Journalling Flash File System, Version 2.
 *
 * Copyright © 2001-2007 Red Hat, Inc.
 * Copyright © 2004-2010 David Woodhouse <dwmw2@infradead.org>
 *
 * Created by David Woodhouse <dwmw2@infradead.org>
 *
 * For licensing information, see the file 'LICENCE' in the
 * jffs2 directory.
 */

#ifndef __LINUX_JFFS2_H__
#define __LINUX_JFFS2_H__

#ifdef __APPLE__
typedef __signed__ char __s8;
typedef unsigned char __u8;

typedef __signed__ short __s16;
typedef unsigned short __u16;

typedef __signed__ int __s32;
typedef unsigned int __u32;

#ifdef __GNUC__
__extension__ typedef __signed__ long long __s64;
__extension__ typedef unsigned long long __u64;
#else
typedef __signed__ long long __s64;
typedef unsigned long long __u64;
#endif
#else
#include <asm/types.h>
#endif

/* Values we may expect to find in the 'magic' field */
#define JFFS2_OLD_MAGIC_BITMASK 0x1984
#define JFFS2_MAGIC_BITMASK 0x1985
#define KSAMTIB_CIGAM_2SFFJ 0x8519 /* For detecting wrong-endian fs */
#define JFFS2_EMPTY_BITMASK 0xffff
#define JFFS2_DIRTY_BITMASK 0x0000

/* Summary node MAGIC marker */
#define JFFS2_SUM_MAGIC	0x02851885

/* We only allow a single char for length, and 0xFF is empty flash so
   we don't want it confused with a real length. Hence max 254.
*/
#define JFFS2_MAX_NAME_LEN 254

/* How small can we sensibly write nodes? */
#define JFFS2_MIN_DATA_LEN 128

#define JFFS2_COMPR_NONE	0x00
#define JFFS2_COMPR_ZERO	0x01
#define JFFS2_COMPR_RTIME	0x02
#define JFFS2_COMPR_RUBINMIPS	0x03
#define JFFS2_COMPR_COPY	0x04
#define JFFS2_COMPR_DYNRUBIN	0x05
#define JFFS2_COMPR_ZLIB	0x06
#define JFFS2_COMPR_LZO		0x07
#define JFFS2_COMPR_LZMA	0x08
/* Compatibility flags. */
#define JFFS2_COMPAT_MASK 0xc000      /* What do to if an unknown nodetype is found */
#define JFFS2_NODE_ACCURATE 0x2000
/* INCOMPAT: Fail to mount the filesystem */
#define JFFS2_FEATURE_INCOMPAT 0xc000
/* ROCOMPAT: Mount read-only */
#define JFFS2_FEATURE_ROCOMPAT 0x8000
/* RWCOMPAT_COPY: Mount read/write, and copy the node when it's GC'd */
#define JFFS2_FEATURE_RWCOMPAT_COPY 0x4000
/* RWCOMPAT_DELETE: Mount read/write, and delete the node when it's GC'd */
#define JFFS2_FEATURE_RWCOMPAT_DELETE 0x0000

#define JFFS2_NODETYPE_DIRENT (JFFS2_FEATURE_INCOMPAT | JFFS2_NODE_ACCURATE | 1)
#define JFFS2_NODETYPE_INODE (JFFS2_FEATURE_INCOMPAT | JFFS2_NODE_ACCURATE | 2)
#define JFFS2_NODETYPE_CLEANMARKER (JFFS2_FEATURE_RWCOMPAT_DELETE | JFFS2_NODE_ACCURATE | 3)
#define JFFS2_NODETYPE_PADDING (JFFS2_FEATURE_RWCOMPAT_DELETE | JFFS2_NODE_ACCURATE | 4)

#define JFFS2_NODETYPE_SUMMARY (JFFS2_FEATURE_RWCOMPAT_DELETE | JFFS2_NODE_ACCURATE | 6)

#define JFFS2_NODETYPE_XATTR (JFFS2_FEATURE_INCOMPAT | JFFS2_NODE_ACCURATE | 8)
#define JFFS2_NODETYPE_XREF (JFFS2_FEATURE_INCOMPAT | JFFS2_NODE_ACCURATE | 9)

/* XATTR Related */
#define JFFS2_XPREFIX_USER		1	/* for "user." */
#define JFFS2_XPREFIX_SECURITY		2	/* for "security." */
#define JFFS2_XPREFIX_ACL_ACCESS	3	/* for "system.posix_acl_access" */
#define JFFS2_XPREFIX_ACL_DEFAULT	4	/* for "system.posix_acl_default" */
#define JFFS2_XPREFIX_TRUSTED		5	/* for "trusted.*" */

#define JFFS2_ACL_VERSION		0x0001

// Maybe later...
//#define JFFS2_NODETYPE_CHECKPOINT (JFFS2_FEATURE_RWCOMPAT_DELETE | JFFS2_NODE_ACCURATE | 3)
//#define JFFS2_NODETYPE_OPTIONS (JFFS2_FEATURE_RWCOMPAT_COPY | JFFS2_NODE_ACCURATE | 4)


#define JFFS2_INO_FLAG_PREREAD	  1	/* Do read_inode() for this one at
					   mount time, don't wait for it to
					   happen later */
#define JFFS2_INO_FLAG_USERCOMPR  2	/* User has requested a specific
					   compression type */


struct jffs2_unknown_node
{
	/* All start like this */
	__u16 magic;
	__u16 nodetype;
	__u32 totlen; /* So we can skip over nodes we don't grok */
	__u32 hdr_crc;
};

struct jffs2_raw_dirent
{
	__u16 magic;
	__u16 nodetype;	/* == JFFS2_NODETYPE_DIRENT */
	__u32 totlen;
	__u32 hdr_crc;
	__u32 pino;
	__u32 version;
	__u32 ino; /* == zero for unlink */
	__u32 mctime;
	__u8 nsize;
	__u8 type;
	__u8 unused[2];
	__u32 node_crc;
	__u32 name_crc;
	__u8 name[0];
};

/* The JFFS2 raw inode structure: Used for storage on physical media.  */
/* The uid, gid, atime, mtime and ctime members could be longer, but
   are left like this for space efficiency. If and when people decide
   they really need them extended, it's simple enough to add support for
   a new type of raw node.
*/
struct jffs2_raw_inode
{
	__u16 magic;      /* A constant magic number.  */
	__u16 nodetype;   /* == JFFS2_NODETYPE_INODE */
	__u32 totlen;     /* Total length of this node (inc data, etc.) */
	__u32 hdr_crc;
	__u32 ino;        /* Inode number.  */
	__u32 version;    /* Version number.  */
	__u32 mode;       /* The file's type or mode.  */
	__u16 uid;        /* The file's owner.  */
	__u16 gid;        /* The file's group.  */
	__u32 isize;      /* Total resultant size of this inode (used for truncations)  */
	__u32 atime;      /* Last access time.  */
	__u32 mtime;      /* Last modification time.  */
	__u32 ctime;      /* Change time.  */
	__u32 offset;     /* Where to begin to write.  */
	__u32 csize;      /* (Compressed) data size */
	__u32 dsize;	     /* Size of the node's data. (after decompression) */
	__u8 compr;       /* Compression algorithm used */
	__u8 usercompr;   /* Compression algorithm requested by the user */
	__u16 flags;	     /* See JFFS2_INO_FLAG_* */
	__u32 data_crc;   /* CRC for the (compressed) data.  */
	__u32 node_crc;   /* CRC for the raw inode (excluding data)  */
	__u8 data[0];
};

struct jffs2_raw_xattr {
	__u16 magic;
	__u16 nodetype;	/* = JFFS2_NODETYPE_XATTR */
	__u32 totlen;
	__u32 hdr_crc;
	__u32 xid;		/* XATTR identifier number */
	__u32 version;
	__u8 xprefix;
	__u8 name_len;
	__u16 value_len;
	__u32 data_crc;
	__u32 node_crc;
	__u8 data[0];
} __attribute__((packed));

struct jffs2_raw_xref
{
	__u16 magic;
	__u16 nodetype;	/* = JFFS2_NODETYPE_XREF */
	__u32 totlen;
	__u32 hdr_crc;
	__u32 ino;		/* inode number */
	__u32 xid;		/* XATTR identifier number */
	__u32 xseqno;	/* xref sequential number */
	__u32 node_crc;
} __attribute__((packed));

struct jffs2_raw_summary
{
	__u16 magic;
	__u16 nodetype; 	/* = JFFS2_NODETYPE_SUMMARY */
	__u32 totlen;
	__u32 hdr_crc;
	__u32 sum_num;	/* number of sum entries*/
	__u32 cln_mkr;	/* clean marker size, 0 = no cleanmarker */
	__u32 padded;	/* sum of the size of padding nodes */
	__u32 sum_crc;	/* summary information crc */
	__u32 node_crc; 	/* node crc */
	__u32 sum[0]; 	/* inode summary info */
};

union jffs2_node_union
{
	struct jffs2_raw_inode i;
	struct jffs2_raw_dirent d;
	struct jffs2_raw_xattr x;
	struct jffs2_raw_xref r;
	struct jffs2_raw_summary s;
	struct jffs2_unknown_node u;
};

/* Data payload for device nodes. */
union jffs2_device_node {
	__u16 old_id;
	__u32 new_id;
};

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
	
struct jffs2_main_args {
	int erase_size;
	int verbose;
	bool keep_unlinked;
};
	
int jffs2extract(char *infile, char *outdir, struct jffs2_main_args);
#ifdef __cplusplus
}
#endif

#endif /* __LINUX_JFFS2_H__ */
