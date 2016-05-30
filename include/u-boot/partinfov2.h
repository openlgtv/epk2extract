#ifndef _PART_INFO2_H_
#define _PART_INFO2_H_

#define P2_PARTITION_MAX				128

struct p2_device_info {
	char name[STR_LEN_MAX];
	unsigned long long size;
	unsigned long long phys;
#if __x86_64__
	unsigned int virt;
	unsigned int cached;
#else
	void *virt;
	void *cached;
#endif
	int bankwidth;
	unsigned int used;
};

struct p2_partition_info {
	char name[STR_LEN_MAX];		/* identifier string                               */
	unsigned long long offset;	/* offset within the master MTD space              */
	unsigned long long size;	/* partition size                                  */
	char filename[STR_LEN_MAX];	/* file name                                       */
	unsigned int filesize;		/* file size                                       */
	unsigned int sw_ver;		/* software version                                */
	unsigned char used;			/* Is this partition is used?                      */
	unsigned char valid;		/* Is this partition is valid?                     */
	unsigned int mask_flags;	/* master MTD flags to mask out for this partition */
};

struct p2_partmap_info {
	unsigned int magic;
	unsigned int cur_epk_ver;
	unsigned int old_epk_ver;
	unsigned char npartition;
	struct p2_device_info dev;
	struct p2_partition_info partition[P2_PARTITION_MAX];
};

#define P2_GET_PART_INFO(x)			((struct p2_partition_info *)&(p2_partinfo.partition[x]))
#define P2_GET_DEV_INFO(x)			((struct p2_device_info *)&(p2_partinfo.dev))

extern struct p2_partmap_info p2_partinfo;
#endif /* _PART_INFO2_H_ */
