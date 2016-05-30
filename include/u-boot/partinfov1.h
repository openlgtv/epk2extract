#ifndef _PART_INFO1_H_
#define _PART_INFO1_H_

struct p1_device_info {
	char name[STR_LEN_MAX];
	unsigned int size;
	unsigned int phys;
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

struct p1_partition_info {
	char name[STR_LEN_MAX];		/* identifier string                               */
	unsigned int offset;		/* offset within the master MTD space              */
	unsigned int size;			/* partition size                                  */
	char filename[STR_LEN_MAX];	/* file name                                       */
	unsigned int filesize;		/* file size                                       */
	unsigned int sw_ver;		/* software version                                */
	unsigned char used;			/* Is this partition is used?                      */
	unsigned char valid;		/* Is this partition is valid?                     */
	unsigned int mask_flags;	/* master MTD flags to mask out for this partition */
};

struct p1_partmap_info {
	unsigned int magic;
	unsigned int cur_epk_ver;
	unsigned int old_epk_ver;
	unsigned char npartition;
	struct p1_device_info dev;
	struct p1_partition_info partition[PM_PARTITION_MAX];
};

#define P1_GET_PART_INFO(x)			((struct p1_partition_info *)&(p1_partinfo.partition[x]))
#define P1_GET_DEV_INFO(x)			((struct p1_device_info *)&(p1_partinfo.dev))

extern struct p1_partmap_info p1_partinfo;
#endif /* _PART_INFO1_H_ */
