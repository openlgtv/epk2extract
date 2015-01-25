#ifndef _MTD_INFO_H_
#    define _MTD_INFO_H_

#    define STR_LEN_MAX					32
#    define MTD_MAP_MAX					4

struct m_device_info {
	char name[STR_LEN_MAX];
	unsigned int size;
	unsigned int phys;
#    if __x86_64__
	unsigned int virt;
	unsigned int cached;
#    else
	void *virt;
	void *cached;
#    endif
	int bankwidth;
	unsigned int used;
};

struct m_partition_info {
	char name[STR_LEN_MAX];		/* identifier string */
	unsigned int offset;		/* offset within the master MTD space */
	unsigned int size;			/* partition size */
	char filename[STR_LEN_MAX];	/* file name */
	unsigned int filesize;		/* file size */
	unsigned int sw_ver;		/* software version */
	unsigned char used;			/* Is this partition is used? */
	unsigned char valid;		/* Is this partition is valid? */
	unsigned char mask_flags;	/* master MTD flags to mask out for this partition */
};

struct m_partmap_info {
	unsigned int magic;
	unsigned int cur_epk_ver;
	unsigned int old_epk_ver;
	unsigned char nmap;
	unsigned char npartition;
	struct m_device_info map[MTD_MAP_MAX];
	struct m_partition_info partition[PM_PARTITION_MAX];
};

#    define M_GET_PART_INFO(x)			((struct m_partition_info *)&(m_partinfo.partition[x]))
#    define M_GET_DEV_INFO(x)			((struct m_device_info *)&(m_partinfo.map[x]))

extern struct m_partmap_info m_partinfo;
#endif /* MTD_INFO_H_ */
