/**
 * LG partition table decoder
 * Original code from u-boot GPL package
 * Copyright 2016 Smx <smxdev4@gmail.com>
 * Copyright 20?? ???
 */
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>

#include "partinfo.h"
#include "util.h"

#ifdef __CYGWIN__
#    define lne "\r\n"
#else
#    define lne "\n"
#endif

#define println()				fprintf(destfile,lne)
#include <errno.h>

extern int errno;

FILE *destfile;

//structs
struct m_partmap_info m_partinfo;
struct p1_partmap_info p1_partinfo;
struct p2_partmap_info p2_partinfo;

const char *m_menu_partition_str[] = {
	"MTD Partition Information ---------------------------------------------------------------------------------",
	"index[%d] - ",
	"cur epk ver : 0x%06x",
	"old epk ver : 0x%06x",
	"\t name	= %s",
	"\t offset	= 0x%08x",
	"\t size	= 0x%08x",
	"\t sw_ver = %d",
	"\t filename = %s",
	"\t MTD flags = %s\n"
};

const char *m_menu_partition_info[] = {
	"[%2d] \"%-12s\" : 0x%08x-0x%08x (0x%08x)",
	" %c%c%c%c",
	" : \"%-20s\"[%d] - 0x%06x : (%c/%c)",
	"[%2d] Empty\n"
};

static const char *p_menu_partition_str[] = {
	"Partition Information ---------------------------------------------------------------------------------",
	"index[%d] - ",
	"cur epk ver : 0x%06x",
	"old epk ver : 0x%06x",
	"\t name	= %s",
	"\t offset	= 0x%08x",
	"\t size	= 0x%08x",
	"\t sw_ver = %d",
	"\t filename = %s",
	"\t flags = %s\n",
	"\t used = %c",
	"\t valid = %c"
};

static const char *p1_menu_partition_info[] = {
	"[%2d] \"%-12s\" : 0x%08x-0x%08x (0x%08x)",
	" %c%c%c%c%c",
	" : \"%-20s\"[%d] - 0x%06x : (%c/%c)",
	"[%2d] Empty\n"
};

static const char *p2_menu_partition_info[] = {
	"[%2d] \"%-12s\" : 0x%01x%08x-0x%01x%08x (0x%01x%08x)",
	" %c%c%c%c%c",
	" : \"%-20s\"[%d] - 0x%06x : (%c/%c) [%3d\%]",
	"[%2d] Empty\n"
};

void print_size(unsigned int devsize) {
	if (devsize % (1024 * 1024 * 1024) == 0) {
		//Gigabytes
		fprintf(destfile, "\tSize: %dGB", (devsize / 1024 / 1024 / 1024));
	} else {
		//Small MTD, use Megabytes
		fprintf(destfile, "\tSize: %dMB", (devsize / 1024 / 1024));
	}
}

unsigned int print_minfo(void) {
	int i = 0;
	struct m_partition_info *bi = NULL;

	struct m_device_info *mtdi = NULL;
	mtdi = M_GET_DEV_INFO(0);
	fprintf(destfile, "MTD Name: %s", mtdi->name);
	unsigned int devsize = mtdi->size;
	print_size(devsize);
	println();

	println();
	fprintf(destfile, "%s", m_menu_partition_str[0]);
	println();
	println();
	fprintf(destfile, "magic : %08x", m_partinfo.magic);
	println();
	println();
	fprintf(destfile, m_menu_partition_str[2], m_partinfo.cur_epk_ver);
	println();
	fprintf(destfile, m_menu_partition_str[3], m_partinfo.old_epk_ver);
	println();
	println();
	for (i = 0; i < (m_partinfo.npartition); i++) {
		bi = M_GET_PART_INFO(i);

		fprintf(destfile, m_menu_partition_info[0], i, bi->name, bi->offset, (bi->offset + bi->size), bi->size);

		fprintf(destfile, m_menu_partition_info[1], (bi->mask_flags & PART_FLG_FIXED) ? 'F' : '-', (bi->mask_flags & PART_FLG_MASTER) ? 'M' : '-', (bi->mask_flags & PART_FLG_IDKEY) ? 'I' : '-', (bi->mask_flags & PART_FLG_CACHE) ? 'C' : '-');

		if (strlen(bi->filename)) {
			fprintf(destfile, m_menu_partition_info[2], bi->filename, bi->filesize, bi->sw_ver, bi->used ? 'U' : 'u', bi->valid ? 'V' : 'v');
			println();
		} else
			println();
	}

	return 0;
}

unsigned int print_p1info(void) {
	int i = 0;
	struct p1_partition_info *p1i = NULL;

	struct p1_device_info *p1di = NULL;
	p1di = P1_GET_DEV_INFO();
	fprintf(destfile, "Flash Name: %s", p1di->name);
	unsigned int devsize = p1di->size;
	print_size(devsize);
	println();

	println();
	fprintf(destfile, "%s", p_menu_partition_str[0]);
	println();
	println();
	fprintf(destfile, "magic : %08x", p1_partinfo.magic);
	println();
	println();
	fprintf(destfile, p_menu_partition_str[2], p1_partinfo.cur_epk_ver);
	println();
	fprintf(destfile, p_menu_partition_str[3], p1_partinfo.old_epk_ver);
	println();
	println();

	if (p1_partinfo.npartition > PM_PARTITION_MAX) {
		printf("[ERROR] Number of partition is %d\n", p1_partinfo.npartition);
		return (unsigned int)-1;
	}

	for (i = 0; i < (p1_partinfo.npartition); i++) {
		p1i = P1_GET_PART_INFO(i);

		fprintf(destfile, p1_menu_partition_info[0], i, p1i->name, p1i->offset, (p1i->offset + p1i->size), p1i->size);

		fprintf(destfile, p1_menu_partition_info[1], (p1i->mask_flags & PART_FLG_FIXED) ? 'F' : '-', (p1i->mask_flags & PART_FLG_MASTER) ? 'M' : '-', (p1i->mask_flags & PART_FLG_SECURED) ? 'S' : '-', (p1i->mask_flags & PART_FLG_IDKEY) ? 'I' : '-', (p1i->mask_flags & PART_FLG_CACHE) ? 'C' : ((p1i->mask_flags & PART_FLG_DATA) ? 'D' : '-')
			);

		if (p1i->mask_flags & PART_FLG_ERASE)
			fprintf(destfile, "*");

		if (strlen(p1i->filename)) {
			fprintf(destfile, p1_menu_partition_info[2], p1i->filename, p1i->filesize, p1i->sw_ver, p1i->used ? 'U' : 'u', p1i->valid ? 'V' : 'v');
			println();
		} else
			println();
	}

	return 0;
}

unsigned int print_p2info(void) {
	int i = 0;
	struct p2_partition_info *p2i = NULL;

	struct p2_device_info *p2di = NULL;
	p2di = P2_GET_DEV_INFO();
	fprintf(destfile, "Flash Name: %s", p2di->name);
	unsigned int devsize = p2di->size;
	print_size(devsize);
	println();

	println();
	fprintf(destfile, "%s", p_menu_partition_str[0]);
	println();
	println();
	fprintf(destfile, "magic : %08x", p2_partinfo.magic);
	println();
	println();
	fprintf(destfile, p_menu_partition_str[2], p2_partinfo.cur_epk_ver);
	println();
	fprintf(destfile, p_menu_partition_str[3], p2_partinfo.old_epk_ver);
	println();
	println();

	if (p2_partinfo.npartition > P2_PARTITION_MAX) {
		printf("[ERROR] Number of partition is %d\n", p2_partinfo.npartition);
		return (unsigned int)-1;
	}

	for (i = 0; i < (p2_partinfo.npartition); i++) {
		p2i = P2_GET_PART_INFO(i);

		fprintf(destfile, p2_menu_partition_info[0], i, p2i->name, U64_UPPER(p2i->offset), U64_LOWER(p2i->offset), U64_UPPER(p2i->offset + p2i->size), U64_LOWER(p2i->offset + p2i->size), U64_UPPER(p2i->size), U64_LOWER(p2i->size));

		fprintf(destfile, p2_menu_partition_info[1], (p2i->mask_flags & PART_FLG_FIXED) ? 'F' : '-', (p2i->mask_flags & PART_FLG_MASTER) ? 'M' : '-', (p2i->mask_flags & PART_FLG_SECURED) ? 'S' : '-', (p2i->mask_flags & PART_FLG_IDKEY) ? 'I' : '-', (p2i->mask_flags & PART_FLG_CACHE) ? 'C' : ((p2i->mask_flags & PART_FLG_DATA) ? 'D' : '-')
			);

		if (p2i->mask_flags & PART_FLG_ERASE)
			fprintf(destfile, "*");

		if (strlen(p2i->filename)) {
			fprintf(destfile, p2_menu_partition_info[2], p2i->filename, p2i->filesize, p2i->sw_ver, p2i->used ? 'U' : 'u', p2i->valid ? 'V' : 'v', (unsigned long)((double)p2i->filesize / p2i->size * 100));
			println();
		} else
			println();
	}

	return 0;
}

unsigned int do_partinfo(void) {
	fprintf(destfile, "%s Detected", modelname);
	println();
	println();

	switch (part_type) {
	case STRUCT_PARTINFOv2:
		print_p2info();
		break;
	case STRUCT_PARTINFOv1:
		print_p1info();
		break;
	case STRUCT_MTDINFO:
		print_minfo();
		break;
	default:
		err_exit("Unhandled partition table structure\n");
		break;
	}
	println();

	char buf[256];
	rewind(destfile);
	printf("\n");
	while (fgets(buf, sizeof buf, destfile)) {	//print file we just wrote to stdout
		printf("%s", buf);
	}
	fclose(destfile);
	return 0;
}

unsigned int load_partinfo(const char *filename) {
	FILE *file;
	file = fopen(filename, "rb");
	if (file == NULL) {
		err_exit("Can't open file %s\n", filename);
	}

	size_t size = 0;

	switch (part_type) {
	case STRUCT_PARTINFOv2:
		size = sizeof(struct p2_partmap_info);
		fread(&p2_partinfo, 1, size, file);
		break;
	case STRUCT_PARTINFOv1:
		size = sizeof(struct p1_partmap_info);
		fread(&p1_partinfo, 1, size, file);
		break;
	case STRUCT_MTDINFO:
		size = sizeof(struct m_partmap_info);
		fread(&m_partinfo, 1, size, file);
		break;
	default:
		fclose(file);
		err_exit("Unhandled partition table structure\n");
		break;
	}
	return 0;
}

unsigned int dump_partinfo(const char *filename, const char *outfile) {
	destfile = fopen(outfile, "w+");
	if (destfile == NULL)
		err_exit("Can't open file %s for writing. Error is: %s\n", outfile, strerror(errno));

	load_partinfo(filename);
	do_partinfo();
	return 0;
}
