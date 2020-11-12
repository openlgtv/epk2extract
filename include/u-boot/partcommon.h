#ifndef _PART_COMMON_H_
#define _PART_COMMON_H_

#define U64_UPPER(x)	(unsigned long)( (x) >> 32 )
#define U64_LOWER(x)	(unsigned long)( (x) & 0xffffffff)

/*#ifndef NO
#define NO							0x00
#define YES							0x01
#endif*/

/*-----------------------------------------------------------------------------
 * partition info
 */
#define PART_FLG_FIXED				1
#define PART_FLG_MASTER				2
#define PART_FLG_IDKEY				4
#define PART_FLG_CACHE				8
#define PART_FLG_DATA				16
#define PART_FLG_SECURED			32
#define PART_FLG_ERASE				64

#define STR_LEN_MAX					32

#define PM_PARTITION_MAX			64

typedef enum PART_INFO {
	PART_INFO_IDX = 0,
	PART_INFO_OFFSET,
	PART_INFO_SIZE,
	PART_INFO_FILESIZE
} PART_INFO_TYPE;

typedef enum {
	STRUCT_INVALID,
	STRUCT_MTDINFO,
	STRUCT_PARTINFOv1,
	STRUCT_PARTINFOv2
} part_struct_type;

unsigned int dump_partinfo(const char *filename, const char *outfile);

extern char *modelname;
extern part_struct_type part_type;

#endif /* _PART_COMMON_H_ */
