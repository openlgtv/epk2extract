/**
 * Copyright 2016 lprot
 * All right reserved
 */
#ifndef __TSFILE_H
#define __TSFILE_H
#include <stdint.h>

struct tsfile_options {
	int video_stream_type;
	int audio_stream_type;
	uint8_t append;
};

void convertSTR2TS(char *inFilename, struct tsfile_options *opts);
void processPIF(const char *filename, char *dest_file);
uint32_t str_crc32(const unsigned char *data, int len);
#endif //__TSFILE_H
