/**
 * Copyright 2016 lprot
 * All right reserved
 */
#ifndef __TSFILE_H
#define __TSFILE_H
#include <stdint.h>

void convertSTR2TS(char *inFilename, int notOverwrite);
void processPIF(const char *filename, char *dest_file);
uint32_t str_crc32(const unsigned char *data, int len);
#endif //__TSFILE_H
