#ifndef __REALTEK_H
#define __REALTEK_H

#include "mfile.h"
MFILE *is_rtk_bspfw(const char *filename);
void split_rtk_bspfw(MFILE *mf, const char *destdir);


#endif