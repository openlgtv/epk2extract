#ifndef BYTESWAP_H
#define	BYTESWAP_H

#ifdef __APPLE__
#include <libkern/OSByteOrder.h> 
#define bswap_16(x) OSSwapInt16(x)
#define bswap_32(x) OSSwapInt32(x)
#else
#include <byteswap.h>
#endif

#endif	/* BYTESWAP_H */

