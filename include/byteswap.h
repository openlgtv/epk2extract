#ifndef BYTESWAP_H
#define	BYTESWAP_H

#ifndef __APPLE__
#include <byteswap.h>
#else
#include <libkern/OSByteOrder.h> 
#define bswap_16(x) OSSwapInt16(x)
#define bswap_32(x) OSSwapInt32(x)
#endif

#endif	/* BYTESWAP_H */

