#ifndef BYTESWAP_H
#define	BYTESWAP_H

#define SWAP(x) SwapBytes(&x, sizeof(x))

#ifdef __APPLE__
#	include <libkern/OSByteOrder.h>
#	define bswap_16(x) OSSwapInt16(x)
#	define bswap_32(x) OSSwapInt32(x)
#else
#	include <byteswap.h>
#endif

void SwapBytes(void *pv, size_t n);
#endif /* BYTESWAP_H */
