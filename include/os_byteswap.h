#ifndef BYTESWAP_H
#    define	BYTESWAP_H

#    define SWAP(x) SwapBytes(&x, sizeof(x))
#    define IS_BE(x) x >> 8 != 0
#    define IS_LE(x) !IS_BE(x)

#    ifdef __APPLE__
#        include <libkern/OSByteOrder.h>
#        define bswap_16(x) OSSwapInt16(x)
#        define bswap_32(x) OSSwapInt32(x)
#    else
#        include <byteswap.h>
#    endif

#endif /* BYTESWAP_H */
