/**
 * Copyright 2016 Smx <smxdev4@gmail.com>
 * All right reserved
 */
#ifndef __COMMON_H
#define __COMMON_H

/* Branch Prediction Hints */
#ifdef __GNUC__
#define LIKELY(x)    __builtin_expect (!!(x), 1)
#define UNLIKELY(x)  __builtin_expect (!!(x), 0)
#else
#define LIKELY(x)	(x)
#define UNLIKELY(x)	(x)
#endif

#ifdef __GNUC__
#define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
#define UNUSED(x) UNUSED_ ## x
#endif

#ifdef __GNUC__
#define UNUSED_FUNCTION(x) __attribute__((__unused__)) UNUSED_ ## x
#else
#define UNUSED_FUNCTION(x) UNUSED_ ## x
#endif

#ifdef __GNUC__
#define FORMAT_PRINTF(x, y) __attribute__((__format__(__printf__, (x), (y))))
#else
#define FORMAT_PRINTF(x, y)
#endif

#define countof(x) (sizeof(x) / sizeof((x)[0]))

#endif
