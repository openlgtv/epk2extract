/**
 * Copyright 2016 Smx <smxdev4@gmail.com>
 * All right reserved
 */
#ifndef __COMMON_H
#define __COMMON_H

#define LIKELY(x)    __builtin_expect (!!(x), 1)
#define UNLIKELY(x)  __builtin_expect (!!(x), 0)

#endif