/*
 * config.h
 *
 *  Created on: 25.02.2011
 *      Author: root
 */

#ifndef CONFIG_H_
#define CONFIG_H_

struct config_opts_t {
	char *config_dir;
	char *dest_dir;
};

#define G_DIR_SEPARATOR_S "/"

#if defined(__APPLE__)
#include <sys/syslimits.h>
#elif defined(__CYGWIN__)
#include <limits.h>
#else
#include <linux/limits.h>
#endif

#ifndef PATH_MAX
	#define PATH_MAX        4096	/* # chars in a path name including nul */
#endif

#endif /* CONFIG_H_ */
