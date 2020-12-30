/**
 * Copyright 20xx sirius
 * All right reserved
 */
#ifndef CONFIG_H_
#    define CONFIG_H_

#include <stdbool.h>
#include <inttypes.h>

typedef struct {
	char *config_dir;
	char *dest_dir;
	int enableSignatureChecking;
	uint8_t video_stream_type;
	uint8_t audio_stream_type;
	uint8_t aes_key[16];
	bool aes_key_provided;
} config_opts_t;

extern config_opts_t config_opts;

#    define G_DIR_SEPARATOR_S "/"

#    if defined(__APPLE__)
#        include <sys/syslimits.h>
#    elif defined(__CYGWIN__)
#        include <limits.h>
#    else
#        include <linux/limits.h>
#    endif

#    ifndef PATH_MAX
#        define PATH_MAX        4096	/* # chars in a path name including nul */
#    endif

#endif /* CONFIG_H_ */
