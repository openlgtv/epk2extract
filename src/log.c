/*
 * Copyright (c) 2011 Roman Tokarev <roman.s.tokarev@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of any co-contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY CONTRIBUTORS ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <log.h>

#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

unsigned verbose = 0;

static FILE *log_f = NULL;
static int log_fd = -1;

int create_log(const char *fname) {
	int r;

	if (fname == NULL)
		return 0;

	log_fd = open(fname, O_CREAT | O_WRONLY | O_APPEND);
	if (log_fd == -1)
		goto error;

	if (fcntl(log_fd, F_SETFD, FD_CLOEXEC) == -1)
		goto error;

	log_f = fdopen(log_fd, "a");
	if (log_f == NULL)
		goto error;

	r = setvbuf(log_f, (char *) NULL, _IOLBF, 0);
	if (r != 0)
		goto error;

	return 0;

	error: fprintf(stderr, "can't open log file `%s': %m\n", fname);
	if (log_f)
		fclose(log_f);
	else if (log_fd)
		close(log_fd);

	return -1;
}

void say(unsigned level, const char *format, ...) {
	va_list ap;

	if (level > verbose)
		return;

	va_start(ap, format);

	if (log_f) {
		fprintf(log_f, "%u: ", getpid());
		vfprintf(log_f, format, ap);
		fprintf(log_f, "\n");
	} else {
		fprintf(stderr, "%u: ", getpid());
		vfprintf(stderr, format, ap);
		fprintf(stderr, "\n");
	}

	va_end(ap);
}
