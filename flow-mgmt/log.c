/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2015 Serghei Samsi (sscdvp@gmail.com).  All rights reserved.
 */

#include <syslog.h>
#include <time.h>
#include <stdio.h>
#include <stdarg.h>
#include <strings.h>

#include "log.h"

int gen_debug_flag = 0;

void
fill_timestamp_buffer_from_value(char *buf, size_t bufsize, struct timeval utc_tv)
{
	char timestamp[GEN_TIMESTAMP_BUFFER_SIZE];
	struct tm p_tm;

	if (localtime_r(&utc_tv.tv_sec, &p_tm) == NULL)
		return;

	(void) strftime(timestamp, sizeof(timestamp) - 1, "%b %d %H:%M:%S", &p_tm);
	(void) snprintf(buf, bufsize - 1, "%s.%03d", timestamp, (uint32_t)(utc_tv.tv_usec / 1000));
}

void
fill_timestamp_buffer(char *buf, size_t bufsize)
{
	char timestamp[GEN_TIMESTAMP_BUFFER_SIZE];
	struct timeval tv;
	time_t utc_time;
	struct tm p_tm;

	tv.tv_sec = tv.tv_usec = 0;

	(void) gettimeofday(&tv, (struct zone *)0);
	utc_time = tv.tv_sec;

	if (localtime_r(&utc_time, &p_tm) == NULL)
		return;

	(void) strftime(timestamp, sizeof(timestamp), "%b %d %H:%M:%S", &p_tm);
	(void) snprintf(buf, bufsize - 1, "%s.%03d", timestamp, (uint32_t)(tv.tv_usec / 1000));
}

void
gen_info(const char *format, ...)
{
	char timestamp[GEN_TIMESTAMP_BUFFER_SIZE];
	char logbuf[GEN_TIMESTAMP_BUFFER_SIZE];
	char formatbuf[GEN_TIMESTAMP_BUFFER_SIZE];
	va_list ap/*, apc*/;
	int buf_len = 0;

	bzero(&formatbuf,sizeof(formatbuf));
	if (strlcat(
	    formatbuf,
	    "[ ", sizeof(formatbuf)) >= sizeof(formatbuf))
		return;
	fill_timestamp_buffer(timestamp, sizeof (timestamp));
	if (strlcat(
	    formatbuf,
	    timestamp, sizeof(formatbuf)) >= sizeof(formatbuf))
		return;
	if (strlcat(
	    formatbuf,
	    " ", sizeof(formatbuf)) >= sizeof(formatbuf))
		return;
/*	if (strlcat(
	    formatbuf,
	    format, sizeof(formatbuf)) >= sizeof(formatbuf))
		return;
	if (strlcat(
	    formatbuf,
	    " ]", sizeof(formatbuf)) >= sizeof(formatbuf))
		return;*/

	bzero(&logbuf,sizeof(logbuf));
	va_start(ap, format);
	if ((ap != NULL)/* && (strlen(ap) > 1) && (strlen(ap) < 255)*/) {
		buf_len = vsnprintf(
		    logbuf,
		    sizeof(logbuf)  - 1, format, ap);
	}
	va_end(ap);
	if ((buf_len > 1) &&
	    (buf_len < sizeof(logbuf) - 1)) {
		syslog(LOG_INFO, "%s%s ]", formatbuf, logbuf);
/*	(void) fprintf(stderr, "%s", logbuf);
	(void) fflush(stderr);*/
	}
}

void
gen_debug(const char *format, ...)
{
	char timestamp[GEN_TIMESTAMP_BUFFER_SIZE];
	char logbuf[GEN_TIMESTAMP_BUFFER_SIZE];
	char formatbuf[GEN_TIMESTAMP_BUFFER_SIZE];
	va_list ap, apc;

	if (gen_debug_flag == 0)
		return;

	bzero(&formatbuf,sizeof(formatbuf));
	if (strlcat(
	    formatbuf,
	    "[ ", sizeof(formatbuf)) >= sizeof(formatbuf))
		return;
	fill_timestamp_buffer(timestamp, sizeof (timestamp));
	if (strlcat(
	    formatbuf,
	    timestamp, sizeof(formatbuf)) >= sizeof(formatbuf))
		return;
	if (strlcat(
	    formatbuf,
	    " ", sizeof(formatbuf)) >= sizeof(formatbuf))
		return;
	if (strlcat(
	    formatbuf,
	    format, sizeof(formatbuf)) >= sizeof(formatbuf))
		return;
	if (strlcat(
	    formatbuf,
	    " ]\n", sizeof(formatbuf)) >= sizeof(formatbuf))
		return;

	bzero(&logbuf,sizeof(logbuf));
	va_start(ap, format);
	if ((ap != NULL) && (strlen(ap) > 1)/* && (strlen(ap) < 255)*/) {
		va_copy(apc, ap);
		vsnprintf(
		    logbuf,
		    GEN_TIMESTAMP_BUFFER_SIZE  - 1, format, apc);
		va_end(apc);
	} else {
	}
	va_end(ap);
/*	(void) fprintf(stderr, "%s", logbuf);
	(void) fflush(stderr);*/
	syslog(LOG_DEBUG, "%s", logbuf);
}
