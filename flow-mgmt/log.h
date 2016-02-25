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

#ifndef GEN_LOG_H
#define GEN_LOG_H

#include <unistd.h>
#include <time.h>

#define GEN_TIMESTAMP_BUFFER_SIZE 255

extern int gen_debug_flag;

void
fill_timestamp_buffer_from_value(char *, size_t, struct timeval);

void
fill_timestamp_buffer(char *, size_t);

void
gen_info(const char *, ...);

void
gen_debug(const char *, ...);

#endif
