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

#ifndef FEM_INTERFACE_H
#define FEM_INTERFACE_H

#include <sys/types.h>
#include <port.h>

#define FEM_HANDLE_NOOP		0
#define FEM_HANDLE_ERROR	1
#define FEM_HANDLE_BADARG	2
#define FEM_HANDLE_OK		3

#define FEM_DEFAULT_AFILE_EVENTS (FILE_MODIFIED)

typedef struct __fem_handle fem_handle_t;

struct __fem_handle {
	file_obj_t file;
	int port_events;
	int port_id;
};

void fem_handle_free(fem_handle_t *fem_handle);

fem_handle_t
*fem_handle_create(
	const char *file_name,
	int port_events);

int fem_handle_register(
	fem_handle_t *fem_handle,
	int events,
	boolean_t retryable);

int fem_handle_wait_until_update(
	fem_handle_t *fem_handle,
	port_event_t *pevent);
int fem_handle_register_again(
	fem_handle_t *fem_handle,
	port_event_t *pevent);

#endif