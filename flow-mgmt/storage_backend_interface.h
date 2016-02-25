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

#ifndef STORAGE_BACKEND_H
#define STORAGE_BACKEND_H

#include <sys/types.h>
#include <pthread.h>
#include <sqlite3.h>

#include "flow_base.h"

#define DEFAULT_STORAGE_BACKEND_DB "/var/run/flow-mgmt.flow.db"

#define STORAGE_BACKEND_STATUS_UNKNOWN		0
#define STORAGE_BACKEND_STATUS_OK		1
#define STORAGE_BACKEND_STATUS_FAILURE		2
#define STORAGE_BACKEND_STATUS_FULL_DUMP	3

#define QUERY_ADD	1
#define QUERY_UPDATE	2
#define QUERY_DELETE	3

#define STORAGE_BACKEND_BUSY_TIMEOUT		3000 /* in millisec */
#define STORAGE_BACKEND_FULL_DUMP_MAX_INTERVAL	60 /* in sec */

#define IS_STORAGE_BACKEND_FAILURE(status) (\
((status == SQLITE_FULL) || \
(status == SQLITE_CANTOPEN) || \
(status == SQLITE_NOTADB) || \
(status == SQLITE_IOERR) || \
(status == SQLITE_CORRUPT)) ? \
B_TRUE : B_FALSE )

typedef struct __storage_backend_handle_t storage_backend_handle_t;

struct __storage_backend_handle_t {
	hrtime_t	crtime;
	pthread_mutex_t	lock;
	pthread_cond_t	cond;
	struct sqlite3	*db;
	int		flags;
	boolean_t	is_connected;
	boolean_t	is_in_use;
};

/* Global variable */
extern storage_backend_handle_t flow_database;

void
backend_handle_ini(
	storage_backend_handle_t *sb_handle);
int
backend_handle_open_read(
	storage_backend_handle_t *sb_handle);
int
backend_handle_open_write(
	storage_backend_handle_t *sb_handle);
boolean_t
backend_handle_close(
	storage_backend_handle_t *sb_handle);
void
backend_handle_fini(
	storage_backend_handle_t *sb_handle);
int
backend_flow_load_all(
	storage_backend_handle_t *sb_handle,
	flow_base_collection_t 	 *fbc);
int
backend_store_flow_collection(
	storage_backend_handle_t *sb_handle,
	flow_collection_t 	 *nfc,
	uint32_t		 store_flag);
void
backend_flow_dump_all(
	storage_backend_handle_t *fdb,
	flow_base_collection_t *fbc);

#endif
