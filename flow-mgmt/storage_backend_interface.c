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
/*
 * This file contains wrappers for Solaris-bundled libsqlite3 routines.
 */

#include <errno.h>
#include <strings.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "dladm_interface.h"
#include "flow_base.h"

#include "storage_backend_interface.h"

void
backend_handle_ini(
	storage_backend_handle_t *sb_handle)
{
	bzero(sb_handle, sizeof(storage_backend_handle_t));
	pthread_mutex_init(&sb_handle->lock, NULL);
	pthread_cond_init(&sb_handle->cond, NULL);
	sb_handle->crtime = gethrtime();

	pthread_mutex_lock(&sb_handle->lock);
	sb_handle->is_connected = B_FALSE;
	sb_handle->is_in_use = B_FALSE;
	pthread_mutex_unlock(&sb_handle->lock);
}

boolean_t
backend_handle_acquire_use(
	storage_backend_handle_t *sb_handle,
	boolean_t need_connected)
{
	pthread_mutex_lock(&sb_handle->lock);
	while (sb_handle->is_in_use != B_FALSE)
		pthread_cond_wait(&sb_handle->cond, &sb_handle->lock);
	if ((need_connected == B_TRUE) &&
	    (sb_handle->is_connected == B_FALSE)) {
		pthread_mutex_unlock(&sb_handle->lock);
		return (B_FALSE);
	}
	sb_handle->is_in_use = B_TRUE;
	pthread_cond_signal(&sb_handle->cond);
	pthread_mutex_unlock(&sb_handle->lock);
	return (B_TRUE);
}

void
backend_handle_disacquire_use(
	storage_backend_handle_t *sb_handle)
{
	pthread_mutex_lock(&sb_handle->lock);
	sb_handle->is_in_use = B_FALSE;
	pthread_cond_signal(&sb_handle->cond);
	pthread_mutex_unlock(&sb_handle->lock);
}

int
backend_handle_open_read(
	storage_backend_handle_t *sb_handle)
{
	struct sqlite3	*db;
	int 		sqlite_status;
	int 		result_status = STORAGE_BACKEND_STATUS_FAILURE;

	if (backend_handle_acquire_use(sb_handle, B_FALSE) == B_FALSE)
		return (result_status);

	sb_handle->flags = SQLITE_OPEN_READONLY;
	sqlite_status = sqlite3_open_v2(
	    DEFAULT_STORAGE_BACKEND_DB,
	    &db,
	    sb_handle->flags,
	    NULL);
	if (sqlite_status == SQLITE_OK) {
		sb_handle->db = db;
		sb_handle->is_connected = B_TRUE;
		result_status = STORAGE_BACKEND_STATUS_OK;
		sqlite3_busy_timeout(
		    sb_handle->db, STORAGE_BACKEND_BUSY_TIMEOUT);
	}
	backend_handle_disacquire_use(sb_handle);

	return (result_status);
}

int
backend_handle_open_write(
	storage_backend_handle_t *sb_handle)
{
	struct sqlite3	*db;
	char 		*sql_query;
	int 		sqlite_status = SQLITE_ERROR;
	int 		result_status = STORAGE_BACKEND_STATUS_FAILURE;

	if (backend_handle_acquire_use(sb_handle, B_FALSE) == B_FALSE)
		return (result_status);

	sb_handle->flags =
	    SQLITE_OPEN_READWRITE |
	    SQLITE_OPEN_CREATE;
	sqlite_status = sqlite3_open_v2(
	    DEFAULT_STORAGE_BACKEND_DB,
	    &db,
	    sb_handle->flags,
	    NULL);
	if (sqlite_status == SQLITE_OK) {
		sb_handle->db = db;
		sb_handle->is_connected = B_TRUE;
		result_status = STORAGE_BACKEND_STATUS_OK;
	} else {
		goto fail;
	}
	sqlite3_busy_timeout(
	    sb_handle->db, STORAGE_BACKEND_BUSY_TIMEOUT);

	/* Create database schema */
	/* 
	 * Synchronous flag is off for that database,
	 * 'cause it resides on volatile storage and 
	 * we don't expect it will survive across system restart.
	 */
	sql_query = sqlite3_mprintf(
	    "BEGIN TRANSACTION; "
	    "CREATE TABLE IF NOT EXISTS flows_table( "
	    "id INTEGER PRIMARY KEY NOT NULL, "
	    "flow_name VARCHAR NOT NULL, "
	    "flow_expire_interval INTEGER DEFAULT '%d', "
	    "flow_expire_time INTEGER NOT NULL); "
	    "CREATE INDEX IF NOT EXISTS flows_table_id ON flows_table (id); "
	    "CREATE INDEX IF NOT EXISTS flows_table_name ON flows_table (flow_name); "
	    "COMMIT; "
	    "PRAGMA default_synchronous = OFF; PRAGMA synchronous = OFF; ",
	    MIN_EXPIRE_INTERVAL);
	if (sql_query == NULL)
		goto fail;
	sqlite_status = sqlite3_exec(
	    sb_handle->db,
	    sql_query,
	    NULL, NULL, NULL);
	sqlite3_free(sql_query);
	if (sqlite_status == SQLITE_OK)
		result_status = STORAGE_BACKEND_STATUS_OK;
	else
		goto fail;
fail:
	backend_handle_disacquire_use(sb_handle);

	if (IS_STORAGE_BACKEND_FAILURE(sqlite_status) == B_TRUE) {
		if (backend_handle_close(sb_handle) == B_TRUE)
			unlink(DEFAULT_STORAGE_BACKEND_DB);
	}
	return (result_status);
}

boolean_t
backend_handle_close(
	storage_backend_handle_t *sb_handle)
{
	if (backend_handle_acquire_use(sb_handle, B_FALSE) == B_FALSE)
		return (B_FALSE);

	if (sb_handle->is_connected == B_TRUE) {
		if (sb_handle->db != NULL) {
			sqlite3_close(sb_handle->db);
			sb_handle->db = NULL;
		}
		sb_handle->is_connected = B_FALSE;
	}
	backend_handle_disacquire_use(sb_handle);
	return (B_TRUE);
}

void
backend_handle_fini(
	storage_backend_handle_t *sb_handle)
{
	if (backend_handle_close(sb_handle) == B_FALSE)
		return;

	pthread_cond_destroy(&sb_handle->cond);
	pthread_mutex_destroy(&sb_handle->lock);
}

int
backend_execute_query(
	storage_backend_handle_t	*sb_handle,
	char				*query_text,
	int				(*fn)(void *, int, char **, char **),
	void				*arg)
{
	char	*error_msg = NULL;
	int	result_status = STORAGE_BACKEND_STATUS_FAILURE;
	int	sqlite_status;

	if (backend_handle_acquire_use(sb_handle, B_TRUE) == B_FALSE)
		return (result_status);

	sqlite_status = sqlite3_exec(
	    sb_handle->db,
	    (const char *)query_text,
	    fn,
	    arg,
	    &error_msg);
	if (sqlite_status == SQLITE_OK) {
		result_status = STORAGE_BACKEND_STATUS_OK;
	} else {
		/* Fixme: probably we should log error message. */
		sqlite3_free(error_msg);
	}

	backend_handle_disacquire_use(sb_handle);
	return (result_status);
}

int
backend_flow_load_all(
	storage_backend_handle_t *sb_handle,
	flow_base_collection_t 	 *fbc)
{
	int result_status = STORAGE_BACKEND_STATUS_FAILURE;

	result_status = backend_execute_query(
		sb_handle,
		"BEGIN TRANSACTION; "
		"SELECT flow_name, flow_expire_interval, flow_expire_time "
		"FROM flows_table; "
		"COMMIT; ",
		dladm_load_flow_via_backend,
		fbc);

	return (result_status);
}

int
backend_store_flow_collection(
	storage_backend_handle_t *sb_handle,
	flow_collection_t 	 *nfc,
	uint32_t		 store_flag)
{
	hrtime_t	now;
	char		flow_name[MAXFLOWNAMELEN];
	char		*sql_query = NULL;
	int		sqlite_status = SQLITE_ERROR;
	int		result_status = STORAGE_BACKEND_STATUS_FAILURE;

	if ((sb_handle == NULL) ||
	    (nfc == NULL))
		return (result_status);

	if (backend_handle_acquire_use(sb_handle, B_TRUE) == B_FALSE)
		return (result_status);

	bzero(&flow_name, sizeof(flow_name));
	if (fill_flow_name(nfc->linkid, flow_name, sizeof(flow_name),
	    &nfc->local_ulp, nfc->dscp_value) !=
	    DLADM_STATUS_OK)
		goto fail;

	if (store_flag == QUERY_ADD) {
		sql_query = sqlite3_mprintf(
		    "BEGIN TRANSACTION; "
		    "DELETE FROM flows_table WHERE flow_name='%q'; "
		    "INSERT INTO flows_table "
		    "(flow_name, flow_expire_interval, flow_expire_time) "
		    "VALUES('%q', '%d', '%lld'); "
		    "COMMIT; ",
		    flow_name,
		    flow_name,
		    nfc->flow_expire_interval,
		    nfc->orig_expire_time / HRTIME2SEC_MULTIPLIER);
	} else if (store_flag == QUERY_UPDATE) {
		sql_query = sqlite3_mprintf(
		    "BEGIN TRANSACTION; "
		    "UPDATE flows_table "
		    "SET flow_expire_interval='%d', flow_expire_time='%lld' "
		    "WHERE flow_name='%q'; "
		    "COMMIT; ",
		    nfc->flow_expire_interval,
		    nfc->orig_expire_time / HRTIME2SEC_MULTIPLIER,
		    flow_name);
	} else if (store_flag == QUERY_DELETE) {
		sql_query = sqlite3_mprintf(
		    "BEGIN TRANSACTION; "
		    "DELETE FROM flows_table WHERE flow_name='%q'; "
		    "COMMIT; ",
		    flow_name);
	}
	if (sql_query == NULL)
		goto fail;
	sqlite_status = sqlite3_exec(
	    sb_handle->db,
	    sql_query,
	    NULL, NULL, NULL);
	sqlite3_free(sql_query);
	if (sqlite_status == SQLITE_OK)
		result_status = STORAGE_BACKEND_STATUS_OK;
	else
		goto fail;

fail:
	backend_handle_disacquire_use(sb_handle);
	/*
	 * Re-open backend file
	 * on error.
	 */
	if (sqlite_status == SQLITE_ERROR) {
		if (backend_handle_close(sb_handle) == B_TRUE)
			backend_handle_open_write(sb_handle);
	}
	/*
	 * Clean up and re-initialize backend file
	 * if something goes wrong.
	 * Then it will try to make full dump of current flow database.
	 */
	if (IS_STORAGE_BACKEND_FAILURE(sqlite_status) == B_TRUE) {
		if (backend_handle_close(sb_handle) == B_TRUE) {
			unlink(DEFAULT_STORAGE_BACKEND_DB);
			backend_handle_open_write(sb_handle);

			now = gethrtime();
			if (sb_handle->crtime / HRTIME2SEC_MULTIPLIER +
			    STORAGE_BACKEND_FULL_DUMP_MAX_INTERVAL <
			    now / HRTIME2SEC_MULTIPLIER) {
				result_status = STORAGE_BACKEND_STATUS_FULL_DUMP;
			}
		}
	}
	return (result_status);
}

void
backend_flow_dump_all(
	storage_backend_handle_t	*fdb,
	flow_base_collection_t  	*fbc)
{
	if ((fdb == NULL) ||
	    (fbc == NULL))
		return;

	pthread_mutex_lock(&fbc->lock);
	if (fbc->flow_name_hash != NULL) {
		/*
		 * Sync backend data with the system.
		 */
		generic_hash_foreach(
		    fbc->flow_name_hash,
		    flow_collection_walk_and_store2backend,
		    fdb);
	}
	fdb->crtime = gethrtime();
	pthread_mutex_unlock(&fbc->lock);
}
