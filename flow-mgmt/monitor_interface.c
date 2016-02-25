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
 * This file contains FEM (File Event Monitoring) wrappers for analytical data files.
 */

#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>

#include "flow_base.h"
#include "ifaddr_interface.h"

#include "monitor_interface.h"

void fem_handle_free(fem_handle_t *fem_handle)
{
	if (fem_handle == NULL)
		return;
	if (fem_handle->port_id != -1) {
		(void) port_dissociate(
		    fem_handle->port_id,
		    PORT_SOURCE_FILE,
		    (uintptr_t)&fem_handle->file);
		close(fem_handle->port_id);
		fem_handle->port_id = -1;
	}
	if (fem_handle->file.fo_name)
		free(fem_handle->file.fo_name);
	free(fem_handle);
}

fem_handle_t
*fem_handle_create(
	const char *file_name,
	int port_events)
{
	fem_handle_t *fem_handle;

	if (file_name == NULL)
		return (NULL);

	/*
	 * We use allocated storage in order to insure
	 * our association has unique file_obj_t.
	 */
	fem_handle = calloc(1, sizeof(fem_handle_t));
	if (fem_handle == NULL)
		return (NULL);
	fem_handle->port_id = -1;

	fem_handle->file.fo_name = (char *)strdup(file_name);
	if (fem_handle->file.fo_name == NULL) {
		fem_handle_free(fem_handle);
		return (NULL);
	}
	fem_handle->port_events = port_events;
	/*
	 * Fixme: need to control the limit
	 * imposed by project:port-max-ids otherwise
	 * port_create() could fail.
	 */
	fem_handle->port_id = port_create();
	if (fem_handle->port_id == -1) {
		fem_handle_free(fem_handle);
		return (NULL);
	}
	return (fem_handle);
}

int fem_handle_register(
	fem_handle_t	*fem_handle,
	int		events,
	boolean_t	retryable)
{
	struct timespec	ts;
	struct stat	st;
	int		r;
	int		status = FEM_HANDLE_BADARG;

	if (fem_handle == NULL)
		return (status);

	if (events != 0) {
		(void) port_dissociate(
		    fem_handle->port_id,
		    PORT_SOURCE_FILE,
		    (uintptr_t)&fem_handle->file);
	}

	while (B_TRUE) {
		errno = 0;
		r = stat(fem_handle->file.fo_name, &st);
		if (r == 0)
			break;
		if (retryable == B_FALSE)
			goto out;
		if (errno != EINTR) {
			next_wait_period(
			    DEFAULT_AFILE_RETRY_INTERVAL * 1000, &ts);
		}
	}

	fem_handle->file.fo_atime = st.st_atim;
	fem_handle->file.fo_ctime = st.st_ctim;
	fem_handle->file.fo_mtime = st.st_mtim;

	while (B_TRUE) {
		errno = 0;
		if (port_associate(
		    fem_handle->port_id,
		    PORT_SOURCE_FILE,
		    (uintptr_t)&fem_handle->file,
		    fem_handle->port_events,
		    (void *)fem_handle) == 0)
			break;
		if (retryable == B_FALSE)
			goto out;
		if (errno != EINTR) {
			next_wait_period(
			    DEFAULT_AFILE_RETRY_INTERVAL * 1000, &ts);
		}
	}
	status = FEM_HANDLE_OK;
out:
	return (status);
}

int fem_handle_wait_until_update(
	fem_handle_t *fem_handle,
	port_event_t *pevent)
{
	struct timespec	ts;
	int		status = FEM_HANDLE_NOOP;

	ts.tv_sec =
	    DEFAULT_AFILE_PARSE_INTERVAL +
	    DEFAULT_AFILE_REFRESH_INTERVAL;
	ts.tv_nsec = 0;
	bzero(pevent, sizeof(port_event_t));
	if (port_get(
	    fem_handle->port_id, pevent, &ts) != 0) {
		status = FEM_HANDLE_ERROR;
	} else {
		status = FEM_HANDLE_OK;
	}
	return (status);
}

int fem_handle_register_again(
	fem_handle_t *fem_handle,
	port_event_t *pevent)
{
	int		status = FEM_HANDLE_NOOP;

	if (fem_handle_register(
	    fem_handle,
	    (pevent->portev_source == PORT_SOURCE_FILE) ?
	    pevent->portev_events : 0,
	    B_TRUE) != FEM_HANDLE_OK)
		status = FEM_HANDLE_ERROR;
	if (status != FEM_HANDLE_ERROR)
		status = FEM_HANDLE_OK;
	return (status);
}
