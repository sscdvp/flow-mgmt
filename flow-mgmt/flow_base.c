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
 * This file contains core logic of product workflow.
 */

#include <strings.h>

#include "ifaddr_interface.h"
#include "socket_multicast.h"
#include "storage_backend_interface.h"
#include "flow_mgmt.h"

#include "flow_base.h"

/* Callback for generic_hash_foreach'func_task */
void expire_queue_interval_hash_delete(
	void				*arg0,
	void				**arg1,
	void				*arg2)
{
	flow_expire_queue_t		*nfe =
	    (flow_expire_queue_t *)arg0;
	flow_base_collection_t		*fbc =
	    (flow_base_collection_t *)arg2;

	if ((nfe == NULL) ||
	    (fbc == NULL) ||
	    (fbc->expire_queue_interval_hash == NULL))
		return;

	if (generic_hash_delete(
	    fbc->expire_queue_interval_hash, nfe) == NULL) {
		gen_info("%s,%d: generic_hash_delete %p failure",
		    __FILE__, __LINE__,
		    nfe);
		return;
	}
	nfe->next_unused =
	    fbc->expire_queue_unused_head;
	fbc->expire_queue_unused_head = nfe;
}

/* Callback for generic_hash_foreach'func_task */
void flow_collection_hash_delete(
	void				*arg0,
	void				**arg1,
	void				*arg2)
{
	flow_collection_t		*nfc =
	    (flow_collection_t *)arg0;
	flow_base_collection_t		*fbc =
	    (flow_base_collection_t *)arg2;

	if ((nfc == NULL) ||
	    (fbc == NULL) ||
	    (fbc->flow_name_hash == NULL))
		return;

	if (generic_hash_delete(
	    fbc->flow_name_hash, nfc) == NULL) {
		gen_info("%s,%d: generic_hash_delete %p failure",
		    __FILE__, __LINE__,
		    nfc);
		return;
	}
	nfc->next_unused =
	    fbc->flow_unused_head;
	fbc->flow_unused_head = nfc;
}

/* Callback for generic_hash_foreach'func_task */
void flow_collection_walk_and_remove(
	void				*arg0,
	void				**arg1,
	void				*arg2)
{
	char				errstr[DLADM_STRSIZE];
	flow_collection_t		*nfc =
	    (flow_collection_t *)arg0;
	flow_base_collection_t		*fbc =
	    (flow_base_collection_t *)arg2;
	dladm_status_t			status;

	if (nfc == NULL ||
	    fbc == NULL)
		return;

	status = remove_flow_collection(nfc);
	if ((status != DLADM_STATUS_OK) &&
	    (status != DLADM_STATUS_NOTFOUND)) {
		gen_info(
		    "%s,%d: remove_flow_collection %p failure %s",
		    __FILE__, __LINE__,
		    nfc, dladm_status2str(status, errstr));
	}
}

/* Callback for generic_hash_foreach'func_task */
void flow_collection_walk_and_add(
	void				*arg0,
	void				**arg1,
	void				*arg2)
{
	char				errstr[DLADM_STRSIZE];
	flow_collection_t		*nfc =
	    (flow_collection_t *)arg0;
	flow_base_collection_t		*fbc =
	    (flow_base_collection_t *)arg2;
	dladm_status_t			status;

	if (nfc == NULL ||
	    fbc == NULL)
		return;

	status = add_flow_collection(nfc);
	if ((status != DLADM_STATUS_OK) &&
	    (status != DLADM_STATUS_EXIST)) {
		gen_info(
		    "%s,%d: add_flow_collection %p failure %s",
		    __FILE__, __LINE__,
		    nfc, dladm_status2str(status, errstr));
	}
}

/* Callback for generic_hash_foreach'func_task */
void flow_collection_walk_and_store2backend(
	void				*arg0,
	void				**arg1,
	void				*arg2)
{
	flow_collection_t		*nfc =
	    (flow_collection_t *)arg0;
	storage_backend_handle_t	*fdb =
	    (storage_backend_handle_t *)arg2;

	if (nfc == NULL ||
	    fdb == NULL)
		return;

	backend_store_flow_collection(fdb, nfc, QUERY_ADD);
}

/*
 * This function assumes:
 * flow_collection_t'expire_interval is assigned,
 * flow_base_collection_t'lock mutex is hold.
 */
int
add_flow_collection_to_expire_queue(
	flow_collection_t		*nfc,
	flow_expire_queue_t		*nfe,
	flow_base_collection_t		*fbc)
{
	int status = FB_STATUS_OK;

	if (nfe == NULL) {
		if (fbc->expire_queue_unused_head != NULL) {
			nfe = fbc->expire_queue_unused_head;
			fbc->expire_queue_unused_head =
			    fbc->expire_queue_unused_head->
			    next_unused;
			bzero(nfe, sizeof(flow_expire_queue_t));
		} else {
			if (generic_hash_length(
			    fbc->expire_queue_interval_hash) >
			    EXPIRE_QUEUE_INTERVAL_HASH_MAX_ENTRIES) {
				fbc->nqueues_overlimit++;
				status = FB_STATUS_TRYAGAIN;
				goto fail;
			}
			nfe = (flow_expire_queue_t *) calloc(
			    1, sizeof(flow_expire_queue_t));
			if (nfe == NULL) {
				fbc->nomem_errors++;
				status = FB_STATUS_NOMEM;
				goto fail;
			}
		}
		nfe->expire_interval = nfc->flow_expire_interval;
		if (generic_hash_add(
		    fbc->expire_queue_interval_hash,
		    nfe, nfe) == NULL) {
			nfe->next_unused =
			    fbc->expire_queue_unused_head;
			fbc->expire_queue_unused_head = nfe;
			status = FB_STATUS_NOMEM;
			goto fail;
		}
	}

	if (nfe->flow_expire_tail == NULL) {
		nfe->flow_expire_head =
		    nfe->flow_expire_tail =
		    nfc;
	} else {
		nfe->flow_expire_tail->next_expire =
		    nfc;
		nfc->prev_expire = nfe->flow_expire_tail;
		nfe->flow_expire_tail = nfc;
	}

fail:
	return (status);
}

/* This function assumes flow_base_collection_t'lock mutex is hold. */
int
remove_flow_collection_from_expire_queue(
	flow_collection_t		*nfc,
	flow_expire_queue_t		*nfe,
	flow_base_collection_t		*fbc)
{
	flow_collection_t *cfc;
	int status = FB_STATUS_OK;

	/* Remove flow from old expiring queue. */
	cfc = nfc->prev_expire;
	if (cfc != NULL) {
		if (nfc->next_expire != NULL) {
			cfc->next_expire =
			    nfc->next_expire;
			nfc->next_expire = NULL;
			cfc->next_expire->prev_expire =
			    cfc;
		} else {
			nfe->flow_expire_tail =
			    cfc;
			cfc->next_expire = NULL;
		}
		nfc->prev_expire = NULL;
	} else if (nfc->next_expire != NULL) {
		nfe->flow_expire_head =
		    nfc->next_expire;
		nfc->next_expire = NULL;
		nfe->flow_expire_head -> prev_expire =
		    NULL;
	} else {
		nfe->flow_expire_head = NULL;
		nfe->flow_expire_tail = NULL;
	}

	/* Remove expiring queue if empty. */
	if (nfe->flow_expire_head == NULL) {
		if (generic_hash_delete(
		    fbc->expire_queue_interval_hash,
		    nfe) == NULL) {
			gen_info(
			    "%s,%d: generic_hash_delete %p failure",
			    __FILE__, __LINE__,
			    nfe);
			    status = FB_STATUS_ERROR;
		}
		nfe->next_unused =
		    fbc->expire_queue_unused_head;
		fbc->expire_queue_unused_head = nfe;
	}

	return (status);
}

/* Callback for generic_hash_foreach'func_task */
void flow_expire_queue_walk_and_drain(
	void				*arg0,
	void				**arg1,
	void				*arg2)
{
	char				errstr[DLADM_STRSIZE];
	flow_expire_queue_t		*nfe =
	    (flow_expire_queue_t *)arg0;
	flow_base_collection_t		*fbc =
	    (flow_base_collection_t *)arg2;
	flow_collection_t		*nfc,
	    *next_nfc, *flow_remove_head = NULL;
	dladm_status_t			status;

	if (nfe == NULL ||
	    fbc == NULL ||
	    nfe->flow_expire_head == NULL)
		return;

	flow_remove_head = NULL;
	for (nfc = nfe->flow_expire_head; nfc != NULL; nfc = next_nfc) {
		next_nfc = nfc->next_expire;
		if (nfc->in_transition == B_TRUE) {
			continue;
		}
		nfc->in_transition = B_TRUE;
		remove_flow_collection_from_expire_queue(nfc, nfe, fbc);
		nfc->next_pending_remove = flow_remove_head;
		flow_remove_head = nfc;
	}

	while (flow_remove_head != NULL) {
		nfc = flow_remove_head;
		flow_remove_head = nfc->next_pending_remove;
		nfc->next_pending_remove = NULL;
		if (generic_hash_delete(
		    fbc->flow_name_hash,
		    nfc) == NULL) {
			gen_info(
			    "%s,%d: generic_hash_delete %p failure",
			    __FILE__, __LINE__,
			    nfc);
		}
		if (fbc->need_synchronization == B_TRUE) {
			status = remove_flow_collection(nfc);
			if ((status != DLADM_STATUS_OK) &&
			    (status != DLADM_STATUS_NOTFOUND)) {
				gen_info(
				    "%s,%d: remove_flow_collection %p failure %s",
				    __FILE__, __LINE__,
				    nfc, dladm_status2str(status, errstr));
			}
		}
		nfc->next_unused =
		    fbc->flow_unused_head;
		fbc->flow_unused_head = nfc;
		if (nfc->in_transition == B_TRUE)
			nfc->in_transition = B_FALSE;
	}
}

void flow_base_collection_ini(
	flow_base_collection_t	*fbc)
{
	bzero(fbc, sizeof(flow_base_collection_t));
	pthread_mutex_init(&fbc->lock, NULL);
	fbc->need_synchronization = B_FALSE;
}

void flow_base_collection_fini(
	flow_base_collection_t	*fbc)
{
	flow_collection_t	*nfc;
	flow_expire_queue_t	*nfe;

	pthread_mutex_lock(&fbc->lock);
	if (fbc->flow_name_hash != NULL) {
		/* Drain expiring list forcibly 
		 * but don't remove flows from the system.
		 */
		if (fbc->expire_queue_interval_hash != NULL) {
			generic_hash_foreach(
			    fbc->expire_queue_interval_hash,
			    flow_expire_queue_walk_and_drain,
			    fbc);
		}
		generic_hash_foreach(
		    fbc->flow_name_hash,
		    flow_collection_hash_delete,
		    fbc);
		generic_hash_free(&fbc->flow_name_hash);
	}
	while (fbc->flow_unused_head != NULL) {
		nfc = fbc->flow_unused_head;
		fbc->flow_unused_head = nfc->next_unused;
		free(nfc);
	}
	if (fbc->expire_queue_interval_hash != NULL) {
		generic_hash_foreach(
		    fbc->expire_queue_interval_hash,
		    expire_queue_interval_hash_delete,
		    fbc);
		generic_hash_free(&fbc->expire_queue_interval_hash);
	}
	while (fbc->expire_queue_unused_head != NULL) {
		nfe = fbc->expire_queue_unused_head;
		fbc->expire_queue_unused_head = nfe->next_unused;
		free(nfe);
	}
	pthread_mutex_unlock(&fbc->lock);

	pthread_mutex_destroy(&fbc->lock);
}

/* Callback for generic_hash_hdl_t'cmp */
int cmp_fe(
	void	*arg0,
	void	*arg1)
{
	flow_expire_queue_t		*fe0 =
	    (flow_expire_queue_t *)arg0;
	flow_expire_queue_t		*fe1 =
	    (flow_expire_queue_t *)arg1;

	if (fe0 == NULL ||
	    fe1 == NULL)
		return (1);
	return (cmp_uint16(
	    &fe0->expire_interval,
	    &fe1->expire_interval));
}

/* Callback for generic_hash_hdl_t'hash */
uint64_t hash_fe(
	void	*arg)
{
	flow_expire_queue_t		*fe =
	    (flow_expire_queue_t *)arg;

	if (fe == NULL)
		return (0);
	return (hash_uint16(&fe->expire_interval));
}

/* Callback for generic_hash_hdl_t'cmp */
int cmp_fbc(
	void	*arg0,
	void	*arg1)
{
	flow_collection_t		*fc0 =
	    (flow_collection_t *)arg0;
	flow_collection_t		*fc1 =
	    (flow_collection_t *)arg1;
	char				keystring0[MAXFLOWNAMELEN];
	char				keystring1[MAXFLOWNAMELEN];

	if (fc0 == NULL ||
	    fc1 == NULL)
		return (1);
	bzero(&keystring0, sizeof(keystring0));
	if (fill_flow_name(fc0->linkid, keystring0, sizeof(keystring0),
	    &fc0->local_ulp, fc0->dscp_value) !=
	    DLADM_STATUS_OK)
		return (1);
	bzero(&keystring1, sizeof(keystring1));
	if (fill_flow_name(fc1->linkid, keystring1, sizeof(keystring1),
	    &fc1->local_ulp, fc1->dscp_value) !=
	    DLADM_STATUS_OK)
		return (1);
	if (strcmp(keystring0, keystring1))
		return (1);
	return (0);
}

/* Callback for generic_hash_hdl_t'hash */
uint64_t hash_fbc(
	void	*arg)
{
	flow_collection_t		*fc =
	    (flow_collection_t *)arg;
	char				keystring[MAXFLOWNAMELEN];

	if (fc == NULL)
		return (0);
	bzero(&keystring, sizeof(keystring));
	if (fill_flow_name(fc->linkid, keystring, sizeof(keystring),
	    &fc->local_ulp, fc->dscp_value) !=
	    DLADM_STATUS_OK)
		return (0);
	return (hash_buf(keystring, strlen(keystring)));
}

int
store_flow_collection_entity(
	datalink_id_t	linkid,
	uint16_t	expire_interval,
	hrtime_t	crtime,
	struct sockaddr *local_ulp,
	uint8_t		dscp_value)
{
	char				errstr[DLADM_STRSIZE];
	flow_expire_queue_t		fe, *nfe, *ofe;
	flow_collection_t		fc, *nfc/*, *cfc*/;
	flow_base_collection_t		*fbc = &flow_base_collection;
	storage_backend_handle_t	*fdb = &flow_database;
	boolean_t			nfc_hash_added = B_FALSE;
	boolean_t			nfc_hash_replaced = B_FALSE;
	boolean_t			nfc_hash_found = B_FALSE;
	hrtime_t			now;
	int				status = DLADM_STATUS_BADARG;
	int				backend_status =
	    STORAGE_BACKEND_STATUS_UNKNOWN;
	int				result_status;

	if (local_ulp == NULL)
		return (DLADM_STATUS_BADARG);

	/* Fixme: just for exclusion of DNS Cache WQ interval. */
	if (expire_interval == 400)
		return (DLADM_STATUS_OK);

	pthread_mutex_lock(&fbc->lock);
	if (fbc->flow_name_hash == NULL) {
		fbc->flow_name_hash = generic_hash_new(
		    FLOW_NAME_HASH_SIZE,
		    cmp_fbc,
		    hash_fbc);
		if (fbc->flow_name_hash == NULL) {
			pthread_mutex_unlock(&fbc->lock);
			return (DLADM_STATUS_NOMEM);
		}
	}
	if (fbc->expire_queue_interval_hash == NULL) {
		fbc->expire_queue_interval_hash = generic_hash_new(
		    EXPIRE_QUEUE_INTERVAL_HASH_SIZE,
		    cmp_fe,
		    hash_fe);
		if (fbc->expire_queue_interval_hash == NULL) {
			pthread_mutex_unlock(&fbc->lock);
			return (DLADM_STATUS_NOMEM);
		}
	}

	bzero(&fc, sizeof(flow_collection_t));
	memcpy(&fc.local_ulp, local_ulp, sizeof(struct sockaddr));
	fc.linkid = linkid;
	fc.dscp_value = dscp_value;

	nfc = generic_hash_find(
	    fbc->flow_name_hash,
	    &fc);
	if (nfc != NULL) {
		nfc_hash_found = B_TRUE;

		now = gethrtime();
		/* Just ignore flow update if it is consequent.
		 * Fixme: it should be made by comparing between
		 * current flooding session ID and saved ID:
		 * file timestamp or something else.
		 */
		if (nfc->start_expire_time / HRTIME2SEC_MULTIPLIER + DEFAULT_AFILE_PARSE_INTERVAL >
		    now / HRTIME2SEC_MULTIPLIER) {
			pthread_mutex_unlock(&fbc->lock);
			return (DLADM_STATUS_EXIST);
		}

		/* Find out expiring queue by using existing
		 * value of flow expiring interval.
		 */
		bzero(&fe, sizeof(flow_expire_queue_t));
		fe.expire_interval = nfc->flow_expire_interval;
		ofe = generic_hash_find(
		    fbc->expire_queue_interval_hash,
		    &fe);
		if (ofe == NULL) {
			pthread_mutex_unlock(&fbc->lock);
			return (DLADM_STATUS_EXIST);
		}

		if (nfc->in_transition == B_TRUE) {
			pthread_mutex_unlock(&fbc->lock);
			return (DLADM_STATUS_EXIST);
		}
		nfc->in_transition = B_TRUE;

		remove_flow_collection_from_expire_queue(nfc, ofe, fbc);
		/*
		 * Synchronize the flow with the system
		 * if DSCP was changed.
		 */
		if (nfc->dscp_value != dscp_value) {
			nfc_hash_replaced = B_TRUE;
			nfc_hash_found = B_FALSE;
			if (generic_hash_delete(
			    fbc->flow_name_hash,
			    nfc) == NULL) {
				gen_info(
				    "%s,%d: generic_hash_delete %p failure",
				    __FILE__, __LINE__,
				    nfc);
			}
			goto add_flow;
		}

/*		if (expire_interval > nfc->flow_expire_interval)*/
		nfc->flow_expire_interval = expire_interval;
		nfc->start_expire_time = now;

		status = DLADM_STATUS_EXIST;
		goto add_expire_queue;
	}

	if (fbc->flow_unused_head != NULL) {
		nfc = fbc->flow_unused_head;
		fbc->flow_unused_head =
		    fbc->flow_unused_head->next_unused;
		bzero(nfc, sizeof(flow_collection_t));
	} else {
		if (generic_hash_length(fbc->flow_name_hash) >
		    FLOW_NAME_HASH_MAX_ENTRIES) {
			fbc->nflows_overlimit++;
			pthread_mutex_unlock(&fbc->lock);
			return (DLADM_STATUS_TRYAGAIN);
		}
		nfc = (flow_collection_t *) calloc(
		    1, sizeof(flow_collection_t));
		if (nfc == NULL) {
			fbc->nomem_errors++;
			pthread_mutex_unlock(&fbc->lock);
			return (DLADM_STATUS_NOMEM);
		}
	}

	nfc->in_transition = B_TRUE;

add_flow:
	nfc->flow_expire_interval = expire_interval;
	nfc->start_expire_time = (crtime == 0) ? gethrtime() : crtime;
	nfc->orig_expire_time = nfc->start_expire_time;

	nfc->linkid = linkid;
	memcpy(&nfc->local_ulp, local_ulp, sizeof(struct sockaddr));
	nfc->dscp_value = dscp_value;

	if (crtime == 0) {
		pthread_mutex_unlock(&fbc->lock);

		if (nfc_hash_replaced == B_TRUE) {
			status = remove_flow_collection(nfc);
			if (status !=
			    DLADM_STATUS_OK &&
			    status !=
			    DLADM_STATUS_NOTFOUND) {
				goto fail;
			}
		}
		/* Add new flow to the system. */
		status = add_flow_collection(nfc);

		if (status !=
		    DLADM_STATUS_OK &&
		    status !=
		    DLADM_STATUS_EXIST) {
			gen_info(
			    "%s,%d: add_flow_collection %p failure %s",
			    __FILE__, __LINE__,
			    nfc, dladm_status2str(status, errstr));
			goto fail;
		} else {
			backend_status =
			    backend_store_flow_collection(
				fdb, nfc, QUERY_ADD);
		}

		pthread_mutex_lock(&fbc->lock);
	}

	if (generic_hash_add(
	    fbc->flow_name_hash,
	    nfc, nfc) == NULL) {
		pthread_mutex_unlock(&fbc->lock);
		goto fail;
	}
	nfc_hash_added = B_TRUE;
	if (crtime != 0) {
		status = DLADM_STATUS_OK;
	}

add_expire_queue:
	bzero(&fe, sizeof(flow_expire_queue_t));
	fe.expire_interval = expire_interval;

	nfe = generic_hash_find(
	    fbc->expire_queue_interval_hash,
	    &fe);
	if (add_flow_collection_to_expire_queue(nfc, nfe, fbc) !=
	     FB_STATUS_OK) {
		pthread_mutex_unlock(&fbc->lock);
		status = DLADM_STATUS_TRYAGAIN;
		goto fail;
	}
	if (nfc_hash_added == B_TRUE) {
		fbc->nflows_added++;
	} else if (nfc_hash_found == B_TRUE) {
		fbc->nflows_updated++;
	}

	if (nfc->in_transition == B_TRUE)
		nfc->in_transition = B_FALSE;
	pthread_mutex_unlock(&fbc->lock);

	if ((nfc_hash_found == B_TRUE) &&
	    (nfc_hash_added == B_FALSE)) {
		backend_status =
		    backend_store_flow_collection(
			fdb, nfc, QUERY_UPDATE);
	}

	if (backend_status == STORAGE_BACKEND_STATUS_FULL_DUMP) {
		backend_flow_dump_all(fdb, fbc);
	}

	return (status);
fail:
	if (nfc != NULL) {
		pthread_mutex_lock(&fbc->lock);
		if (nfc_hash_added == B_TRUE ||
		    nfc_hash_found == B_TRUE) {
			generic_hash_delete(
			    fbc->flow_name_hash,
			    nfc);
		}
		nfc->next_unused =
		    fbc->flow_unused_head;
		fbc->flow_unused_head = nfc;

		if (nfc->in_transition == B_TRUE)
			nfc->in_transition = B_FALSE;
		pthread_mutex_unlock(&fbc->lock);

		if (nfc_hash_added == B_TRUE ||
		    nfc_hash_found == B_TRUE) {
			/* Remove flow from the system. */
			result_status = remove_flow_collection(nfc);
			if (result_status == DLADM_STATUS_OK ||
			    result_status == DLADM_STATUS_NOTFOUND) {
				backend_status =
				    backend_store_flow_collection(
					fdb, nfc, QUERY_DELETE);
				    if (backend_status ==
					STORAGE_BACKEND_STATUS_FULL_DUMP) {
					    backend_flow_dump_all(fdb, fbc);
				    }
			}
		}
	}
	return (status);
}

/* Callback for generic_hash_foreach'func_task */
void flow_expire_queue_walk_and_expire(
	void *arg0,
	void **arg1,
	void *arg2)
{
	flow_expire_queue_t		*nfe =
	    (flow_expire_queue_t *)arg0;
	flow_base_collection_t  	*fbc =
	    (flow_base_collection_t *)arg2;
	flow_expire_queue_t		*cfe, fe;
	flow_collection_t		*nfc, *next_nfc;
	flow_collection_t		*flow_remove_head = NULL,
	    *flow_replace_head = NULL;
	storage_backend_handle_t	*fdb = &flow_database;
	boolean_t			backend_need_full_dump = B_FALSE;
	int				result_status =
	    DLADM_STATUS_NOTFOUND;
	int				backend_status =
	    STORAGE_BACKEND_STATUS_UNKNOWN;
	hrtime_t			now;
	uint16_t			expire_interval = 0;
	uint64_t			removed_count = 0,
	    replaced_count = 0;

	if (nfe == NULL ||
	    fbc == NULL)
		return;

	pthread_mutex_lock(&fbc->lock);
	expire_interval = nfe->expire_interval;
	if (nfe->flow_expire_head == NULL ||
	    fbc->flow_name_hash == NULL)
		goto end;
	/* flow_expire_head is a stack list, head is the oldest entry. */
	for (nfc = nfe->flow_expire_head; nfc != NULL; nfc = next_nfc) {
		next_nfc = nfc->next_expire;

		now = gethrtime();
		/* Stop looping if it isn't expired yet. */
		if (nfc->start_expire_time / HRTIME2SEC_MULTIPLIER +
		    nfc->flow_expire_interval +
		    DEFAULT_AFILE_REFRESH_INTERVAL + DEFAULT_AFILE_PARSE_INTERVAL >
		    now / HRTIME2SEC_MULTIPLIER)
			goto stage2;

		if (nfc->in_transition == B_TRUE) {
			continue;
		}
		nfc->in_transition = B_TRUE;

		/* Remove flow from expiring queue. */
		remove_flow_collection_from_expire_queue(nfc, nfe, fbc);
		if (((expire_interval & 1) == 1) &&
		    (expire_interval != PROBE_EXPIRE_INTERVAL)) {
			nfc->next_pending_replace =
			    flow_replace_head;
			flow_replace_head = nfc;
		} else {
			/* Remove flow from flow name hash. */
			if (generic_hash_delete(
			    fbc->flow_name_hash,
			    nfc) == NULL) {
				gen_info(
				    "%s,%d: generic_hash_delete %p failure",
				    __FILE__, __LINE__,
				    nfc);
			}
			/*
			 * Insert flow into standalone flow_remove_head list
			 * which is used in order to avoid
			 * mutex lock/unlock for each iteration.
			 */
			nfc->next_pending_remove =
			    flow_remove_head;
			flow_remove_head = nfc;
		}
	};

stage2:
	/* Remove expired flows from the system. */
	pthread_mutex_unlock(&fbc->lock);
	for (nfc = flow_remove_head;
	    nfc != NULL;
	    nfc = nfc->next_pending_remove) {
		result_status = remove_flow_collection(nfc);
		if (result_status == DLADM_STATUS_OK) {
			removed_count++;
			backend_status = backend_store_flow_collection(
			    fdb, nfc, QUERY_DELETE);
			if (backend_status ==
			    STORAGE_BACKEND_STATUS_FULL_DUMP) {
				backend_need_full_dump = B_TRUE;
			}
		} else if (result_status == DLADM_STATUS_NOTFOUND) {
			gen_info(
			    "%s,%d: flow %p not found",
			    __FILE__, __LINE__,
			    nfc);
		} else {
			gen_info(
			    "%s,%d: remove_flow_collection %p failure",
			    __FILE__, __LINE__,
			    nfc);
		}
	}
	/* Re-insert flow_replace_head elements into scope expire queue. */
	cfe = NULL;
	while (flow_replace_head != NULL) {
		nfc = flow_replace_head;
		flow_replace_head = nfc->next_pending_replace;
		nfc->next_pending_replace = NULL;

		/*
		 * Fixme: probably we should use DLDIOC_MODIFYFLOW instead of
		 * doing DLDIOC_REMOVEFLOW + DLDIOC_ADDFLOW sequence.
		 */
		result_status = remove_flow_collection(nfc);
		if (result_status == DLADM_STATUS_OK) {
			/* Update flow DSCP. */
			nfc->dscp_value = PROBE_DSCP_CS;
			nfc->start_expire_time = gethrtime();
			nfc->flow_expire_interval = PROBE_EXPIRE_INTERVAL;
			result_status = add_flow_collection(nfc);

			if (result_status == DLADM_STATUS_OK) {
				backend_status = backend_store_flow_collection(
				    fdb, nfc, QUERY_UPDATE);
				if (backend_status ==
				    STORAGE_BACKEND_STATUS_FULL_DUMP) {
					backend_need_full_dump = B_TRUE;
				}
			}
		}
		/* We are trying our best with re-insertion. */
		pthread_mutex_lock(&fbc->lock);
		if (result_status == DLADM_STATUS_OK) {
			if (cfe == NULL) {
				bzero(&fe, sizeof(flow_expire_queue_t));
				fe.expire_interval = nfc->flow_expire_interval;

				cfe = generic_hash_find(
				    fbc->expire_queue_interval_hash,
				    &fe);
			}
			if (add_flow_collection_to_expire_queue(
			    nfc, cfe, fbc) !=
			    FB_STATUS_OK) {
				goto replace_failed;
			}
			replaced_count++;
		} else {
replace_failed:
			/* Remove flow from flow name hash. */
			if (generic_hash_delete(
			    fbc->flow_name_hash,
			    nfc) == NULL) {
				gen_info(
				    "%s,%d: generic_hash_delete %p failure",
				    __FILE__, __LINE__,
				    nfc);
			}
			nfc->next_unused =
			    fbc->flow_unused_head;
			fbc->flow_unused_head = nfc;
			removed_count++;
		}
		if (nfc->in_transition == B_TRUE)
			nfc->in_transition = B_FALSE;
		pthread_mutex_unlock(&fbc->lock);
	}

	pthread_mutex_lock(&fbc->lock);
	/* Update flow statistical counters. */
	if (removed_count > 0) {
		fbc->nflows_deleted += removed_count;
	}
	if (replaced_count > 0) {
		fbc->nflows_updated += replaced_count;
	}
	/* Populate flow_unused_head for further use. */
	while (flow_remove_head != NULL) {
		nfc = flow_remove_head;
		flow_remove_head = nfc->next_pending_remove;
		nfc->next_pending_remove = NULL;

		nfc->next_unused =
		    fbc->flow_unused_head;
		fbc->flow_unused_head = nfc;

		if (nfc->in_transition == B_TRUE)
			nfc->in_transition = B_FALSE;
	}

end:
	pthread_mutex_unlock(&fbc->lock);
	if (backend_need_full_dump == B_TRUE) {
		backend_flow_dump_all(fdb, fbc);
	}
	if ((removed_count > 0) ||
	    (replaced_count > 0))
		gen_info("flow_expire_queue_walk_and_expire(): "
		    "updated %llu, deleted %llu for interval %d",
		    replaced_count, removed_count, expire_interval);
	return;
}

int
flow_base_collection_walk_and_expire()
{
	flow_base_collection_t  	*fbc =
	    &flow_base_collection;
	int				result_status = DLADM_STATUS_OK;

	if (fbc->expire_queue_interval_hash == NULL)
		return (result_status);

	if (generic_hash_foreach(
	    fbc->expire_queue_interval_hash,
	    flow_expire_queue_walk_and_expire,
	    fbc) != HASH_STATUS_OK)
		result_status = DLADM_STATUS_FAILED;

	return (result_status);
}
