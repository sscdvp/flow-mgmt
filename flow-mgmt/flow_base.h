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

#ifndef FLOW_BASE_H
#define FLOW_BASE_H

#include <pthread.h>

#include "hash_interface.h"
#include "dladm_interface.h"

#define FLOW_NAME_HASH_SIZE			GENERIC4_HASH_SIZE
/*#define FLOW_NAME_HASH_MAX_ENTRIES		(FLOW_NAME_HASH_SIZE / 16)*/
#define FLOW_NAME_HASH_MAX_ENTRIES		(2500)

#define EXPIRE_QUEUE_INTERVAL_HASH_SIZE		GENERIC0_HASH_SIZE
#define EXPIRE_QUEUE_INTERVAL_HASH_MAX_ENTRIES \
    (EXPIRE_QUEUE_INTERVAL_HASH_SIZE * 4)

#define DEFAULT_FLOW_STR_PREFFIX		"dnsc"

#define DEFAULT_AFILE_REFRESH_INTERVAL		60
#define DEFAULT_AFILE_PARSE_INTERVAL		15
#define DEFAULT_AFILE_RETRY_INTERVAL		5

/* Default communication port. */
#define DEFAULT_FLOW_MGMT_PORT			11380

/*
 * List of supported DSCP class selectors.
 * See details about values in RFC 2474.
 */
#define PROBE_DSCP_CS				8 /* ToS 0x20 */
#define DROPALL_DSCP_CS				16 /* ToS 0x40 */
#define GENERIC_DSCP_CS				32 /* ToS 0x80 */
#define DEFAULT_DSCP_CS				GENERIC_DSCP_CS

/* Max port number for UDP, TCP, SCTP. */
#define	MAX_PORT				65535

#define FB_STATUS_OK				1
#define FB_STATUS_ERROR				2
#define FB_STATUS_TRYAGAIN			3
#define FB_STATUS_NOMEM				4

typedef struct __flow_expire_queue_t flow_expire_queue_t;

/*
 * Each expiring queue is a two-way linked list,
 * the members sorted by time of start, newer on the tail.
 */
struct __flow_expire_queue_t {
#define MAX_EXPIRE_INTERVAL			2400
#define DEFAULT_EXPIRE_INTERVAL			400
#define PROBE_EXPIRE_INTERVAL			(\
DEFAULT_AFILE_PARSE_INTERVAL + DEFAULT_AFILE_REFRESH_INTERVAL)
#define MIN_EXPIRE_INTERVAL			10
	uint16_t		expire_interval;
	flow_collection_t	*flow_expire_head;
	flow_collection_t	*flow_expire_tail;
	flow_expire_queue_t	*next_unused;
};

typedef struct __flow_base_collection_t flow_base_collection_t;

struct __flow_base_collection_t {
	/* Statistic counters */
	uint64_t		nflows_updated_last;
	uint64_t		nflows_updated;
	uint64_t		nflows_added;
	uint64_t		nflows_added_last;
	uint64_t		nflows_deleted;
	uint64_t		nflows_deleted_last;
	uint64_t		nflows_overlimit;
	uint64_t		nflows_overlimit_last;
	uint64_t		nomem_errors;
	uint64_t		nomem_errors_last;
	uint64_t		nqueues_overlimit;
	uint64_t		nqueues_overlimit_last;
	/* Protecting mutex */
	pthread_mutex_t		lock;
	/* 
	 * Hash table of unique flow names. We aren't enforcing the things;
	 * flow name must be unique within current zone.
	 */
	generic_hash_hdl_t	*flow_name_hash;
	/*
	 * Hash table of expiring queues
	 */
	generic_hash_hdl_t	*expire_queue_interval_hash;
	/*
	 * Store allocations to be re-used later.
	 */
	flow_expire_queue_t	*expire_queue_unused_head;
	flow_collection_t	*flow_unused_head;
	/* Flag whether to get rid of system flow on delete action. */
	boolean_t		need_synchronization;
};

/* Global variable */
extern flow_base_collection_t	flow_base_collection;

/* Exported life-cycle routines */
void flow_base_collection_ini(flow_base_collection_t *fbc);
void flow_base_collection_fini(flow_base_collection_t *fbc);
int
store_flow_collection_entity(
	datalink_id_t	linkid,
	uint16_t	expire_interval,
	hrtime_t	crtime,
	struct sockaddr *local_ulp,
	uint8_t		dscp_value);
int
flow_base_collection_walk_and_expire(void);
void flow_collection_walk_and_add(
	void				*arg0,
	void				**arg1,
	void				*arg2);
void flow_collection_walk_and_remove(
	void				*arg0,
	void				**arg1,
	void				*arg2);
void flow_collection_walk_and_store2backend(
	void				*arg0,
	void				**arg1,
	void				*arg2);

#endif
