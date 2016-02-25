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

#ifndef IFADDR_INTERFACE_H
#define IFADDR_INTERFACE_H

#include <sys/types.h>
#include <pthread.h>
#include <ifaddrs.h>

#include "hash_interface.h"
#include "log.h"

#include "socket_generic.h"

#define IFS_WALK_CONTINUE 1
#define IFS_WALK_TERMINATE 2

#define IFA_WALK_CONTINUE 1
#define IFA_WALK_TERMINATE 2

typedef struct __ifa_if_link_t ifa_if_link_t;
struct __ifa_if_link_t {
	struct sockaddr	target_addr;
	struct sockaddr	addr;
	char		*ifname;
	uint16_t	ifnamelen;
	uint16_t	ifindex;
	datalink_id_t	linkid;
	ifa_if_link_t	*next_sibling;
	ifa_if_link_t	*tail_sibling;
};

typedef struct __ifs_if_search_t {
	ifa_if_link_t	iflink;
	boolean_t	done;
} ifs_if_search_t;

typedef struct __ifa_collection_t {
	generic_hash_hdl_t	*ifa_if_hash;
	struct sockaddr		target_addr;
	pthread_mutex_t		lock;
	pthread_mutex_t		timed_lock;
	boolean_t		error;
} ifa_collection_t;

typedef struct __lac_collection_t lac_collection_t;

struct __lac_collection_t {
	struct in_addr		target_addr;
	struct in_addr		target_net;
#define LAC_TYPE_UNKNOWN 0
#define LAC_TYPE_IFIP 1
#define LAC_TYPE_NEXTHOP 2
	uint8_t			target_type;
	lac_collection_t	*next;
};

void fill_sockaddr_from_ipv4_tuple(
	struct in_addr *,
	uint16_t,
	struct sockaddr *);
void fill_str_from_sockaddr(
	struct sockaddr *sa,
	char *addrstr,
	int addrstrlen,
	char *portstr,
	int portstrlen,
	boolean_t *is_error);
void ifa_collection_ini(
	ifa_collection_t *);
void ifa_collection_fini(
	ifa_collection_t *);
int ifa_complete_ifip_hash_by_addr(
	struct sockaddr *,
	struct ifaddrs *,
	void *);
int ifa_complete_ifip_hash_by_netaddr(
	struct sockaddr *,
	struct ifaddrs *,
	void *);
int ifa_complete_ifname_hash_all(
	struct sockaddr *,
	struct ifaddrs *,
	void *);
int ifa_complete_ifname_hash_by_netaddr(
	struct sockaddr *,
	struct ifaddrs *,
	void *);
void ifa_walk(
	struct sockaddr *,
	void *,
	int (*)(struct sockaddr *, struct ifaddrs *, void *));

void ifa_collection_load_flows(
	void *arg0,
	void **arg1,
	void *arg2);
void ifa_collection_print(
	void *,
	void **,
	void *);
void ifa_collection_walk(
	ifa_collection_t *,
	void *,
	void (*)(void *, void **, void *));

void next_wait_period(
	int millis,
	struct timespec *ts);

#endif
