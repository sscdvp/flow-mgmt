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

#ifndef DLADM_INTERFACE_H
#define DLADM_INTERFACE_H

#include <sys/types.h>
#include <libdladm.h>
#if 0
#include "include/libdlvnic.h"
#endif
#include "include/libdlflow.h"
#include <libdllink.h>

typedef struct __flow_stat_t {
	hrtime_t	crtime;
	hrtime_t	snaptime;
	uint64_t	ipackets;
	uint64_t	opackets;
	uint64_t	rbytes;
	uint64_t	obytes;
	uint64_t	idrops;
	uint64_t	odrops;
	uint64_t	ierrors;
	uint64_t	oerrors;
} flow_stat_t;

typedef struct __flow_partdesc_t {
	flow_mask_t	fd_mask;
	uint8_t		fd_ipversion;
	uint8_t		fd_protocol;
	in6_addr_t	fd_local_addr;
	in6_addr_t	fd_local_netmask;
	in6_addr_t	fd_remote_addr;
	in6_addr_t	fd_remote_netmask;
	in_port_t	fd_local_port;
	in_port_t	fd_remote_port;
	uint8_t		fd_dsfield;
	uint8_t		fd_dsfield_mask;
} flow_partdesc_t;

#define HRTIME2SEC_MULTIPLIER (1000000000L)

typedef struct __flow_expire_param_t flow_expire_param_t;
struct __flow_expire_param_t {
	uint16_t		flow_expire_interval;
	hrtime_t		orig_expire_time;
};

typedef struct __flow_collection_t flow_collection_t;
struct __flow_collection_t {
	struct sockaddr		local_ulp;
	datalink_id_t		linkid;
	hrtime_t		orig_expire_time;
	hrtime_t		start_expire_time;
	flow_collection_t	*prev_expire;
	flow_collection_t	*next_expire;
	flow_collection_t	*next_unused;
	flow_collection_t	*next_pending_remove;
	flow_collection_t	*next_pending_replace;
	uint16_t		flow_expire_interval;
	uint8_t			dscp_value;
	/* Flag if busy out. */
	boolean_t		in_transition;
};
#if 0
boolean_t
vnic_belongs_to_an_vlan(uint16_t vlan_vid);
#endif

int
fill_flow_name(
	datalink_id_t	linkid,
	char		*flow_name,
	int		flow_name_len,
	struct sockaddr	*local_ulp,
	uint8_t		dscp_value);
int
add_flow_collection(flow_collection_t *nfc);
int
remove_flow_collection(flow_collection_t *nfc);
void
dladm_flow_print_all_on_link(datalink_id_t linkid);
int
dladm_flow_load_all_on_link(datalink_id_t linkid);
int
dladm_flow_load_all_on_ifname(char *ifa_name);
int
dladm_flow_load_all_via_kstat();
int dladm_load_flow_via_backend(
	void	*arg,
	int	columns,
	char	**row_value,
	char	**column_name);
datalink_id_t
dladm_get_linkid_for_ifname(char *ifa_name);
boolean_t
dladm_handle_create(char *arg);
void
dladm_handle_destroy(void);

dladm_status_t
cust_dladm_flow_add(dladm_handle_t handle, datalink_id_t linkid,
    dladm_arg_list_t *attrlist, dladm_arg_list_t *proplist, char *flowname,
    boolean_t tempop, const char *root);

#endif
