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
 * This file contains wrappers for Solaris-bundled libdladm routines.
 */

#include <strings.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/crc32.h>
#include <kstat.h>
#include <arpa/inet.h>
#include <inet/ip.h>
#include <inet/ip6.h>

#include "hash_interface.h"
#include "ifaddr_interface.h"
#include "flow_base.h"

#include "dladm_interface.h"

#define KEYWORD_FLOW_PROP_BW_LIMIT "maxbw"
#define KEYWORD_FLOW_PROP_PRIORITY "priority"
#define KEYWORD_FLOW_PROP_DSCP "dscp"

#define KEYWORD_FLOW_ATTR_LOCAL_IP_ADDR "local_ip"
#define KEYWORD_FLOW_ATTR_REMOTE_IP_ADDR "remote_ip"
#define KEYWORD_FLOW_ATTR_TRANSPORT "transport"
#define KEYWORD_FLOW_ATTR_LOCAL_PORT "local_port"
#define KEYWORD_FLOW_ATTR_REMOTE_PORT "remote_port"
#define KEYWORD_FLOW_ATTR_DSFIELD "dsfield"

dladm_handle_t		dld_handle = NULL;
kstat_ctl_t		*kcp_handle = NULL;

int dladm_flow_load(
	dladm_handle_t		dld_handle,
	dladm_flow_attr_t	*flow_attrs,
	void			*arg);

#if 0
typedef struct __link_vnic_search_data_t {
	datalink_id_t linkid;
	uint16_t vlan_vid;
	boolean_t found;
} link_vnic_search_data_t;

static int
vnic_search(
	dladm_handle_t		dld_handle,
	dladm_datalink_info_t	*linkinfo,
	void			*data)
{
	dladm_status_t	status;

	printf("dladm linkid=%d\n", (linkinfo) ? linkinfo->di_linkid : -1);
	
	printf("dladm linkname=%s\n", linkinfo->di_linkname);

	if (linkinfo->di_class != DATALINK_CLASS_VNIC)
	    return (DLADM_WALK_CONTINUE);

	dladm_vnic_attr_t		attr, *vnic = &attr;

/*printf("sizeof(dladm_vnic_attr_t)=%x\n", sizeof(dladm_vnic_attr_t));*/
	bzero(&attr, sizeof(dladm_vnic_attr_t));

	if ((status = dladm_vnic_info(dld_handle, linkinfo->di_linkid, vnic, DLADM_OPT_ACTIVE)) !=
	    DLADM_STATUS_OK)
		return (DLADM_WALK_CONTINUE);

	    printf("vid=%d\n", vnic->va_vlan.vv_vid);
	    printf("ownerzoneid=%ld\n", vnic->va_owner_zone_id);
	    printf("zoneid=%ld\n", vnic->va_zone_id);

	return (DLADM_WALK_CONTINUE);
}

#if 0
static int
vnic_search(const char *name, void *data)
{
	char			vnicname[MAXLINKNAMELEN];
	link_vnic_search_data_t	*lvsd = data;
	datalink_id_t		linkid;
	dladm_status_t		status;
	int			i;

	if (dladm_name2info(dld_handle, name, &linkid, NULL, NULL, NULL) !=
	    DLADM_STATUS_OK)
		return (DLADM_WALK_CONTINUE);
	printf("dladm linkid=%d\n", linkid);

	if (dladm_datalink_id2info(dld_handle, linkid, NULL, NULL,
		NULL, vnicname, sizeof (vnicname)) != DLADM_STATUS_OK)
		return (DLADM_WALK_CONTINUE);
	printf("dladm linkname=%s\n", vnicname);

/*	if ((status = dladm_vnic_info(dld_handle, linkid, &attr, DLADM_OPT_ACTIVE)) !=
//	if ((status = dladm_vnic_info(dld_handle, linkid, vnic, DLADM_OPT_PERSIST)) !=
	    DLADM_STATUS_OK)
		return (DLADM_WALK_CONTINUE);

	if (dladm_datalink_id2info(dld_handle, linkid, NULL, NULL,
		NULL, vnicname, sizeof (vnicname)) != DLADM_STATUS_OK)
		return (DLADM_WALK_CONTINUE);
	    printf("dladm linkname=%s\n", vnicname);

//	if (vnic->va_link_id != DATALINK_INVALID_LINKID) {
	    printf("vid=%d\n", vnic->va_vlan.vv_vid);
	    printf("linkid=%d\n", vnic->va_link_id);
	    printf("zoneid=%d\n", vnic->va_zone_id);
//	}
*/
printf("dladm name: %s\n",name);


/*	if (dladm_aggr_info(dld_handle, linkid, &ginfo, DLADM_OPT_ACTIVE)
	    != DLADM_STATUS_OK || ginfo.lg_nports == 0)
		return (DLADM_WALK_CONTINUE);

	for (i = 0; i < ginfo.lg_nports; i++) {
		if (lvsd->linkid == ginfo.lg_ports[i].lp_linkid) {
			lvsd->found = B_TRUE;
			return (DLADM_WALK_TERMINATE);
		}
	}
	free(ginfo.lg_ports);
*/
	return (DLADM_WALK_CONTINUE);
}
#endif

boolean_t
vnic_belongs_to_an_vlan(
	uint16_t	vlan_vid)
{
	link_vnic_search_data_t	lvsd;

/*	if (dladm_name2info(dld_handle, name, &lvsd.linkid, NULL, NULL, NULL)
	    != DLADM_STATUS_OK)
		return (B_FALSE);*/
	lvsd.linkid = DATALINK_ALL_LINKID;
	lvsd.found = B_FALSE;
#if 0
	(void) dladm_walk(vnic_search, dld_handle, &lvsd,
	    DATALINK_CLASS_VNIC, DATALINK_ANY_MEDIATYPE, DLADM_OPT_ACTIVE);
#endif
	(void) dladm_walk_datalinks(dld_handle, lvsd.linkid,
	    vnic_search, &lvsd, DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE, DLADM_OPT_ACTIVE, 0, NULL);
	return (lvsd.found);
}
#endif

static boolean_t
match_str_by_name(
	char	*str,
	char	*param_name,
	char	**out_start_value,
	char	**out_end_value)
{
	char	*start_name, *end_name;
	char	*start_value, *end_value;

	if (str == NULL)
		return (B_FALSE);

	start_name = strcasestr(
	    (const char *)str,
	    (const char *)param_name);
	if (start_name == NULL)
		return (B_FALSE);
	end_name = strstr(start_name, "=");
	if (end_name == NULL)
		return (B_FALSE);
	start_value = end_name + 1;
	end_value = strstr(start_value, ",");
	if (end_value == NULL)
	    end_value = str + strlen(str);
	if ((int)(end_value - start_value) <= 0)
	    return (B_FALSE);
	if (out_start_value != NULL)
	    *out_start_value = start_value;
	if (out_end_value != NULL)
	    *out_end_value = end_value;
	return (B_TRUE);
}

static int
fill_flow_args(
	char	*argstr,
	char	*arg_name,
	char	*arg_value)
{
	boolean_t	not_empty = B_FALSE;

	if (argstr[0] != '\0')
		not_empty = B_TRUE;
	if (not_empty == B_TRUE) {
		if (strlcat(argstr, ",", DLADM_STRSIZE) >=
		    DLADM_STRSIZE) {
			goto toolong;
		}
	}
	if (match_str_by_name(argstr, arg_name, NULL, NULL) == B_TRUE) {
		printf("attribute already exist '%s'\n", argstr);
		return (DLADM_STATUS_OK);
	}

	if ( strlcat(argstr, arg_name, DLADM_STRSIZE) >=
	    DLADM_STRSIZE) {
toolong:
		printf("attribute list too long '%s'\n", argstr);
		return (DLADM_STATUS_BADARG);
	}
	if (strlcat(argstr, "=", DLADM_STRSIZE) >=
	    DLADM_STRSIZE) {
		goto toolong;
	}
	if (strlcat(argstr, arg_value, DLADM_STRSIZE) >=
	    DLADM_STRSIZE) {
		goto toolong;
	}
	return (DLADM_STATUS_OK);
}

static int
remove_flow(
	char	*flow_name)
{
	dladm_status_t	status;

	status = dladm_flow_remove(dld_handle,
	    flow_name,
	    B_TRUE, NULL);
	if (status == DLADM_STATUS_NOTFOUND) {
		printf("flow already removed\n");
	} else if (status != DLADM_STATUS_OK) {
		printf("remove flow failed\n");
		goto out;
	}

out:
	return (status);
}

static int
add_flow_on_link(
	datalink_id_t	linkid,
	char		*flow_name,
	char		*origattrstr,
	char		*origpropstr)
{
	dladm_arg_list_t	*attrlist = NULL;
	dladm_arg_list_t	*proplist = NULL;
	dladm_status_t		status;
	char			attrstr[DLADM_STRSIZE];
	char			propstr[DLADM_STRSIZE];

	bzero(&attrstr, DLADM_STRSIZE);
	bzero(&propstr, DLADM_STRSIZE);

	(void) strlcat(attrstr, origattrstr, DLADM_STRSIZE);
	(void) strlcat(propstr, origpropstr, DLADM_STRSIZE);

	if ((status = dladm_parse_flow_attrs(attrstr, &attrlist, B_FALSE))
	    != DLADM_STATUS_OK) {
		printf("invalid flow attribute specified\n");
		goto out;
	}
	if ((status = dladm_parse_flow_props(propstr, &proplist, B_FALSE))
	    != DLADM_STATUS_OK) {
		printf("invalid flow property specified\n");
		goto out;
	}

	/*
	 * Right now we use cust_dladm_flow_add()
	 * instead of libdladm'dladm_flow_add().
	 * See comments in the beginning of dladm_dlflow file
	 * for more information.
	 */
	 /*
	 status = dladm_flow_add(dld_handle, linkid,
	 */
	status = cust_dladm_flow_add(dld_handle, linkid,
	    attrlist, proplist, flow_name,
	    B_TRUE, NULL);
	if (status == DLADM_STATUS_EXIST) {
		printf("flow already exist\n");
	} else if (status != DLADM_STATUS_OK) {
		printf("add flow failed\n");
		goto out;
	}

out:
	dladm_free_attrs(attrlist);
	dladm_free_props(proplist);

	return (status);
}

static uint32_t cust_crc32_table[] = { CRC32_TABLE };

uint32_t chksum_crc32 (
	char		*block,
	unsigned int	length)
{
	uint32_t	crc = 0;

	CRC32 (crc, block, length, -1U, cust_crc32_table);
	return crc;
}

int
fill_flow_name(
	datalink_id_t	linkid,
	char		*flow_name,
	int		flow_name_len,
	struct sockaddr	*local_ulp,
	uint8_t		dscp_value)
{
	struct sockaddr_in	*local_addr_in =
	    (struct sockaddr_in *)local_ulp;
	char			crcbuf[MAXFLOWNAMELEN];
	uint16_t		crcbuf_len = sizeof(crcbuf);
	uint16_t		port;
	uint32_t		ip;

	if (local_ulp == NULL)
		return (DLADM_STATUS_BADARG);

	ip = ntohl(local_addr_in->sin_addr.s_addr);
	if (ip == INADDR_NONE)
		return (DLADM_STATUS_BADARG);
	port = ntohs(local_addr_in->sin_port);

	bzero(&crcbuf, crcbuf_len);
	if (strlcat(
	    crcbuf, lltostr(
		linkid, &crcbuf[crcbuf_len - 1]),
	    crcbuf_len) >=
	    crcbuf_len)
		return (DLADM_STATUS_BADARG);
	if (strlcat(crcbuf, "_", crcbuf_len) >=
	    crcbuf_len)
		return (DLADM_STATUS_BADARG);
/*	if (strlcat(
	    crcbuf, lltostr(
		dscp_value, &crcbuf[crcbuf_len - 1]),
	    crcbuf_len) >=
	    crcbuf_len)
		return (DLADM_STATUS_BADARG);
	if (strlcat(crcbuf, "_", crcbuf_len) >=
	    crcbuf_len)
		return (DLADM_STATUS_BADARG);
*/
	if (strlcat(crcbuf, lltostr(
	    ip, &crcbuf[crcbuf_len - 1]),
	    crcbuf_len) >=
	    crcbuf_len)
		return (DLADM_STATUS_BADARG);

/*	if ((local_port != NULL) &&
	    (strtol(local_port, NULL, 10) > 0)) {
		if (strlcat(crcbuf, ".", crcbuf_len) >=
		    crcbuf_len)
			return (DLADM_STATUS_BADARG);
		if (strlcat(crcbuf, local_port, crcbuf_len) >=
		    crcbuf_len)
			return (DLADM_STATUS_BADARG);
	}*/
	if (port > 0) {
		if (strlcat(crcbuf, ".", crcbuf_len) >=
		    crcbuf_len)
			return (DLADM_STATUS_BADARG);
		if (strlcat(crcbuf, lltostr(
		    port, &crcbuf[crcbuf_len - 1]),
		    crcbuf_len) >=
		    crcbuf_len)
			return (DLADM_STATUS_BADARG);
	}

	if (snprintf(flow_name, flow_name_len - 1,
	    "%s.%x",
	    DEFAULT_FLOW_STR_PREFFIX, chksum_crc32(crcbuf, strlen(crcbuf))) >=
		flow_name_len - 1)
		return (DLADM_STATUS_BADARG);

	return (DLADM_STATUS_OK);
}

int
add_flow_collection(
	flow_collection_t	*nfc)
{
	dladm_status_t	status;
	char		propstr[DLADM_STRSIZE];
	char		attrstr[DLADM_STRSIZE];
	char		flowname[MAXFLOWNAMELEN];
	char		local_ip[INET6_ADDRSTRLEN + 1];
	char		local_port[ULONG_STRLEN];
	boolean_t	is_error = B_FALSE;

	bzero(&propstr, sizeof(propstr));
	bzero(&attrstr, sizeof(attrstr));

	if (nfc == NULL)
		return (DLADM_STATUS_BADARG);

	fill_str_from_sockaddr(&nfc->local_ulp,
	    local_ip, sizeof(local_ip),
	    local_port, sizeof(local_port), &is_error);
	if (is_error == B_TRUE)
		return (DLADM_STATUS_BADARG);

	if ((local_port != NULL) &&
	    (strtol(local_port, NULL, 10) > 0)) {
	    if (fill_flow_args(
		attrstr, KEYWORD_FLOW_ATTR_TRANSPORT, "udp") !=
		DLADM_STATUS_OK)
		    return (DLADM_STATUS_BADARG);
	}

	if (fill_flow_args(
	    attrstr, KEYWORD_FLOW_ATTR_LOCAL_IP_ADDR, local_ip) !=
	    DLADM_STATUS_OK)
		return (DLADM_STATUS_BADARG);

	if ((local_port != NULL) &&
	    (strtol(local_port, NULL, 10) > 0)) {
		if (fill_flow_args(
		    attrstr, KEYWORD_FLOW_ATTR_LOCAL_PORT, local_port) !=
		    DLADM_STATUS_OK)
			return (DLADM_STATUS_BADARG);
	}

	if (fill_flow_args(propstr, KEYWORD_FLOW_PROP_DSCP,
	    lltostr(nfc->dscp_value, &propstr[DLADM_STRSIZE - 1])) !=
	    DLADM_STATUS_OK)
		return (DLADM_STATUS_BADARG);

	if (fill_flow_name(nfc->linkid, flowname, sizeof(flowname),
	    &nfc->local_ulp, nfc->dscp_value) !=
	    DLADM_STATUS_OK)
		return (DLADM_STATUS_BADARG);

/*	printf("attr: %s\n", attrstr);
	printf("prop: %s\n", propstr);
	printf("flowname: %s\n", flowname);
*/
	status = add_flow_on_link(nfc->linkid, flowname,
	    attrstr, propstr);
	return (status);
}

int
remove_flow_collection(
	flow_collection_t	*nfc)
{
	dladm_status_t	status;
	char		flowname[MAXLINKNAMELEN];

	if (nfc == NULL)
		return (DLADM_STATUS_BADARG);

	if (fill_flow_name(nfc->linkid, flowname, sizeof(flowname),
	    &nfc->local_ulp, nfc->dscp_value) !=
	    DLADM_STATUS_OK)
		return (DLADM_STATUS_BADARG);

	status = remove_flow(flowname);
	return (status);
}

void dladm_flow_attr_ipaddr2str(
	flow_desc_t flow_desc,
	in6_addr_t flow_ipaddr,
	char *ipaddr_buf,
	size_t ipaddr_buf_len)
{
	if (flow_desc.fd_ipversion == IPV6_VERSION) {
		(void) inet_ntop(AF_INET6, &flow_desc.fd_local_addr, ipaddr_buf,
		    INET6_ADDRSTRLEN);
	} else {
		struct in_addr ipaddr;
		ipaddr.s_addr = flow_desc.fd_local_addr._S6_un._S6_u32[3];
		snprintf(ipaddr_buf,
		    ipaddr_buf_len -1 , "%s", inet_ntoa(ipaddr));
	}
}

int
dladm_kstat_find_value(
	kstat_t		*ksp,
	const char	*name,
	uint8_t		type,
	void		*buf)
{
	kstat_named_t	*knp;

	if (ksp == NULL)
		return (-1);

	if ((knp = kstat_data_lookup(ksp, (char *)name)) == NULL)
		return (-1);

	if (knp->data_type != type)
		return (-1);

	switch (type) {
	case KSTAT_DATA_UINT64:
		*(uint64_t *)buf = knp->value.ui64;
		break;
	case KSTAT_DATA_UINT32:
		*(uint32_t *)buf = knp->value.ui32;
		break;
	default:
		return (-1);
	}

	return (0);
}

kstat_t *dladm_flow_kstat_lookup(
	dladm_handle_t		dld_handle,
	dladm_flow_attr_t	*flow_attrs,
	flow_stat_t		*currstats)
{
	kstat_ctl_t	*kcp = kcp_handle;
	kstat_t		*ksp;
	hrtime_t now;

	if (flow_attrs == NULL)
		return (NULL);

	/* lookup kstat entry */
	ksp = kstat_lookup(
	    kcp, NULL, -1, flow_attrs->fa_flowname);

	if (ksp == NULL)
		return (NULL);

	now = gethrtime();
printf("created %lu sec ago\n",
    (long int)
    (now - ksp->ks_crtime) / HRTIME2SEC_MULTIPLIER);

	bzero(currstats, sizeof(flow_stat_t));
	currstats->crtime = ksp->ks_crtime;
	currstats->snaptime = ksp->ks_snaptime;

	return (ksp);
}

int dladm_flow_kstat_read(
	dladm_handle_t		dld_handle,
	dladm_flow_attr_t	*flow_attrs,
	flow_stat_t		*currstats)
{
	kstat_ctl_t	*kcp = kcp_handle;
	kstat_t		*ksp;

	if (flow_attrs == NULL)
		return (DLADM_WALK_CONTINUE);

	/* lookup kstat entry */
	ksp = dladm_flow_kstat_lookup(dld_handle,
	    flow_attrs, currstats);

	if (ksp == NULL)
		return (DLADM_WALK_CONTINUE);

/*printf("crtime: %lu\n", ksp->ks_crtime / HRTIME2SEC_MULTIPLIER);
printf("nowtime: %lu\n", now / HRTIME2SEC_MULTIPLIER);
printf("snaptime: %lu\n", ksp->ks_snaptime / HRTIME2SEC_MULTIPLIER);*/
/*printf("created %d sec ago\n", (now - currstats->crtime) / HRTIME2SEC_MULTIPLIER);*/

	/* read packet and byte stats */
	if (kstat_read(kcp, ksp, NULL) == -1)
		return (DLADM_WALK_CONTINUE);

	if (dladm_kstat_find_value(ksp, "ipackets", KSTAT_DATA_UINT64,
	    &currstats->ipackets) < 0)
		return (DLADM_WALK_CONTINUE);
	if (dladm_kstat_find_value(ksp, "opackets", KSTAT_DATA_UINT64,
	    &currstats->opackets) < 0)
		return (DLADM_WALK_CONTINUE);
	if (dladm_kstat_find_value(ksp, "rbytes", KSTAT_DATA_UINT64,
	    &currstats->rbytes) < 0)
		return (DLADM_WALK_CONTINUE);
	if (dladm_kstat_find_value(ksp, "obytes", KSTAT_DATA_UINT64,
	    &currstats->obytes) < 0)
		return (DLADM_WALK_CONTINUE);
	if (dladm_kstat_find_value(ksp, "idrops", KSTAT_DATA_UINT64,
	    &currstats->idrops) < 0)
		return (DLADM_WALK_CONTINUE);
	if (dladm_kstat_find_value(ksp, "odrops", KSTAT_DATA_UINT64,
    	    &currstats->odrops) < 0)
		return (DLADM_WALK_CONTINUE);
printf("ipackets: %lu\n", (long int)currstats->ipackets);
printf("idrops: %lu\n", (long int)currstats->idrops);

	return (DLADM_WALK_CONTINUE);
}

/* Callback for dladm_flow_load_all_via_kstat (generic_hash_foreach'func_task) */
int
dladm_kstat_walk_flow(
	const char *name,
	int (*fn)(dladm_handle_t, dladm_flow_attr_t *, void *),
	void *arg)
{
	kstat_ctl_t		*kcp = kcp_handle;
	kstat_t			*ksp = NULL;
	dladm_flow_attr_t	flow_attrs;
	dladm_status_t		status = DLADM_STATUS_OK;

	if (fn == NULL)
		return(status);

	for (ksp = kcp->kc_chain; ksp != NULL; ksp = ksp->ks_next) {
		if ((strcmp(ksp->ks_module, "unix") == 0) &&
		    (name == NULL || strcmp(ksp->ks_name, name) == 0) &&
		    (strcmp(ksp->ks_class, "flow") == 0)) {
			/* Flow name is ksp->ks_name. */
			bzero(&flow_attrs, sizeof(dladm_flow_attr_t));
			if (dladm_flow_info(
			    dld_handle,
			    ksp->ks_name,
			    &flow_attrs) != DLADM_STATUS_OK)
				continue;
			if (fn(dld_handle, &flow_attrs, arg) ==
			    DLADM_WALK_TERMINATE) {
				status = DLADM_STATUS_FAILED;
				break;
			}
		}
	}

	return (status);
}

int dladm_flow_load_all_via_kstat()
{
	flow_base_collection_t	*fbc =
	    &flow_base_collection;
	dladm_status_t		status;
	uint64_t		last_entries, new_entries;

	last_entries = generic_hash_length(fbc->flow_name_hash);
	status = dladm_kstat_walk_flow(
	    NULL, dladm_flow_load, NULL);
	new_entries = generic_hash_length(fbc->flow_name_hash);
	if (new_entries - last_entries > 0) {
		gen_info(
		    "dladm_flow_load_all_via_kstat: "
		    "loaded %lld flow(s)",
		    new_entries - last_entries);
	}
	return (status);
}

/* Callback for backend_execute_query'fn (sqlite3_exec'callback) */
int dladm_load_flow_via_backend(
	void	*arg,
	int	columns,
	char	**row_value,
	char	**column_name)
{
	char			*flow_name = NULL;
	int			i;
	flow_expire_param_t	fep;
	dladm_flow_attr_t	flow_attrs;
	dladm_status_t		status = DLADM_STATUS_FAILED;

	bzero(&fep, sizeof(flow_expire_param_t));
	for (i = 0; i < columns; i++) {
		if (column_name[i] == NULL)
			continue;
/*		gen_info("dladm_load_flow_via_backend: %s = %s",
		    column_name[i],
		    row_value[i] ? row_value[i] : "NULL");*/
		if (strcasecmp(
		    column_name[i], "flow_name") == 0) {
			flow_name = row_value[i];
		} else if (strcasecmp(
		    column_name[i], "flow_expire_interval") == 0) {
			errno = 0;
			fep.flow_expire_interval =
			    (uint16_t)strtol(row_value[i], NULL, 10);
			if ((errno != 0) ||
			    (fep.flow_expire_interval < MIN_EXPIRE_INTERVAL) ||
			    (fep.flow_expire_interval > MAX_EXPIRE_INTERVAL))
				goto fail;
		} else if (strcasecmp(
		    column_name[i], "flow_expire_time") == 0) {
			errno = 0;
			fep.orig_expire_time =
			    (uint32_t)strtol(row_value[i], NULL, 10);
			if (errno != 0)
				goto fail;
			fep.orig_expire_time *= HRTIME2SEC_MULTIPLIER;
		}
	}

	bzero(&flow_attrs, sizeof(dladm_flow_attr_t));
	if (dladm_flow_info(
	    dld_handle,
	    flow_name,
	    &flow_attrs) != DLADM_STATUS_OK)
		goto fail;
	if (dladm_flow_load(dld_handle, &flow_attrs, &fep) ==
	    DLADM_WALK_TERMINATE)
		goto fail;
	status = DLADM_STATUS_OK;

fail:
	return (status);
}

/* Callback for dladm_walk_flow'fn, dladm_kstat_walk_flow'fn etc */
int dladm_flow_load(
	dladm_handle_t		dld_handle,
	dladm_flow_attr_t	*flow_attrs,
	void			*arg)
{
/*	char			flow_local_ipaddr[INET6_ADDRSTRLEN + 1];
	char			flow_local_port[ULONG_STRLEN];*/
	struct sockaddr		local_ulp;
	uint16_t		port;
	uint16_t		expire_interval;
	hrtime_t		crtime;
	dladm_status_t		status;
	mac_resource_props_t	*mrp;

	if (flow_attrs == NULL)
		return (DLADM_WALK_CONTINUE);

	crtime = 0;
	expire_interval = MIN_EXPIRE_INTERVAL;
	if (arg != NULL) {
		flow_expire_param_t *fep =
		    (flow_expire_param_t *)arg;
		expire_interval = fep->flow_expire_interval;
		crtime = fep->orig_expire_time;
	}

	if (strncasecmp(
	    flow_attrs->fa_flowname,
	    DEFAULT_FLOW_STR_PREFFIX,
	    strlen(DEFAULT_FLOW_STR_PREFFIX)))
		return (DLADM_WALK_CONTINUE);

	/* We are interested strictly in DSCP flows. */
	mrp = &(flow_attrs->fa_resource_props);
	if (!(mrp->mrp_mask & MRP_DSCP)) {
		return (DLADM_WALK_CONTINUE);
	}

/*	bzero(&flow_local_ipaddr, sizeof (flow_local_ipaddr));
	dladm_flow_attr_ipaddr2str(
	    flow_attrs->fa_flow_desc,
	    flow_attrs->fa_flow_desc.fd_local_addr,
	    &flow_local_ipaddr[0], sizeof(flow_local_ipaddr));

	bzero(&flow_local_port, sizeof(flow_local_port));
	if (strlcat(flow_local_port,
	    lltostr(
	    htons(flow_attrs->fa_flow_desc.fd_local_port),
	    &flow_local_port[sizeof(flow_local_port) - 1]),
	    sizeof(flow_local_port)) >= sizeof(flow_local_port)) {
		return (DLADM_WALK_CONTINUE);
	}*/
	if (flow_attrs->fa_flow_desc.fd_ipversion == IPV6_VERSION) {
	        /* Unimplemented yet */
		return (DLADM_WALK_CONTINUE);
	} else {
		struct in_addr		addr;
		addr.s_addr =
		    flow_attrs->fa_flow_desc.fd_local_addr._S6_un._S6_u32[3];
		port = htons(flow_attrs->fa_flow_desc.fd_local_port);
		/* Fixme: just resetting port to 0 for avoiding 
		 * flow selector conflict on the same link.
		 */
		port = 0;
		fill_sockaddr_from_ipv4_tuple(&addr, port, &local_ulp);
	}

	if (crtime == 0) {
		flow_stat_t	currstats;
		kstat_t		*ksp;
		ksp = dladm_flow_kstat_lookup(
		    dld_handle, flow_attrs, &currstats);
		if (ksp == NULL) {
			printf("ksp is null\n");
			crtime = gethrtime();
		} else {
			crtime = currstats.crtime;
		}
	}

/*	gen_info("Loading flow: %s,  linkid: %d",
	    flow_attrs->fa_flowname, flow_attrs->fa_linkid);*/
/*	printf("flow desc local_ip: %s\n",
	    flow_local_ipaddr);
	printf("flow desc local_port: %s\n",
	    flow_local_port);
*/
	(void) printf("flow dscp %d\n",
	    mrp->mrp_dscp);

	status = store_flow_collection_entity(
	    flow_attrs->fa_linkid,
	    expire_interval,
	    crtime,
	    &local_ulp,
	    mrp->mrp_dscp);
	if (status == DLADM_STATUS_EXIST) {
		printf("Loading flow %s: skipped - already exists\n",
		    flow_attrs->fa_flowname);
	} else if (status != DLADM_STATUS_OK) {
		gen_info("Loading flow %s: failed - %d",
		    flow_attrs->fa_flowname, status);
	}
	return (DLADM_WALK_CONTINUE);
}

datalink_id_t dladm_get_linkid_for_ifname(
	char *ifa_name)
{
	datalink_id_t	linkid = DATALINK_INVALID_LINKID;
	if (dladm_name2info(dld_handle, ifa_name, &linkid, NULL, NULL, NULL) !=
	    DLADM_STATUS_OK)
		return (DATALINK_INVALID_LINKID);
	return (linkid);
}

int dladm_flow_load_all_on_ifname(
	char	*ifa_name)
{
	datalink_id_t	linkid;

	/* dladm walk_flow() always fails on loopback. */
	if (strcmp("lo0", ifa_name) == 0)
		return (DLADM_STATUS_OK);

	linkid = dladm_get_linkid_for_ifname(ifa_name);
	if (linkid ==
	    DATALINK_INVALID_LINKID)
		return (DLADM_STATUS_OK);
	return dladm_flow_load_all_on_link(linkid);
}

int dladm_flow_load_all_on_link(
	datalink_id_t	linkid)
{
	flow_base_collection_t	*fbc =
	    &flow_base_collection;
	dladm_status_t		status;
	uint64_t		last_entries, new_entries;

	last_entries = generic_hash_length(fbc->flow_name_hash);
	status = dladm_walk_flow(
	    dladm_flow_load, dld_handle,
	    linkid, NULL, B_FALSE);
	new_entries = generic_hash_length(fbc->flow_name_hash);
	if (new_entries - last_entries > 0) {
		gen_info(
		    "dladm_flow_load_all_on_link: "
		    "linkid %d, loaded %lld flow(s)",
		    linkid, new_entries - last_entries);
	}
	return (status);
}

/* Callback for dladm_walk_flow'fn etc */
int dladm_flow_print(
	dladm_handle_t		dld_handle,
	dladm_flow_attr_t	*flow_attrs,
	void			*stub)
{
	char			flow_ipaddr[INET6_ADDRSTRLEN + 1];
	char			buf[DLADM_STRSIZE];
	flow_stat_t		currstats;
	mac_resource_props_t	*mrp;

	if (flow_attrs == NULL)
		return (DLADM_WALK_CONTINUE);

	bzero(&flow_ipaddr, sizeof (flow_ipaddr));
	printf("flowname: %s\n", flow_attrs->fa_flowname);
	printf("flow linkid: %d\n", flow_attrs->fa_linkid);
	dladm_flow_attr_ipaddr2str(
	    flow_attrs->fa_flow_desc,
	    flow_attrs->fa_flow_desc.fd_local_addr,
	    &flow_ipaddr[0], sizeof(flow_ipaddr));
	printf("flow desc local_ip: %s\n",
	    flow_ipaddr);
	printf("flow desc local_port: %d\n",
	    htons(flow_attrs->fa_flow_desc.fd_local_port));
	mrp = &(flow_attrs->fa_resource_props);
	if (mrp->mrp_mask & MRP_PRIORITY) {
		(void) printf("flow priority %s\n",
		    dladm_pri2str(mrp->mrp_priority, buf));
	}
	if (mrp->mrp_mask & MRP_DSCP) {
		(void) printf("flow dscp %d\n",
		    mrp->mrp_dscp);
	}
	dladm_flow_kstat_read(dld_handle, flow_attrs, &currstats);
	return (DLADM_WALK_CONTINUE);
}

void dladm_flow_print_all_on_link(
	datalink_id_t	linkid)
{
	dladm_walk_flow(
	    dladm_flow_print, dld_handle,
	    linkid, NULL, B_FALSE);
}

boolean_t
dladm_handle_create(
	char	*arg)
{
	if (dladm_open(&dld_handle, arg) != DLADM_STATUS_OK)
		return B_FALSE;
	if ((kcp_handle = kstat_open()) == NULL) {
		return B_FALSE;
	}

	return B_TRUE;
}

void
dladm_handle_destroy(void)
{
	if (dld_handle != NULL)
		dladm_close(dld_handle);
	if (kcp_handle != NULL)
		(void) kstat_close(kcp_handle);
}
