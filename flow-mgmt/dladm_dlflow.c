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
 * This file contains pieces of code that were taken from Illumos sources (libdladm):
 * http://src.illumos.org/source/xref/illumos-gate/usr/src/lib/libdladm/common/flowattr.c
 * http://src.illumos.org/source/xref/illumos-gate/usr/src/lib/libdladm/common/flowprop.c
 *
 * It is for temporary purposes: just until multiple memory leaks 
 * in libdladm'do_maxbw_check(), do_dscp_check(),
 * i_dladm_flow_proplist_extract_one() will be fixed,
 * we are implementing cust_dladm_flow_add() with fixed leaks
 * which is used instead of libdladm'dladm_flow_add().
 * Those libdladm memory leaks make any attempt to run dladm_flow_add()
 * in long-running process unsuitable for production use.
 */

#include <strings.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/dld.h>
#include <arpa/inet.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include "include/sys/dld_ioc.h"
#include <libdladm.h>
#include "include/libdladm_impl.h"
#include "include/libdlflow.h"
#include "include/libdlflow_impl.h"
#include <libdllink.h>

#include "flow_base.h"

#define	RESET_VAL		((uintptr_t)-1) 

/* MRP_MAXBW_MINVAL for S11.2 */
#define	MRP_MAXBW_MINVAL	(1024)

static fpd_getf_t	do_get_maxbw;
static fpd_setf_t	do_set_maxbw;
static fpd_checkf_t	do_check_maxbw;

static fpd_getf_t	do_get_dscp;
static fpd_setf_t	do_set_dscp;
static fpd_checkf_t	do_check_dscp;

static fpd_getf_t	do_get_priority;
static fpd_setf_t	do_set_priority;
static fpd_checkf_t	do_check_priority;

static fprop_desc_t	prop_table[] = {
	{ "maxbw",	{ "", NULL }, NULL, 0, B_FALSE,
	    do_set_maxbw, NULL,
	    do_get_maxbw, do_check_maxbw},
	{ "dscp",	{ "", NULL }, NULL, 0, B_FALSE,
	    do_set_dscp, NULL,
	    do_get_dscp, do_check_dscp},
	{ "priority",	{ "", MPL_RESET }, NULL, 0, B_FALSE,
	    do_set_priority, NULL,
	    do_get_priority, do_check_priority}
};

#define	DLADM_MAX_FLOWPROPS	(sizeof (prop_table) / sizeof (fprop_desc_t))

static resource_prop_t rsrc_prop_table[] = {
	{"maxbw",	extract_maxbw},
	{"dscp",	extract_dscp},
	{"priority",	extract_priority}
};
#define	DLADM_MAX_RSRC_PROP (sizeof (rsrc_prop_table) / \
	sizeof (resource_prop_t))

static fad_checkf_t do_check_local_ip;
static fad_checkf_t do_check_remote_ip;
static fad_checkf_t do_check_protocol;
static fad_checkf_t do_check_local_port;
static fad_checkf_t do_check_remote_port;

static dladm_status_t do_check_port(char *, boolean_t, flow_desc_t *);

static fattr_desc_t	attr_table[] = {
	{ "local_ip",		do_check_local_ip },
	{ "remote_ip",		do_check_remote_ip },
	{ "transport",		do_check_protocol },
	{ "local_port",		do_check_local_port },
	{ "remote_port",	do_check_remote_port },
	{ "dsfield",		do_check_dsfield },
};

#define	DLADM_MAX_FLOWATTRS	(sizeof (attr_table) / sizeof (fattr_desc_t))

/* ARGSUSED */
dladm_status_t
extract_maxbw(val_desc_t *vdp, uint_t cnt, void *arg)
{
	mac_resource_props_t *mrp = arg;

	if (vdp->vd_val == RESET_VAL) {
		mrp->mrp_maxbw = MRP_MAXBW_RESETVAL;
	} else {
		bcopy((char *)vdp->vd_val, &mrp->mrp_maxbw, sizeof (uint64_t));
		free((void *)vdp->vd_val);
	}
	mrp->mrp_mask |= MRP_MAXBW;

	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
dladm_status_t
extract_dscp(val_desc_t *vdp, uint_t cnt, void *arg)
{
	mac_resource_props_t *mrp = arg;

	if (vdp->vd_val == RESET_VAL) {
		mrp->mrp_maxbw = MRP_DSCP_RESETVAL;
	} else {
		bcopy((char *)vdp->vd_val, &mrp->mrp_dscp, sizeof (uint8_t));
		free((void *)vdp->vd_val);
	}
	mrp->mrp_mask |= MRP_DSCP;

	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
dladm_status_t
extract_priority(val_desc_t *vdp, uint_t cnt, void *arg)
{
	mac_resource_props_t *mrp = arg;

	if (cnt != 1)
		return (DLADM_STATUS_BADVAL);

	mrp->mrp_priority = (mac_priority_level_t)vdp->vd_val;
	mrp->mrp_mask |= MRP_PRIORITY;

	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
do_get_maxbw(dladm_handle_t handle, const char *flow, char **prop_val,
    uint_t *val_cnt)
{
	char 			buf[DLADM_STRSIZE];
	mac_resource_props_t	*mrp;
	dladm_flow_attr_t	fa;
	dladm_status_t		status;

	status = dladm_flow_info(handle, flow, &fa);
	if (status != DLADM_STATUS_OK)
		return (status);
	mrp = &(fa.fa_resource_props);

	*val_cnt = 1;
	if (mrp->mrp_mask & MRP_MAXBW) {
		(void) snprintf(prop_val[0], DLADM_STRSIZE, "%s",
		    dladm_bw2str(mrp->mrp_maxbw, buf));
	} else {
		return (DLADM_STATUS_NOTSUP);
	}
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
do_check_maxbw(fprop_desc_t *pdp, char **prop_val, uint_t val_cnt,
    val_desc_t **vdpp)
{
	uint64_t	*maxbw;
	val_desc_t	*vdp = NULL;
	dladm_status_t	status = DLADM_STATUS_OK;

	if (val_cnt != 1)
		return (DLADM_STATUS_BADVALCNT);

	maxbw = malloc(sizeof (uint64_t));
	if (maxbw == NULL)
		return (DLADM_STATUS_NOMEM);

	status = dladm_str2bw(*prop_val, maxbw);
	if (status != DLADM_STATUS_OK) {
		free(maxbw);
		return (status);
	}

	if ((*maxbw < MRP_MAXBW_MINVAL) && (*maxbw != 0)) {
		free(maxbw);
		return (DLADM_STATUS_MINMAXBW);
	}

	vdp = *vdpp;
	if (vdp == NULL) {
		free(maxbw);
		return (DLADM_STATUS_BADARG);
	}

	vdp->vd_val = (uintptr_t)maxbw;
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
do_set_maxbw(dladm_handle_t handle, const char *flow, val_desc_t *vdp,
    uint_t val_cnt)
{
	dld_ioc_modifyflow_t	attr;
	mac_resource_props_t	mrp;
	void			*val;

	if (val_cnt != 1)
		return (DLADM_STATUS_BADVALCNT);

	bzero(&mrp, sizeof (mrp));
	if (vdp != NULL && (val = (void *)vdp->vd_val) != NULL) {
		bcopy(val, &mrp.mrp_maxbw, sizeof (int64_t));
		free(val);
	} else {
		mrp.mrp_maxbw = MRP_MAXBW_RESETVAL;
	}
	mrp.mrp_mask = MRP_MAXBW;

	bzero(&attr, sizeof (attr));
	(void) strlcpy(attr.mf_name, flow, sizeof (attr.mf_name));
	bcopy(&mrp, &attr.mf_resource_props, sizeof (mac_resource_props_t));

	if (ioctl(dladm_dld_fd(handle), DLDIOC_MODIFYFLOW, &attr) < 0)
		return (dladm_errno2status(errno));

	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
do_get_dscp(dladm_handle_t handle, const char *flow, char **prop_val,
    uint_t *val_cnt)
{
	mac_resource_props_t	*mrp;
	dladm_flow_attr_t	fa;
	dladm_status_t		status;

	status = dladm_flow_info(handle, flow, &fa);
	if (status != DLADM_STATUS_OK)
		return (status);
	mrp = &(fa.fa_resource_props);

	*val_cnt = 1;
	if (mrp->mrp_mask & MRP_DSCP) {
		(void) snprintf(prop_val[0], DLADM_STRSIZE, "%u",
		    mrp->mrp_dscp);
	} else {
		return (DLADM_STATUS_NOTSUP);
	}
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
do_check_dscp(fprop_desc_t *pdp, char **prop_val, uint_t val_cnt,
    val_desc_t **vdpp)
{
	char *endp = NULL;
	uint8_t		*dscp, value;
	val_desc_t	*vdp = NULL;

	if (val_cnt != 1)
		return (DLADM_STATUS_BADVALCNT);

	dscp = malloc(sizeof (uint8_t));
	if (dscp == NULL)
		return (DLADM_STATUS_NOMEM);

	errno = 0;
	value = strtoul(*prop_val, &endp, 10);
	if (errno != 0 || *endp != '\0') {
		free(dscp);
		return (DLADM_STATUS_BADARG);
	}
	*dscp = value;

	if (((*dscp < MRP_DSCP_MINVAL) ||
	    (*dscp > MRP_DSCP_MAXVAL)) &&
	    (*dscp != MRP_DSCP_RESETVAL)) {
		free(dscp);
		return (DLADM_STATUS_BADPROP);
	}

	vdp = *vdpp;
	if (vdp == NULL) {
		free(dscp);
		return (DLADM_STATUS_BADARG);
	}

	vdp->vd_val = (uintptr_t)dscp;
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
do_set_dscp(dladm_handle_t handle, const char *flow, val_desc_t *vdp,
    uint_t val_cnt)
{
	dld_ioc_modifyflow_t	attr;
	mac_resource_props_t	mrp;
	void			*val;

	if (val_cnt != 1)
		return (DLADM_STATUS_BADVALCNT);

	bzero(&mrp, sizeof (mrp));
	if (vdp != NULL && (val = (void *)vdp->vd_val) != NULL) {
		bcopy(val, &mrp.mrp_dscp, sizeof (int8_t));
		free(val);
	} else {
		mrp.mrp_dscp = MRP_DSCP_RESETVAL;
	}
	mrp.mrp_mask = MRP_DSCP;

	bzero(&attr, sizeof (attr));
	(void) strlcpy(attr.mf_name, flow, sizeof (attr.mf_name));
	bcopy(&mrp, &attr.mf_resource_props, sizeof (mac_resource_props_t));

	if (ioctl(dladm_dld_fd(handle), DLDIOC_MODIFYFLOW, &attr) < 0)
		return (dladm_errno2status(errno));

	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
do_get_priority(dladm_handle_t handle, const char *flow, char **prop_val,
    uint_t *val_cnt)
{
	mac_resource_props_t	*mrp;
	char 			buf[DLADM_STRSIZE];
	dladm_flow_attr_t	fa;
	dladm_status_t		status;

	bzero(&fa, sizeof (dladm_flow_attr_t));
	status = dladm_flow_info(handle, flow, &fa);
	if (status != DLADM_STATUS_OK)
		return (status);
	mrp = &(fa.fa_resource_props);

	*val_cnt = 1;
	if (mrp->mrp_mask & MRP_PRIORITY) {
		(void) snprintf(prop_val[0], DLADM_STRSIZE, "%s",
		    dladm_pri2str(mrp->mrp_priority, buf));
	} else {
		return (DLADM_STATUS_NOTSUP);
	}
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
do_set_priority(dladm_handle_t handle, const char *flow, val_desc_t *vdp,
    uint_t val_cnt)
{
	dld_ioc_modifyflow_t	attr;
	mac_resource_props_t	mrp;

	if (val_cnt != 1)
		return (DLADM_STATUS_BADVALCNT);

	bzero(&mrp, sizeof (mrp));
	if (vdp != NULL) {
		bcopy(&vdp->vd_val, &mrp.mrp_priority,
		    sizeof (mac_priority_level_t));
	} else {
		mrp.mrp_priority = MPL_RESET;
	}
	mrp.mrp_mask = MRP_PRIORITY;

	bzero(&attr, sizeof (attr));
	(void) strlcpy(attr.mf_name, flow, sizeof (attr.mf_name));
	bcopy(&mrp, &attr.mf_resource_props, sizeof (mac_resource_props_t));

	if (ioctl(dladm_dld_fd(handle), DLDIOC_MODIFYFLOW, &attr) < 0)
		return (dladm_errno2status(errno));

	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
do_check_priority(fprop_desc_t *pdp, char **prop_val, uint_t val_cnt,
    val_desc_t **vdpp)
{
	mac_priority_level_t	pri;
	val_desc_t	*vdp = NULL;
	dladm_status_t	status = DLADM_STATUS_OK;

	if (val_cnt != 1)
		return (DLADM_STATUS_BADVALCNT);

	status = dladm_str2pri(*prop_val, &pri);
	if (status != DLADM_STATUS_OK)
		return (status);

	if (pri == -1)
		return (DLADM_STATUS_BADVAL);

	vdp = *vdpp;
	if (vdp == NULL)
		return (DLADM_STATUS_NOMEM);

	vdp->vd_val = (uint_t)pri;
	return (DLADM_STATUS_OK);
}

/*
 * Retrieve the named property from a proplist, check the value and
 * convert to a kernel structure.
 */
static dladm_status_t
i_dladm_flow_proplist_extract_one(dladm_arg_list_t *proplist,
    const char *name, void *arg)
{
	dladm_status_t		status;
	dladm_arg_info_t	*aip = NULL;
	int			i, j;

	/* Find named property in proplist */
	for (i = 0; i < proplist->al_count; i++) {
		aip = &proplist->al_info[i];
		if (strcasecmp(aip->ai_name, name) == 0)
			break;
	}

	/* Property not in list */
	if (i == proplist->al_count)
		return (DLADM_STATUS_OK);

	for (i = 0; i < DLADM_MAX_FLOWPROPS; i++) {
		fprop_desc_t	*pdp = &prop_table[i];
		val_desc_t	*vdp;

		vdp = malloc(sizeof (val_desc_t) * aip->ai_count);
		if (vdp == NULL)
			return (DLADM_STATUS_NOMEM);

		if (strcasecmp(aip->ai_name, pdp->pd_name) != 0) {
			free(vdp);
			continue;
		}

		if (aip->ai_val == NULL) {
			free(vdp);
			return (DLADM_STATUS_BADARG);
		}

		/* Check property value */
		if (pdp->pd_check != NULL) {
			status = pdp->pd_check(pdp, aip->ai_val,
			    aip->ai_count, &vdp);
		} else {
			status = DLADM_STATUS_BADARG;
		}

		if (status != DLADM_STATUS_OK) {
			free(vdp);
			return (status);
		}

		for (j = 0; j < DLADM_MAX_RSRC_PROP; j++) {
			resource_prop_t	*rpp = &rsrc_prop_table[j];

			if (strcasecmp(aip->ai_name, rpp->rp_name) != 0)
				continue;

			/* Extract kernel structure */
			if (rpp->rp_extract != NULL) {
				status = rpp->rp_extract(vdp,
				    aip->ai_count, arg);
			} else {
				status = DLADM_STATUS_BADARG;
			}
			break;
		}
		free(vdp);

		if (status != DLADM_STATUS_OK)
			return (status);

		break;
	}
	return (status);
}

/*
 * Extract properties from a proplist and convert to mac_resource_props_t.
 */
dladm_status_t
cust_dladm_flow_proplist_extract(dladm_arg_list_t *proplist,
    mac_resource_props_t *mrp)
{
	dladm_status_t	status = DLADM_STATUS_OK;

	status = i_dladm_flow_proplist_extract_one(proplist, "maxbw", mrp);
	if (status != DLADM_STATUS_OK)
		return (status);
	status = i_dladm_flow_proplist_extract_one(proplist, "dscp", mrp);
	if (status != DLADM_STATUS_OK)
		return (status);
	status = i_dladm_flow_proplist_extract_one(proplist, "priority", mrp);
	if (status != DLADM_STATUS_OK)
		return (status);
	return (status);
}

static dladm_status_t
do_check_local_ip(char *attr_val, flow_desc_t *fdesc)
{
	return (do_check_ip_addr(attr_val, B_TRUE, fdesc));
}

static dladm_status_t
do_check_remote_ip(char *attr_val, flow_desc_t *fdesc)
{
	return (do_check_ip_addr(attr_val, B_FALSE, fdesc));
}

dladm_status_t
do_check_ip_addr(char *addr_str, boolean_t local, flow_desc_t *fd)
{
	dladm_status_t	status;
	int		prefix_max, prefix_len = 0;
	char		*prefix_str, *endp = NULL;
	flow_mask_t	mask;
	in6_addr_t	*addr;
	uchar_t		*netmask;
	struct in_addr	v4addr;
	struct in6_addr	v6addr;
	int		family;

	if ((prefix_str = strchr(addr_str, '/')) != NULL) {
		*prefix_str++ = '\0';
		errno = 0;
		prefix_len = (int)strtol(prefix_str, &endp, 10);
		if (errno != 0 || prefix_len == 0 || *endp != '\0')
			return (DLADM_STATUS_INVALID_PREFIXLEN);
	}
	if (inet_pton(AF_INET, addr_str, &v4addr.s_addr) == 1) {
		family = AF_INET;
	} else if (inet_pton(AF_INET6, addr_str, v6addr.s6_addr) == 1) {
		family = AF_INET6;
	} else {
		return (DLADM_STATUS_INVALID_IP);
	}

	mask = FLOW_IP_VERSION;
	if (local) {
		mask |= FLOW_IP_LOCAL;
		addr = &fd->fd_local_addr;
		netmask = (uchar_t *)&fd->fd_local_netmask;
	} else {
		mask |= FLOW_IP_REMOTE;
		addr = &fd->fd_remote_addr;
		netmask = (uchar_t *)&fd->fd_remote_netmask;
	}

	if (family == AF_INET) {
		IN6_INADDR_TO_V4MAPPED(&v4addr, addr);
		prefix_max = IP_ABITS;
		fd->fd_ipversion = IPV4_VERSION;
		netmask = (uchar_t *)
		    &(V4_PART_OF_V6((*((in6_addr_t *)(void *)netmask))));
	} else {
		*addr = v6addr;
		prefix_max = IPV6_ABITS;
		fd->fd_ipversion = IPV6_VERSION;
	}

	if (prefix_len == 0)
		prefix_len = prefix_max;

	status = dladm_prefixlen2mask(prefix_len, prefix_max, netmask);

	if (status != DLADM_STATUS_OK) {
		return (DLADM_STATUS_INVALID_PREFIXLEN);
	}

	fd->fd_mask |= mask;
	return (DLADM_STATUS_OK);
}

dladm_status_t
do_check_protocol(char *attr_val, flow_desc_t *fdesc)
{
	uint8_t	protocol;

	protocol = dladm_str2proto(attr_val);

	if (protocol != 0) {
		fdesc->fd_mask |= FLOW_IP_PROTOCOL;
		fdesc->fd_protocol = protocol;
		return (DLADM_STATUS_OK);
	} else {
		return (DLADM_STATUS_INVALID_PROTOCOL);
	}
}

dladm_status_t
do_check_local_port(char *attr_val, flow_desc_t *fdesc)
{
	return (do_check_port(attr_val, B_TRUE, fdesc));
}

dladm_status_t
do_check_remote_port(char *attr_val, flow_desc_t *fdesc)
{
	return (do_check_port(attr_val, B_FALSE, fdesc));
}

dladm_status_t
do_check_port(char *attr_val, boolean_t local, flow_desc_t *fdesc)
{
	char	*endp = NULL;
	long	val;

	val = strtol(attr_val, &endp, 10);
	if (val < 1 || val > MAX_PORT || *endp != '\0')
		return (DLADM_STATUS_INVALID_PORT);
	if (local) {
		fdesc->fd_mask |= FLOW_ULP_PORT_LOCAL;
		fdesc->fd_local_port = htons((uint16_t)val);
	} else {
		fdesc->fd_mask |= FLOW_ULP_PORT_REMOTE;
		fdesc->fd_remote_port = htons((uint16_t)val);
	}

	return (DLADM_STATUS_OK);
}

dladm_status_t
do_check_dsfield(char *str, flow_desc_t *fd)
{
	char		*mask_str, *endp = NULL;
	uint_t		mask = 0xff, value;

	if ((mask_str = strchr(str, ':')) != NULL) {
		*mask_str++ = '\0';
		errno = 0;
		mask = strtoul(mask_str, &endp, 16);
		if (errno != 0 || mask == 0 || mask > 0xff ||
		    *endp != '\0')
			return (DLADM_STATUS_INVALID_DSFMASK);
	}
	errno = 0;
	endp = NULL;
	value = strtoul(str, &endp, 16);
	if (errno != 0 || value == 0 || value > 0xff || *endp != '\0')
		return (DLADM_STATUS_INVALID_DSF);

	fd->fd_dsfield = (uint8_t)value;
	fd->fd_dsfield_mask = (uint8_t)mask;
	fd->fd_mask |= FLOW_IP_DSFIELD;
	return (DLADM_STATUS_OK);
}

/*
 * Convert an attribute list to a flow_desc_t using the attribute ad_check()
 * functions.
 */
dladm_status_t
dladm_flow_attrlist_extract(dladm_arg_list_t *attrlist, flow_desc_t *flowdesc)
{
	dladm_status_t	status = DLADM_STATUS_BADARG;
	int		i;

	for (i = 0; i < attrlist->al_count; i++) {
		dladm_arg_info_t	*aip = &attrlist->al_info[i];
		int			j;

		for (j = 0; j < DLADM_MAX_FLOWATTRS; j++) {
			fattr_desc_t	*adp = &attr_table[j];

			if (strcasecmp(aip->ai_name, adp->ad_name) != 0)
				continue;

			if ((aip->ai_val == NULL) || (*aip->ai_val == NULL))
				return (DLADM_STATUS_BADARG);

			if (adp->ad_check != NULL)
				status = adp->ad_check(*aip->ai_val, flowdesc);
			else
				status = DLADM_STATUS_BADARG;

			if (status != DLADM_STATUS_OK)
				return (status);
		}
	}

	/*
	 * Make sure protocol is specified if either local or
	 * remote port is specified.
	 */
	if ((flowdesc->fd_mask &
	    (FLOW_ULP_PORT_LOCAL | FLOW_ULP_PORT_REMOTE)) != 0 &&
	    (flowdesc->fd_mask & FLOW_IP_PROTOCOL) == 0)
		return (DLADM_STATUS_PORT_NOPROTO);

	return (status);
}

static dladm_status_t
i_dladm_flow_add(dladm_handle_t handle, char *flowname, datalink_id_t linkid,
    flow_desc_t *flowdesc, mac_resource_props_t *mrp)
{
	dld_ioc_addflow_t	attr;

	/* create flow */
	bzero(&attr, sizeof (attr));
	bcopy(flowdesc, &attr.af_flow_desc, sizeof (flow_desc_t));
	if (mrp != NULL) {
		bcopy(mrp, &attr.af_resource_props,
		    sizeof (mac_resource_props_t));
	}

	(void) strlcpy(attr.af_name, flowname, sizeof (attr.af_name));
	attr.af_linkid = linkid;

	if (ioctl(dladm_dld_fd(handle), DLDIOC_ADDFLOW, &attr) < 0)
		return (dladm_errno2status(errno));

	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
dladm_status_t
cust_dladm_flow_add(dladm_handle_t handle, datalink_id_t linkid,
    dladm_arg_list_t *attrlist, dladm_arg_list_t *proplist, char *flowname,
    boolean_t tempop, const char *root)
{
#if 0
	dld_flowinfo_t		db_attr;
#endif
	flow_desc_t		flowdesc;
	mac_resource_props_t	mrp;
	dladm_status_t		status;

	/* Extract flow attributes from attrlist */
	bzero(&flowdesc, sizeof (flow_desc_t));
	if (attrlist != NULL && (status = dladm_flow_attrlist_extract(attrlist,
	    &flowdesc)) != DLADM_STATUS_OK) {
		return (status);
	}

	/* Extract resource_ctl and cpu_list from proplist */
	bzero(&mrp, sizeof (mac_resource_props_t));
	if (proplist != NULL && (status = cust_dladm_flow_proplist_extract(proplist,
	    &mrp)) != DLADM_STATUS_OK) {
		return (status);
	}

	/* Add flow in kernel */
	status = i_dladm_flow_add(handle, flowname, linkid, &flowdesc, &mrp);
	if (status != DLADM_STATUS_OK)
		return (status);

#if 0
	/* Add flow to DB */
	if (!tempop) {
		bzero(&db_attr, sizeof (db_attr));
		bcopy(&flowdesc, &db_attr.fi_flow_desc, sizeof (flow_desc_t));
		(void) strlcpy(db_attr.fi_flowname, flowname,
		    sizeof (db_attr.fi_flowname));
		db_attr.fi_linkid = linkid;

		if ((status = i_dladm_flow_create_db(&db_attr, root)) !=
		    DLADM_STATUS_OK) {
			(void) i_dladm_flow_remove(handle, flowname);
			return (status);
		}
		/* set flow properties */
		if (proplist != NULL) {
			status = i_dladm_set_flow_proplist_db(handle, flowname,
			    proplist);
			if (status != DLADM_STATUS_OK) {
				(void) i_dladm_flow_remove(handle, flowname);
				return (status);
			}
		}
	}
#endif
	return (status);
}
