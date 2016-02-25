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
 * This file contains various IPv4 address routines and
 * implementation of ifa_collection.
 */

#include <time.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>

#include "dladm_interface.h"

#include "ifaddr_interface.h"

/* Prototypes */

/* Basic functionality */

void fill_sockaddr_from_ipv4_tuple(
	struct in_addr *sa,
	uint16_t port,
	struct sockaddr *da)
{
	uint16_t sport;

	bzero(da, sizeof(struct sockaddr));
	da->sa_family = AF_INET;

	/* Both sockaddr and in_addr have the same byte order. */
	sport = htons(port);
	memcpy(&da->sa_data[0], &sport, sizeof(uint16_t));
	memcpy(&da->sa_data[2], &sa->s_addr, sizeof(uint32_t));
}

void fill_str_from_sockaddr(
	struct sockaddr *sa,
	char *addrstr,
	int addrstrlen,
	char *portstr,
	int portstrlen,
	boolean_t *is_error)
{
	uint16_t ulp_port;
	struct sockaddr_in *addr_in =
	    (struct sockaddr_in *)sa;
	struct sockaddr_in6 *addr_in6 =
	    (struct sockaddr_in6 *)sa;

	if (sa == NULL)
		goto fail;

	bzero(addrstr, addrstrlen);
	if (sa->sa_family == AF_INET) {
		if (inet_ntop(sa->sa_family, 
		    (void *)&(addr_in->sin_addr), 
		    addrstr, addrstrlen) == NULL) {
			goto fail;
		}
		ulp_port = ntohs(addr_in->sin_port);
	} else if (sa->sa_family == AF_INET6) {
		if (inet_ntop(sa->sa_family, 
		    (void *)&(addr_in6->sin6_addr), 
		    addrstr, addrstrlen) == NULL) {
			goto fail;
		}
		ulp_port = ntohs(addr_in6->sin6_port);
	} else {
		goto fail;
	}

	bzero(portstr, portstrlen);
	if (strlcat(portstr, lltostr(ulp_port, 
		&portstr[portstrlen - 1]), 
		portstrlen) >= portstrlen)
		goto fail;

	if (is_error == NULL)
		*is_error = B_FALSE;
	return;
fail:
	if (is_error == NULL)
		*is_error = B_TRUE;
}

uint8_t ipv4_maskbits(
	struct in_addr ipnetmsk)
{
	uint8_t bn;
	uint8_t msklen;
	unsigned char netmsk[4];

	/* Copy IPv4 address into an array. */
	memcpy(&netmsk, &ipnetmsk.s_addr, 4);

	msklen = 0;
	for (bn = 0; bn < 4; ++bn) {
		unsigned char ch = netmsk[bn];
		switch (ch) {
		    case 255:
			msklen += 8; break;
		    case 254:
			msklen += 7; break;
		    case 252:
			msklen += 6; break;
		    case 248:
			msklen += 5; break;
		    case 240:
			msklen += 4; break;
		    case 224:
			msklen += 3; break;
		    case 192:
			msklen += 2; break;
		    case 128:
			msklen += 1; break;
		    default:
			break;
		}
	}
	return (msklen);
}

void ipv4_get_network_addr(
	struct in_addr *ipaddr,
	struct in_addr *netmaskaddr,
	struct in_addr *netaddr)
{
	uint8_t bn;
	unsigned char ip[4];
	unsigned char netmsk[4];
	unsigned char net[4];

	/* Copy IPv4 address into an array */
	memcpy(&ip, &ipaddr->s_addr, 4);
	memcpy(&netmsk, &netmaskaddr->s_addr, 4);

	for (bn = 0; bn < 4; ++bn) {
		net[bn] = ip[bn] & netmsk[bn];
	}

	memcpy(&netaddr->s_addr, &net, 4);

	return;
}

boolean_t ipv4_addr_same_network(
	struct in_addr *ipaddr,
	struct in_addr *netaddr,
	struct in_addr *netmaskaddr)
{
	uint8_t mask_len = ipv4_maskbits(*netmaskaddr);

	uint32_t ip_bits = ipaddr->s_addr;
	uint32_t net_bits = netaddr->s_addr;
	uint32_t netmask_bits = net_bits & ((1 << mask_len) - 1);

	if ((ip_bits & netmask_bits) == net_bits)
		return B_TRUE;
	return (B_FALSE);
}

boolean_t ipv4_str_same_network(
	const char	*addr,
	const char	*net,
	const char	*netmask)
{
	struct in_addr ipaddr;
	struct in_addr netaddr;
	struct in_addr netmaskaddr;

	if (!inet_aton(addr, &ipaddr)) return (B_FALSE);
	if (!inet_aton(net, &netaddr)) return (B_FALSE);
	if (!inet_aton(netmask, &netmaskaddr)) return (B_FALSE);

	return (ipv4_addr_same_network(
	    &ipaddr, &netaddr, &netmaskaddr));
}

/* Callback for generic_hash_hdl_t'cmp */
int cmp_ifac(
	void *arg0,
	void *arg1)
{
	ifa_if_link_t *iil0 =
	    (ifa_if_link_t *)arg0;
	ifa_if_link_t *iil1 =
	    (ifa_if_link_t *)arg1;
	if (iil0 == NULL ||
	    iil1 == NULL)
		return (1);
	if (strcmp(iil0->ifname, iil1->ifname))
		return (1);
	return (0);
}

/* Callback for generic_hash_hdl_t'hash */
uint64_t hash_ifac(
	void *arg)
{
	ifa_if_link_t *iil =
	    (ifa_if_link_t *)arg;
	char keystring[MAXLINKNAMELEN];

	if (iil == NULL || iil->ifname == NULL)
		return (0);
	bzero(&keystring, sizeof(keystring));
	if (strlcat(keystring, iil->ifname, sizeof(keystring)) >=
	    sizeof(keystring))
		return (0);
	return (hash_buf(keystring, iil->ifnamelen));
}

boolean_t sockaddr_equal(
	struct sockaddr *sa1,
	struct sockaddr *sa2)
{
	if ((sa1 == NULL) ||
	    (sa2 == NULL))
		return B_FALSE;
	if (sa1->sa_family != sa2->sa_family)
		return B_FALSE;
	if (sa1->sa_family == AF_INET) {
		struct sockaddr_in *a1 = (typeof(a1))sa1,
		    *a2 = (typeof (a2))sa2;
		return (a1->sin_addr.s_addr == a2->sin_addr.s_addr)
		    ? B_TRUE : B_FALSE;
	} else if (sa1->sa_family == AF_INET6) {
		struct sockaddr_in6 *a1 = (typeof(a1))sa1,
		    *a2 = (typeof (a2))sa2;
		return (memcmp(a1, a2, sizeof(*a1)) == 0)
		    ? B_TRUE : B_FALSE;
	}
	return B_FALSE;
}

/* Callback for generic_hash_hdl_t'cmp */
int cmp_ipac(
	void *arg0,
	void *arg1)
{
	ifa_if_link_t *iil0 =
	    (ifa_if_link_t *)arg0;
	ifa_if_link_t *iil1 =
	    (ifa_if_link_t *)arg1;
	if (iil0 == NULL ||
	    iil1 == NULL)
		return (1);
	if (sockaddr_equal(
	    &iil0->target_addr,
	    &iil1->target_addr) == B_FALSE)
		return (1);
	return (0);
}

/* Callback for generic_hash_hdl_t'hash */
uint64_t hash_ipac(
	void *arg)
{
	ifa_if_link_t *iil =
	    (ifa_if_link_t *)arg;
	char keystring[INET6_ADDRSTRLEN + 1];
	struct sockaddr_in *addr_in;

	if (iil == NULL)
		return (0);

	addr_in =
	    (struct sockaddr_in *)(&(iil->target_addr));
	bzero(&keystring, sizeof(keystring));
	if (strlcat(
	    keystring, inet_ntoa(addr_in->sin_addr), sizeof(keystring)) >=
	    sizeof(keystring))
		return (0);
	return (hash_buf(keystring, sizeof(keystring)));
}

void free_ifa_if_link(
	ifa_if_link_t *iil)
{
	if (iil == NULL)
		return;
	if (iil->ifname)
		free(iil->ifname);
	free(iil);
}

/* Callback for ifs_walk'fn */
int ifs_get_ifindex_by_ifname(
	struct if_nameindex *i,
	void *arg0)
{
	ifs_if_search_t *s =
	    (ifs_if_search_t *)arg0;

	if (strcmp(i->if_name, s->iflink.ifname) == 0) {
		s->iflink.ifindex = i->if_index;
		s->done = B_TRUE;
		return IFS_WALK_TERMINATE;
	}
	return (IFS_WALK_CONTINUE);
}

void ifs_walk(
	void *arg0,
	int (*fn)(struct if_nameindex *, void *))
{
	struct if_nameindex *if_ni, *i;

	if (fn == NULL)
		goto fail;

	if_ni = if_nameindex();
	if (if_ni == NULL)
		goto fail;

	for (i = if_ni; !((i->if_index == 0) && (i->if_name == NULL)); i++) {
		if (fn(i, arg0) == IFS_WALK_TERMINATE)
			break;
	}
        if_freenameindex(if_ni);
fail:
	return;
}

/* Callback for ifa_collection_walk (generic_hash_foreach'func_task) */
void ifa_collection_free(
	void *arg0,
	void **arg1,
	void *arg2)
{
	ifa_if_link_t *iilc, *iiln;
	ifa_if_link_t *iil0 =
	    (ifa_if_link_t *)arg0;
	ifa_collection_t *imc =
	    (ifa_collection_t *)arg2;

	if (iil0 == NULL)
		return;
	if (imc == NULL ||
	    imc->ifa_if_hash == NULL)
		return;

	if (generic_hash_delete(
	    imc->ifa_if_hash, iil0) == NULL)
		return;
	for (iilc = iil0; iilc != NULL; iilc = iiln) {
		iiln = iilc->next_sibling;
		free_ifa_if_link(iilc);
	}
}

void ifa_collection_ini(
	ifa_collection_t *imc)
{
	bzero(imc, sizeof(ifa_collection_t));
	pthread_mutex_init(&imc->lock, NULL);
	pthread_mutex_init(&imc->timed_lock, NULL);

}

void ifa_collection_fini(
	ifa_collection_t *imc)
{
	pthread_mutex_lock(&imc->lock);
	if (imc->ifa_if_hash != NULL) {
		generic_hash_foreach(
		    imc->ifa_if_hash, ifa_collection_free, imc);
		generic_hash_free(&imc->ifa_if_hash);
	}
	pthread_mutex_unlock(&imc->lock);
	pthread_mutex_destroy(&imc->lock);
	pthread_mutex_destroy(&imc->timed_lock);
}

void next_wait_period(
	int millis,
	struct timespec *ts)
{
	poll(NULL,0,millis);
#if 0
	bzero(ts, sizeof(struct timespec));
	if (clock_gettime(CLOCK_REALTIME, ts) == -1)
		return;
	ts->tv_sec += millis / 1000;
#endif
#if 0
	struct timeval tv;
    
        gettimeofday(&tv, NULL);
        ts->tv_sec = tv.tv_sec + millis / 1000;
        ts->tv_nsec = tv.tv_usec * 1000 + 1000 * 1000 * (millis % 1000);
        ts->tv_sec += ts->tv_nsec / (1000 * 1000 * 1000);
        ts->tv_nsec %= (1000 * 1000 * 1000);
#endif
}

/* Callback for ifa_collection_walk (generic_hash_foreach'func_task) */
void ifa_collection_load_flows(
	void *arg0,
	void **arg1,
	void *arg2)
{
	ifa_if_link_t *iil0 =
	    (ifa_if_link_t *)arg0;
	ifa_collection_t *imc =
	    (ifa_collection_t *)arg2;
	dladm_status_t status;

	if (iil0 == NULL ||
	    imc == NULL)
		return;

	status = dladm_flow_load_all_on_ifname(iil0->ifname);
	if (status != DLADM_STATUS_OK) {
		imc->error = B_TRUE;
		gen_info("ifa_collection_load_flows: error on %s", iil0->ifname);
	}
}

/* Callback for ifa_collection_walk (generic_hash_foreach'func_task) */
void ifa_collection_print(
	void *arg0,
	void **arg1,
	void *arg2)
{
	ifa_if_link_t *iil0 =
	    (ifa_if_link_t *)arg0;
	struct sockaddr_in *addr;

	if (iil0 == NULL)
		return;

	printf("member ifname: %s\n", iil0->ifname);
	printf("member ifindex: %d\n", iil0->ifindex);
	addr = (struct sockaddr_in *)&(iil0->addr);
	printf("member IP address: %s\n", inet_ntoa(addr->sin_addr));
}

void ifa_collection_walk(
	ifa_collection_t *imc,
	void *arg0,
	void (*fn)(void *, void **, void *))
{
	if (fn == NULL ||
	    imc == NULL ||
	    imc->ifa_if_hash == NULL)
		return;

	pthread_mutex_lock(&imc->lock);
	generic_hash_foreach(
	    imc->ifa_if_hash, fn, arg0);
	pthread_mutex_unlock(&imc->lock);

	return;
}

/* Callback for ifa_walk (generic_hash_foreach'func_task) */
int ifa_complete_ifip_hash_by_netaddr(
	struct sockaddr *sa_target,
	struct ifaddrs *ifap,
	void *arg0)
{
	struct sockaddr_in *addr_orig =
	    (struct sockaddr_in *)sa_target;
	struct sockaddr_in *addr_in =
	    (struct sockaddr_in *)ifap->ifa_addr;
	struct sockaddr_in *maskaddr_in =
	    (struct sockaddr_in *)ifap->ifa_netmask;
	struct in_addr addr;
	ifa_collection_t *iac =
	    (ifa_collection_t *)arg0;
	ifs_if_search_t iis;
	ifa_if_link_t  *iil, *iin/*, *iim*/;

	if ((iac == NULL) ||
	    (sa_target == NULL))
		return (IFA_WALK_TERMINATE);

	if (ipv4_addr_same_network(
	    &(addr_in->sin_addr),
		    &(addr_orig->sin_addr),
		    &(maskaddr_in->sin_addr)) == B_FALSE)
		return (IFA_WALK_CONTINUE);

	bzero(&iis, sizeof(ifs_if_search_t));
	iis.iflink.ifname = ifap->ifa_name;
	iis.iflink.ifnamelen =
	    strlen(ifap->ifa_name);
	iis.done = B_FALSE;

	ifs_walk(&iis, ifs_get_ifindex_by_ifname);
	if (iis.done == B_FALSE)
		return (IFA_WALK_CONTINUE);

	pthread_mutex_lock(&iac->lock);
	if (iac->ifa_if_hash == NULL) {
		iac->ifa_if_hash = generic_hash_new(
		    GENERIC1_HASH_SIZE,
		    cmp_ipac, hash_ipac);
		if (iac->ifa_if_hash == NULL) {
			goto error;
		}
	}
	iin = calloc(
	    1, sizeof(ifa_if_link_t));
	if (iin == NULL)
		goto error;
	/* Fill values for storage */
	iin->ifname = strdup(ifap->ifa_name);
	if (iin->ifname == NULL) {
nomemory:
		free_ifa_if_link(iin);
error:
		iac->error = B_TRUE;
		pthread_mutex_unlock(&iac->lock);
		return (IFA_WALK_TERMINATE);
	}
	iin->ifnamelen =
	    strlen(ifap->ifa_name);
	iin->ifindex = iis.iflink.ifindex;
	iin->linkid = dladm_get_linkid_for_ifname(ifap->ifa_name);
	if (iin->linkid == DATALINK_INVALID_LINKID)
		goto nomemory;

	bzero(&addr, sizeof(struct in_addr));
	ipv4_get_network_addr(&(addr_in->sin_addr),
	    &(maskaddr_in->sin_addr), &addr);
	fill_sockaddr_from_ipv4_tuple(
	    &addr, 0, &(iis.iflink.target_addr));

	fill_sockaddr_from_ipv4_tuple(
	    &addr, 0, &(iin->target_addr));
	fill_sockaddr_from_ipv4_tuple(
	    &(addr_in->sin_addr), 0, &(iin->addr));

	iil = generic_hash_find(
	    iac->ifa_if_hash,
	    &(iis.iflink));
	if (iil == NULL) {
		if (generic_hash_add(
		    iac->ifa_if_hash,
		    iin, iin) == NULL) {
			goto nomemory;
		}
		iin->tail_sibling = iin;
	} else {
		iil->tail_sibling->next_sibling = iin;
		iil->tail_sibling = iin;
	}

	pthread_mutex_unlock(&iac->lock);

	return (IFA_WALK_CONTINUE);
}

/* Callback for ifa_walk (generic_hash_foreach'func_task) */
int ifa_complete_ifip_hash_by_addr(
	struct sockaddr *sa_target,
	struct ifaddrs *ifap,
	void *arg0)
{
	struct sockaddr_in *addr_orig =
	    (struct sockaddr_in *)sa_target;
	ifa_collection_t *iac =
	    (ifa_collection_t *)arg0;
	ifs_if_search_t iis;
	ifa_if_link_t  *iil, *iin/*, *iim*/;

	if ((iac == NULL) ||
	    (sa_target == NULL))
		return (IFA_WALK_TERMINATE);

	if (sockaddr_equal(sa_target, ifap->ifa_addr) == B_FALSE)
		return (IFA_WALK_CONTINUE);

	bzero(&iis, sizeof(ifs_if_search_t));
	iis.iflink.ifname = ifap->ifa_name;
	iis.iflink.ifnamelen =
	    strlen(ifap->ifa_name);
	iis.done = B_FALSE;

	ifs_walk(&iis, ifs_get_ifindex_by_ifname);
	if (iis.done == B_FALSE)
		return (IFA_WALK_CONTINUE);

	fill_sockaddr_from_ipv4_tuple(
	    &(addr_orig->sin_addr), 0, &(iis.iflink.target_addr));

	pthread_mutex_lock(&iac->lock);
	if (iac->ifa_if_hash == NULL) {
		iac->ifa_if_hash = generic_hash_new(
		    GENERIC1_HASH_SIZE,
		    cmp_ipac, hash_ipac);
		if (iac->ifa_if_hash == NULL) {
			goto error;
		}
	}
	iin = calloc(
	    1, sizeof(ifa_if_link_t));
	if (iin == NULL)
		goto error;
	/* Fill values for storage */
	iin->ifname = strdup(ifap->ifa_name);
	if (iin->ifname == NULL) {
nomemory:
		free_ifa_if_link(iin);
error:
		iac->error = B_TRUE;
		pthread_mutex_unlock(&iac->lock);
		return (IFA_WALK_TERMINATE);
	}
	iin->ifnamelen =
	    strlen(ifap->ifa_name);
	iin->ifindex = iis.iflink.ifindex;
	iin->linkid = dladm_get_linkid_for_ifname(ifap->ifa_name);
	if (iin->linkid == DATALINK_INVALID_LINKID)
		goto nomemory;
	fill_sockaddr_from_ipv4_tuple(
	    &(addr_orig->sin_addr), 0, &(iin->target_addr));
	iil = generic_hash_find(
	    iac->ifa_if_hash,
	    &(iis.iflink));
	if (iil == NULL) {
		if (generic_hash_add(
		    iac->ifa_if_hash,
		    iin, iin) == NULL) {
			goto nomemory;
		}
		iin->tail_sibling = iin;
	} else {
		iil->tail_sibling->next_sibling = iin;
		iil->tail_sibling = iin;
	}

	pthread_mutex_unlock(&iac->lock);

	return (IFA_WALK_CONTINUE);
}

/* Callback for ifa_walk (generic_hash_foreach'func_task) */
int ifa_complete_ifname_hash_all(
	struct sockaddr *sa_target,
	struct ifaddrs *ifap,
	void *arg0)
{
	struct sockaddr_in *addr_in =
	    (struct sockaddr_in *)ifap->ifa_addr;
	ifa_collection_t *iac =
	    (ifa_collection_t *)arg0;
	ifs_if_search_t iis;
	ifa_if_link_t  *iil = NULL;

	if (iac == NULL)
		return (IFA_WALK_TERMINATE);

	if (ifap->ifa_addr->sa_family != AF_INET)
		return (IFA_WALK_CONTINUE);

	bzero(&iis, sizeof(ifs_if_search_t));
	iis.iflink.ifname = ifap->ifa_name;
	iis.iflink.ifnamelen =
	    strlen(ifap->ifa_name);
	iis.done = B_FALSE;

	ifs_walk(&iis, ifs_get_ifindex_by_ifname);
	if (iis.done == B_FALSE)
		return (IFA_WALK_CONTINUE);
/*	gen_info("ifa_complete_ifname_hash_all found ipaddr %s, "
	    " ifindex is %d", inet_ntoa(addr_in->sin_addr), iis.iflink.ifindex);*/

	pthread_mutex_lock(&iac->lock);
	if (iac->ifa_if_hash == NULL) {
		iac->ifa_if_hash = generic_hash_new(
		    GENERIC1_HASH_SIZE,
		    cmp_ifac, hash_ifac);
		if (iac->ifa_if_hash == NULL) {
			goto error;
		}
	}
	if ((iil = generic_hash_find(
	    iac->ifa_if_hash,
	    &(iis.iflink))) == NULL) {
		iil = calloc(
		    1, sizeof(ifa_if_link_t));
		if (iil == NULL)
			goto error;
		iil->ifname = strdup(ifap->ifa_name);
		if (iil->ifname == NULL) {
nomemory:
			free_ifa_if_link(iil);
error:
			iac->error = B_TRUE;
			pthread_mutex_unlock(&iac->lock);
			return (IFA_WALK_TERMINATE);
		}
		iil->ifnamelen =
		    strlen(ifap->ifa_name);
		if (generic_hash_add(
		    iac->ifa_if_hash,
		    iil, iil) == NULL) {
			goto nomemory;
		}
	}
	/* Fill values for storage */
	iil->ifindex = iis.iflink.ifindex;
	fill_sockaddr_from_ipv4_tuple(
	    &(addr_in->sin_addr), 0, &(iil->addr));
	pthread_mutex_unlock(&iac->lock);

	return (IFA_WALK_CONTINUE);
}

/* Callback for ifa_walk (generic_hash_foreach'func_task) */
int ifa_complete_ifname_hash_by_netaddr(
	struct sockaddr *sa_target,
	struct ifaddrs *ifap,
	void *arg0)
{
	struct sockaddr_in *addr_orig =
	    (struct sockaddr_in *)sa_target;
	struct sockaddr_in *addr_in =
	    (struct sockaddr_in *)ifap->ifa_addr;
	struct sockaddr_in *maskaddr_in =
	    (struct sockaddr_in *)ifap->ifa_netmask;
	ifa_collection_t *imc =
	    (ifa_collection_t *)arg0;
	ifs_if_search_t iis;
	ifa_if_link_t  *iil = NULL;

	if ((imc == NULL) ||
	    (sa_target == NULL))
		return (IFA_WALK_TERMINATE);

	if (ipv4_addr_same_network(
	    &(addr_in->sin_addr),
		    &(addr_orig->sin_addr),
		    &(maskaddr_in->sin_addr)) == B_FALSE) {
		return (IFA_WALK_CONTINUE);
	}

	bzero(&iis, sizeof(ifs_if_search_t));
	iis.iflink.ifname = ifap->ifa_name;
	iis.iflink.ifnamelen =
	    strlen(ifap->ifa_name);
	iis.done = B_FALSE;

	ifs_walk(&iis, ifs_get_ifindex_by_ifname);
	if (iis.done == B_FALSE)
		return (IFA_WALK_CONTINUE);
/*		gen_info("ifa_complete_ifname_hash_by_netaddr found ipaddr %s in the same network, "
		    " ifindex is %d", inet_ntoa(addr_in->sin_addr), iis.iflink.ifindex);*/

	pthread_mutex_lock(&imc->lock);
	if (imc->ifa_if_hash == NULL) {
		imc->ifa_if_hash = generic_hash_new(
		    GENERIC1_HASH_SIZE,
		    cmp_ifac, hash_ifac);
		if (imc->ifa_if_hash == NULL) {
			goto error;
		}
	}
	if ((iil = generic_hash_find(
	    imc->ifa_if_hash,
	    &(iis.iflink))) == NULL) {
		iil = calloc(
		    1, sizeof(ifa_if_link_t));
		if (iil == NULL)
			goto error;
		iil->ifname = strdup(ifap->ifa_name);
		if (iil->ifname == NULL) {
nomemory:
			free_ifa_if_link(iil);
error:
			imc->error = B_TRUE;
			pthread_mutex_unlock(&imc->lock);
			return (IFA_WALK_TERMINATE);
		}
		iil->ifnamelen =
		    strlen(ifap->ifa_name);

		if (generic_hash_add(
		    imc->ifa_if_hash,
		    iil, iil) == NULL) {
			goto nomemory;
		}
	}
	/* Fill values for storage */
	iil->ifindex = iis.iflink.ifindex;
	fill_sockaddr_from_ipv4_tuple(
	    &(addr_in->sin_addr), 0, &(iil->addr));
	pthread_mutex_unlock(&imc->lock);

	return (IFA_WALK_CONTINUE);
}

void ifa_walk(
	struct sockaddr *sa_target,
	void *arg0,
	int (*fn)(struct sockaddr *, struct ifaddrs *, void *))
{
	struct ifaddrs	*ifap;
	struct ifaddrs	*ifa = NULL;
	int		ifa_family;

	if (fn == NULL)
		goto fail;

	/* Calculate length of buffer for addr_in string */
	ifa_family = (sa_target) ? sa_target->sa_family : AF_UNSPEC;
	if ((ifa_family != AF_INET) &&
	    (ifa_family != AF_INET6) &&
	    (ifa_family != AF_UNSPEC))
		goto fail;

	/* We need all addresses to get the interface state */
/*	if (getallifaddrs(AF_UNSPEC, &ifa, (LIFC_NOXMIT|LIFC_TEMPORARY|
	    LIFC_ALLZONES|LIFC_UNDER_IPMP)) != 0)*/
	if (getifaddrs(&ifa) != 0)
		goto fail;

	/* We need all interfaces, so check only for address family. */
	for (ifap = ifa; ifap != NULL; ifap = ifap->ifa_next) {
		if (ifap->ifa_netmask == NULL)
			continue;
		if ((ifa_family != AF_UNSPEC) &&
		    (ifap->ifa_addr->sa_family != ifa_family))
			continue;
		if (fn(sa_target, ifap, arg0) == IFA_WALK_TERMINATE)
			break;
	}
	if (ifap == NULL) {
		goto fail;
	}
fail:
	if (ifa) {
		freeifaddrs(ifa);
		ifa = NULL;
	}
	return;
}
