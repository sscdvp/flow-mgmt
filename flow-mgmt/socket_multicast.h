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

#ifndef MULTICAST_H
#define MULTICAST_H

#include "socket_generic.h"

typedef struct __multicast_conn {
	struct sockaddr_in	addr;
	struct sockaddr_in	recv_addr;
	struct ip_mreq		mreq;
	int			addrlen;
	socklen_t		recv_addrlen;
	int			sock;
	uint_t			outifindex;
	uint16_t		port;
} multicast_conn_t;

int socket_multicast(
	multicast_conn_t *conn, uint16_t port);
int socket_multicast_close(
	multicast_conn_t *conn);

int socket_multicast_bind(
	multicast_conn_t *conn);

int socket_multicast_reuse(
	multicast_conn_t *conn);

int socket_multicast_set_loopback(
	multicast_conn_t *conn, uchar_t loopback_flag);

int socket_multicast_set_outinterface(
	multicast_conn_t *conn, char *if_ipaddr);

int socket_multicast_set_ifaddr(
	multicast_conn_t *conn, char *if_ipaddr);

int socket_multicast_set_group(
	multicast_conn_t *conn, char *group_ipaddr);

int socket_multicast_set_groupaddr(
	multicast_conn_t *conn, char *group_ipaddr);

int socket_multicast_add_membership(
	multicast_conn_t *conn, char *if_ipaddr);

int socket_multicast_send(
	multicast_conn_t *conn,
	char *buf, int buflen);

int socket_multicast_recv(
	multicast_conn_t *conn,
	char *buf, int buflen);

int multicast_conn_send(
	char *output_line,
	int output_line_len,
	void *arg);

#endif
