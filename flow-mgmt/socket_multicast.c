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
 * This file contains wrappers for IP multicast routines.
 */

#include <unistd.h>
#include <errno.h>
#include <strings.h>
#include <stdio.h>

#include "socket_multicast.h"

int socket_multicast(
	multicast_conn_t *conn, 
	uint16_t port) {

	conn->sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (conn->sock < 0)
		return (-1);
	conn->port = port;

	bzero((char *)&conn->addr, sizeof(conn->addr));
	conn->addr.sin_family = AF_INET;
	conn->addr.sin_addr.s_addr = htonl(INADDR_ANY);
	conn->addr.sin_port = htons(conn->port);
	conn->addrlen = sizeof(conn->addr);

	conn->recv_addrlen = sizeof(struct sockaddr_in);

	return (conn->sock);
}

int socket_multicast_close(
	multicast_conn_t *conn) {

	if (conn->sock == -1)
		return (-1);
	if (close(conn->sock) == -1)
		return (-1);
	conn->sock = -1;

	return (0);
}

int socket_multicast_bind(
	multicast_conn_t *conn) {

	if (conn->sock == -1)
		return (-1);
	if (bind(conn->sock,
	    (struct sockaddr *) &conn->addr,
	    conn->addrlen) == -1)
	return (-1);

	return (0);
}

int socket_multicast_reuse(
	multicast_conn_t *conn) {
	int opt = 1;

	if (setsockopt(conn->sock,
	    SOL_SOCKET, SO_REUSEADDR,
	    (char *)&opt, sizeof opt) == -1)
	return (-1);

	return (0);
}

int socket_multicast_set_outinterface(
	multicast_conn_t *conn, 
	char *if_ipaddr) {
	struct in_addr addr;
	int addrlen;
	addrlen = sizeof(addr);
	bzero(&addr, addrlen);
	addr.s_addr = inet_addr(if_ipaddr);
	if (addr.s_addr == INADDR_NONE)
		return (-1);

	if (setsockopt(conn->sock, IPPROTO_IP,
	    IP_MULTICAST_IF,
	    &addr, addrlen) == -1)
	return (-1);

	return (0);
}

int socket_multicast_set_loopback(
	multicast_conn_t *conn, 
	uchar_t loopback_flag) {

	if (setsockopt(conn->sock, IPPROTO_IP,
	    IP_MULTICAST_LOOP,
	    &loopback_flag, sizeof(loopback_flag)) == -1)
		return (-1);

	return (0);
}

int socket_multicast_set_groupaddr(
	multicast_conn_t *conn, char *group_ipaddr) {

	conn->addr.sin_addr.s_addr = inet_addr(group_ipaddr);
	if (conn->addr.sin_addr.s_addr == INADDR_NONE)
		return (-1);

	return 0;
}

int socket_multicast_set_ifaddr(
	multicast_conn_t *conn, 
	char *if_ipaddr) {

	conn->mreq.imr_interface.s_addr = inet_addr(if_ipaddr);
	if (conn->mreq.imr_interface.s_addr == INADDR_NONE)
		return (-1);

	return (0);
}

int socket_multicast_set_group(
	multicast_conn_t *conn, 
	char *group_ipaddr) {

	conn->mreq.imr_multiaddr.s_addr = inet_addr(group_ipaddr);
	if (conn->mreq.imr_multiaddr.s_addr == INADDR_NONE ||
	    !IN_MULTICAST(htonl(conn->mreq.imr_multiaddr.s_addr))) {
		errno = EINVAL;
		return (-1);
	}
	conn->mreq.imr_interface.s_addr = htonl(INADDR_ANY);

	return (0);
}

int socket_multicast_add_membership(
	multicast_conn_t *conn, 
	char *if_ipaddr) {

	if (if_ipaddr != NULL) {
		if (socket_multicast_set_ifaddr(conn, if_ipaddr) == -1)
			return (-1);
	}

	if (setsockopt(conn->sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
	    &conn->mreq, sizeof(conn->mreq)) < 0)
		return (-1);

	return (0);
}

int socket_multicast_send(
	multicast_conn_t *conn, 
	char *buf, int buflen) {

	return sendto(conn->sock, buf, buflen, 0,
	    (struct sockaddr *) &conn->addr, conn->addrlen);
}

int socket_multicast_recv(
	multicast_conn_t *conn, 
	char *buf, int buflen) {

	bzero(&conn->recv_addr, sizeof(struct sockaddr_in));

	return recvfrom(conn->sock, buf, buflen, 0,
	    (struct sockaddr *) &conn->recv_addr, &conn->recv_addrlen);
}

int multicast_conn_send(char *output_line, int output_line_len, void *arg)
{
	multicast_conn_t *conn =
	    (multicast_conn_t *)arg;
	if (conn ==  NULL)
		return (-1);

	if (socket_multicast_send(
	    conn, output_line, output_line_len) == -1)
		return (-1);

	return (0);
}
