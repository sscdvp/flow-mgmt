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

#ifndef PARSE_INTERFACE_H
#define PARSE_INTERFACE_H

#include <sys/types.h>

#include "monitor_interface.h"

#define KEYWORD_IPV4_SRC_ADDR "ipv4-src-addr"
#define KEYWORD_IPV4_SRC_PORT "ipv4-src-port"
#define KEYWORD_IPV4_DST_ADDR "ipv4-dst-addr"
#define KEYWORD_IPV4_DST_NET "ipv4-dst-net"
#define KEYWORD_IPV4_GW_ADDR "ipv4-gw-addr"
#define KEYWORD_EXPIRE_TIME "expire-time"

typedef enum {
	CMD_STATUS_OK = 0,
	CMD_STATUS_NOOP,
	CMD_STATUS_READ_ERROR,
	CMD_STATUS_PARSE_ERROR,
	CMD_STATUS_BADARG_ERROR,
	CMD_STATUS_CMD_ERROR
} cmd_status_t;

#define FILE_WALK_CONTINUE 1
#define FILE_WALK_TERMINATE 2

typedef struct __afile_collection_t afile_collection_t;

struct __afile_collection_t {
	char			file_name[MAXPATHLEN];
	afile_collection_t	*next;
	fem_handle_t		*fem_handle;
};

typedef struct __aclient_collection_t aclient_collection_t;

struct __aclient_collection_t {
	char			key_file_path[MAXPATHLEN];
	char			key_file_name[MAXPATHLEN];
	aclient_collection_t	*next;
	int			msg_id;
	key_t			msg_key;
};

typedef struct __rcmd_arg_t {
	int			expire_interval;
	char			*local_ip;
	char			*local_port;
	char			*target_ip;
	char			*target_net;
	uint8_t			lac_type;
} rcmd_arg_t;

cmd_status_t afile_parse_line(
	char *line,
	char *output_line,
	int output_line_len,
	void *arg,
	cmd_status_t *status);

int afile_walk(
	cmd_status_t (*fn1)(char *, char *, int, void *, cmd_status_t *),
	int (*fn2)(char *, int, void *),
	void *arg,
	lac_collection_t *lac,
	afile_collection_t *afc);

int aclient_walk(
	cmd_status_t (*fn1)(char *, char *, int, void *, cmd_status_t *),
	int (*fn2)(char *, int, void *),
	void *arg,
	lac_collection_t *lac,
	aclient_collection_t *acc);

cmd_status_t rcmd_walk(
	int (*fn1)(
	    int (*)(rcmd_arg_t *, void *),
	    char *, int, void *),
	int (*fn2)(rcmd_arg_t *, void *),
	void *arg0,
	void *arg1);

int rcmd_parse(
	int (*fn1)(rcmd_arg_t *, void *),
	char *message,
	int message_len,
	void *arg);

int rcmd_add_flow(
	rcmd_arg_t *rarg,
	void *arg);

#endif
