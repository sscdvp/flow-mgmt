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
 * This file contains storage-based parser and
 * network parser.
 */

#include <sys/types.h>
#include <sys/msg.h>
#include <strings.h>
#include <errno.h>

#include "ifaddr_interface.h"
#include "socket_multicast.h"
#include "dladm_interface.h"
#include "flow_base.h"
#include "flow_mgmt.h"

#include "parse_interface.h"

typedef struct __aclient_msgbuf aclient_msgbuf;
struct __aclient_msgbuf {
	long msg_type;
	char msg_line[MAXLINELEN];
};

/* Separators which are in use by analytic data file. */
#define TOKENDELIM ':'
#define SEPDELIM ','
#define SPACEDELIM ' '
#define DOTDELIM '.'
#define VPDELIM '='
#define OPENPARANTHESE '{'
#define CLOSEPARANTHESE '}'

/* 
 * Parse file with analytic data generated by outside application.
 * These data is used for flooding via IP multicast and receiving on flow
 * management daemon side.
 * File format is predefined.
 */
/* Callback for afile_walk'fn1 or aclient_walk'fn1 */
cmd_status_t
afile_parse_line(
	char *line,
	char *output_line,
	int output_line_len,
	void *arg,
	cmd_status_t *status)
{
	char *starts, *ends;
	char token[MAXLINELEN];
	char add_line1[MAXLINELEN], 
	    add_line2[MAXLINELEN];
	char addrstr[INET6_ADDRSTRLEN + 1],
	    gwaddrstr[INET6_ADDRSTRLEN + 1];
	char portstr[ULONG_STRLEN];
	char *lac_type;
	int lac_target_type = LAC_TYPE_UNKNOWN;
	int port;
	int expire_interval;
	int token_len, token2_len, token3_len;
	struct in_addr ipaddr, gwipaddr;
	lac_collection_t *lac =
	    (lac_collection_t *)arg;

	/* First field is source IPv4 address and port tuple. */
	starts = strchr(line, TOKENDELIM);
	if (starts == NULL)
		goto fail;
	token_len = (int)(starts - line);
	if (token_len < 1 ||
	    (token_len > output_line_len))
		goto fail;
	bzero(&token, sizeof(token));
	memcpy(token, line,
	    token_len);
	ends = strrchr(token, DOTDELIM);
	if (ends == NULL)
		goto fail;
	token2_len = (int)(ends - token);
	if (token2_len < 1 ||
	    (token2_len > output_line_len))
		goto fail;

	bzero(&addrstr, sizeof(addrstr));
	memcpy(addrstr, token,
	    token2_len);

	if (inet_aton(addrstr, &ipaddr) == NULL)
		goto fail;

	/* Address and port are separated by dot. */
	bzero(&portstr, sizeof(portstr));
	memcpy(portstr, ends + 1,
	    token_len - token2_len - 1);

	errno = 0;
	port = strtol(portstr, NULL, 10);
	if ((errno != 0) ||
	    (port < 0) ||
	    (port > MAX_PORT))
		goto fail;

	/* 2nd field is timestamp, unused yet. */
	ends = strchr(starts + 1, TOKENDELIM);
	if (ends == NULL)
		goto fail;
	/* 3rd field is expiring interval. */
	starts = strchr(ends + 1, TOKENDELIM);
	if (starts == NULL)
		goto fail;
	token2_len = (int)(starts - ends);
	if (token2_len < 1 ||
	    (token2_len > output_line_len))
		goto fail;
	bzero(&token, sizeof(token));
	memcpy(token, ends + 1,
	    token2_len);

	errno = 0;
	expire_interval = strtol(token, NULL, 10);
	if ((errno != 0) ||
	    (expire_interval < MIN_EXPIRE_INTERVAL) ||
	    (expire_interval > MAX_EXPIRE_INTERVAL))
		goto fail;
	/* Fixme: just for exclusion of DNS Cache WQ interval. */
/*	if (expire_interval == 400)
		goto noop;*/

	if (lac == NULL) {
		/* 4th field is record type, unused yet. */
		ends = strchr(starts + 1, TOKENDELIM);
		if (ends == NULL)
			goto fail;
		/* 5th field is record length, unused yet. */
		starts = strchr(ends + 1, TOKENDELIM);
		if (starts == NULL)
			goto fail;
		/* 6th field is LAC_TYPE_NEXTHOP. */
		ends = strchr(starts + 1, TOKENDELIM);
		if (ends == NULL)
			goto fail;
		starts = strchr(ends + 1, TOKENDELIM);
		if (starts == NULL)
			goto fail;
		token3_len = (int)(starts - ends);
		if (token3_len < 1 ||
		    (token3_len > output_line_len))
			goto fail;
		bzero(&gwaddrstr, sizeof(gwaddrstr));
		memcpy(gwaddrstr, ends + 1,
		    token3_len);

		if (inet_aton(gwaddrstr, &gwipaddr) == NULL)
			goto fail;

		lac_type = KEYWORD_IPV4_GW_ADDR;
		lac_target_type = LAC_TYPE_NEXTHOP;
		snprintf(add_line1, sizeof(add_line1) - 1,
		    "%s%c%s",
		    lac_type,
		    VPDELIM, inet_ntoa(gwipaddr));
	} else {
		/* Add scope IP address which isn't present in file. */
		lac_target_type = lac->target_type;
		if (lac_target_type == LAC_TYPE_IFIP) {
			lac_type = KEYWORD_IPV4_DST_ADDR;
			snprintf(add_line2, sizeof(add_line2) - 1,
			    "%c %s%c%s",
			    SEPDELIM,
			    KEYWORD_IPV4_DST_NET,
			    VPDELIM, inet_ntoa(lac->target_net));
		} else if (lac_target_type == LAC_TYPE_NEXTHOP) {
			lac_type = KEYWORD_IPV4_GW_ADDR;
		} else {
			goto fail;
		}
		snprintf(add_line1, sizeof(add_line1) - 1,
		    "%s%c%s",
		    lac_type,
		    VPDELIM, inet_ntoa(lac->target_addr));
	}
	/* Construct JSON command line finally. */
	if (snprintf(output_line, output_line_len - 1,
	    "{ %s%c%s%c %s%c%d%c %s%c%d%c %s%s }",
	    KEYWORD_IPV4_SRC_ADDR, VPDELIM, addrstr, SEPDELIM,
	    KEYWORD_IPV4_SRC_PORT, VPDELIM, port, SEPDELIM,
	    KEYWORD_EXPIRE_TIME, VPDELIM, expire_interval, SEPDELIM,
	    add_line1,
	    (lac_target_type == LAC_TYPE_IFIP) ? add_line2 : "") >=
	    output_line_len - 1)
		goto fail;
/*
 * Insert conditional debug here.
 */
/*
	if (<condition>)
		gen_info("afile_parse_line: addrstr=%s, portstr=%s", addrstr, portstr);
		gen_info("afile_parse_line: output=%s", output_line);
	}
*/

	if (status)
		*status = CMD_STATUS_OK;
	return (FILE_WALK_CONTINUE);
fail:
	if (status)
		*status = CMD_STATUS_PARSE_ERROR;
	return (FILE_WALK_CONTINUE);
/*noop:
	if (status)
		*status = CMD_STATUS_NOOP;
	return (FILE_WALK_CONTINUE);*/
}

int afile_walk(
	cmd_status_t (*fn1)(char *, char *, int, void *, cmd_status_t *),
	int (*fn2)(char *, int, void *),
	void *arg,
	lac_collection_t *lac,
	afile_collection_t *afc)
{
	lac_collection_t *nac;
	afile_collection_t *nfc = afc;
	char line[MAXLINELEN],
	    output_line[MAXLINELEN];
	cmd_status_t output_status = CMD_STATUS_OK;
	int result_status = CMD_STATUS_NOOP;
	FILE *fp = NULL;

	if (fn1 == NULL ||
	    nfc == NULL ||
	    lac == NULL)
		goto fail;

start_file:
	fp = fopen(nfc->file_name, "r");
	if (fp == NULL)
		goto fail;
	while (fgets(line, MAXLINELEN, fp) != NULL) {
		if (mark_for_exit)
			goto done;
		for (nac = lac; nac != NULL; nac = nac->next) {
			/* On permanent error next available file will be parsed. */
			if (fn1(line, output_line,
			    MAXLINELEN, nac, &output_status) ==
			    FILE_WALK_TERMINATE)
				goto next_file;
			if ((output_status == CMD_STATUS_OK) && (fn2 != NULL)) {
			    fn2(output_line, strlen(output_line), arg);
			}
		}
	}
next_file:
	if (nfc->next != NULL) {
		if (fp != NULL) {
			fclose(fp);
			fp = NULL;
		}
		nfc = nfc->next;
		if (!mark_for_exit)
			goto start_file;
	}
done:
	result_status = CMD_STATUS_OK;
fail:
	if (fp != NULL) {
		fclose(fp);
		fp = NULL;
	}
	return (result_status);
}

int aclient_walk(
	cmd_status_t (*fn1)(char *, char *, int, void *, cmd_status_t *),
	int (*fn2)(char *, int, void *),
	void *arg,
	lac_collection_t *lac,
	aclient_collection_t *acc)
{
	lac_collection_t *nac;
	aclient_collection_t *ncc = acc;
	aclient_msgbuf amsgbuf;
	struct timespec ts;
	char output_line[MAXLINELEN];
	cmd_status_t output_status = CMD_STATUS_OK;
	int result_status = CMD_STATUS_NOOP;
	int msg_size;

	if (fn1 == NULL ||
	    ncc == NULL)
		goto fail;

	while (ncc->msg_id == -1) {
		errno = 0;
		ncc->msg_id = msgget(ncc->msg_key, 0600);
		if (ncc->msg_id == -1) {
			if (mark_for_exit)
				goto fail;
			if (errno != EINTR) {
				next_wait_period(
				    DEFAULT_AFILE_RETRY_INTERVAL * 1000, &ts);
			}
		}
	}

	while (B_TRUE) {
		bzero(&amsgbuf, sizeof(aclient_msgbuf));
		errno = 0;
		msg_size = msgrcv(
		    ncc->msg_id,
		    &amsgbuf, sizeof(amsgbuf.msg_line),
		    0, 0);
		if (msg_size == -1) {
			if (mark_for_exit)
				goto fail;
			if (errno == EIDRM) {
				ncc->msg_id = -1;
				goto fail;
			} else if (errno != EINTR) {
				next_wait_period(
				    DEFAULT_AFILE_RETRY_INTERVAL * 1000, &ts);
			}
			continue;
		}
		if (lac != NULL) {
			for (nac = lac; nac != NULL; nac = nac->next) {
				if (fn1(amsgbuf.msg_line, output_line,
				    MAXLINELEN, nac, &output_status) ==
				    FILE_WALK_TERMINATE)
					goto done;
				if ((output_status == CMD_STATUS_OK) && (fn2 != NULL)) {
					fn2(output_line, strlen(output_line), arg);
				}
			}
		} else {
			if (fn1(amsgbuf.msg_line, output_line,
			    MAXLINELEN, NULL, &output_status) ==
			    FILE_WALK_TERMINATE)
				goto done;
			if ((output_status == CMD_STATUS_OK) && (fn2 != NULL)) {
				fn2(output_line, strlen(output_line), arg);
			}
		}
	}

done:
	result_status = CMD_STATUS_OK;
fail:
	return (result_status);
}

cmd_status_t parse_token(
	char *line,
	char *output_line,
	int output_line_len,
	char startc,
	char endc)
{
	char *starts, *ends;
	char token[MAXLINELEN];
	int token_len;
	cmd_status_t result_status = CMD_STATUS_PARSE_ERROR;

	starts = strchr(line, startc);
	if (starts == NULL)
		goto fail;
	ends = strrchr(starts, endc);
	if (ends == NULL)
		goto fail;
	token_len = (int)(ends - starts);
	if (token_len <= 0 ||
	    (token_len > output_line_len))
		goto fail;
	bzero(&token, sizeof(token));
	memcpy(token, starts,
	    token_len);
	bzero(output_line, output_line_len);
	memcpy(output_line, token, token_len);
	result_status = CMD_STATUS_OK;
fail:
	return (result_status);
}

cmd_status_t parse_pvtoken(
	char *line,
	char *output_line,
	int output_line_len,
	char *keyword)
{
	char *starts, *ends;
	char token[MAXLINELEN];
	int token_len;
	cmd_status_t result_status = CMD_STATUS_PARSE_ERROR;

	if (keyword == NULL ||
	    strlen(keyword) == 0)
		goto fail;

	starts = strcasestr(line, keyword);
	if (starts == NULL)
		goto fail;
	starts += strlen(keyword);
	if (*starts != VPDELIM)
		goto fail;
	starts++;
	if (*starts == '\0')
		goto fail;
	ends = strchr(starts, SEPDELIM);
	if (ends == NULL)
		ends = strchr(starts, SPACEDELIM);
	if (ends == NULL)
		goto fail;
	token_len = (int)(ends - starts);
	if (token_len <= 0 ||
	    (token_len > output_line_len))
		goto fail;
	bzero(&token, sizeof(token));
	memcpy(token, starts,
	    token_len);
	bzero(output_line, output_line_len);
	memcpy(output_line, token, token_len);
	result_status = CMD_STATUS_OK;
fail:
	return (result_status);
}

/* Callback for rcmd_walk'fn2 */
int rcmd_add_flow(
	rcmd_arg_t *rcmd,
	void *arg)
{
	ifa_collection_t	*ilc =
	    (ifa_collection_t *)arg;
	ifa_if_link_t		iif, *iil, *iin;
	boolean_t		filled;
	struct sockaddr		local_ulp;
	struct in_addr		addr;
	uint16_t		port;
	uint8_t			dscp_cs;
	int			result_status = CMD_STATUS_CMD_ERROR;

	if (ilc == NULL ||
	    (rcmd == NULL) ||
	    (rcmd->target_ip == NULL) ||
	    (rcmd->local_ip == NULL))
		return (result_status);

	bzero(&addr, sizeof(struct in_addr));
	addr.s_addr = inet_addr(rcmd->target_ip);
	if (addr.s_addr == INADDR_NONE)
		return (result_status);

	filled = B_FALSE;
	if (ilc->ifa_if_hash == NULL) {
fill:
		fill_sockaddr_from_ipv4_tuple(&addr, 0, &ilc->target_addr);
		ilc->error = B_FALSE;
		ifa_walk(
		    &ilc->target_addr, ilc,
		    (rcmd->lac_type == LAC_TYPE_NEXTHOP) ?
		    ifa_complete_ifip_hash_by_addr :
		    ifa_complete_ifip_hash_by_netaddr);
		if (ilc->error != B_FALSE)
			return (result_status);
		if (ilc->ifa_if_hash == NULL) {
			return (result_status);
		}
		filled = B_TRUE;
	}

	bzero(&iif, sizeof(ifa_if_link_t));
	fill_sockaddr_from_ipv4_tuple(&addr, 0, &iif.target_addr);

	iil = generic_hash_find(
	    ilc->ifa_if_hash, &iif);
	if (iil == NULL) {
		if (filled == B_FALSE) {
			goto fill;
		}
		return (result_status);
	}

	bzero(&addr, sizeof(struct in_addr));
	addr.s_addr = inet_addr(rcmd->local_ip);
	if (addr.s_addr == INADDR_NONE)
		return (result_status);
	port = 0;
	if (rcmd->local_port != NULL) {
		errno = 0;
		port =
		    (uint16_t)strtol(
			rcmd->local_port, NULL, 10);
		if ((errno != 0) ||
		    (port < 0) ||
		    (port > MAX_PORT))
			return (result_status);
		/* Fixme: just resetting port to 0 for avoiding 
		 * flow selector conflict on the same link.
		 */
		port = 0;
	}
	fill_sockaddr_from_ipv4_tuple(&addr, port, &local_ulp);

	dscp_cs = DEFAULT_DSCP_CS;
	/* Even values of expiring interval belong to 100% dropping policy. */
	if ((rcmd->expire_interval & 1) == 1)
		dscp_cs = DROPALL_DSCP_CS;

	for (iin = iil; iin != NULL; iin = iin->next_sibling) {
/*		printf("linkid %d, expire_interval %d, ip %s, port %s\n",
		    iin->linkid, rcmd->expire_interval,
		    rcmd->local_ip, rcmd->local_port);*/
		result_status = store_flow_collection_entity(
		    iin->linkid, rcmd->expire_interval, 0,
		    &local_ulp, dscp_cs);
	}
	if (result_status == DLADM_STATUS_OK ||
	    result_status == DLADM_STATUS_EXIST)
		result_status = CMD_STATUS_OK;
	else
		result_status = CMD_STATUS_CMD_ERROR;

	return (result_status);
}

/* Callback for rcmd_walk'fn1 */
int rcmd_parse(
	int (*fn)(rcmd_arg_t *, void *),
	char *message,
	int message_len,
	void *arg)
{
	rcmd_arg_t rcmd;
	char cmdtoken[MAXLINELEN],
	addrstr[INET6_ADDRSTRLEN + 1],
	taddrstr[INET6_ADDRSTRLEN + 1],
	tnetstr[INET6_ADDRSTRLEN + 1],
	portstr[ULONG_STRLEN],
	expirestr[ULONG_STRLEN];
	cmd_status_t result_status = CMD_STATUS_PARSE_ERROR;

	if (fn == NULL) {
		result_status = CMD_STATUS_BADARG_ERROR;
		goto fail;
	}

	bzero(&rcmd, sizeof(rcmd_arg_t));
	/* Argument order is determined by afile_parse_line() routine. */
	if (parse_token(
	    message, cmdtoken, sizeof(cmdtoken),
	    OPENPARANTHESE, CLOSEPARANTHESE) != CMD_STATUS_OK)
		goto fail;
	if (parse_pvtoken(
	    cmdtoken, addrstr, sizeof(addrstr),
	    KEYWORD_IPV4_SRC_ADDR) != CMD_STATUS_OK)
		goto fail;
	rcmd.local_ip = &addrstr[0];

	if (parse_pvtoken(
	    cmdtoken, portstr, sizeof(portstr),
	    KEYWORD_IPV4_SRC_PORT) != CMD_STATUS_OK)
		goto fail;
	rcmd.local_port = &portstr[0];

	if (parse_pvtoken(
	    cmdtoken, expirestr, sizeof(expirestr),
	    KEYWORD_EXPIRE_TIME) != CMD_STATUS_OK)
		goto fail;
	errno = 0;
	rcmd.expire_interval = strtol(expirestr, NULL, 10);
	if ((errno != 0) ||
	    (rcmd.expire_interval < MIN_EXPIRE_INTERVAL) ||
	    (rcmd.expire_interval > MAX_EXPIRE_INTERVAL))
		goto fail;

	if (parse_pvtoken(
	    cmdtoken, taddrstr, sizeof(taddrstr),
	    KEYWORD_IPV4_DST_ADDR) != CMD_STATUS_OK) {
		if (parse_pvtoken(
		    cmdtoken, taddrstr, sizeof(taddrstr),
		    KEYWORD_IPV4_GW_ADDR) != CMD_STATUS_OK) {
			goto fail;
		} else {
			rcmd.lac_type = LAC_TYPE_NEXTHOP;
		}
	} else {
		rcmd.lac_type = LAC_TYPE_IFIP;
	}
	rcmd.target_ip = &taddrstr[0];

	if (rcmd.lac_type == LAC_TYPE_IFIP) {
		if (parse_pvtoken(
		    cmdtoken, tnetstr, sizeof(tnetstr),
		    KEYWORD_IPV4_DST_NET) != CMD_STATUS_OK)
			goto fail;
		rcmd.target_net = &tnetstr[0];
	}
/*	gen_info("rcmd_parse: addr=%s,port=%s,expire=%s\n", addrstr, portstr, expirestr);*/

	result_status = fn(&rcmd, arg);
/*
 * Insert conditional debug here.
 */
/*
	if (<condition>)
		gen_info("rcmd_parse: addr=%s,port=%s,expire=%s status %d",
		    addrstr, portstr, expirestr, result_status);
		gen_info("rcmd_parse: message=%s", message);
	}
*/
fail:
	return (result_status);
}

cmd_status_t rcmd_walk(
	int (*fn1)(int (*)(rcmd_arg_t *, void *),
	    char *, int, void *),
	int (*fn2)(rcmd_arg_t *, void *),
	void *arg0,
	void *arg1)
{
	char message[MAXLINELEN];
	int result_status = CMD_STATUS_CMD_ERROR;
	int message_len;

	multicast_conn_t *conn =
	    (multicast_conn_t *)arg0;

	if (fn1 == NULL)
		goto fail;

	bzero(&message, sizeof(message));
	if (socket_multicast_recv(conn,
	    message, sizeof(message)) == -1)
		goto fail;
	message_len = strlen(message);
	if ((message_len <= 0) ||
	    (message_len >= MAXLINELEN))
		goto fail;
	result_status = fn1(fn2, message, message_len, arg1);
fail:
	return (result_status);
}
