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
 * Daemon code.
 */

#include <sys/types.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <thread.h>
#include <fcntl.h>
#include <unistd.h>
#include <strings.h>
#include <errno.h>
#include <syslog.h>
#include <time.h>

#include "dladm_interface.h"
#include "ifaddr_interface.h"
#include "socket_multicast.h"
#include "flow_base.h"
#include "parse_interface.h"
#include "monitor_interface.h"
#include "storage_backend_interface.h"
#include "log.h"

#include "flow_mgmt.h"

enum app_mode {
	ANALYTIC_RECEIVER = 0,
	ANALYTIC_FILE_SENDER,
	ANALYTIC_CLIENT_SENDER
};

/* Application global variables. */
int				mark_for_exit = 0;
flow_base_collection_t		flow_base_collection;
storage_backend_handle_t	flow_database;

/* Main object local variables. */
static char			*progname = NULL;
static int			daemon_child_fds[2];
static int			daemon_debug_level = 0;
static boolean_t		daemon_logflag = B_FALSE;
static boolean_t		daemon_informed = B_FALSE;
static enum app_mode		generic_app_mode = ANALYTIC_RECEIVER;
static uint16_t			generic_app_port = DEFAULT_FLOW_MGMT_PORT;
static multicast_conn_t		main_conn;
static ifa_collection_t		imc, iac, ilc;
static aclient_collection_t	*acc_head, *acc_tail;
static afile_collection_t	*afc_head, *afc_tail;
static lac_collection_t		*lac_head, *lac_tail;

void acc_collections_free()
{
	aclient_collection_t *acc, *next_acc;
	for (acc = acc_head; acc != NULL; acc = next_acc) {
		next_acc = acc->next;
		free(acc);
	}
	acc_head = NULL;
	acc_tail = NULL;
}

void afc_collections_free()
{
	afile_collection_t *afc, *next_afc;
	for (afc = afc_head; afc != NULL; afc = next_afc) {
		next_afc = afc->next;
		fem_handle_free(afc->fem_handle);
		free(afc);
	}
	afc_head = NULL;
	afc_tail = NULL;
}

void lac_collections_free()
{
	lac_collection_t *lac, *next_lac;
	for (lac = lac_head; lac != NULL; lac = next_lac) {
		next_lac = lac->next;
		free(lac);
	}
	lac_head = NULL;
	lac_tail = NULL;
}

struct option longopts[] =
{
	{ "debuglevel",0,NULL,'d'},
	{ "interactivemode",0,NULL,'c'},
	{ "sender",0,NULL,'s'},
	{ "analyticsfile",0,NULL,'f'},
	{ "interactivekeypath",0,NULL,'l'},
	{ "interfaceaddress",1,NULL,'i'},
	{ "targetaddress",1,NULL,'j'},
	{ "targetnexthopaddress",1,NULL,'k'},
	{ "networkeaddress",1,NULL,'n'},
	{ "groupaddress",1,NULL,'g'},
	{ "version",0,NULL,'v'},
	{ "help",0,NULL,'h'},
	{ 0 }
};

static int usage(char *progname)
{
	printf("Usage: %s [-d <debuglevel>]"
	    " [-i -l <absolutepath>:<relativepath>...]"
	    " [-s -f <analyticsfile>...]"
	    " [-j <targetaddr>/<targetmask>]..."
	    " [-k <targetnexthopaddr>...]"
	    " [-i <interfaceaddr>]"
	    " [-n <networkaddress>]"
	    " [-g <multicastgroupaddr>]\n",
	    (progname != NULL) ? progname : "<>");
	printf("where:\n");
	printf("      -i, --interactivemode : "
	    "interactive client sender\n");
	printf("      -l, --interactivekeypath <absolutepath>:<relativepath> : "
	    "interactive key absolute and relative path\n");
	printf("      -s, --sender : "
	    "sender mode\n");
	printf("      -f, --analyticsfile <filepath> : "
	    "analytics data file\n");
	printf("      -j, --targetaddress <ipaddr>/<mask> : "
	    "target IP address\n");
	printf("      -k, --targetnexthopaddress <ipaddr> : "
	    "target next hop IP address\n");
	printf("      -i, --interfaceaddress <interfaceaddr> : "
	    "outbound interface address\n");
	printf("      -n, --networkaddress <networkeaddr> : "
	    "listen on all interfaces that belongs to the network address\n");
	printf("      -g, --groupaddress <multicastgroupaddr> : "
	    "service multicast group\n");

	exit(1);
}

static int showversion(char *progname)
{
	printf("%s version 2.1.2\n",
	    (progname != NULL) ? progname : "<>");
	exit(1);
}

/*
 * This is called by the child process to inform the parent process to
 * exit with the given return value. Note that the child process
 * (the daemon process) informs the parent process to exit when anything
 * goes wrong or when all the intialization is done.
 */
static int
daemon_inform_parent_exit(int status)
{
	int err = 0;

	/*
	 * If daemon_debug_level is none-zero, flow-mgmtd is not running as
	 * a daemon.
	 */
	if (daemon_debug_level != 0)
		return (0);

	/* Test if daemon was already informed. */
	if (daemon_informed == B_TRUE)
		return (0);
	daemon_informed = B_TRUE;

	if (write(daemon_child_fds[1], &status, sizeof (int)) != sizeof (int)) {
		err = errno;
	}
	(void) close(daemon_child_fds[1]);
	return (err);
}

static int
daemon_init()
{
	pid_t	pid;
	int	status;

	if (getenv("SMF_FMRI") == NULL) {
		printf("daemon_init(): %s is an smf(5) managed "
		    "service and should not be run from the command line.\n",
		    progname);
		return (-1);
	}

	/*
	 * Create the pipe used for the child process to inform the parent
	 * process to exit after all initialization is done.
	 */
	if (pipe(daemon_child_fds) < 0) {
		printf("daemon_init(): %s pipe() failed: %s\n",
		    progname,
		    strerror(errno));
		return (-1);
	}

	if ((pid = fork()) < 0) {
		printf("daemon_init(): %s fork() failed: %s\n",
		    progname,
		    strerror(errno));
		(void) close(daemon_child_fds[0]);
		(void) close(daemon_child_fds[1]);
		return (-1);
	}

	if (pid != 0) { /* Parent */
		(void) close(daemon_child_fds[1]);

		/*
		 * Read the child process's result status value
		 * from the file descriptor array.
		 * If the child process exits unexpectedly,
		 * read() returns -1.
		 */
		if (read(daemon_child_fds[0], &status, sizeof (int)) != sizeof (int)) {
			printf("daemon_init(): %s child process "
			    "exited unexpectedly %s\n",
			    progname,
			    strerror(errno));
			(void) kill(pid, SIGTERM);
			status = EXIT_FAILURE;
		}
		(void) close(daemon_child_fds[0]);
		exit(status);
	}

	/*
	 * Child process.
	 */
	(void) close(daemon_child_fds[0]);
	(void) chdir("/");
	(void) setsid();
	(void) close(0);
	(void) close(1);
	(void) close(2);
	(void) open("/dev/null", O_RDWR, 0);
	(void) dup2(0, 1);
	(void) dup2(0, 2);
	openlog("flow-mgmtd", LOG_PID, LOG_LOCAL4);
	daemon_logflag = B_TRUE;
	return (0);
}


void signal_handler(
	int signal)
{
	if (signal == SIGINT ||
	    signal == SIGQUIT ||
	    signal == SIGTERM)
		mark_for_exit = 1;
}

void *ifa_collection_update_thr(
	void *arg)
{
	struct timespec ts;

	while (B_TRUE) {
		next_wait_period(5 * 1000, &ts);
		if (mark_for_exit)
			break;
		pthread_mutex_lock(&imc.timed_lock);
		imc.error = B_FALSE;
		ifa_walk(&(imc.target_addr), &imc,
		    ifa_complete_ifname_hash_by_netaddr);
		pthread_mutex_unlock(&imc.timed_lock);
		if (imc.error != B_FALSE) {
		    gen_info(
			"%s.%d: ifa_complete_ifname_hash_by_netaddr failure",
			__FILE__,
			__LINE__);
		}
	}
	return (NULL);
}

void ifa_collection_start_update(void)
{
	pthread_t thr;
	pthread_create(&thr, NULL,
	    ifa_collection_update_thr, NULL);
}

void *flow_collection_expire_thr(
	void *arg)
{
	struct timespec ts;

	while (B_TRUE) {
		next_wait_period(
		    DEFAULT_AFILE_PARSE_INTERVAL * 1000, &ts);
		if (mark_for_exit)
			break;
		flow_base_collection_walk_and_expire();
	}
	return (NULL);
}

void flow_collection_start_expire(void)
{
	pthread_t thr;
	pthread_create(&thr, NULL,
	    flow_collection_expire_thr, NULL);
}

void *flow_collection_report_thr(
	void *arg)
{
	flow_base_collection_t	*fbc =
	    &flow_base_collection;
	struct timespec		ts;
	int			delay_sec = 1;
	uint64_t		nflows_total;
	uint64_t		nflows_added;
	uint64_t		nflows_updated;
	uint64_t		nflows_deleted;
	uint64_t		nflows_overlimit;
	uint64_t		nqueues_overlimit;
	uint64_t		nomem_errors;

	while (B_TRUE) {
		next_wait_period(delay_sec * 1000, &ts);
		if (mark_for_exit)
			break;

		pthread_mutex_lock(&fbc->lock);

		nflows_total = generic_hash_length(fbc->flow_name_hash);

		nflows_added = 0;
		if (fbc->nflows_added > 0) {
			nflows_added =
			    fbc->nflows_added /
			    delay_sec;
		}
		fbc->nflows_added_last =
		    fbc->nflows_added;
		fbc->nflows_added = 0;

		nflows_updated = 0;
		if (fbc->nflows_updated > 0) {
			nflows_updated =
			    fbc->nflows_updated /
			    delay_sec;
		}
		fbc->nflows_updated_last =
		    fbc->nflows_updated;
		fbc->nflows_updated = 0;

		nflows_deleted = 0;
		if (fbc->nflows_deleted > 0) {
			nflows_deleted =
			    fbc->nflows_deleted /
			    delay_sec;
		}
		fbc->nflows_deleted_last =
		    fbc->nflows_deleted;
		fbc->nflows_deleted = 0;

		nflows_overlimit = 0;
		if (fbc->nflows_overlimit > 0) {
			nflows_overlimit =
			    fbc->nflows_overlimit /
			    delay_sec;
		}
		fbc->nflows_overlimit_last =
		    fbc->nflows_overlimit;
		fbc->nflows_overlimit = 0;

		nqueues_overlimit = 0;
		if (fbc->nqueues_overlimit > 0) {
			nqueues_overlimit =
			    fbc->nqueues_overlimit /
			    delay_sec;
		}
		fbc->nqueues_overlimit_last =
		    fbc->nqueues_overlimit;
		fbc->nqueues_overlimit = 0;

		nomem_errors = 0;
		if (fbc->nomem_errors > 0) {
			nomem_errors =
			    fbc->nomem_errors /
			    delay_sec;
		}
		fbc->nomem_errors_last =
		    fbc->nomem_errors;
		fbc->nomem_errors = 0;

		pthread_mutex_unlock(&fbc->lock);

		if (nflows_added > 0)
			gen_info("Added %lld flow(s) rate per sec"
			" (total flow(s) %lld)",
			    nflows_added, nflows_total);
		if (nflows_updated > 0)
			gen_info("Updated %lld flow(s) rate per sec"
			" (total flow(s) %lld)",
			    nflows_updated, nflows_total);
		if (nflows_deleted > 0)
			gen_info("Deleted %lld flow(s) rate per sec"
			" (total flow(s) %lld)",
			    nflows_deleted, nflows_total);
		if (nflows_overlimit > 0)
			gen_info("Overlimited %lld flow(s) rate per sec"
			" (total flow(s) %lld)",
			    nflows_overlimit, nflows_total);
		if (nqueues_overlimit > 0)
			gen_info("Overlimited %lld expiring queue(s)"
			    " rate per sec",
			    nqueues_overlimit);
		if (nomem_errors > 0)
			gen_info("Out-of-memory errors %lld rate per sec",
			    nomem_errors);
	}
	return (NULL);
}

void flow_collection_start_report(void)
{
	pthread_t thr;
	pthread_create(&thr, NULL,
	    flow_collection_report_thr, NULL);
}

void *afile_mon_thr(
	void *arg)
{
	afile_collection_t *nfc =
	    (afile_collection_t *)arg;
	afile_collection_t cfc;
	port_event_t event;

	bzero(&cfc, sizeof(afile_collection_t));
	memcpy(&cfc.file_name, nfc->file_name, strlen(nfc->file_name));

	while (B_TRUE) {
		if (mark_for_exit) {
			/*
			 * It is safe because fem_handle_free
			 * does also port dissociation if needed.
			 */
			break;
		}
		fem_handle_wait_until_update(
		    nfc->fem_handle, &event);
		/* Process file which created FEM event. */
		afile_walk(
		    afile_parse_line,
		    multicast_conn_send,
		    &main_conn, lac_head, &cfc);
		fem_handle_register_again(
		    nfc->fem_handle, &event);
	}
	fem_handle_free(
	    nfc->fem_handle);
	nfc->fem_handle = NULL;
	return (NULL);
}

void afile_start_mon(afile_collection_t *nfc)
{
	pthread_t thr;

	nfc->fem_handle =
	    fem_handle_create(nfc->file_name,
	    FEM_DEFAULT_AFILE_EVENTS);
	if (nfc->fem_handle == NULL)
		return;
	if (fem_handle_register(
	    nfc->fem_handle, 0, B_FALSE) != FEM_HANDLE_OK) {
		gen_info(
		    "Unable to register for file events on %s",
		    nfc->file_name);
		goto fail;
	}

	if (pthread_create(&thr, NULL,
	    afile_mon_thr, (void *)nfc) != 0) {
		gen_info(
		    "Unable to pthread_create() on %p",
		    nfc);
		goto fail;
	}
	return;
fail:
	fem_handle_free(
	    nfc->fem_handle);
	nfc->fem_handle = NULL;
}

void *aclient_mon_thr(
	void *arg)
{
	aclient_collection_t *ncc =
	    (aclient_collection_t *)arg;

	while (B_TRUE) {
		if (mark_for_exit) {
			break;
		}
		aclient_walk(
		    afile_parse_line,
		    multicast_conn_send,
		    &main_conn, lac_head, ncc);
	}
	return (NULL);
}

void aclient_start_mon(aclient_collection_t *ncc)
{
	pthread_t thr;

	if (pthread_create(&thr, NULL,
	    aclient_mon_thr, (void *)ncc) != 0) {
		gen_info(
		    "Unable to pthread_create() on %p",
		    ncc);
	}
	return;
}

/* Callback for generic_hash_foreach'func_task */
void ifa_collection_participate_client(
	void *arg0,
	void **arg1,
	void *arg2)
{
	ifa_if_link_t *iil0 =
	    (ifa_if_link_t *)arg0;
	ifa_collection_t *imc =
	    (ifa_collection_t *)arg2;
	struct sockaddr_in *addr;

	if (iil0 == NULL)
		return;
	addr = (struct sockaddr_in *)&(iil0->addr);

	if (socket_multicast_add_membership(&main_conn,
	    inet_ntoa(addr->sin_addr)) == -1) {
		if (imc != NULL)
			imc->error = B_TRUE;
	}
}

/* Callback for generic_hash_foreach'func_task */
void ifa_collection_participate_sender(
	void *arg0,
	void **arg1,
	void *arg2)
{
	ifa_if_link_t *iil0 =
	    (ifa_if_link_t *)arg0;
	ifa_collection_t *imc =
	    (ifa_collection_t *)arg2;
	struct sockaddr_in *addr;

	if (iil0 == NULL)
		return;
	addr = (struct sockaddr_in *)&(iil0->addr);

	if (socket_multicast_set_outinterface(&main_conn,
	    inet_ntoa(addr->sin_addr)) == -1) {
		if (imc != NULL)
			imc->error = B_TRUE;
	}
}

int main(int argc, char **argv) {
	sigset_t		app_ss;
	struct sigaction 	app_sg;
	char			*p;
	char			*ifaddr;
	char			*netaddr;
	char			*groupaddr;
	int			status = EXIT_FAILURE;

	acc_head = acc_tail = NULL;
	afc_head = afc_tail = NULL;
	lac_head = lac_tail = NULL;
	ifaddr = NULL;
	netaddr = NULL;
	groupaddr = NULL;

	/* Extract daemon name for logging purposes. */
	progname = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);

	/* Basic initializations. */
	flow_base_collection_ini(&flow_base_collection);
	ifa_collection_ini(&imc);
	ifa_collection_ini(&iac);
	ifa_collection_ini(&ilc);
	backend_handle_ini(&flow_database);
	bzero(&main_conn,sizeof(main_conn));
	main_conn.sock = -1;

	if (dladm_handle_create(progname) != B_TRUE)
		goto done;

	/* Set up signal actions. */
	bzero(&app_sg, sizeof(struct sigaction));
	sigfillset(&app_ss);
	(void) thr_sigsetmask(SIG_UNBLOCK, &app_ss, NULL);
	app_sg.sa_handler = &signal_handler;
	app_sg.sa_flags = 0;
	sigemptyset(&app_sg.sa_mask);
	if (sigaction(SIGINT, &app_sg, NULL) == -1)
		goto done;
	if (sigaction(SIGQUIT, &app_sg, NULL) == -1)
		goto done;
	if (sigaction(SIGTERM, &app_sg, NULL) == -1)
		goto done;

	daemon_debug_level = 0;

	while (B_TRUE) {
		char	addrstr[INET6_ADDRSTRLEN + 1];
		char	netstr[INET6_ADDRSTRLEN + 1];
		int opt;
		int s_len;
		char *s;
		uint8_t lac_type;
		struct stat st;

		opt = getopt_long(
		    argc, argv,
		    "d:cl:sf:i:j:k:n:g:vh",
		    longopts, 0);

		if (opt == EOF)
			break;

		switch (opt) {
		    case 0:
			break;
		    case 'd':
			daemon_debug_level = atoi(optarg);
			break;
		    case 'c':
			generic_app_mode = ANALYTIC_CLIENT_SENDER;
			break;
		    case 's':
			generic_app_mode = ANALYTIC_FILE_SENDER;
			break;
		    case 'l': {
			aclient_collection_t	*ncc;
			int rootdir_fd;
			char			abspath[MAXPATHLEN];
			char			relpath[MAXPATHLEN];

			s = strchr(optarg, ':');
			if (s == NULL) {
invalid_key_path:
				gen_info("Invalid format of argument: "
				    "should be "
				    "absolutefilepath:relativefilepath");
				usage(progname);
			}
			s_len = (int)(s - optarg);
			if (s_len <= 0 ||
			    s_len > strlen(optarg))
				goto invalid_key_path;

			snprintf(abspath, sizeof(abspath) - 1,
			    "%.*s", s_len, optarg);
			snprintf(relpath, sizeof(relpath) - 1,
			    "%.*s", strlen(optarg) - 1 - s_len, s + 1);

			if ((stat(abspath, &st) == -1) ||
			    !((st.st_mode & S_IFMT) == S_IFDIR)) {
				gen_info("Unable to stat path %s", abspath);
				goto done;
			}

			ncc = calloc(1, sizeof(aclient_collection_t));
			if (ncc == NULL)
				goto done;
			memcpy(ncc->key_file_path, abspath, strlen(abspath));
			memcpy(ncc->key_file_name, relpath, strlen(relpath));
			ncc->msg_key = -1;
			ncc->msg_id = -1;

			rootdir_fd = open("/", O_RDONLY);
			if (chdir(ncc->key_file_path) == -1) {
				gen_info("Unable to chdir path %s", ncc->key_file_path);
				free(ncc);
				close(rootdir_fd);
				goto done;
			}
			if (chroot(".") == -1) {
				gen_info("Unable to chroot path %s", ncc->key_file_path);
				free(ncc);
				close(rootdir_fd);
				goto done;
			}
			ncc->msg_key = ftok(ncc->key_file_name,'M');
			/*
			 * We calculated file token and
			 * should restore saved chroot point.
			 */
			fchdir(rootdir_fd);
			close(rootdir_fd);

			if (ncc->msg_key == (key_t)-1) {
				gen_info("Unable to ftok path %s", ncc->key_file_name);
				free(ncc);
				goto done;
			}

			if (acc_head == NULL) {
				acc_head = acc_tail = ncc;
			} else {
				acc_tail->next = ncc;
				acc_tail = ncc;
			}
			break;
		    }
		    case 'f': {
			afile_collection_t	*nfc;

			if ((stat(optarg, &st) == -1) ||
			    !((st.st_mode & S_IFMT) == S_IFREG)) {
				gen_info("Unable to stat file %s", optarg);
				goto done;
			}
			nfc = calloc(1, sizeof(afile_collection_t));
			if (nfc == NULL)
				goto done;
			memcpy(nfc->file_name, optarg, strlen(optarg));
			if (afc_head == NULL) {
				afc_head = afc_tail = nfc;
			} else {
				afc_tail->next = nfc;
				afc_tail = nfc;
			}
			break;
		    }
		    case 'j': {
			lac_type = LAC_TYPE_IFIP;
			s = strchr(optarg, '/');
			if (s == NULL) {
invalid_addr_or_mask:
				gen_info("Invalid format of argument: "
				    "should be network/mask");
				usage(progname);
			}
			s_len = (int)(s - optarg);
			if (s_len <= 0 ||
			    s_len > strlen(optarg))
				goto invalid_addr_or_mask;
			snprintf(addrstr, sizeof(addrstr) - 1,
			    "%.*s", s_len, optarg);
			snprintf(netstr, sizeof(netstr) - 1,
			    "%.*s", strlen(optarg) - 1 - s_len, s + 1);
			goto new_lac;
		    }
		    case 'k':
			lac_type = LAC_TYPE_NEXTHOP;
new_lac:
			{
				lac_collection_t *lac;

				lac = calloc(1, sizeof(lac_collection_t));
				if (lac == NULL)
					goto done;
				lac->target_type = lac_type;
				bzero(&lac->target_addr, sizeof(struct in_addr));
				if (lac_type == LAC_TYPE_IFIP) {
					bzero(&lac->target_net, sizeof(struct in_addr));
					lac->target_net.s_addr = inet_addr(netstr);
					if (lac->target_net.s_addr == INADDR_NONE) {
						gen_info("Invalid netmask address: %s",
						    netstr);
						free(lac);
						goto done;
					}
					lac->target_addr.s_addr = inet_addr(addrstr);
				} else {
					lac->target_addr.s_addr = inet_addr(optarg);
				}
				if (lac->target_addr.s_addr == INADDR_NONE) {
					gen_info("Invalid IP address specified");
					free(lac);
					goto done;
				}
				if (lac_head == NULL) {
					lac_head = lac_tail = lac;
				} else {
					lac_tail->next = lac;
					lac_tail = lac;
				}
				break;
			}
		    case 'i':
			if (ifaddr != NULL) {
				usage(progname);
			}
			ifaddr = optarg;
			break;
		    case 'n':
			if (netaddr != NULL) {
				usage(progname);
			}
			netaddr = optarg;
			break;
		    case 'g':
			if (groupaddr != NULL) {
				usage(progname);
			}
			groupaddr = optarg;
			break;
		    case 'v':
			showversion(progname);
			break;
		    case 'h':
			usage(progname);
			break;
		    default:
			usage(progname);
			break;
		}
	}

	if (groupaddr == NULL) {
		usage(progname);
	}

	if ((generic_app_mode == ANALYTIC_FILE_SENDER) &&
	    (afc_head == NULL)) {
		usage(progname);
	}

	if ((generic_app_mode == ANALYTIC_CLIENT_SENDER) &&
	    ((acc_head == NULL) || (lac_head == NULL))) {
		usage(progname);
	}

	if ((daemon_debug_level == 0) &&
	    (daemon_init() != 0)) {
		printf("Unable to run as daemon");
		goto done;
	}
	gen_info("Daemon is started.");

	/*
	 * Load all existing flows in sender mode,
	 * start flow expiring task in background.
	 */
	if (generic_app_mode == ANALYTIC_RECEIVER) {
		boolean_t	need_fdb_full_dump =
		    B_FALSE;
		uint64_t	new_entries, old_entries;

		iac.error = B_FALSE;
		ifa_walk(NULL, &iac, ifa_complete_ifname_hash_all);
		if (iac.error != B_FALSE)
			goto done;
		if (iac.ifa_if_hash == NULL) {
			gen_info("Not found network interfaces");
			goto done;
		}
		gen_info("Found %d network interface(s)",
		    generic_hash_length(iac.ifa_if_hash));

		/*
		 * Datalink flow loading via DLIOC_WALKFLOW
		 * is too memory expensive for production use:
		 * RSS goes over 80MB after 4000 flows loaded.
		 * We store flows in backend file.
		 * On daemon start we try to load backend file if possible,
		 * then it removes loaded flow entries and
		 * starts loading via datalink. This is just to be sure
		 * if on previous daemon exit some flows might not be
		 * synchronized due to storage backend nature.
		 */
		if (backend_handle_open_read(&flow_database) ==
		    STORAGE_BACKEND_STATUS_OK) {
			if (backend_flow_load_all(
			    &flow_database,
			    &flow_base_collection) !=
			    STORAGE_BACKEND_STATUS_OK) {
				gen_info("Something wrong with "
				    "flow loading via storage backend");
				/* Clean up storage file as damaged. */
				unlink(DEFAULT_STORAGE_BACKEND_DB);
				need_fdb_full_dump = B_TRUE;
			}
			backend_handle_close(&flow_database);

			pthread_mutex_lock(&flow_base_collection.lock);
			if (flow_base_collection.flow_name_hash != NULL) {
				/*
				 * Temporarily remove flows from the system.
				 */
				generic_hash_foreach(
				    flow_base_collection.flow_name_hash,
				    flow_collection_walk_and_remove,
				    &flow_base_collection);
			}
			pthread_mutex_unlock(&flow_base_collection.lock);
		}

		old_entries = generic_hash_length(
		    flow_base_collection.flow_name_hash);
		gen_info("Loaded %llu flow(s) via storage backend",
		    old_entries);

		/*
		 * After datalink loading procedure is over, flow entries are
		 * returned back to the system.
		 * If backend procedure fails, only datalink loading is probed.
		 */
		iac.error = B_FALSE;
		ifa_collection_walk(&iac, &iac, ifa_collection_load_flows);

		if (old_entries > 0) {
			pthread_mutex_lock(&flow_base_collection.lock);
			if (flow_base_collection.flow_name_hash != NULL) {
				/*
				 * Add removed flows to the system.
				 */
				generic_hash_foreach(
				    flow_base_collection.flow_name_hash,
				    flow_collection_walk_and_add,
				    &flow_base_collection);
			}
			pthread_mutex_unlock(&flow_base_collection.lock);
		}
		if (iac.error != B_FALSE) {
			gen_info("Something wrong with "
			    "flow loading via datalink management");
			goto done;
		}
		new_entries = generic_hash_length(
		    flow_base_collection.flow_name_hash);
		if (new_entries - old_entries > 0) {
			need_fdb_full_dump = B_TRUE;
		}
		gen_info("Loaded %llu flow(s) via datalink management",
		    (new_entries - old_entries > 0) ?
		    new_entries - old_entries : 0);

		/*
		 * Tries to initialize RW access to backend file.
		 * Also it is created if not exist or 
		 * something is wrong with database.
		 */
		if (backend_handle_open_write(&flow_database) !=
		    STORAGE_BACKEND_STATUS_OK) {
			gen_info("Unable to write flow database");
		}
		/*
		 * Does fresh backend synchronization in order
		 * to be consistent with the system.
		 */
		if (need_fdb_full_dump == B_TRUE) {
			backend_flow_dump_all(
			    &flow_database,
			    &flow_base_collection);
		}

		/* Starts expiring task. */
		flow_collection_start_expire();
		/*
		 * Starts task for generating flow 
		 * fluctuation reports.
		 */
		flow_collection_start_report();
	}

	/*
	 * Finds out which network intefaces could be used for IP multicast
	 * transport.
	 */
	if (netaddr != NULL) {
		struct in_addr addr;

		bzero(&addr, sizeof(struct in_addr));
		addr.s_addr = inet_addr(netaddr);
		if (addr.s_addr == INADDR_NONE)
			goto done;

		fill_sockaddr_from_ipv4_tuple(&addr, 0, &imc.target_addr);
		imc.error = B_FALSE;
		ifa_walk(
		    &imc.target_addr, &imc,
		    ifa_complete_ifname_hash_by_netaddr);
		if (imc.error != B_FALSE)
			goto done;
		if ((imc.ifa_if_hash == NULL) ||
		    (generic_hash_length(imc.ifa_if_hash) == 0)) {
			gen_info("Not found interface "
			    "that belongs to network %s",
			    inet_ntoa(addr));
			goto done;
		}
		/*
		 * Runs a thread just to ensure that 
		 * new network interfaces are in sync with
		 * our data.
		 */
		ifa_collection_start_update();
	}

	/* Prepares IP multicast socket for communications. */
	if (socket_multicast(&main_conn, generic_app_port) == -1)
		goto done;
	if (socket_multicast_reuse(&main_conn) == -1)
		goto done;

	/*
	 * Runs main application loop in dependence of configured mode.
	 * Possible schemes include:
	 *
	 *  --------------------------     ------------------------
	 * / File with analytic data / --> | ANALYTIC_FILE_SENDER |
	 * --------------------------      ------------------------
	 *                                   |    ...         |
	 *                                   V                V
	 *                  ---------------------     ---------------------
	 *                  | ANALYTIC_RECEIVER |     | ANALYTIC_RECEIVER |
	 *	            --------------------- ... ---------------------
	 *
	 * ---------------------------     --------------------------
	 * | UNIX message queue app. | --> | ANALYTIC_CLIENT_SENDER |
	 * ---------------------------     --------------------------
	 *                                   |    ...         |
	 *                                   V                V
	 *                  ---------------------     ---------------------
	 *                  | ANALYTIC_RECEIVER |     | ANALYTIC_RECEIVER |
	 *	            --------------------- ... ---------------------
	 *
	 * ANALYTIC_RECEIVER is a daemon which provisions Crossbow flows.
	 * ANALYTIC_FILE_SENDER is a daemon which use file and
	 * generates flow commands via IP multicast on triggered file changes.
	 * ANALYTIC_CLIENT_SENDER is a daemon which acts as proxy between
	 * UNIX message queue sending application and flow commands consumer.
	 */
	if (generic_app_mode == ANALYTIC_RECEIVER) {
		if (socket_multicast_bind(&main_conn) == -1)
			goto done;

		if (socket_multicast_set_group(
		    &main_conn, groupaddr) == -1)
			goto done;

		if (ifaddr != NULL) {
			if (socket_multicast_add_membership(
			    &main_conn, ifaddr) == -1)
				goto done;
		}

		if (netaddr != NULL) {
			imc.error = B_FALSE;
			ifa_collection_walk(
			    &imc, &imc, ifa_collection_participate_client);
			if (imc.error != B_FALSE) {
				goto done;
			}
		}

		if (daemon_inform_parent_exit(EXIT_SUCCESS) != 0) {
			gen_info("daemon_inform_parent_exit() failed");
			goto done;
		}

		while (B_TRUE) {
			rcmd_walk(
			    rcmd_parse,
			    rcmd_add_flow,
			    &main_conn, &ilc);
			if (mark_for_exit)
				break;
		}
	} else if ((generic_app_mode == ANALYTIC_FILE_SENDER) ||
		    (generic_app_mode == ANALYTIC_CLIENT_SENDER)) {
		struct timespec ts;

		if (socket_multicast_set_loopback(&main_conn, 0) == -1)
			goto done;

		if (socket_multicast_set_groupaddr(
		    &main_conn, groupaddr) == -1)
			goto done;

		if (ifaddr != NULL) {
			if (socket_multicast_set_outinterface(&main_conn,
			    ifaddr) == -1)
				goto done;
		}

		if (netaddr != NULL) {
			imc.error = B_FALSE;
			ifa_collection_walk(
			    &imc, &imc, ifa_collection_participate_sender);
			if (imc.error != B_FALSE)
				goto done;
		}

		/*
		 * Send all file collections
		 * unconditionally on daemon start.
		 */
		afile_walk(
		    afile_parse_line,
		    multicast_conn_send,
		    &main_conn, lac_head, afc_head);

		if (generic_app_mode == ANALYTIC_FILE_SENDER) {
			afile_collection_t	*nfc;
			uint32_t		afc_count = 0;

			/* Start update tasks. */
			for (nfc = afc_head; nfc != NULL; nfc = nfc->next) {
				afile_start_mon(nfc);
				if (nfc->fem_handle != NULL)
					afc_count++;
			}
			if (afc_count == 0) {
				gen_info(
				    "No valid analytical file collection");
				goto done;
			}
		} else if (generic_app_mode == ANALYTIC_CLIENT_SENDER) {
			aclient_collection_t	*ncc;
			uint32_t		acc_count = 0;

			/* Start the listen-for-updates tasks. */
			for (ncc = acc_head; ncc != NULL; ncc = ncc->next) {
				aclient_start_mon(ncc);
				acc_count++;
			}
			if (acc_count == 0) {
				gen_info(
				    "No valid analytical client collection");
				goto done;
			}
		}

		if (daemon_inform_parent_exit(EXIT_SUCCESS) != 0) {
			gen_info("daemon_inform_parent_exit() failed");
			goto done;
		}

		while (B_TRUE) {
			next_wait_period(
			    5 * 1000, &ts);
			if (mark_for_exit)
				break;
		}
	}

	status = EXIT_SUCCESS;
done:
	gen_info("Daemon is stopped.");

	socket_multicast_close(&main_conn);
	ifa_collection_fini(&iac);
	ifa_collection_fini(&imc);
	flow_base_collection_fini(&flow_base_collection);
	backend_handle_fini(&flow_database);
	acc_collections_free();
	afc_collections_free();
	lac_collections_free();
	dladm_handle_destroy();

	if (status != EXIT_SUCCESS)
		gen_info (
		    "%s error: %s", progname, strerror(errno));
	(void) daemon_inform_parent_exit(status);
	if (daemon_logflag == B_TRUE)
		(void) closelog();
	return (status);
}
