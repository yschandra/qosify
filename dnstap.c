// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2022 Subhash Chandra <yschandra@gmail.com>
 */
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <errno.h>
#include <resolv.h>
#include <unistd.h>
#include <pwd.h>

#include <libubus.h>
#include <libubox/uloop.h>
#include <libubox/avl-cmp.h>

#include "qosify.h"

#define DNSTAP_SOCKET_PATH_MAX 100
#define DNSTAP_USER_MAX (32 + 1)

static bool dnstap_enabled = false;
//static char dnstap_scoket[DNSTAP_SOCKET_PATH_MAX];
//static char dnstap_user[DNSTAP_USER_MAX];

static struct uloop_fd dnstap_fd;

void qosify_read_dnstap_socket(void);
void qosify_close_dnstap_socket(void);
int qosify_open_dnstap_socket(const char *sock_path, const char *usr);

static void
qosify_dnstap_socket_cb(struct uloop_fd *fd, unsigned int events)
{
	qosify_read_dnstap_socket();
}

void
qosify_dnstap_set_config(struct blob_attr *dtap_sock, struct blob_attr *dtap_usr)
{
	int sfd;
	char *dsock = blobmsg_get_string(dtap_sock);
	char *sock_usr = blobmsg_get_string(dtap_usr);

	if (dnstap_enabled) {
		uloop_fd_delete(&dnstap_fd);
		qosify_close_dnstap_socket();
		dnstap_enabled = false;
	}

	sfd = qosify_open_dnstap_socket(dsock, sock_usr);

	if (sfd > 0) {
		dnstap_enabled = true;
		dnstap_fd.fd = sfd;
		dnstap_fd.cb = qosify_dnstap_socket_cb;
		uloop_fd_add(&dnstap_fd, ULOOP_READ);
		ULOG_NOTE("Listening on dnstap socket: %s\n", dsock);
	}

	return;
}

// vim: noexpandtab ts=2
