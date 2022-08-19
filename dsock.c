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

#include <libubox/uloop.h>
#include <libubox/avl-cmp.h>

#include <fstrm.h>

#include "qosify.h"

#include "dnstap.pb-c.h"

typedef void (*dns_pkt_cb_t)(struct packet *);

struct dsock_state {
	int sfd;
	const char *sock_path;
	const char *sock_user;
	struct fstrm_reader *sock_reader;
	dns_pkt_cb_t dns_pkt_cb;
};

static struct dsock_state dsock_ctx;

static fstrm_res
dsock_destroy(void *obj)
{
	return fstrm_res_success;
}

static fstrm_res
dsock_open(void *obj)
{
	struct dsock_state *ctx = (struct dsock_state *)obj;
	struct sockaddr_un usock;
	int sfd;

	if (ctx->sock_path == NULL)
		return fstrm_res_failure;

	memset(&usock, 0, sizeof(usock));
	usock.sun_family = AF_UNIX;
	strncpy(usock.sun_path, ctx->sock_path, sizeof(usock.sun_path) - 1);

	sfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sfd == -1) {
		ULOG_ERR("failed to create dnstap unix socket: %s\n", strerror(errno));
		return fstrm_res_failure;
	}

	unlink(usock.sun_path);

	if (bind(sfd, (struct sockaddr *)&usock, sizeof(usock))) {
		ULOG_ERR("failed to bind unix socket to %s: %s\n",
			 ctx->sock_path,
			 strerror(errno));
		goto error;
	}

	if (ctx->sock_user != NULL) {
		struct passwd *pwd = getpwnam(ctx->sock_user);
		if (pwd != NULL) {
			if (chown(usock.sun_path, pwd->pw_uid, pwd->pw_gid)) {
				ULOG_ERR("failed to set owner ship of %s to %s: %s\n",
						usock.sun_path, ctx->sock_user, strerror(errno));
				goto error;
			}
		} else {
			ULOG_ERR("user %s is not found in the system: %s\n", ctx->sock_user, strerror(errno));
			goto error;
		}
	}

	ctx->sfd = sfd;

	return fstrm_res_success;

error:
	close(ctx->sfd);
	ctx->sfd = -1;
	return fstrm_res_failure;
}

static fstrm_res
dsock_close(void *obj)
{
	struct dsock_state *ctx = (struct dsock_state *)obj;
	if (ctx->sfd > 0) {
		close(ctx->sfd);
		ctx->sfd = -1;
	}
	return fstrm_res_success;
}

static fstrm_res
dsock_read(void *obj,  void *data, size_t count)
{
	struct dsock_state *ctx = (struct dsock_state *)obj;
	ssize_t size;

	size = recvfrom(ctx->sfd, data, count, MSG_DONTWAIT | MSG_PEEK, NULL, NULL);

	if (size != count)
		return fstrm_res_failure;

	size = recvfrom(ctx->sfd, data, count, MSG_WAITALL, NULL, NULL);

	return fstrm_res_success;
}

int
qosify_init_dnstap_socket(void)
{
	struct fstrm_reader *r;
	struct fstrm_rdwr *rdwr;

	memset(&dsock_ctx, 0, sizeof(dsock_ctx));

	rdwr = fstrm_rdwr_init((void *)&dsock_ctx);

	if (rdwr == NULL)
		return -1;

	fstrm_rdwr_set_destroy(rdwr, dsock_destroy);
	fstrm_rdwr_set_open(rdwr, dsock_open);
	fstrm_rdwr_set_close(rdwr, dsock_close);
	fstrm_rdwr_set_read(rdwr, dsock_read);

	r = fstrm_reader_init(NULL, &rdwr);

	if (r == NULL) {
		fstrm_rdwr_destroy(&rdwr);
		return -1;
	}

	dsock_ctx.sock_reader = r;

	return 0;

}

int
qosify_open_dnstap_socket(const char *sock_path, const char *usr)
{
	dsock_ctx.sock_path = sock_path;
	dsock_ctx.sock_user = usr;

	if (fstrm_reader_open(dsock_ctx.sock_reader) != fstrm_res_success) {
		return -1;
	}

	return 0;
}

void
qosify_close_dnstap_socket(void)
{
	fstrm_reader_close(dsock_ctx.sock_reader);
	dsock_ctx.sock_path = NULL;
	dsock_ctx.sock_user = NULL;
}

void
qosify_read_dnstap_socket(void)
{
	const uint8_t *data;
	size_t size;
	fstrm_res result;
	Dnstap__Dnstap *dtap_data = NULL;
	struct packet pkt;


	do {
		size = 0;
		result = fstrm_reader_read(dsock_ctx.sock_reader, &data, &size);

		if (result == fstrm_res_success) {

			dtap_data = dnstap__dnstap__unpack(NULL, size, data);

			if (dtap_data != NULL) {
				//if (dtap_data->message->type == DNSTAP__MESSAGE__TYPE__RESOLVER_RESPONSE) {
				if (dtap_data->message->type == DNSTAP__MESSAGE__TYPE__FORWARDER_RESPONSE) {
					pkt.buffer = dtap_data->message->response_message.data;
					pkt.len = dtap_data->message->response_message.len;
					if (dsock_ctx.dns_pkt_cb != NULL)
						dsock_ctx.dns_pkt_cb(&pkt);
				}
			}

		}

	} while (result == fstrm_res_success);

	return;
}

void
qosify_set_dnstap_cb(dns_pkt_cb_t cb)
{
	dsock_ctx.dns_pkt_cb = cb;
}

// vim: noexpandtab ts=2
