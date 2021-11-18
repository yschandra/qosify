// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2021 Felix Fietkau <nbd@nbd.name>
 */
#include <arpa/inet.h>

#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>
#include <fnmatch.h>
#include <glob.h>

#include <libubox/uloop.h>
#include <libubox/avl-cmp.h>

#include "qosify.h"

struct qosify_map_class;

static int qosify_map_entry_cmp(const void *k1, const void *k2, void *ptr);

static int qosify_map_fds[__CL_MAP_MAX];
static AVL_TREE(map_data, qosify_map_entry_cmp, false, NULL);
static LIST_HEAD(map_files);
static struct qosify_map_class *map_class[QOSIFY_MAX_CLASS_ENTRIES];
static uint32_t next_timeout;
static uint8_t qosify_dscp_default[2] = { 0xff, 0xff };
int qosify_map_timeout;
int qosify_active_timeout;
struct qosify_config config;
struct qosify_flow_config flow_config;

struct qosify_map_file {
	struct list_head list;
	char filename[];
};

struct qosify_map_class {
	const char *name;
	struct qosify_class data;
};

static const struct {
	const char *name;
	const char *type_name;
} qosify_map_info[] = {
	[CL_MAP_TCP_PORTS] = { "tcp_ports", "tcp_port" },
	[CL_MAP_UDP_PORTS] = { "udp_ports", "udp_port" },
	[CL_MAP_IPV4_ADDR] = { "ipv4_map", "ipv4_addr" },
	[CL_MAP_IPV6_ADDR] = { "ipv6_map", "ipv6_addr" },
	[CL_MAP_CONFIG] = { "config", "config" },
	[CL_MAP_CLASS] = { "class_map", "class" },
	[CL_MAP_DNS] = { "dns", "dns" },
};

static const struct {
	const char name[5];
	uint8_t val;
} codepoints[] = {
	{ "CS0", 0 },
	{ "CS1", 8 },
	{ "CS2", 16 },
	{ "CS3", 24 },
	{ "CS4", 32 },
	{ "CS5", 40 },
	{ "CS6", 48 },
	{ "CS7", 56 },
	{ "AF11", 10 },
	{ "AF12", 12 },
	{ "AF13", 14 },
	{ "AF21", 18 },
	{ "AF22", 20 },
	{ "AF22", 22 },
	{ "AF31", 26 },
	{ "AF32", 28 },
	{ "AF33", 30 },
	{ "AF41", 34 },
	{ "AF42", 36 },
	{ "AF43", 38 },
	{ "EF", 46 },
	{ "VA", 44 },
	{ "LE", 1 },
	{ "DF", 0 },
};

static void qosify_map_timer_cb(struct uloop_timeout *t)
{
	qosify_map_gc();
}

static struct uloop_timeout qosify_map_timer = {
	.cb = qosify_map_timer_cb,
};

static uint32_t qosify_gettime(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return ts.tv_sec;
}

static const char *
qosify_map_path(enum qosify_map_id id)
{
	static char path[128];
	const char *name;

	if (id >= ARRAY_SIZE(qosify_map_info))
		return NULL;

	name = qosify_map_info[id].name;
	if (!name)
		return NULL;

	snprintf(path, sizeof(path), "%s/%s", CLASSIFY_DATA_PATH, name);

	return path;
}

static int qosify_map_get_fd(enum qosify_map_id id)
{
	const char *path = qosify_map_path(id);
	int fd;

	if (!path)
		return -1;

	fd = bpf_obj_get(path);
	if (fd < 0)
		fprintf(stderr, "Failed to open map %s: %s\n", path, strerror(errno));

	return fd;
}

static void qosify_map_clear_list(enum qosify_map_id id)
{
	int fd = qosify_map_fds[id];
	__u32 key[4] = {};

	while (bpf_map_get_next_key(fd, &key, &key) != -1)
		bpf_map_delete_elem(fd, &key);
}

static void __qosify_map_set_dscp_default(enum qosify_map_id id, uint8_t val)
{
	struct qosify_map_data data = {
		.id = id,
	};
	struct qosify_class class = {
		.val.ingress = val,
		.val.egress = val,
	};
	uint32_t key;
	int fd;
	int i;

	if (id == CL_MAP_TCP_PORTS)
		key = QOSIFY_MAX_CLASS_ENTRIES;
	else if (id == CL_MAP_UDP_PORTS)
		key = QOSIFY_MAX_CLASS_ENTRIES + 1;
	else
		return;

	fd = qosify_map_fds[CL_MAP_CLASS];
	if (val & QOSIFY_DSCP_CLASS_FLAG) {
		uint8_t fallback = val & QOSIFY_DSCP_FALLBACK_FLAG;

		val &= QOSIFY_DSCP_VALUE_MASK;
		if (val > ARRAY_SIZE(map_class) || !map_class[val])
			return;

		class.val.ingress = map_class[val]->data.val.ingress | fallback;
		class.val.egress = map_class[val]->data.val.egress | fallback;
	}

	memcpy(&class.config, &flow_config, sizeof(class.config));
	bpf_map_update_elem(fd, &key, &class, BPF_ANY);

	val = key | QOSIFY_DSCP_CLASS_FLAG;
	fd = qosify_map_fds[id];
	for (i = 0; i < (1 << 16); i++) {
		data.addr.port = htons(i);
		if (avl_find(&map_data, &data))
			continue;

		bpf_map_update_elem(fd, &data.addr, &val, BPF_ANY);
	}
}

void qosify_map_set_dscp_default(enum qosify_map_id id, uint8_t val)
{
	bool udp;

	if (id == CL_MAP_TCP_PORTS)
		udp = false;
	else if (id == CL_MAP_UDP_PORTS)
		udp = true;
	else
		return;

	if (!memcmp(&qosify_dscp_default[udp], &val, sizeof(val)))
		return;

	qosify_dscp_default[udp] = val;
	__qosify_map_set_dscp_default(id, val);
}

int qosify_map_init(void)
{
	int i;

	for (i = 0; i < CL_MAP_DNS; i++) {
		qosify_map_fds[i] = qosify_map_get_fd(i);
		if (qosify_map_fds[i] < 0)
			return -1;
	}

	qosify_map_clear_list(CL_MAP_IPV4_ADDR);
	qosify_map_clear_list(CL_MAP_IPV6_ADDR);
	qosify_map_reset_config();

	return 0;
}

static char *str_skip(char *str, bool space)
{
	while (*str && isspace(*str) == space)
		str++;

	return str;
}

static int
qosify_map_codepoint(const char *val)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(codepoints); i++)
		if (!strcmp(codepoints[i].name, val))
			return codepoints[i].val;

	return 0xff;
}

static int qosify_map_entry_cmp(const void *k1, const void *k2, void *ptr)
{
	const struct qosify_map_data *d1 = k1;
	const struct qosify_map_data *d2 = k2;

	if (d1->id != d2->id)
		return d2->id - d1->id;

	if (d1->id == CL_MAP_DNS)
		return strcmp(d1->addr.dns.pattern, d2->addr.dns.pattern);

	return memcmp(&d1->addr, &d2->addr, sizeof(d1->addr));
}

static struct qosify_map_entry *
__qosify_map_alloc_entry(struct qosify_map_data *data)
{
	struct qosify_map_entry *e;
	char *pattern;
	char *c;

	if (data->id < CL_MAP_DNS) {
		e = calloc(1, sizeof(*e));
		memcpy(&e->data.addr, &data->addr, sizeof(e->data.addr));

		return e;
	}

	e = calloc_a(sizeof(*e), &pattern, strlen(data->addr.dns.pattern) + 1);
	strcpy(pattern, data->addr.dns.pattern);
	e->data.addr.dns.pattern = pattern;

	for (c = pattern; *c; c++)
		*c = tolower(*c);

	if (pattern[0] == '/' &&
	    regcomp(&e->data.addr.dns.regex, pattern + 1,
		    REG_EXTENDED | REG_NOSUB)) {
		free(e);
		return NULL;
	}

	return e;
}

static void __qosify_map_set_entry(struct qosify_map_data *data)
{
	int fd = qosify_map_fds[data->id];
	struct qosify_map_entry *e;
	bool file = data->file;
	uint8_t prev_dscp = 0xff;
	int32_t delta = 0;
	bool add = data->dscp != 0xff;

	e = avl_find_element(&map_data, data, e, avl);
	if (!e) {
		if (!add)
			return;

		e = __qosify_map_alloc_entry(data);
		if (!e)
			return;

		e->avl.key = &e->data;
		e->data.id = data->id;
		avl_insert(&map_data, &e->avl);
	} else {
		prev_dscp = e->data.dscp;
	}

	if (file)
		e->data.file = add;
	else
		e->data.user = add;

	if (add) {
		if (file)
			e->data.file_dscp = data->dscp;
		if (!e->data.user || !file)
			e->data.dscp = data->dscp;
	} else if (e->data.file && !file) {
		e->data.dscp = e->data.file_dscp;
	}

	if (e->data.dscp != prev_dscp && data->id < CL_MAP_DNS) {
		struct qosify_ip_map_val val = {
			.dscp = e->data.dscp,
			.seen = 1,
		};

		bpf_map_update_elem(fd, &data->addr, &val, BPF_ANY);
	}

	if (add) {
		if (qosify_map_timeout == ~0 || file) {
			e->timeout = ~0;
			return;
		}

		e->timeout = qosify_gettime() + qosify_map_timeout;
		delta = e->timeout - next_timeout;
		if (next_timeout && delta >= 0)
			return;
	}

	uloop_timeout_set(&qosify_map_timer, 1);
}

static int
qosify_map_set_port(struct qosify_map_data *data, const char *str)
{
	unsigned long start_port, end_port;
	char *err;
	int i;

	start_port = end_port = strtoul(str, &err, 0);
	if (err && *err) {
		if (*err == '-')
			end_port = strtoul(err + 1, &err, 0);
		if (*err)
			return -1;
	}

	if (!start_port || end_port < start_port ||
	    end_port >= 65535)
		return -1;

	for (i = start_port; i <= end_port; i++) {
		data->addr.port = htons(i);
		__qosify_map_set_entry(data);
	}

	return 0;
}

static int
qosify_map_fill_ip(struct qosify_map_data *data, const char *str)
{
	int af;

	if (data->id == CL_MAP_IPV6_ADDR)
		af = AF_INET6;
	else
		af = AF_INET;

	if (inet_pton(af, str, &data->addr) != 1)
		return -1;

	return 0;
}

int qosify_map_set_entry(enum qosify_map_id id, bool file, const char *str,
			 uint8_t dscp)
{
	struct qosify_map_data data = {
		.id = id,
		.file = file,
		.dscp = dscp,
	};

	switch (id) {
	case CL_MAP_DNS:
		data.addr.dns.pattern = str;
		break;
	case CL_MAP_TCP_PORTS:
	case CL_MAP_UDP_PORTS:
		return qosify_map_set_port(&data, str);
	case CL_MAP_IPV4_ADDR:
	case CL_MAP_IPV6_ADDR:
		if (qosify_map_fill_ip(&data, str))
			return -1;
		break;
	default:
		return -1;
	}

	__qosify_map_set_entry(&data);

	return 0;
}

static int
__qosify_map_dscp_value(const char *val, uint8_t *dscp_val)
{
	unsigned long dscp;
	bool fallback = false;
	char *err;

	if (*val == '+') {
		fallback = true;
		val++;
	}

	dscp = strtoul(val, &err, 0);
	if (err && *err)
		dscp = qosify_map_codepoint(val);

	if (dscp >= 64)
		return -1;

	*dscp_val = dscp | (fallback << 6);

	return 0;
}

static int
qosify_map_check_class(const char *val, uint8_t *dscp_val)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(map_class); i++) {
		if (map_class[i] && !strcmp(val, map_class[i]->name)) {
			*dscp_val = i | QOSIFY_DSCP_CLASS_FLAG;
			return 0;
		}
	}

	return -1;
}

int qosify_map_dscp_value(const char *val, uint8_t *dscp_val)
{
	uint8_t fallback = 0;

	if (*val == '+') {
		fallback = QOSIFY_DSCP_FALLBACK_FLAG;
		val++;
	}

	if (qosify_map_check_class(val, dscp_val) &&
	    __qosify_map_dscp_value(val, dscp_val))
			return -1;

	*dscp_val |= fallback;

	return 0;
}

static void
qosify_map_dscp_codepoint_str(char *dest, int len, uint8_t dscp)
{
	int i;

	if (dscp & QOSIFY_DSCP_FALLBACK_FLAG) {
		*(dest++) = '+';
		len--;
		dscp &= ~QOSIFY_DSCP_FALLBACK_FLAG;
	}

	for (i = 0; i < ARRAY_SIZE(codepoints); i++) {
		if (codepoints[i].val != dscp)
			continue;

		snprintf(dest, len, "%s", codepoints[i].name);
		return;
	}

	snprintf(dest, len, "0x%x", dscp);
}

static void
qosify_map_parse_line(char *str)
{
	const char *key, *value;
	uint8_t dscp;

	str = str_skip(str, true);
	key = str;

	str = str_skip(str, false);
	if (!*str)
		return;

	*(str++) = 0;
	str = str_skip(str, true);
	value = str;

	if (qosify_map_dscp_value(value, &dscp))
		return;

	if (!strncmp(key, "dns:", 4))
		qosify_map_set_entry(CL_MAP_DNS, true, key + 4, dscp);
	if (!strncmp(key, "tcp:", 4))
		qosify_map_set_entry(CL_MAP_TCP_PORTS, true, key + 4, dscp);
	else if (!strncmp(key, "udp:", 4))
		qosify_map_set_entry(CL_MAP_UDP_PORTS, true, key + 4, dscp);
	else if (strchr(key, ':'))
		qosify_map_set_entry(CL_MAP_IPV6_ADDR, true, key, dscp);
	else if (strchr(key, '.'))
		qosify_map_set_entry(CL_MAP_IPV4_ADDR, true, key, dscp);
}

static void
__qosify_map_load_file_data(FILE *f)
{
	char line[1024];
	char *cur;

	while (fgets(line, sizeof(line), f)) {
		cur = strchr(line, '#');
		if (cur)
			*cur = 0;

		cur = line + strlen(line);
		if (cur == line)
			continue;

		while (cur > line && isspace(cur[-1]))
			cur--;

		*cur = 0;
		qosify_map_parse_line(line);
	}

}

static int
__qosify_map_load_file(const char *file)
{
	glob_t gl;
	FILE *f;
	int i;

	if (!file)
		return 0;

	glob(file, 0, NULL, &gl);

	for (i = 0; i < gl.gl_pathc; i++) {
		f = fopen(file, "r");
		if (!f)
			continue;

		__qosify_map_load_file_data(f);
		fclose(f);
	}

	globfree(&gl);

	return 0;
}

int qosify_map_load_file(const char *file)
{
	struct qosify_map_file *f;

	if (!file)
		return 0;

	f = calloc(1, sizeof(*f) + strlen(file) + 1);
	strcpy(f->filename, file);
	list_add_tail(&f->list, &map_files);

	return __qosify_map_load_file(file);
}

static void qosify_map_reset_file_entries(void)
{
	struct qosify_map_entry *e;

	avl_for_each_element(&map_data, e, avl)
		e->data.file = false;
}

void qosify_map_clear_files(void)
{
	struct qosify_map_file *f, *tmp;

	qosify_map_reset_file_entries();

	list_for_each_entry_safe(f, tmp, &map_files, list) {
		list_del(&f->list);
		free(f);
	}
}

void qosify_map_reset_config(void)
{
	qosify_map_clear_files();
	qosify_map_set_dscp_default(CL_MAP_TCP_PORTS, 0);
	qosify_map_set_dscp_default(CL_MAP_UDP_PORTS, 0);
	qosify_map_timeout = 3600;
	qosify_active_timeout = 300;

	memset(&config, 0, sizeof(config));
	flow_config.dscp_prio = 0xff;
	flow_config.dscp_bulk = 0xff;
	config.dscp_icmp = 0xff;
}

void qosify_map_reload(void)
{
	struct qosify_map_file *f;

	qosify_map_reset_file_entries();

	list_for_each_entry(f, &map_files, list)
		__qosify_map_load_file(f->filename);

	qosify_map_gc();
}

static void qosify_map_free_entry(struct qosify_map_entry *e)
{
	int fd = qosify_map_fds[e->data.id];

	avl_delete(&map_data, &e->avl);
	if (e->data.id < CL_MAP_DNS)
		bpf_map_delete_elem(fd, &e->data.addr);
	free(e);
}

static bool
qosify_map_entry_refresh_timeout(struct qosify_map_entry *e)
{
	struct qosify_ip_map_val val;
	int fd = qosify_map_fds[e->data.id];

	if (e->data.id != CL_MAP_IPV4_ADDR &&
	    e->data.id != CL_MAP_IPV6_ADDR)
		return false;

	if (bpf_map_lookup_elem(fd, &e->data.addr, &val))
		return false;

	if (!val.seen)
		return false;

	e->timeout = qosify_gettime() + qosify_active_timeout;
	val.seen = 0;
	bpf_map_update_elem(fd, &e->data.addr, &val, BPF_ANY);

	return true;
}

void qosify_map_gc(void)
{
	struct qosify_map_entry *e, *tmp;
	int32_t timeout = 0;
	uint32_t cur_time = qosify_gettime();

	next_timeout = 0;
	avl_for_each_element_safe(&map_data, e, avl, tmp) {
		int32_t cur_timeout;

		if (e->data.user && e->timeout != ~0) {
			cur_timeout = e->timeout - cur_time;
			if (cur_timeout <= 0 &&
			    qosify_map_entry_refresh_timeout(e))
				cur_timeout = e->timeout - cur_time;
			if (cur_timeout <= 0) {
				e->data.user = false;
				e->data.dscp = e->data.file_dscp;
			} else if (!timeout || cur_timeout < timeout) {
				timeout = cur_timeout;
				next_timeout = e->timeout;
			}
		}

		if (e->data.file || e->data.user)
			continue;

		qosify_map_free_entry(e);
	}

	if (!timeout)
		return;

	uloop_timeout_set(&qosify_map_timer, timeout * 1000);
}


int qosify_map_add_dns_host(char *host, const char *addr, const char *type, int ttl)
{
	struct qosify_map_data data = {
		.id = CL_MAP_DNS,
		.addr.dns.pattern = "",
	};
	struct qosify_map_entry *e;
	int prev_timeout = qosify_map_timeout;
	char *c;

	e = avl_find_ge_element(&map_data, &data, e, avl);
	if (!e)
		return 0;

	memset(&data, 0, sizeof(data));
	data.user = true;
	if (!strcmp(type, "A"))
		data.id = CL_MAP_IPV4_ADDR;
	else if (!strcmp(type, "AAAA"))
		data.id = CL_MAP_IPV6_ADDR;
	else
		return 0;

	if (qosify_map_fill_ip(&data, addr))
		return -1;

	for (c = host; *c; c++)
		*c = tolower(*c);

	avl_for_element_to_last(&map_data, e, e, avl) {
		regex_t *regex = &e->data.addr.dns.regex;

		if (e->data.id != CL_MAP_DNS)
			return 0;

		if (e->data.addr.dns.pattern[0] == '/') {
			if (regexec(regex, host, 0, NULL, 0) != 0)
				continue;
		} else {
			if (fnmatch(e->data.addr.dns.pattern, host, 0))
				continue;
		}

		if (ttl)
			qosify_map_timeout = ttl;
		data.dscp = e->data.dscp;
		__qosify_map_set_entry(&data);
		qosify_map_timeout = prev_timeout;
	}

	return 0;
}

static void
blobmsg_add_dscp(struct blob_buf *b, const char *name, uint8_t dscp)
{
	int buf_len = 8;
	char *buf;

	if (dscp & QOSIFY_DSCP_CLASS_FLAG) {
		const char *val;
		int idx;

		idx = dscp & QOSIFY_DSCP_VALUE_MASK;
		if (map_class[idx])
			val = map_class[idx]->name;
		else
			val = "<invalid>";

		blobmsg_printf(b, name, "%s%s",
			       (dscp & QOSIFY_DSCP_FALLBACK_FLAG) ? "+" : "", val);
		return;
	}

	buf = blobmsg_alloc_string_buffer(b, name, buf_len);
	qosify_map_dscp_codepoint_str(buf, buf_len, dscp);
	blobmsg_add_string_buffer(b);
}


void qosify_map_dump(struct blob_buf *b)
{
	struct qosify_map_entry *e;
	uint32_t cur_time = qosify_gettime();
	int buf_len = INET6_ADDRSTRLEN + 1;
	char *buf;
	void *a;
	int af;

	a = blobmsg_open_array(b, "entries");
	avl_for_each_element(&map_data, e, avl) {
		void *c;

		if (!e->data.file && !e->data.user)
			continue;

		c = blobmsg_open_table(b, NULL);
		if (e->data.user && e->timeout != ~0) {
			int32_t cur_timeout = e->timeout - cur_time;

			if (cur_timeout < 0)
				cur_timeout = 0;

			blobmsg_add_u32(b, "timeout", cur_timeout);
		}

		blobmsg_add_u8(b, "file", e->data.file);
		blobmsg_add_u8(b, "user", e->data.user);

		blobmsg_add_dscp(b, "dscp", e->data.dscp);

		blobmsg_add_string(b, "type", qosify_map_info[e->data.id].type_name);

		switch (e->data.id) {
		case CL_MAP_TCP_PORTS:
		case CL_MAP_UDP_PORTS:
			blobmsg_printf(b, "addr", "%d", ntohs(e->data.addr.port));
			break;
		case CL_MAP_IPV4_ADDR:
		case CL_MAP_IPV6_ADDR:
			buf = blobmsg_alloc_string_buffer(b, "addr", buf_len);
			af = e->data.id == CL_MAP_IPV6_ADDR ? AF_INET6 : AF_INET;
			inet_ntop(af, &e->data.addr, buf, buf_len);
			blobmsg_add_string_buffer(b);
			break;
		case CL_MAP_DNS:
			blobmsg_add_string(b, "addr", e->data.addr.dns.pattern);
			break;
		default:
			break;
		}
		blobmsg_close_table(b, c);
	}
	blobmsg_close_array(b, a);
}

static int32_t
qosify_map_get_class_id(const char *name)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(map_class); i++)
		if (map_class[i] && !strcmp(map_class[i]->name, name))
			return i;

	for (i = 0; i < ARRAY_SIZE(map_class); i++)
		if (!map_class[i])
			return i;

	for (i = 0; i < ARRAY_SIZE(map_class); i++) {
		if (!(map_class[i]->data.flags & QOSIFY_CLASS_FLAG_PRESENT)) {
			free(map_class[i]);
			map_class[i] = NULL;
			return i;
		}
	}

	return -1;
}

int map_fill_dscp_value(uint8_t *dest, struct blob_attr *attr, bool reset)
{
	if (reset)
		 *dest = 0xff;

	if (!attr)
		return 0;

	if (qosify_map_dscp_value(blobmsg_get_string(attr), dest))
		return -1;

	return 0;
}

int map_parse_flow_config(struct qosify_flow_config *cfg, struct blob_attr *attr,
			  bool reset)
{
	enum {
		CL_CONFIG_DSCP_PRIO,
		CL_CONFIG_DSCP_BULK,
		CL_CONFIG_BULK_TIMEOUT,
		CL_CONFIG_BULK_PPS,
		CL_CONFIG_PRIO_PKT_LEN,
		__CL_CONFIG_MAX
	};
	static const struct blobmsg_policy policy[__CL_CONFIG_MAX] = {
		[CL_CONFIG_DSCP_PRIO] = { "dscp_prio", BLOBMSG_TYPE_STRING },
		[CL_CONFIG_DSCP_BULK] = { "dscp_bulk", BLOBMSG_TYPE_STRING },
		[CL_CONFIG_BULK_TIMEOUT] = { "bulk_trigger_timeout", BLOBMSG_TYPE_INT32 },
		[CL_CONFIG_BULK_PPS] = { "bulk_trigger_pps", BLOBMSG_TYPE_INT32 },
		[CL_CONFIG_PRIO_PKT_LEN] = { "prio_max_avg_pkt_len", BLOBMSG_TYPE_INT32 },
	};
	struct blob_attr *tb[__CL_CONFIG_MAX];
	struct blob_attr *cur;

	if (reset)
	    memset(cfg, 0, sizeof(*cfg));

	blobmsg_parse(policy, __CL_CONFIG_MAX, tb, blobmsg_data(attr), blobmsg_len(attr));

	if (map_fill_dscp_value(&cfg->dscp_prio, tb[CL_CONFIG_DSCP_PRIO], reset) ||
	    map_fill_dscp_value(&cfg->dscp_bulk, tb[CL_CONFIG_DSCP_BULK], reset))
		return -1;

	if ((cur = tb[CL_CONFIG_BULK_TIMEOUT]) != NULL)
		cfg->bulk_trigger_timeout = blobmsg_get_u32(cur);

	if ((cur = tb[CL_CONFIG_BULK_PPS]) != NULL)
		cfg->bulk_trigger_pps = blobmsg_get_u32(cur);

	if ((cur = tb[CL_CONFIG_PRIO_PKT_LEN]) != NULL)
		cfg->prio_max_avg_pkt_len = blobmsg_get_u32(cur);

	return 0;
}

static int
qosify_map_create_class(struct blob_attr *attr)
{
	struct qosify_map_class *class;
	enum {
		MAP_CLASS_INGRESS,
		MAP_CLASS_EGRESS,
		__MAP_CLASS_MAX
	};
	static const struct blobmsg_policy policy[__MAP_CLASS_MAX] = {
		[MAP_CLASS_INGRESS] = { "ingress", BLOBMSG_TYPE_STRING },
		[MAP_CLASS_EGRESS] = { "egress", BLOBMSG_TYPE_STRING },
	};
	struct blob_attr *tb[__MAP_CLASS_MAX];
	const char *name;
	char *name_buf;
	int32_t slot;

	blobmsg_parse(policy, __MAP_CLASS_MAX, tb,
		      blobmsg_data(attr), blobmsg_len(attr));

	if (!tb[MAP_CLASS_INGRESS] || !tb[MAP_CLASS_EGRESS])
		return -1;

	name = blobmsg_name(attr);
	slot = qosify_map_get_class_id(name);
	if (slot < 0)
		return -1;

	class = map_class[slot];
	if (!class) {
		class = calloc_a(sizeof(*class), &name_buf, strlen(name) + 1);
		class->name = strcpy(name_buf, name);
		map_class[slot] = class;
	}

	class->data.flags |= QOSIFY_CLASS_FLAG_PRESENT;
	if (__qosify_map_dscp_value(blobmsg_get_string(tb[MAP_CLASS_INGRESS]),
				    &class->data.val.ingress) ||
	    __qosify_map_dscp_value(blobmsg_get_string(tb[MAP_CLASS_EGRESS]),
				    &class->data.val.egress)) {
		map_class[slot] = NULL;
		free(class);
		return -1;
	}

	return 0;
}

void qosify_map_set_classes(struct blob_attr *val)
{
	int fd = qosify_map_fds[CL_MAP_CLASS];
	struct qosify_class empty_data = {};
	struct blob_attr *cur;
	int32_t i;
	int rem;

	for (i = 0; i < ARRAY_SIZE(map_class); i++)
		if (map_class[i])
			map_class[i]->data.flags &= ~QOSIFY_CLASS_FLAG_PRESENT;

	blobmsg_for_each_attr(cur, val, rem)
		qosify_map_create_class(cur);

	for (i = 0; i < ARRAY_SIZE(map_class); i++) {
		if (map_class[i] &&
		    (map_class[i]->data.flags & QOSIFY_CLASS_FLAG_PRESENT))
			continue;

		free(map_class[i]);
		map_class[i] = NULL;
	}

	blobmsg_for_each_attr(cur, val, rem) {
		i = qosify_map_get_class_id(blobmsg_name(cur));
		if (i < 0 || !map_class[i])
			continue;

		map_parse_flow_config(&map_class[i]->data.config, cur, true);
	}

	for (i = 0; i < ARRAY_SIZE(map_class); i++) {
		struct qosify_class *data;

		data = map_class[i] ? &map_class[i]->data : &empty_data;
		bpf_map_update_elem(fd, &i, data, BPF_ANY);
	}
}

void qosify_map_update_config(void)
{
	int fd = qosify_map_fds[CL_MAP_CONFIG];
	uint32_t key = 0;

	bpf_map_update_elem(fd, &key, &config, BPF_ANY);
}
