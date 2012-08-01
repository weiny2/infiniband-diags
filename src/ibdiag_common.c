/*
 * Copyright (c) 2006-2007 The Regents of the University of California.
 * Copyright (c) 2004-2009 Voltaire, Inc. All rights reserved.
 * Copyright (c) 2002-2010 Mellanox Technologies LTD. All rights reserved.
 * Copyright (c) 1996-2003 Intel Corporation. All rights reserved.
 * Copyright (c) 2009 HNR Consulting. All rights reserved.
 * Copyright (c) 2011 Lawrence Livermore National Security. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

/**
 * Define common functions which can be included in the various C based diags.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>
#include <config.h>
#include <getopt.h>
#include <limits.h>
#include <sys/stat.h>
#include <stdarg.h>

#include <infiniband/umad.h>
#include <infiniband/mad.h>
#include <ibdiag_common.h>
#include <ibdiag_version.h>

int ibverbose;
enum MAD_DEST ibd_dest_type = IB_DEST_LID;
ib_portid_t *ibd_sm_id;
static ib_portid_t sm_portid = { 0 };

/* general config options */
#define IBDIAG_CONFIG_GENERAL IBDIAG_CONFIG_PATH"/ibdiag.conf"
char *ibd_ca = NULL;
int ibd_ca_port = 0;
int ibd_timeout = 0;
uint32_t ibd_ibnetdisc_flags = IBND_CONFIG_MLX_EPI;
uint64_t ibd_mkey;
uint64_t ibd_sakey = 0;
int show_keys = 0;

static const char *prog_name;
static const char *prog_args;
static const char **prog_examples;
static struct option *long_opts = NULL;
static const struct ibdiag_opt *opts_map[256];

const static char *get_build_version(void)
{
	return "BUILD VERSION: " IBDIAG_VERSION " Build date: " __DATE__ " "
	    __TIME__;
}

static void pretty_print(int start, int width, const char *str)
{
	int len = width - start;
	const char *p, *e;

	while (1) {
		while (isspace(*str))
			str++;
		p = str;
		do {
			e = p + 1;
			p = strchr(e, ' ');
		} while (p && p - str < len);
		if (!p) {
			fprintf(stderr, "%s", str);
			break;
		}
		if (e - str == 1)
			e = p;
		fprintf(stderr, "%.*s\n%*s", (int)(e - str), str, start, "");
		str = e;
	}
}

static inline int val_str_true(const char *val_str)
{
	return ((strncmp(val_str, "TRUE", strlen("TRUE")) == 0) ||
		(strncmp(val_str, "true", strlen("true")) == 0));
}

void read_ibdiag_config(const char *file)
{
	char buf[1024];
	FILE *config_fd = NULL;
	char *p_prefix, *p_last;
	char *name;
	char *val_str;
	struct stat statbuf;

	/* silently ignore missing config file */
	if (stat(file, &statbuf))
		return;

	config_fd = fopen(file, "r");
	if (!config_fd)
		return;

	while (fgets(buf, sizeof buf, config_fd) != NULL) {
		p_prefix = strtok_r(buf, "\n", &p_last);
		if (!p_prefix)
			continue; /* ignore blank lines */

		if (*p_prefix == '#')
			continue; /* ignore comment lines */

		name = strtok_r(p_prefix, "=", &p_last);
		val_str = strtok_r(NULL, "\n", &p_last);

		if (strncmp(name, "CA", strlen("CA")) == 0) {
			free(ibd_ca);
			ibd_ca = strdup(val_str);
		} else if (strncmp(name, "Port", strlen("Port")) == 0) {
			ibd_ca_port = strtoul(val_str, NULL, 0);
		} else if (strncmp(name, "timeout", strlen("timeout")) == 0) {
			ibd_timeout = strtoul(val_str, NULL, 0);
		} else if (strncmp(name, "MLX_EPI", strlen("MLX_EPI")) == 0) {
			if (val_str_true(val_str)) {
				ibd_ibnetdisc_flags |= IBND_CONFIG_MLX_EPI;
			} else {
				ibd_ibnetdisc_flags &= ~IBND_CONFIG_MLX_EPI;
			}
		} else if (strncmp(name, "m_key", strlen("m_key")) == 0) {
			ibd_mkey = strtoull(val_str, 0, 0);
		} else if (strncmp(name, "sa_key",
				   strlen("sa_key")) == 0) {
			ibd_sakey = strtoull(val_str, 0, 0);
		}
	}

	fclose(config_fd);
}


void ibdiag_show_usage()
{
	struct option *o = long_opts;
	int n;

	fprintf(stderr, "\nUsage: %s [options] %s\n\n", prog_name,
		prog_args ? prog_args : "");

	if (long_opts[0].name)
		fprintf(stderr, "Options:\n");
	for (o = long_opts; o->name; o++) {
		const struct ibdiag_opt *io = opts_map[o->val];
		n = fprintf(stderr, "  --%s", io->name);
		if (isprint(io->letter))
			n += fprintf(stderr, ", -%c", io->letter);
		if (io->has_arg)
			n += fprintf(stderr, " %s",
				     io->arg_tmpl ? io->arg_tmpl : "<val>");
		if (io->description && *io->description) {
			n += fprintf(stderr, "%*s  ", 24 - n > 0 ? 24 - n : 0,
				     "");
			pretty_print(n, 74, io->description);
		}
		fprintf(stderr, "\n");
	}

	if (prog_examples) {
		const char **p;
		fprintf(stderr, "\nExamples:\n");
		for (p = prog_examples; *p && **p; p++)
			fprintf(stderr, "  %s %s\n", prog_name, *p);
	}

	fprintf(stderr, "\n");

	exit(2);
}

static int process_opt(int ch, char *optarg)
{
	char *endp;
	long val;

	switch (ch) {
	case 'z':
		read_ibdiag_config(optarg);
		break;
	case 'h':
		ibdiag_show_usage();
		break;
	case 'V':
		fprintf(stderr, "%s %s\n", prog_name, get_build_version());
		exit(0);
	case 'e':
		madrpc_show_errors(1);
		break;
	case 'v':
		ibverbose++;
		break;
	case 'd':
		ibdebug++;
		madrpc_show_errors(1);
		umad_debug(ibdebug - 1);
		break;
	case 'C':
		ibd_ca = optarg;
		break;
	case 'P':
		ibd_ca_port = strtoul(optarg, 0, 0);
		break;
	case 'D':
		ibd_dest_type = IB_DEST_DRPATH;
		break;
	case 'L':
		ibd_dest_type = IB_DEST_LID;
		break;
	case 'G':
		ibd_dest_type = IB_DEST_GUID;
		break;
	case 't':
		errno = 0;
		val = strtol(optarg, &endp, 0);
		if (errno || (endp && *endp != '\0') || val <= 0 ||
		    val > INT_MAX)
			IBERROR("Invalid timeout \"%s\".  Timeout requires a "
				"positive integer value < %d.", optarg, INT_MAX);
		else {
			madrpc_set_timeout((int)val);
			ibd_timeout = (int)val;
		}
		break;
	case 's':
		/* srcport is not required when resolving via IB_DEST_LID */
		if (resolve_portid_str(ibd_ca, ibd_ca_port, &sm_portid, optarg,
				IB_DEST_LID, 0, NULL) < 0)
			IBERROR("cannot resolve SM destination port %s",
				optarg);
		ibd_sm_id = &sm_portid;
		break;
	case 'K':
		show_keys = 1;
		break;
	case 'y':
		errno = 0;
		ibd_mkey = strtoull(optarg, &endp, 0);
		if (errno || *endp != '\0') {
			errno = 0;
			ibd_mkey = strtoull(getpass("M_Key: "), &endp, 0);
			if (errno || *endp != '\0') {
				IBERROR("Bad M_Key");
			}
                }
                break;
	default:
		return -1;
	}

	return 0;
}

static const struct ibdiag_opt common_opts[] = {
	{"config", 'z', 1, "<config>", "use config file, default: " IBDIAG_CONFIG_GENERAL},
	{"Ca", 'C', 1, "<ca>", "Ca name to use"},
	{"Port", 'P', 1, "<port>", "Ca port number to use"},
	{"Direct", 'D', 0, NULL, "use Direct address argument"},
	{"Lid", 'L', 0, NULL, "use LID address argument"},
	{"Guid", 'G', 0, NULL, "use GUID address argument"},
	{"timeout", 't', 1, "<ms>", "timeout in ms"},
	{"sm_port", 's', 1, "<lid>", "SM port lid"},
	{"show_keys", 'K', 0, NULL, "display security keys in output"},
	{"m_key", 'y', 1, "<key>", "M_Key to use in request"},
	{"errors", 'e', 0, NULL, "show send and receive errors"},
	{"verbose", 'v', 0, NULL, "increase verbosity level"},
	{"debug", 'd', 0, NULL, "raise debug level"},
	{"help", 'h', 0, NULL, "help message"},
	{"version", 'V', 0, NULL, "show version"},
	{0}
};

static void make_opt(struct option *l, const struct ibdiag_opt *o,
		     const struct ibdiag_opt *map[])
{
	l->name = o->name;
	l->has_arg = o->has_arg;
	l->flag = NULL;
	l->val = o->letter;
	if (!map[l->val])
		map[l->val] = o;
}

static struct option *make_long_opts(const char *exclude_str,
				     const struct ibdiag_opt *custom_opts,
				     const struct ibdiag_opt *map[])
{
	struct option *long_opts, *l;
	const struct ibdiag_opt *o;
	unsigned n = 0;

	if (custom_opts)
		for (o = custom_opts; o->name; o++)
			n++;

	long_opts = malloc((sizeof(common_opts) / sizeof(common_opts[0]) + n) *
			   sizeof(*long_opts));
	if (!long_opts)
		return NULL;

	l = long_opts;

	if (custom_opts)
		for (o = custom_opts; o->name; o++)
			make_opt(l++, o, map);

	for (o = common_opts; o->name; o++) {
		if (exclude_str && strchr(exclude_str, o->letter))
			continue;
		make_opt(l++, o, map);
	}

	memset(l, 0, sizeof(*l));

	return long_opts;
}

static void make_str_opts(const struct option *o, char *p, unsigned size)
{
	unsigned i, n = 0;

	for (n = 0; o->name && n + 2 + o->has_arg < size; o++) {
		p[n++] = (char)o->val;
		for (i = 0; i < (unsigned)o->has_arg; i++)
			p[n++] = ':';
	}
	p[n] = '\0';
}

int ibdiag_process_opts(int argc, char *const argv[], void *cxt,
			const char *exclude_common_str,
			const struct ibdiag_opt custom_opts[],
			int (*custom_handler) (void *cxt, int val,
					       char *optarg),
			const char *usage_args, const char *usage_examples[])
{
	char str_opts[1024];
	const struct ibdiag_opt *o;

	prog_name = argv[0];
	prog_args = usage_args;
	prog_examples = usage_examples;

	if (long_opts)
		free(long_opts);

	long_opts = make_long_opts(exclude_common_str, custom_opts, opts_map);
	if (!long_opts)
		return -1;

	read_ibdiag_config(IBDIAG_CONFIG_GENERAL);

	make_str_opts(long_opts, str_opts, sizeof(str_opts));

	while (1) {
		int ch = getopt_long(argc, argv, str_opts, long_opts, NULL);
		if (ch == -1)
			break;
		o = opts_map[ch];
		if (!o)
			ibdiag_show_usage();
		if (custom_handler) {
			if (custom_handler(cxt, ch, optarg) &&
			    process_opt(ch, optarg))
				ibdiag_show_usage();
		} else if (process_opt(ch, optarg))
			ibdiag_show_usage();
	}

	return 0;
}

void iberror(const char *fn, char *msg, ...)
{
	char buf[512];
	va_list va;
	int n;

	va_start(va, msg);
	n = vsprintf(buf, msg, va);
	va_end(va);
	buf[n] = 0;

	if (ibdebug)
		printf("%s: iberror: [pid %d] %s: failed: %s\n",
		       prog_name ? prog_name : "", getpid(), fn, buf);
	else
		printf("%s: iberror: failed: %s\n",
		       prog_name ? prog_name : "", buf);

	exit(-1);
}

char *
conv_cnt_human_readable(uint64_t val64, float *val, int data)
{
	uint64_t tmp = val64;
	int ui = 0;
	int div = 1;

	tmp /= 1024;
	while (tmp) {
		ui++;
		tmp /= 1024;
		div *= 1024;
	}

	*val = (float)(val64);
	if (data) {
		*val *= 4;
		if (*val/div > 1024) {
			ui++;
			div *= 1024;
		}
	}
	*val /= div;

	if (data) {
		switch (ui) {
			case 0:
				return ("B");
			case 1:
				return ("KB");
			case 2:
				return ("MB");
			case 3:
				return ("GB");
			case 4:
				return ("TB");
			case 5:
				return ("PB");
			case 6:
				return ("EB");
			default:
				return ("");
		}
	} else {
		switch (ui) {
			case 0:
				return ("");
			case 1:
				return ("K");
			case 2:
				return ("M");
			case 3:
				return ("G");
			case 4:
				return ("T");
			case 5:
				return ("P");
			case 6:
				return ("E");
			default:
				return ("");
		}
	}
	return ("");
}

int is_mlnx_ext_port_info_supported(uint32_t devid)
{
	if (ibd_ibnetdisc_flags & IBND_CONFIG_MLX_EPI) {
		if (devid == 0xc738)
			return 1;
		if (devid >= 0x1003 && devid <= 0x1011)
			return 1;
	}
	return 0;
}

/** =========================================================================
 * Resolve the SM portid using the umad layer rather than using
 * ib_resolve_smlid_via which requires a PortInfo query on the local port.
 */
int resolve_sm_portid(char *ca_name, uint8_t portnum, ib_portid_t *sm_id)
{
	umad_port_t port;
	int rc;

	if (!sm_id)
		return (-1);

	if ((rc = umad_get_port(ca_name, portnum, &port)) < 0)
		return rc;

	memset(sm_id, 0, sizeof(*sm_id));
	sm_id->lid = port.sm_lid;
	sm_id->sl = port.sm_sl;

	umad_release_port(&port);

	return 0;
}

/** =========================================================================
 * Resolve local CA characteristics using the umad layer rather than using
 * ib_resolve_self_via which requires SMP queries on the local port.
 */
int resolve_self(char *ca_name, uint8_t ca_port, ib_portid_t *portid,
		 int *portnum, ibmad_gid_t *gid)
{
	umad_port_t port;
	uint64_t prefix, guid;
	int rc;

	if (!(portid || portnum || gid))
		return (-1);

	if ((rc = umad_get_port(ca_name, ca_port, &port)) < 0)
		return rc;

	if (portid) {
		memset(portid, 0, sizeof(*portid));
		portid->lid = port.base_lid;
		portid->sl = port.sm_sl;
	}
	if (portnum)
		*portnum = port.portnum;
	if (gid) {
		memset(gid, 0, sizeof(*gid));
		prefix = cl_hton64(port.gid_prefix);
		guid = cl_hton64(port.port_guid);
		mad_encode_field(*gid, IB_GID_PREFIX_F, &prefix);
		mad_encode_field(*gid, IB_GID_GUID_F, &guid);
	}

	umad_release_port(&port);

	return 0;
}

int resolve_gid(char *ca_name, uint8_t ca_port, ib_portid_t * portid,
		ibmad_gid_t gid, ib_portid_t * sm_id,
		const struct ibmad_port *srcport)
{
	ib_portid_t sm_portid;
	char buf[IB_SA_DATA_SIZE] = { 0 };

	if (!sm_id) {
		sm_id = &sm_portid;
		if (resolve_sm_portid(ca_name, ca_port, sm_id) < 0)
			return -1;
	}

	if ((portid->lid =
	     ib_path_query_via(srcport, gid, gid, sm_id, buf)) < 0)
		return -1;

	return 0;
}

int resolve_guid(char *ca_name, uint8_t ca_port, ib_portid_t *portid,
		 uint64_t *guid, ib_portid_t *sm_id,
		 const struct ibmad_port *srcport)
{
	ib_portid_t sm_portid;
	uint8_t buf[IB_SA_DATA_SIZE] = { 0 };
	uint64_t prefix;
	ibmad_gid_t selfgid;

	if (!sm_id) {
		sm_id = &sm_portid;
		if (resolve_sm_portid(ca_name, ca_port, sm_id) < 0)
			return -1;
	}

	if (resolve_self(ca_name, ca_port, NULL, NULL, &selfgid) < 0)
		return -1;

	memcpy(&prefix, portid->gid, sizeof(prefix));
	if (!prefix)
		mad_set_field64(portid->gid, 0, IB_GID_PREFIX_F,
				IB_DEFAULT_SUBN_PREFIX);
	if (guid)
		mad_set_field64(portid->gid, 0, IB_GID_GUID_F, *guid);

	if ((portid->lid =
	     ib_path_query_via(srcport, selfgid, portid->gid, sm_id, buf)) < 0)
		return -1;

	mad_decode_field(buf, IB_SA_PR_SL_F, &portid->sl);
	return 0;
}

/*
 * Callers of this function should ensure their ibmad_port has been opened with
 * IB_SA_CLASS as this function may require the SA to resolve addresses.
 */
int resolve_portid_str(char *ca_name, uint8_t ca_port, ib_portid_t * portid,
		       char *addr_str, enum MAD_DEST dest_type,
		       ib_portid_t *sm_id, const struct ibmad_port *srcport)
{
	ibmad_gid_t gid;
	uint64_t guid;
	int lid;
	char *routepath;
	ib_portid_t selfportid = { 0 };
	int selfport = 0;

	memset(portid, 0, sizeof *portid);

	switch (dest_type) {
	case IB_DEST_LID:
		lid = strtol(addr_str, 0, 0);
		if (!IB_LID_VALID(lid))
			return -1;
		return ib_portid_set(portid, lid, 0, 0);

	case IB_DEST_DRPATH:
		if (str2drpath(&portid->drpath, addr_str, 0, 0) < 0)
			return -1;
		return 0;

	case IB_DEST_GUID:
		if (!(guid = strtoull(addr_str, 0, 0)))
			return -1;

		/* keep guid in portid? */
		return resolve_guid(ca_name, ca_port, portid, &guid, sm_id,
				    srcport);

	case IB_DEST_DRSLID:
		lid = strtol(addr_str, &routepath, 0);
		routepath++;
		if (!IB_LID_VALID(lid))
			return -1;
		ib_portid_set(portid, lid, 0, 0);

		/* handle DR parsing and set DrSLID to local lid */
		if (resolve_self(ca_name, ca_port, &selfportid, &selfport,
				 NULL) < 0)
			return -1;
		if (str2drpath(&portid->drpath, routepath, selfportid.lid, 0) <
		    0)
			return -1;
		return 0;

	case IB_DEST_GID:
		if (inet_pton(AF_INET6, addr_str, &gid) <= 0)
			return -1;
		return resolve_gid(ca_name, ca_port, portid, gid, sm_id,
				   srcport);
	default:
		IBWARN("bad dest_type %d", dest_type);
	}

	return -1;
}

/* define a common SA query structure
 * This is by no means optimal but it moves the saquery functionality out of
 * the saquery tool and provides it to other utilities.
 */
/* =========================================================================
 * Begin HACK RDMA code
 * ========================================================================= */

/** =========================================================================
 * Issues
 *    1) Packet Sequence numbers on both QPs?  (Always start at 0?)
 *    2) need to have a full path record to the SA.  Most efficient if the SM
 *       would program that in addition to the QPN
 *       ie what is mtu?
 *    3) How does the client know the buffer size (num records) being returned?
 *       The SA does not indicate the number of records returned in a
 *       SubnAdmGetTableResp does it?
 *    4) Have to pass QPN and ETH info (local address, rkey, and length) in the
 *       query.  I don't see room in the header for this.
 *       OK I see Sean proposes to add this to the end of the query.
 *       Define "struct sa_eth_info" for this purpose
 */

#include <infiniband/verbs.h>
#include <infiniband/sa.h>

#define SA_RDMA_REQUEST (CL_HTON16(0x0001))
#define SA_RDMA_COMPLETE (0x0009)
#define SA_RECV_WRID (uint64_t)(0xDEADBEEF)

/* this is the struct defining the SA client information passed to the SA */
struct sa_eth_info {
	uint32_t qpn;
	uint64_t addr;
	uint32_t r_key;
	uint32_t length;
} __attribute__((packed));

/* This is the information the SA sends at the end of the packet to tell the
 * client information about the data sent */
struct sa_rdma_res_info {
	uint32_t length;
} __attribute__((packed));

//typedef struct sa_rdma_ctx;
struct rdma_conn {
	struct sa_rdma_ctx     *ctx;
	struct ibv_sa_path_rec  path;
	struct ibv_qp          *qp;
	uint32_t                rqpn;
};
static struct sa_rdma_ctx {
	char                    *device_name;
	int                      device_port;
	struct ibv_context      *dev_ctx;
	struct ibv_pd           *pd;
	/* perhaps will want to have a separate CQ for each QP */
	struct ibv_cq           *cq;
	struct ibv_comp_channel *comp_ch;
	struct rdma_conn         conn;

	/* FIXME for now hack these here */
	uint8_t  sa_mtu;
	uint8_t  sa_sl;
	uint8_t  sa_dlid;
} rdma_ctx;

int sa_rdma_config_qp_path(struct rdma_conn *conn)
{
	conn->path.mtu = rdma_ctx.sa_mtu;
	conn->path.sl = rdma_ctx.sa_sl;
	conn->path.dlid = rdma_ctx.sa_dlid;
	return (0);
}

int sa_rdma_connect_qp(struct rdma_conn *conn, uint32_t rqpn)
{
	conn->rqpn = rqpn;

	struct ibv_qp_attr attr = {
		.qp_state		= IBV_QPS_RTR,
		.path_mtu		= conn->path.mtu,
		.dest_qp_num		= conn->rqpn,
		.rq_psn			= 1,
		.max_dest_rd_atomic	= 1,
		.min_rnr_timer		= 12,
		.ah_attr		= {
			.is_global	= 0,
			.dlid		= conn->path.dlid,
			.sl		= conn->path.sl,
			.src_path_bits	= 0,
			.port_num	= rdma_ctx.device_port
		}
	};

	if (ibv_modify_qp(conn->qp, &attr,
			  IBV_QP_STATE              |
			  IBV_QP_PATH_MTU           |
			  IBV_QP_DEST_QPN           |
			  IBV_QP_RQ_PSN             |
			  IBV_QP_MAX_DEST_RD_ATOMIC |
			  IBV_QP_MIN_RNR_TIMER      |
			  IBV_QP_AV)) {
		fprintf(stderr, "Failed to modify QP to RTR\n");
		return 1;
	}

	attr.qp_state	     = IBV_QPS_RTS;
	attr.timeout	     = 14;
	attr.retry_cnt	     = 7;
	attr.rnr_retry	     = 7;
	attr.sq_psn	     = 1;
	attr.max_rd_atomic   = 1;
	if (ibv_modify_qp(conn->qp, &attr,
			  IBV_QP_STATE              |
			  IBV_QP_TIMEOUT            |
			  IBV_QP_RETRY_CNT          |
			  IBV_QP_RNR_RETRY          |
			  IBV_QP_SQ_PSN             |
			  IBV_QP_MAX_QP_RD_ATOMIC)) {
		fprintf(stderr, "Failed to modify QP to RTS\n");
		return 1;
	}

	IBWARN("QPn %u connected to SA QPn %u (SM LID: %u; SL %d; mtu %d)\n",
		conn->qp->qp_num, conn->rqpn,
			conn->path.dlid,
			conn->path.sl,
			conn->path.mtu
				);
	return 0;
}

/* register the buffer and post a recieve for it */
struct rdma_memory *sa_rdma_malloc(struct ibv_pd *pd, size_t size)
{
	struct rdma_memory *rc = malloc(sizeof(*rc));
	if (!rc)
		return (NULL);

	rc->buf = calloc(1, size);
	if (!rc->buf) {
		free(rc);
		return (NULL);
	}

	rc->size = size;
	rc->mr = ibv_reg_mr(pd, rc->buf, rc->size,
				IBV_ACCESS_LOCAL_WRITE |
				IBV_ACCESS_REMOTE_READ |
				IBV_ACCESS_REMOTE_WRITE);
	if (!rc->mr) {
		free(rc);
		free(rc->buf);
		return (NULL);
	}
	return (rc);
}

void sa_rdma_free(struct rdma_memory *mem)
{
	ibv_dereg_mr(mem->mr);
	free(mem->buf);
	free(mem);
}

int sa_rdma_post_recv(struct rdma_conn *conn, struct rdma_memory *buf)
{
	struct ibv_sge list = {
		.addr	= (uintptr_t) buf->buf,
		.length = buf->size,
		.lkey	= buf->mr->lkey
	};
	struct ibv_recv_wr wr = {
		.wr_id	    = SA_RECV_WRID,
		.sg_list    = &list,
		.num_sge    = 1,
	};
	struct ibv_recv_wr *bad_wr;

	if (ibv_post_recv(conn->qp, &wr, &bad_wr))
		return (-EFAULT);

	return (0);
}

int sa_rdma_wait_completion(struct rdma_conn *conn)
{
	struct ibv_cq *cq = rdma_ctx.cq;
	struct ibv_wc wc;
	int rc = 0;
	int timeout = 1;

	if (rdma_ctx.comp_ch) {
		ibv_get_cq_event(rdma_ctx.comp_ch, &cq, NULL);
		ibv_ack_cq_events(cq, 1);
		ibv_req_notify_cq(cq, 0);
	}
	do {
		rc = ibv_poll_cq(cq, 1, &wc);
		if (rc == 0) {
			sleep(1);
		}
	} while (rc == 0 && timeout-- > 0);

	if (rc <= 0 || wc.status != IBV_WC_SUCCESS) {
		IBERROR("RDMA: Work Completion error, rc %d; status: 0x%x\n",
				rc,
				ibv_wc_status_str(wc.status));
	}

	return (0);
}

int sa_rdma_create_qp(void)
{
	struct ibv_qp *qp;

	struct ibv_qp_init_attr attr = {
		.send_cq = rdma_ctx.cq,
		.recv_cq = rdma_ctx.cq,
		.cap     = {
			.max_send_wr  = 10,
			.max_recv_wr  = 10,
			.max_send_sge = 1,
			.max_recv_sge = 1
		},
		.qp_type = IBV_QPT_RC
	};
	
	qp = ibv_create_qp(rdma_ctx.pd, &attr);
	if (!qp) {
		IBERROR("RDMA: Failed to create QP\n");
		return (-ENOMEM);
	}

	{
		struct ibv_qp_attr attr = {
			.qp_state        = IBV_QPS_INIT,
			.pkey_index      = 0,
			.port_num	 = rdma_ctx.device_port,
			.qp_access_flags = IBV_ACCESS_REMOTE_WRITE |
					   IBV_ACCESS_REMOTE_READ  |
					   IBV_ACCESS_LOCAL_WRITE
		};

		if (ibv_modify_qp(qp, &attr,
				  IBV_QP_STATE              |
				  IBV_QP_PKEY_INDEX         |
				  IBV_QP_PORT               |
				  IBV_QP_ACCESS_FLAGS)) {
			printf("%s: %d\n", rdma_ctx.device_name,
					rdma_ctx.device_port);
			IBERROR("RDMA: Failed to modify QP to INIT\n");
			return (-ENOMEM);
		}
	}

	rdma_ctx.conn.qp = qp;

	IBWARN("QPn = %u\n", rdma_ctx.conn.qp->qp_num);
	return (0);
}

int sa_rdma_init(uint8_t sa_mtu, uint8_t sa_sl, uint16_t sa_dlid)
{
	struct ibv_device *dev = NULL;
	struct ibv_device **dev_list; 
	int num_dev;
	int i;

	memset(&rdma_ctx, 0, sizeof(rdma_ctx));

	rdma_ctx.device_name = ibd_ca;
	rdma_ctx.device_port = ibd_ca_port;
	rdma_ctx.sa_mtu = sa_mtu;
	rdma_ctx.sa_sl = sa_sl;
	rdma_ctx.sa_dlid = sa_dlid;

	dev_list = ibv_get_device_list(&num_dev);
	if (!dev_list) {
		IBERROR("RDMA: Failed to get device list\n");
		return (-ENODEV);
	}

	for (i = 0; i<num_dev; i++) {
		if (strcmp(dev_list[i]->name, rdma_ctx.device_name) == 0) {
			dev = dev_list[i];
			break;
		}
	}

printf("%s:%d\n", ibd_ca, ibd_ca_port);
	if (!dev) {
		IBERROR("RDMA: Failed to find RDMA device: %s\n",
			rdma_ctx.device_name);
fprintf(stderr, "RDMA: Failed to find RDMA device: %s\n",
			rdma_ctx.device_name);
		return (-ENODEV);
	}

	rdma_ctx.dev_ctx = ibv_open_device(dev);
	if (!rdma_ctx.dev_ctx) {
		IBERROR("RDMA: Failed to open device: %s\n",
				ibv_get_device_name(dev));
		return (-ENODEV);
	}

	// not sure why this works here.
	// but it might not be ok to do this
	//ibv_free_device_list(dev_list);

#if 0
	rdma_ctx.comp_ch = ibv_create_comp_channel(rdma_ctx.dev_ctx);
	if (!rdma_ctx.comp_ch) {
		IBERROR("RDMA: Failed to create completion channel: %s\n", dev->name);
		goto CloseDevice;
	}
	#endif
	rdma_ctx.comp_ch = NULL;

	rdma_ctx.cq = ibv_create_cq(rdma_ctx.dev_ctx, 1000,
			     (void *)&rdma_ctx,
			     rdma_ctx.comp_ch,
			     0);
	if (!rdma_ctx.cq) {
		IBERROR("RDMA: Failed to create CQ: %s\n",
				ibv_get_device_name(dev));
		goto DestroyCompCh;
	}

	if ((ibv_req_notify_cq(rdma_ctx.cq, 0)) != 0) {
		IBERROR("RDMA: Request Notify CQ failed: %s\n",
				ibv_get_device_name(dev));
		goto DestroyCQ;
	}

	rdma_ctx.pd = ibv_alloc_pd(rdma_ctx.dev_ctx);
	if (!rdma_ctx.pd) {
		IBERROR("RDMA: Failed to allocate the PD: %s\n",
				ibv_get_device_name(dev));
		goto DestroyCQ;
	}

	IBWARN("SA Query RDMA configured on %s:%d (SM LID: %u; SL %d; mtu %d)\n",
				ibv_get_device_name(dev),
				rdma_ctx.device_port,
				rdma_ctx.sa_dlid,
				rdma_ctx.sa_sl,
				rdma_ctx.sa_mtu
				);
	return (sa_rdma_create_qp());

DestroyCQ:
	ibv_destroy_cq(rdma_ctx.cq);
DestroyCompCh:
	if (rdma_ctx.comp_ch)
		ibv_destroy_comp_channel(rdma_ctx.comp_ch);
//CloseDevice:
	ibv_close_device(rdma_ctx.dev_ctx);
	return (-ENOMEM);
}


int sa_rdma_close(void)
{
	ibv_dealloc_pd(rdma_ctx.pd);
	ibv_destroy_cq(rdma_ctx.cq);
	if (rdma_ctx.comp_ch)
		ibv_destroy_comp_channel(rdma_ctx.comp_ch);
	ibv_close_device(rdma_ctx.dev_ctx);
	return (0);
}


/* =========================================================================
 * END Hack RDMA code
 * ========================================================================= */

bind_handle_t sa_get_bind_handle(uint32_t sa_qpn, uint8_t sa_mtu,
				uint32_t rdma_size_mb)
{
	bind_handle_t handle;
	handle = calloc(1, sizeof(*handle));
	if (!handle)
		IBPANIC("calloc failed");

	handle->rdma_size_mb = rdma_size_mb ? rdma_size_mb : 1;

	resolve_sm_portid(ibd_ca, ibd_ca_port, &handle->dport);
	if (!handle->dport.lid) {
		IBWARN("No SM/SA found on port %s:%d",
			ibd_ca ? "" : ibd_ca,
			ibd_ca_port);
		free(handle);
		return (NULL);
	}

	if (sa_qpn) {
		if (sa_rdma_init(sa_mtu, handle->dport.sl, handle->dport.lid)) {
			IBWARN("Failed to init RDMA\n");
		}
		if (sa_rdma_config_qp_path(&rdma_ctx.conn)) {
			IBWARN("Failed to init RDMA connection path\n");
		}
		if (sa_rdma_connect_qp(&rdma_ctx.conn, sa_qpn)) {
			IBWARN("Failed to connect RC QP\n");
		}
		handle->use_rdma = 1;
	}

	handle->dport.qp = 1;
	if (!handle->dport.qkey)
		handle->dport.qkey = IB_DEFAULT_QP1_QKEY;

	handle->fd = umad_open_port(ibd_ca, ibd_ca_port);
	handle->agent = umad_register(handle->fd, IB_SA_CLASS, 2, 1, NULL);

	return handle;
}

void sa_free_bind_handle(bind_handle_t h)
{
	if (h->use_rdma)
		sa_rdma_close();
	umad_unregister(h->fd, h->agent);
	umad_close_port(h->fd);
	free(h);
}

int ibmad_packet_hexdump(FILE *f, uint32_t *buf, size_t n)
{
	int j = 0;
	int i = 0;
	int rc = 0;

	fprintf(f, "    -- MAD header --\n");
	for (j = 0, i = 0; i < (n/4); i++, j+=4) {
		if (j == 24)
			fprintf(f, "    -- MAD data --\n");
		rc += fprintf(f, "%4d: %08x\n", j, htonl(buf[i]));
	}
	rc += fprintf(f, "\n");
	return (rc);
}

#include <sys/time.h>
static inline void diff_time(struct timeval *before, struct timeval *after,
			     struct timeval *diff)
{
	struct timeval tmp = *after;
	if (tmp.tv_usec < before->tv_usec) {
		tmp.tv_sec--;
		tmp.tv_usec += 1000000;
	}
	diff->tv_sec = tmp.tv_sec - before->tv_sec;
	diff->tv_usec = tmp.tv_usec - before->tv_usec;
}

int sa_query(bind_handle_t h, uint8_t method,
		    uint16_t attr, uint32_t mod, uint64_t comp_mask,
		    uint64_t sm_key, void *data, size_t datasz,
		    struct sa_query_result *result)
{
	ib_rpc_t rpc;
	void *umad, *mad;
	int ret, offset, len = 256;
	struct rdma_memory *buf = NULL;

	struct timeval tv_start;
	struct timeval tv_end;
	struct timeval tv_diff;


	memset(&rpc, 0, sizeof(rpc));
	rpc.mgtclass = IB_SA_CLASS;
	rpc.method = method;
	rpc.attr.id = attr;
	rpc.attr.mod = mod;
	rpc.mask = comp_mask;
	rpc.datasz = datasz;
	rpc.dataoffs = IB_SA_DATA_OFFS;

	// len must be 256 here
	umad = calloc(1, len + umad_size());
	if (!umad)
		IBPANIC("cannot alloc mem for umad: %s\n", strerror(errno));

	// build packet as before
	mad_build_pkt(umad, &rpc, &h->dport, NULL, data);
	mad_set_field64(umad_get_mad(umad), 0, IB_SA_MKEY_F, sm_key);

	gettimeofday(&tv_start, NULL);

/* RDMA Prototype */
	if (h->use_rdma) {
		struct sa_eth_info *eth_info;
		/* set up our buffer */
		buf = sa_rdma_malloc(rdma_ctx.pd, h->rdma_size_mb*1024*1024);
		if (!buf)
			IBPANIC("Failed to register buffer\n");

#if 0
// Optional for RC QP response
		if (sa_rdma_post_recv(&rdma_ctx.conn, buf))
			IBPANIC("Failed to post recv\n");
#endif

		/* add the QPN and ETH info to the end of the query */
		mad = umad_get_mad(umad);

		((uint16_t *)mad)[9] = SA_RDMA_REQUEST;
		// add the SA eth info...
		eth_info = mad + 256 - sizeof(struct sa_eth_info);
		eth_info->qpn    = cl_hton32(rdma_ctx.conn.qp->qp_num);
		eth_info->addr   = cl_hton64((uint64_t)buf->mr->addr);
		eth_info->r_key  = cl_hton32(buf->mr->rkey);
		eth_info->length = cl_hton32(buf->mr->length);

		fprintf(stderr, "sizeof %ld; addr %"PRIx64"; rkey %x; length %lx; size %lx\n",
			sizeof(struct sa_eth_info),
			(uint64_t)buf->mr->addr,
			buf->mr->rkey,
			buf->mr->length,
			buf->size
			);
#if 0
		//ibmad_packet_hexdump(stdout, (uint32_t*)mad, 256);
#endif
	}

	if (ibdebug > 1)
		xdump(stdout, "SA Request:\n", umad_get_mad(umad), len);

	ret = umad_send(h->fd, h->agent, umad, len, ibd_timeout, 0);
	if (ret < 0) {
		IBWARN("umad_send failed: attr %u: %s\n",
			attr, strerror(errno));
		free(umad);
		return (-ret);
	}

recv_mad:
	ret = umad_recv(h->fd, umad, &len, ibd_timeout);
	if (ret < 0) {
		if (errno == ENOSPC) {
			umad = realloc(umad, umad_size() + len);
			goto recv_mad;
		}
		IBWARN("umad_recv failed: attr 0x%x: %s\n", attr,
			strerror(errno));
		free(umad);
		return (-ret);
	}

	if ((ret = umad_status(umad))) {
		free(umad);
		return ret;
	}

	mad = umad_get_mad(umad);

	//ibmad_packet_hexdump(stdout, (uint32_t*)mad, 256);
	/* set up for "normal" processing */
	result->rdma_res = NULL;

	method = (uint8_t) mad_get_field(mad, 0, IB_MAD_METHOD_F);
	offset = mad_get_field(mad, 0, IB_SA_ATTROFFS_F);
	result->status = mad_get_field(mad, 0, IB_MAD_STATUS_F);

/* prototype will return "RDMA complete" status */
	if (h->use_rdma && result->status == SA_RDMA_COMPLETE) {

#if 0
// Optional for RC QP response
		sa_rdma_wait_completion(&rdma_ctx.conn);
#endif

		/* extract the length of the data returned from status MAD */
		struct sa_rdma_res_info *tmp = mad + 256 - sizeof(struct sa_rdma_res_info);
		len = tmp->length;

		/* set up 'fake' MAD for user from the RDMA buffer here */
		mad = buf->buf;
		/* store this so we can free the result properly */
		result->rdma_res = buf;
		result->status = IB_SA_MAD_STATUS_SUCCESS;
		free(umad);
	} else if (h->use_rdma) {
		IBWARN("SA RDMA failed; status = %x\n", result->status);
	}

	if (ibdebug > 1)
		xdump(stdout, "SA Response:\n", mad, len);

	result->p_result_madw = mad;
	if (result->status != IB_SA_MAD_STATUS_SUCCESS)
		result->result_cnt = 0;
	else if (method != IB_MAD_METHOD_GET_TABLE)
		result->result_cnt = 1;
	else if (!offset)
		result->result_cnt = 0;
	else
		result->result_cnt = (len - IB_SA_DATA_OFFS) / (offset << 3);

	gettimeofday(&tv_end, NULL);
	diff_time(&tv_start, &tv_end, &tv_diff);
	fprintf(stderr, "Query complete:\n"
		"%u records in %ld.%06ld sec\n",
		result->result_cnt,
		tv_diff.tv_sec, tv_diff.tv_usec);

	return 0;
}

void sa_free_result_mad(struct sa_query_result *result)
{
	if (result->rdma_res) {
		sa_rdma_free(result->rdma_res);
	} else if (result->p_result_madw) {
		free((uint8_t *) result->p_result_madw - umad_size());
	}
	result->p_result_madw = NULL;
}

void *sa_get_query_rec(void *mad, unsigned i)
{
	int offset = mad_get_field(mad, 0, IB_SA_ATTROFFS_F);
	return (uint8_t *) mad + IB_SA_DATA_OFFS + i * (offset << 3);
}

static const char *ib_sa_error_str[] = {
	"SA_NO_ERROR",
	"SA_ERR_NO_RESOURCES",
	"SA_ERR_REQ_INVALID",
	"SA_ERR_NO_RECORDS",
	"SA_ERR_TOO_MANY_RECORDS",
	"SA_ERR_REQ_INVALID_GID",
	"SA_ERR_REQ_INSUFFICIENT_COMPONENTS",
	"SA_ERR_REQ_DENIED",
	"SA_ERR_STATUS_PRIO_SUGGESTED",
	"SA_ERR_UNKNOWN"
};

#define ARR_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define SA_ERR_UNKNOWN (ARR_SIZE(ib_sa_error_str) - 1)

static inline const char *ib_sa_err_str(IN uint8_t status)
{
	if (status > SA_ERR_UNKNOWN)
		status = SA_ERR_UNKNOWN;
	return (ib_sa_error_str[status]);
}

void sa_report_err(int status)
{
	int st = status & 0xff;
	char sm_err_str[64] = { 0 };
	char sa_err_str[64] = { 0 };

	if (st)
		sprintf(sm_err_str, " SM(%s)", ib_get_err_str(st));

	st = status >> 8;
	if (st)
		sprintf(sa_err_str, " SA(%s)", ib_sa_err_str((uint8_t) st));

	fprintf(stderr, "ERROR: Query result returned 0x%04x, %s%s\n",
		status, sm_err_str, sa_err_str);
}

static unsigned int get_max(unsigned int num)
{
	unsigned r = 0;		// r will be lg(num)

	while (num >>= 1)	// unroll for more speed...
		r++;

	return (1 << r);
}

void get_max_msg(char *width_msg, char *speed_msg, int msg_size, ibnd_port_t * port)
{
	char buf[64];
	uint32_t max_speed = 0;
	uint32_t cap_mask, rem_cap_mask, fdr10;
	uint8_t *info = NULL;

	uint32_t max_width = get_max(mad_get_field(port->info, 0,
						   IB_PORT_LINK_WIDTH_SUPPORTED_F)
				     & mad_get_field(port->remoteport->info, 0,
						     IB_PORT_LINK_WIDTH_SUPPORTED_F));
	if ((max_width & mad_get_field(port->info, 0,
				       IB_PORT_LINK_WIDTH_ACTIVE_F)) == 0)
		// we are not at the max supported width
		// print what we could be at.
		snprintf(width_msg, msg_size, "Could be %s",
			 mad_dump_val(IB_PORT_LINK_WIDTH_ACTIVE_F,
				      buf, 64, &max_width));

	if (port->node->type == IB_NODE_SWITCH) {
		if (port->node->ports[0])
			info = (uint8_t *)&port->node->ports[0]->info;
	}
	else
		info = (uint8_t *)&port->info;

	if (info)
		cap_mask = mad_get_field(info, 0, IB_PORT_CAPMASK_F);
	else
		cap_mask = 0;

	info = NULL;
	if (port->remoteport->node->type == IB_NODE_SWITCH) {
		if (port->remoteport->node->ports[0])
			info = (uint8_t *)&port->remoteport->node->ports[0]->info;
	} else
		info = (uint8_t *)&port->remoteport->info;

	if (info)
		rem_cap_mask = mad_get_field(info, 0, IB_PORT_CAPMASK_F);
	else
		rem_cap_mask = 0;
	if (cap_mask & CL_NTOH32(IB_PORT_CAP_HAS_EXT_SPEEDS) &&
	    rem_cap_mask & CL_NTOH32(IB_PORT_CAP_HAS_EXT_SPEEDS))
		goto check_ext_speed;
check_fdr10_supp:
	fdr10 = (mad_get_field(port->ext_info, 0,
			       IB_MLNX_EXT_PORT_LINK_SPEED_SUPPORTED_F) & FDR10)
		&& (mad_get_field(port->remoteport->ext_info, 0,
				  IB_MLNX_EXT_PORT_LINK_SPEED_SUPPORTED_F) & FDR10);
	if (fdr10)
		goto check_fdr10_active;

	max_speed = get_max(mad_get_field(port->info, 0,
					  IB_PORT_LINK_SPEED_SUPPORTED_F)
			    & mad_get_field(port->remoteport->info, 0,
					    IB_PORT_LINK_SPEED_SUPPORTED_F));
	if ((max_speed & mad_get_field(port->info, 0,
				       IB_PORT_LINK_SPEED_ACTIVE_F)) == 0)
		// we are not at the max supported speed
		// print what we could be at.
		snprintf(speed_msg, msg_size, "Could be %s",
			 mad_dump_val(IB_PORT_LINK_SPEED_ACTIVE_F,
				      buf, 64, &max_speed));
	return;

check_ext_speed:
	if (mad_get_field(port->info, 0,
			  IB_PORT_LINK_SPEED_EXT_SUPPORTED_F) == 0 ||
	    mad_get_field(port->remoteport->info, 0,
			  IB_PORT_LINK_SPEED_EXT_SUPPORTED_F) == 0)
		goto check_fdr10_supp;
	max_speed = get_max(mad_get_field(port->info, 0,
					  IB_PORT_LINK_SPEED_EXT_SUPPORTED_F)
			    & mad_get_field(port->remoteport->info, 0,
					    IB_PORT_LINK_SPEED_EXT_SUPPORTED_F));
	if ((max_speed & mad_get_field(port->info, 0,
				       IB_PORT_LINK_SPEED_EXT_ACTIVE_F)) == 0)
		// we are not at the max supported extended speed
		// print what we could be at.
		snprintf(speed_msg, msg_size, "Could be %s",
			 mad_dump_val(IB_PORT_LINK_SPEED_EXT_ACTIVE_F,
				      buf, 64, &max_speed));
	return;

check_fdr10_active:
	if ((mad_get_field(port->ext_info, 0,
			   IB_MLNX_EXT_PORT_LINK_SPEED_ACTIVE_F) & FDR10) == 0)
		snprintf(speed_msg, msg_size, "Could be FDR10");
}

int vsnprint_field(char *buf, size_t n, enum MAD_FIELDS f, int spacing,
		   const char *format, va_list va_args)
{
	int len, i, ret;

	len = strlen(mad_field_name(f));
        if (len + 2 > n || spacing + 1 > n)
		return 0;

	strncpy(buf, mad_field_name(f), n);
	buf[len] = ':';
	for (i = len+1; i < spacing+1; i++) {
		buf[i] = '.';
	}

	ret = vsnprintf(&buf[spacing+1], n - spacing, format, va_args);
	if (ret >= n - spacing)
		buf[n] = '\0';

	return ret + spacing;
}

int snprint_field(char *buf, size_t n, enum MAD_FIELDS f, int spacing,
		  const char *format, ...)
{
	va_list val;
	int ret;

	va_start(val, format);
	ret = vsnprint_field(buf, n, f, spacing, format, val);
	va_end(val);

	return ret;
}

void dump_portinfo(void *pi, int pisize, int tabs)
{
	int field, i;
	char val[64];
	char buf[1024];

	for (field = IB_PORT_FIRST_F; field < IB_PORT_LAST_F; field++) {
		for (i=0;i<tabs;i++)
			printf("\t");
		if (field == IB_PORT_MKEY_F && show_keys == 0) {
			snprint_field(buf, 1024, field, 32, NOT_DISPLAYED_STR);
		} else {
			mad_decode_field(pi, field, val);
			if (!mad_dump_field(field, buf, 1024, val))
				return;
		}
		printf("%s\n", buf);
	}

	for (field = IB_PORT_CAPMASK2_F;
	     field < IB_PORT_LINK_SPEED_EXT_LAST_F; field++) {
		for (i=0;i<tabs;i++)
			printf("\t");
		mad_decode_field(pi, field, val);
		if (!mad_dump_field(field, buf, 1024, val))
			return;
		printf("%s\n", buf);
	}
}
