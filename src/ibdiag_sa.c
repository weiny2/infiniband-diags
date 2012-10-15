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


#include <errno.h>
#include <infiniband/umad.h>

#include "ibdiag_common.h"
#include "ibdiag_sa.h"

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
	uint16_t sa_dlid;
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

	IBWARN("QP 0x%x connected to SA QPn 0x%x\n",
		conn->qp->qp_num, conn->rqpn);
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
			.port_num        = rdma_ctx.device_port,
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

	IBWARN("QPn = 0x%x\n", rdma_ctx.conn.qp->qp_num);
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

	IBWARN("SA Query RDMA configured on %s:%d; mtu %d; sl %d; dlid %u\n",
				ibv_get_device_name(dev),
				rdma_ctx.device_port,
				rdma_ctx.sa_mtu,
				rdma_ctx.sa_sl,
				rdma_ctx.sa_dlid);
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


/* =========================================================================
 * END Hack RDMA code
 * ========================================================================= */


struct sa_handle * sa_get_handle(uint32_t sa_qpn, uint8_t sa_mtu,
				uint32_t rdma_size_mb)
{
	struct sa_handle * handle;
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

void sa_free_handle(struct sa_handle * h)
{
	if (h->use_rdma)
		sa_rdma_close();
	umad_unregister(h->fd, h->agent);
	umad_close_port(h->fd);
	free(h);
}

int sa_query(struct sa_handle * h, uint8_t method,
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
		result->rdma_res = NULL;
	} else if (result->p_result_madw) {
		free((uint8_t *) result->p_result_madw - umad_size());
		result->p_result_madw = NULL;
	}
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

static const char *ib_mad_inv_field_str[] = {
	"MAD No invalid fields",
	"MAD Bad version",
	"MAD Method specified is not supported",
	"MAD Method/Attribute combination is not supported",
	"MAD Reserved",
	"MAD Reserved",
	"MAD Reserved",
	"MAD Invalid value in Attribute field(s) or Attribute Modifier"
	"MAD UNKNOWN ERROR"
};
#define MAD_ERR_UNKNOWN (ARR_SIZE(ib_mad_inv_field_str) - 1)

static inline const char *ib_mad_inv_field_err_str(IN uint8_t f)
{
	if (f > MAD_ERR_UNKNOWN)
		f = MAD_ERR_UNKNOWN;
	return (ib_mad_inv_field_str[f]);
}

void sa_report_err(int status)
{
	int st = status & 0xff;
	char mad_err_str[64] = { 0 };
	char sa_err_str[64] = { 0 };

	if (st)
		sprintf(mad_err_str, " (%s; %s; %s)",
			(st & 0x1) ? "BUSY" : "",
			(st & 0x2) ? "Redirection Required" : "",
			ib_mad_inv_field_err_str(st>>2));


	st = status >> 8;
	if (st)
		sprintf(sa_err_str, " SA(%s)", ib_sa_err_str((uint8_t) st));

	fprintf(stderr, "ERROR: Query result returned 0x%04x, %s%s\n",
		status, mad_err_str, sa_err_str);
}
