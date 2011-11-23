/*
 * Copyright (c) 2011 Lawrence Livermore National Lab.  All rights reserved.
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

#include <stdlib.h>
#include <stdio.h>
#include <infiniband/verbs.h>
#include "ud_qp.h"

#define rx_depth 1024

/**
 * define a structure to manage the UD QP connection.
 */
void free_ud_qp(ud_qp_context *ctx)
{
	if (ctx->qp && ibv_destroy_qp(ctx->qp)) {
		fprintf(stderr, "Couldn't destroy QP\n");
	}

	if (ctx->cq && ibv_destroy_cq(ctx->cq)) {
		fprintf(stderr, "Couldn't destroy CQ\n");
	}

	if (ctx->mr && ibv_dereg_mr(ctx->mr)) {
		fprintf(stderr, "Couldn't deregister MR\n");
	}

	if (ctx->pd && ibv_dealloc_pd(ctx->pd)) {
		fprintf(stderr, "Couldn't deallocate PD\n");
	}

	if (ctx->channel && ibv_destroy_comp_channel(ctx->channel)) {
		fprintf(stderr, "Couldn't destroy completion channel\n");
	}

	if (ctx->context && ibv_close_device(ctx->context)) {
		fprintf(stderr, "Couldn't release context\n");
	}

	free(ctx);
}

ud_qp_context *
setup_ud_qp(char *hca, int port)
{
	int i = 0;
	struct ibv_device **dev_list;
	struct ibv_device  *ib_dev;
	ud_qp_context *rc = NULL;
	struct ibv_context *dev_ctx = NULL;

	/* find the device */
	dev_list = ibv_get_device_list(NULL);
	if (!dev_list)
		return (NULL);
	for (i=0; dev_list[i]; i++)
		if (!strcmp(ibv_get_device_name(dev_list[i]), hca))
			break;
	ib_dev = dev_list[i];
	if (!ib_dev)
		return (NULL);
	dev_ctx = ibv_open_device(ib_dev);
	ibv_free_device_list(dev_list);

	if (!dev_ctx)
		return (NULL);

	/* create ud_qp_context */
	rc = malloc(sizeof *rc);
	if (!rc)
		return (NULL);

	rc->context = dev_ctx;
	rc->port = port;

	/* protection domain */
	rc->pd = ibv_alloc_pd(rc->context);
	if (!rc->pd) {
		free_ud_qp(rc);
		return (NULL);
	}

	/* completion queue */
	rc->channel = NULL; // ignore this for now
	rc->cq = ibv_create_cq(rc->context, rx_depth + 1, NULL, rc->channel, 0);
	if (!rc->cq) {
		free_ud_qp(rc);
		return (NULL);
	}

	/* create QP */
	{
		struct ibv_qp_init_attr attr = {
			.send_cq = rc->cq,
			.recv_cq = rc->cq,
			.cap     = {
				.max_send_wr  = 1,
				.max_recv_wr  = rx_depth,
				.max_send_sge = 1,
				.max_recv_sge = 1
			},
			.qp_type = IBV_QPT_UD,
		};

		rc->qp = ibv_create_qp(rc->pd, &attr);
	}
	if (!rc->qp) {
		free_ud_qp(rc);
		return (NULL);
	}

	/* Transition to init */
	{
		struct ibv_qp_attr attr = {
			.qp_state        = IBV_QPS_INIT,
			.pkey_index      = 0,
			.port_num        = port,
			.qkey            = 0x11111111
		};

		if (ibv_modify_qp(rc->qp, &attr,
				  IBV_QP_STATE              |
				  IBV_QP_PKEY_INDEX         |
				  IBV_QP_PORT               |
				  IBV_QP_QKEY)) {
			fprintf(stderr, "Failed to modify QP to INIT\n");
			free_ud_qp(rc);
			return NULL;
		}
	}

	/* transition */
	{
		/* RTR */
		struct ibv_qp_attr attr = {
			.qp_state		= IBV_QPS_RTR
		};
		if (ibv_modify_qp(rc->qp, &attr, IBV_QP_STATE)) {
			fprintf(stderr, "Failed to modify QP to RTR\n");
			free_ud_qp(rc);
			return NULL;
		}

		/* RTS */
		attr.qp_state	    = IBV_QPS_RTS;
		attr.sq_psn	    = 1;
		if (ibv_modify_qp(rc->qp, &attr,
				  IBV_QP_STATE              |
				  IBV_QP_SQ_PSN)) {
			fprintf(stderr, "Failed to modify QP to RTS\n");
			free_ud_qp(rc);
			return NULL;
		}
	}

	return (rc);
}

uint32_t
send_something(ud_qp_context *ctx, uint16_t lid, uint8_t sl,
		union ibv_gid *gid,
		uint8_t *buf, size_t len,
		void (*complete_cb)(uint64_t wrid,
			uint8_t *resp_buf, size_t resp_len))
{
	struct ibv_ah_attr ah_attr = {
		.is_global     = 0,
		.dlid          = lid,
		.sl            = sl,
		.src_path_bits = 0,
		.port_num      = ctx->port
	};
	struct ibv_ah *ah;

	if (gid) {
		ah_attr.is_global = 1;
		ah_attr.grh.hop_limit = 1;
		ah_attr.grh.dgid = *gid;
		ah_attr.grh.sgid_index = 0; /* FIXME: param? */
	}


	/* memory region */
	//rc->mr = ibv_reg_mr(rc->pd, rc->buf, size + 40, IBV_ACCESS_LOCAL_WRITE);

	/* post a recv buffer for this */
		/* memory region??? */

	/* post a send message */
		/* memory region??? */
	/* where are we sending */
	ah = ibv_create_ah(ctx->pd, &ah_attr);


/* single threaded model */
	/* poll cq for send completion */
	/* poll cq for rcv completion */
	/* give the user their data */

}

