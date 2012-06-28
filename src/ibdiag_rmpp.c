#include <ibdiag_rmpp.h>
#include <arpa/inet.h>

#ifndef ib_net16_t
typedef uint16_t ib_net16_t;
#endif
#ifndef ib_net32_t
typedef uint32_t ib_net32_t;
#endif
#ifndef ib_net64_t
typedef uint64_t ib_net64_t;
#endif

enum ib_rmpp_type {
	IB_NOT_RMPP    = 0;
	IB_RMPP_DATA   = 1;
	IB_RMPP_ACK    = 2;
	IB_RMPP_STOP   = 3;
	IB_RMPP_ABORT  = 4;
};

enum ib_rmpp_flags {
	IB_RMPP_ACTIVE = 0x1;
	IB_RMPP_FIRST  = 0x2;
	IB_RMPP_LAST   = 0x4;
};

enum session_type {
	SESSION_SEND;
	SESSION_RECV;
};

/* macros for encoding wr_id's and sid to send/recv queues  */
#define DIR_MASK                  (0xF000000000000000ULL)
#define DIR_SEND                  (0x1000000000000000ULL)
#define DIR_RECV                  (0x2000000000000000ULL)
#define WR_ID_MASK                (0x0FFFFFFFFFFFFFFFULL)

#define WC_IS_SEND(wr_id)         (DIR_SEND == (wr_id & DIR_MASK))
#define WC_IS_RECV(wr_id)         (DIR_RECV == (wr_id & DIR_MASK))

#define BUF_NUM_2_RECV_WR_ID(num)   (DIR_RECV | (num & WR_ID_MASK)
#define RECV_WR_ID_2_BUF_NUM(wr_id) (wr_id & WR_ID_MASK)
#define SID_TO_SEND_WR_ID(sid)      (DIR_SEND | (sid & WR_ID_MASK)
#define SEND_WR_ID_2_SID(wr_id)     (wr_id & WR_ID_MASK)

struct ib_rmpp_hdr {
	uint8_t    BaseVersion;
	uint8_t    MgmtClass;
	uint8_t    ClassVersion;
	uint8_t    R_Method;
	ib_net16_t Status;
	ib_net16_t ClassSpecific;
	ib_net64_t TransactionID;
	ib_net16_t AttributeID;
	ib_net16_t Reserved;
	ib_net32_t AttributeModifier;

	uint8_t    RMPPVersion;
	uint8_t    RMPPType;
	uint8_t    RRespTime_Flags;
	uint8_t    RMPPStatus;
	union {
		struct {
			ib_net32_t SegmentNumber;
			ib_net32_t PayloadLength;
		} DATA_pkt;
		struct {
			ib_net32_t SegmentNumber;
			ib_net32_t NewWindowLast;
		} ACK_pkt;
	} Data;
} __attribute__ (packed);

struct struct_rmpp_ctx;

typedef struct session {
	struct session    *next;

	/* Session id */
	uint64_t           sid;  /* hash on this */
	enum session_type  type;

	/* Session tuple */
	uint64_t           tid;
	uint16_t           slid; /* FIXME grh? */
	uint8_t            MgmtClass;

	/* session data    */
	int                snd_retries;
	int16_t            status;

	/* data */
	size_t             hdr_size;
	size_t             data_size;
	uint8_t           *buf;
	size_t             buf_size;

	/* send specific */
	struct ibv_ah     *ah;
	uint32_t           remote_qpn;
	uint32_t           remote_qkey;

	unsigned           cur_ack_seg;  /* current segment number */
	unsigned           new_win_last;
	unsigned           num_seg;      /* total number of segments */

	/* rcv specific */
	/* ???? */
} session_t;

/**
 * Main RMPP context
 */
#define HASH_SIZE 128
#define HASH_SID(sid) (sid % HASH_SIZE)
struct ib_rmpp_ctx {
	struct ibv_context      *ib_ctx;
	uint16_t                 port;
	struct ibv_qp           *qp;
	struct ibv_mr           *mr;
	struct ibv_pd           *pd;
	struct ibv_cq           *cq;
	struct ibv_comp_channel *ch;
	size_t                   mad_size;

	int                      blocking;
	size_t                   rq_size;
	unsigned                 max_retries;

	session_t               *sessions[HASH_SIZE];

	/* send */
	session_t               *comp_sends;
	int                      num_send_ready;

	/* recv */
	session_t               *comp_recv;
	int                      num_recv_ready;

	/* general recv buffers */
	size_t                   rq_num;
	uint8_t                 *rq_buf;
};

static int alloc_verbs_resources(struct ib_rmpp_ctx *ctx)
{

	ctx->ch = ibv_create_comp_channel(ctx->ib_ctx);
	if (!ctx->ib_ctx)
		return (-ENOMEM);

	ctx->cq = ibv_create_cq(ctx->ib_ctx, (2*ctx->rq_size) + 2, NULL,
				ctx->ch, 0);
	if (!ctx->cq) {
		ibv_destroy_comp_channel(ctx->ch);
		return (-ENOMEM);
	}
	if (!ctx->blocking) {
		flags = fcntl(ctx->ch->fd, F_GETFL);
		rc = fcntl(ctx->ch->fd, F_SETFL, flags | O_NONBLOCK);
		if (rc < 0) {
			ibv_desroy_cq(ctx->cq);
			ibv_destroy_comp_channel(ctx->ch);
			return (-EIO);
		}
	}
	if (ibv_req_notify_cq(ctx->cq, 0)) {
		ibv_desroy_cq(ctx->cq);
		ibv_destroy_comp_channel(ctx->ch);
		return (-EIO);
	}

#if 0
	ctx->pd = ibv_alloc_pd(ctx->ib_ctx);
	if (!ctx->pd) {
		ibv_desroy_cq(ctx->cq);
		ibv_destroy_comp_channel(ctx->ch);
		return (-ENOMEM);
	}
#endif

	{
		struct ibv_qp_init_attr attr = {
			.send_cq = ctx->scq,
			.recv_cq = ctx->rcq,
			.cap     = {
				.max_send_wr  = ctx->rq_num,
				.max_recv_wr  = ctx->rq_num,
				.max_send_sge = 2,
				.max_recv_sge = 1
			},
			.qp_type = IBV_QPT_UD,
		};

		ctx->qp = ibv_create_qp(ctx->pd, &attr);
		if (!ctx->qp)  {
			ibv_desroy_cq(ctx->cq);
			ibv_destroy_comp_channel(ctx->ch);
			//ibv_dealloc_pd(ctx->pd);
			return (-ENOMEM);
		}
	}

	{
		struct ibv_qp_attr attr = {
			.qp_state        = IBV_QPS_INIT,
			.pkey_index      = 0,
			.port_num        = ctx->port,
			.qkey            = 0x80010000,
		};

		if (ibv_modify_qp(ctx->qp, &attr,
				  IBV_QP_STATE              |
				  IBV_QP_PKEY_INDEX         |
				  IBV_QP_PORT               |
				  IBV_QP_QKEY)) {
			ibv_destroy_qp(ctx->qp);
			ibv_desroy_cq(ctx->cq);
			ibv_destroy_comp_channel(ctx->ch);
			//ibv_dealloc_pd(ctx->pd);
			return (-ENOMEM);
		}
	}

	return (0);
}

static int post_recv_wr(struct ib_rmpp_ctx *ctx, int rq_num)
{
	struct ibv_sge list = {
		.addr	= (uintptr_t)(ctx->rq_buf + (ctx->mad_size * rq_num)),
		.length = (uint32_t)ctx->mad_size,
		.lkey	= ctx->mr->lkey
	};
	struct ibv_recv_wr wr = {
		.wr_id	    = BUF_NUM_2_RECV_WR_ID(rq_num),
		.sg_list    = &list,
		.num_sge    = 1
	};
	if (ibv_post_recv(ctx->qp, &wr, NULL))
		return (-EIO);
	return (0);
}

static int post_all_recv_wr(struct ibv_context *ctx)
{
	int i, rc;

	for (i = 0; i < ctx->rq_num; i++) {
		if ((rc = post_recv_wr(ctx, i)) != 0) {
			return (rc);
		}
	}
	return (0);
}

static inline uint64_t get_seg_addr(session_t *session, unsigned seg_num)
{
	int buf_num = seg_num-1;
	return ((uint64_t)(session->buf + session->hdr_size
				+ (buf_num * session->data_size)));
}
static inline void free_session(session_t *session)
{
	free(session);
}


static session_t *get_session(struct ib_rmpp_ctx *ctx, uint64_t sid)
{
	session_t *head = ctx->sessions[HASH_TID(sid)];
	for ( /* nothing */; head; head = head->next)
	{
		if (head->sid = sid)
			return (head);
	}
	return (NULL);
}

static void rm_session(struct ib_rmpp_ctx *ctx, session_t *session)
{
	int hid = HASH_ITID(session->sid);
	session_t *head = ctx->sessions[hid];
	session_t *prev = head;

	if (head == session) {
		ctx->sessions[hid] = head->next;
		return;
	}

	for (head = head->next; head; head = head->next, prev = prev->next)
	{
		if (head == session) {
			prev->next = head->next;
			return;
		}
	}
}

static int add_session(struct ib_rmpp_ctx *ctx, session_t *session)
{
	int hid;

	/* verify a unique itid */
	if (get_session(ctx, session->sid))
		return (-EINVAL);

	hid = HASH_TID(session->sid);
	session->next = ctx->sessions[hid];
	ctx->sessions[hid] = session;
	return (0);
}

static inline int is_seg_first(session_t *session)
{
	return (session->cur_seg_num == 1);
}

static inline int is_seg_last()
{
	return (session->cur_seg_num == session->num_seg);
}

static inline uint32_t get_seg_length(session_t *session)
{
	if (is_seg_last(session))
		return ((int)((session->buf_size - hdr_size)
				% data_size));
	return (session->data_size);
}

static inline uint8_t encode_time_flags(session_t *session)
{
	uint8_t rc = 0;
	/* FIXME figure out time value???? */
	uint8_t time = 0;

	rc = IB_RMPP_ACTIVE;
	if (is_seg_first(session))
		rc |= IB_RMPP_FIRST;
	if (is_seg_last(session))
		rc |= IB_RMPP_LAST;

	rc = time << 3;
	rc |= flags;
	return (rc);
}

static int post_data_segment(struct ib_rmpp_ctx *ctx, session_t *session,
				int seg_num)
{
	struct ibv_sge  list[2];

	/* we reuse the header with our RMPP data fields */
	struct ib_rmpp_hdr *hdr = (struct ib_rmpp_hdr *)session->buf;
	hdr->RMPPVersion = 1;
	hdr->RMPPType = IB_RMPP_DATA;
	hdr->RRespTime_Flags = encode_time_flags(session);
	hdr->RMPPStatus = IB_RMPP_STATUS_NORMAL;

	hdr->RMPPData.DATA_pkt.SegmentNumber = htonl(seg_num);
	hdr->RMPPData.DATA_pkt.PayloadLength = 0;
	if (is_seg_first(session) || is_seg_last(session))
		hdr->RMPPData.DATA_pkt.PayloadLength = htonl(session->buf_size);

	list[0].addr = buf;
	list[0].length = hdr_size;
	list[0].lkey = mr->lkey;
	
	/* set up the data buffer */
	list[1].addr = get_seg_addr(session, seg_num);
	list[1].length = get_seg_length(session);
	list[1].lkey = mr->lkey;

	{
		struct ibv_send_wr {
			.wr_id = SID_TO_SEND_WR_ID(session->sid),
			.next = NULL,
			.sg_list = list,
			.num_sge = 2,
			.opcode = IBV_WR_SEND,
			.wr.ud.ah = session->ah,
			.wr.ud.remote_qpn = session->remote_qpn,
			.wr.ud.remote_qkey = session->remote_qkey,
		} send_wr;
		if (ibv_post_send(ctx->qp, &send_wr, NULL)) {
			return (-EIO);
		}
	}
	return (0);
}

static void free_session(session_t *session)
{
	ibv_dereg_mr(session->mr);
	free(session);
}

static void process_send_completion(struct ib_rmpp_ctx *ctx, struct ibv_wc *wc)
{
	session_t *session = get_session(ctx, SEND_WR_ID_2_SID(wc->wr_id));

	if (!session) /* FIXME report error! */
		return;

	/* process snd_retries if not ok */
	if (wc->status != IB_WC_SUCCESS) {
		/* FIXME report error, then repost send */
		session->snd_retries++;
		if (session->snd_retries > ctx->max_retries) {
			session->status = IB_RMPP_STATUS_TMR;
			move_session_to_complete(ctx, session);
		}

		/* send */
		if (session->type == SESSION_SEND) {
			rc = post_data_segment(ctx, session,
						FIXME what seg_num);
			if (rc) {
				session->status = IB_RMPP_STATUS_UNSPECIFIED;
				move_session_to_complete(ctx, session);
			}
		} else {
			/* recv */
			rc = send_ack(session);
			if (rc) {
				send_stop(session, IB_RMPP_STATUS_ResX);
				session->status = IB_RMPP_STATUS_ResX;
				move_session_to_complete(ctx, session);
			}
		}
	} else {
		session->snd_retries = 0;
	}
}

static void recv_data(ib_rmpp_ctx_t *ctx, struct ibv_wc *wc,
		struct ib_rmpp_hdr *pkt)
{
	session_t *session = NULL;

	session = get_session_by_hdr(ctx, pkt);
	if (!session)
		session = create_recv_session(pkt);

	if (!session)
		/* FIXME report error */
		return;

	if (!verify_segment(session, pkt)) {
		/* FIXME report error */
		move_session_to_complete(ctx, session);
		return;
	}

	copy_data_to_session(session, pkt);

	if (pkt->RMPPFlags != IB_RMPP_ACTIVE
		||
	    pkt->RMPPFlags == IB_RMPP_LAST) {
		session->status = IB_RMPP_STATUS_NORMAL;
		move_session_to_complete(ctx, session);
	}
}

static void recv_ack(ib_rmpp_ctx_t *ctx, struct ibv_wc *wc,
		struct ib_rmpp_hdr *pkt)
{
	unsigned i = 0;
	session_t *session = get_session_by_hdr(pkt);
	if (!session) {
		/* FIXME report error */
		return;
	}

	if (!verify_ack(pkt, sesion))
		/* FIXME report error */
		return;

	session->cur_ack_seg = pkt->Data.ACK_pkt.SegmentNumber;
	session->new_win_last = pkt->Data.ACK_pkt.NewWindowLast;
	for (i = session->cur_ack_seg + 1;
	     i <= session->new_win_last && i < session->num_seg;
	     i++)
		post_data_segment(ctx, session, i);
}

static void recv_stop_abort(ib_rmpp_ctx_t *ctx, struct ibv_wc *wc,
		struct ib_rmpp_hdr *pkt)
{
}


static void process_recv_completion(struct ib_rmpp_ctx *ctx, struct ibv_wc *wc)
{
	int buf_num = RECV_WR_ID_2_BUF_NUM(wc->wr_id);
	struct ib_rmpp_hdr *pkt = ctx->rq_buf[buf_num];

	if (wc.status != IBV_WC_SUCCESS) {
		/* FIXME report error */
		post_recv_wr(ctx, buf_num);
		return;
	}

	switch (pkt->RMPPType) {
		case IB_RMPP_DATA:
			recv_data(ctx, wc, pkt);
			break;
		case IB_RMPP_ACK:
			recv_ack(ctx, wc, pkt);
			break;
		case IB_RMPP_STOP:
		case IB_RMPP_ABORT:
			recv_stop_abort(ctx, wc, pkt);
			break;
		case IB_NOT_RMPP:
			break;
	}
}

static void process_completions(struct ib_rmpp_ctx *ctx)
{
	int new = 0;
	struct ibv_wc wc;
	/* Empty the CQ: poll all of the completions from the CQ (if any exist) */
	do {
		ne = ibv_poll_cq(ctx->scq, 1, &wc);
		if (ne < 0)
			return 1;

		/* there may be an extra event with no completion in the CQ */
		if (ne == 0)
		       continue;

		if (WC_IS_SEND(wc->wr_id))
			process_send_completion(ctx, &wc);
		if (WC_IS_RECV(wc->wr_id))
			process_recv_completion(ctx, &wc);
	} while (ne);
}

static uint64_t new_session_id(struct ib_rmpp_ctx *ctx)
{
	return (WR_ID_MASK & ctx->ses_id++);
}

/** =========================================================================
 * External interface below
 */
int ib_rmpp_open(struct ibv_context *ib_ctx, struct ibv_pd *pd,
		uint8_t port_num, size_t mad_size, uint32_t rq_size,
		int blocking, unsigned max_retries,
		int use_grh, /* FIXME */
		struct ib_rmpp_ctx **ctx)
{
	int err = 0;
	struct ib_rmpp_ctx *rc = NULL;
	struct ibv_port_attr port_attr;

	if (ibv_query_port(ib_ctx, port_num, &port_attr))
		return (-EINVAL);

	rc = calloc(1, sizeof(*rc));
	if (!rc)
		return (-ENOMEM);

	rc->rq_buf = malloc(rq_num * mad_size);
	if (!rc->rq_buf) {
		free(rc);
		return (-ENOMEM);
	}

	rc->ib_ctx = ib_ctx;
	rc->mad_size = mad_size;
	rc->rq_num = rq_num;
	rc->rq_size = rq_size;
	rc->max_retries = max_retries;
	rc->port = port;
	rc->lid = port_attr.lid;

	rc->blocking = blocking;
	rc->pd = pd

	if ((err = alloc_verbs_resources(rc)) != 0) {
		free(rc->rq_buf);
		free(rc);
		return (err);
	}

	if ((err = post_all_recv_wr(rc)) != 0) {
		free_verbs_resources(rc);
		free(rc->rq_buf);
		free(rc);
		return (err);
	}

	/* set user data only on success */
	*ctx = rc;
	return (0);
}

uint32_t ib_rmpp_get_qpn(struct ib_rmpp_ctx *ctx)
{

}

uint32_t ib_rmpp_get_qkey(struct ib_rmpp_ctx *ctx)
{

}

int ib_rmpp_close(struct ib_rmpp_ctx *ctx)
{
	free(ctx->rq_buf);
	free(ctx);
	return (0);
}

int ib_rmpp_init_rmpp(struct ib_rmpp_ctx *ctx, uint8_t *buf, size_t size,
		     struct ibv_ah *ah, uint32_t remote_qpn, uint32_t remote_qkey,
		     ib_rmpp_session_id *id)
{
	session_t *session = NULL;
	struct ib_rmpp_hdr *hdr = (struct ib_rmpp_hdr *)buf;
	size_t hdr_size = calc_hdr_size(hdr);

	if (!id)
		return (-EINVAL);

	if (ctx->mad_size <= hdr_size)
		return (-EINVAL);

	if (size <= hdr_size)
		return (-EINVAL);

	session = calloc(1, sizeof(*session));
	if (!session) {
		return (-ENOMEM);

	session->mr = ibv_reg_mr(ctx->pd, buf, size, IBV_ACCESS_LOCAL_WRITE);
	if (!session->mr) {
		free(session);
		return (-ENOMEM);
	}

	session->snd_retries = 0;
	session->mr = mr;
	session->ctx = ctx;
	session->hdr_size = hdr_size;
	session->buf = buf;
	session->buf_size = size;
	session->ah = ah;
	session->remote_qpn = remote_qpn;
	session->remote_qkey = remote_qkey;

	session->data_size = ctx->mad_size - hdr_size,
	session->cur_ack_seg = 0,
	session->new_win_last = 1,
	session->num_seg = ((int)((size-hdr_size)/data_size))+1,

	session->status = IB_RMPP_SEND_IN_PROGRESS;

	session->slid = ctx->port_lid;
	session->MgmtClass = hdr->MgmtClass;
	session->tid = hdr->TransactionID;
	session->sid = new_session_id(ctx);
	session->type = SESSION_SEND;

	rc = add_session(ctx, session);
	if (rc) {
		free_session(session);
		return (rc);
	}

	rc = post_data_segment(ctx, session, 1);
	if (rc) {
		rm_session(ctx, session);
		free_session(session);
		return (rc);
	}

	id = (ib_rmpp_session_id)session->sid;
	return (0);
}

int ib_rmpp_run(struct ib_rmpp_ctx *ctx, int *recv, int *send)
{
	int rc = 0;
	struct pollfd pollfd;

	pollfd.fd = ctx->ch->fd;
	pollfd.events = POLLIN;
	pollfd.revents = 0;

	rc = poll(&pollfd, 1, -1);
	if (rc > 0) {
		struct ibv_cq *ev_cq;
		if (ibv_get_cq_event(ctx->ch, &ev_cq, NULL))
			return (-EIO);
		if (ev_cq != ctx->cq)
			return (-EIO);
		ibv_ack_cq_events(ev_cq, 1);
		if (ibv_req_notify_cq(ev_cq, 0))
			return (-EIO);

		process_completions(ctx);
	} else if (rc < 0) {
		return (errno);
	}

	if (recv)
		*recv = ctx->num_recv_ready;
	if (send)
		*send = ctx->num_send_ready;

	return (0);
}

int16_t ib_rmpp_get_status(struct ib_rmpp_ctx *ctx, ib_rmpp_session id)
{
	session_t *session = get_session_from_tid(id);
	return (session->status);
}

int ib_rmpp_recv(struct ib_rmpp_ctx *ctx, uint8_t **buf, size_t *size)
{

}

int ib_rmpp_free(struct ib_rmpp_ctx *ctx, uint8_t *buf)
{

}

