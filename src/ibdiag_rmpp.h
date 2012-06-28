#include <infiniband/verbs.h>

#define IB_RMPP_SEND_IN_PROGRESS (-1)
enum ib_rmpp_status {
	/* DATA/ACK */
	IB_RMPP_STATUS_NORMAL = 0;

	/* STOP */
	IB_RMPP_STATUS_ResX   = 1;

	/* ABORT */
	IB_RMPP_STATUS_T2L              = 118;
	IB_RMPP_STATUS_INC_LAST_LENGTH  = 119;
	IB_RMPP_STATUS_INC_FIRST_SEG    = 120;
	IB_RMPP_STATUS_BadT             = 121;
	IB_RMPP_STATUS_W2S              = 122;
	IB_RMPP_STATUS_S2B              = 123;
	IB_RMPP_STATUS_ILLEGAL_STATUS   = 124;
	IB_RMPP_STATUS_UnV              = 125;
	IB_RMPP_STATUS_TMR              = 126;
	IB_RMPP_STATUS_UNSPECIFIED      = 127;

	/* IB_RMPP_STATUS_CLASS_SPECIFIC   = 128-191; */
	/* FIXME figure out how to hand class specific error codes to user */

	/*
	 * IB_RMPP_STATUS_VENDOR_SPECIFIC  = 192-255;
	 * These force termination of the protocol which are easy to send to
	 * the user.
	 */
	IB_RMPP_STATUS_VENDOR_SPECIFIC  = 192;
};

typedef uint64_t ib_rmpp_session_id;
struct ib_rmpp_ctx;

/**
 * Open the rmpp connection using the local and remote resources supplied
 * The QP/CQ are "controlled" until "ib_rmpp_close" is called.  It is
 * undefined what will happen if the user posts WR to the QP or reads
 * completions from the CQ during this time.
 */
int ib_rmpp_open(struct ibv_context *ib_ctx, struct ibv_pd *pd,
		size_t mad_size, uint32_t rq_size,
		int blocking, unsigned max_retries,
		struct ib_rmpp_ctx **ctx);

/*
FIXME how does the user know the qpn and qkey to send to the other side for
recieves?
*/
uint32_t ib_rmpp_get_qpn(struct ib_rmpp_ctx *ctx);
uint32_t ib_rmpp_get_qkey(struct ib_rmpp_ctx *ctx);

/**
 * NOTE: close does not release any of the resources passed into "ib_rmpp_open"
 */
int ib_rmpp_close(struct ib_rmpp_ctx *ctx);

/**
 * Initiates the RMPP transfer by setting up the session and sending the
 * first packet.  The user must call ib_rmpp_run in a loop to process the
 * entire session until the session ID is shown as complete
 *
 * @ctx: context
 * @hdr_size: the header size for this class.  This is used to determine how
 *            much of "buf" is to be replicated as the header for the individual
 *            segements.
 * @buf: pointer to buffer including a single header
 * @size: full buffer size (header + data)
 * @ah: Address handler of remote node
 * @remote_qpn: QP number of remote QP
 * @remote_qkey: QKey of the remote QP
 * @id: _required_ returns the session id initiated.
 */
int ib_rmpp_init_rmpp(struct ib_rmpp_ctx *ctx, uint8_t *buf, size_t size,
		     struct ibv_ah *ah, uint32_t remote_qpn, uint32_t remote_qkey,
		     ib_rmpp_session_id *id)

/**
 * Send the buffer "buf" as a single non_rmpp MAD
 * @size: size of buffer (must be < ib_rmpp_open.mad_size)
int ib_rmpp_send(struct ib_rmpp_ctx *ctx, uint8_t *buf, size_t size,
	     struct ibv_ah *ah, uint32_t remote_qpn, uint32_t remote_qkey,
	     ib_rmpp_session_id *id);
 */

/**
 * Run the even loop to process send/recv packets
 * @ctx: context to run
 * @recv: if !NULL return number of recv packets available
 *        (call ib_rmpp_recv to get them)
 */
int ib_rmpp_run(struct ib_rmpp_ctx *ctx, int block, int *recv);

/**
 * if session is complete
 *        return rmpp_status in lower 8 bits
 * else
 *        return IB_RMPP_SEND_IN_PROGRESS
 */
int16_t ib_rmpp_get_status(struct ib_rmpp_ctx *ctx, ib_rmpp_session id);

/**
 * buf will start with the first MAD header and contain only that header
 */
int ib_rmpp_recv(struct ib_rmpp_ctx *ctx, uint8_t **buf, size_t *size);

/**
 * free buffer returned in ib_rmpp_recv
 */
int ib_rmpp_free(struct ib_rmpp_ctx *ctx, uint8_t *buf);


