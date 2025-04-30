
#include "nxfsd.hxx"
#include "node.hxx"
#include "noded.hxx"
#include "nxfsd_stats.hxx"
#include "smbd_conf.hxx"
#include "smbd_open.hxx"
#include <sys/uio.h>

struct x_noded_t
{
	x_strm_srv_t base;
};

struct x_noded_conn_t
{
	x_nxfsd_conn_t base;
	enum { MAX_MSG = 4 };
	x_noded_conn_t(int fd, const x_sockaddr_t &saddr);
	~x_noded_conn_t();

	uint64_t num_msg = 0;
	x_node_hdr_t node_hdr;
	const x_noded_proto_t *proto = nullptr;
	x_ddlist_t open_list;
};

static inline x_noded_conn_t *noded_conn_from_base(x_nxfsd_conn_t *base);

template <>
x_noded_conn_t *x_ref_inc(x_noded_conn_t *noded_conn)
{
	x_ref_inc(&noded_conn->base);
	return noded_conn;
}

template <>
void x_ref_dec(x_noded_conn_t *noded_conn)
{
	x_ref_dec(&noded_conn->base);
}

#define MAX_NODED_PROTOS 2
static x_noded_proto_t x_noded_protos[MAX_NODED_PROTOS];

struct x_noded_requ_context_t
{
	~x_noded_requ_context_t()
	{
		cleanup();
	}

	void cleanup()
	{
		X_REF_DEC_IF(smbd_open);
	}

	const x_noded_proto_t *proto;
	uint64_t compound_id;
	x_out_buf_t out_buf;
	x_in_buf_t in_buf{};
	uint32_t in_msgsize;
	NTSTATUS status{NT_STATUS_OK};
	x_smbd_open_t *smbd_open{};
};

static void noded_conn_queue_buf(x_noded_conn_t *noded_conn, x_bufref_t *buf_head,
		x_bufref_t *buf_tail, uint32_t length, uint32_t magic)
{
	auto outhdr = (x_node_hdr_t *)buf_head->back(sizeof(x_node_hdr_t));
	outhdr->magic = X_H2BE32(magic);
	outhdr->length = X_H2BE32(length);

	x_nxfsd_conn_queue_buf(&noded_conn->base, buf_head, buf_tail);
}

static void noded_conn_queue(x_noded_conn_t *noded_conn,
		x_out_buf_t &out_buf, uint32_t magic)
{
	auto out_buf_head = std::exchange(out_buf.head, nullptr);
	auto out_buf_tail = std::exchange(out_buf.tail, nullptr);
	auto out_length = std::exchange(out_buf.length, 0);
	X_ASSERT(out_buf_head);
	X_ASSERT(out_length > 0);

	noded_conn_queue_buf(noded_conn, out_buf_head, out_buf_tail,
			out_length, magic);
}

static void noded_conn_queue(x_noded_conn_t *noded_conn, x_noded_requ_context_t &requ_ctx)
{
	noded_conn_queue(noded_conn, requ_ctx.out_buf, requ_ctx.proto->magic);
}

static void noded_conn_queue(x_noded_conn_t *noded_conn, x_noded_requ_t *noded_requ)
{
	noded_conn_queue(noded_conn, noded_requ->compound_out_buf, noded_requ->proto->magic);
}

void x_noded_conn_send_unsolicited(x_noded_conn_t *noded_conn, x_bufref_t *buf,
		uint8_t opcode, uint32_t magic)
{
	x_node_resp_t *node_resp = (x_node_resp_t *)buf->get_data();
	node_resp->next_command = 0;
	node_resp->status = { 0 };
	node_resp->mid = X_H2LE64(uint64_t(-1));
	node_resp->opcode = opcode;
	noded_conn_queue_buf(noded_conn, buf, buf, buf->length, magic);
}

static void x_noded_set_reply_hdr(x_noded_requ_t *noded_requ,
		NTSTATUS status,
		x_out_buf_t &out_buf)
{
	X_LOG(NODED, DBG, X_NODED_REQU_DBG_FMT " %s", X_NODED_REQU_DBG_ARG(noded_requ), x_ntstatus_str(status));
	x_node_resp_t *node_resp = (x_node_resp_t *)out_buf.head->get_data();
	node_resp->mid = X_H2LE64(noded_requ->in_node_requ.mid);
	node_resp->next_command = 0;
	node_resp->opcode = noded_requ->in_node_requ.opcode;
	node_resp->unused0 = 0;
	node_resp->flags = 0;
	node_resp->status = { X_H2LE32(NT_STATUS_V(status)) };
	node_resp->unused1 = 0;
}

#define X_NODED_UPDATE_OP_HISTOGRAM(r) do { \
	auto __now = x_tick_now(); \
	auto __elapsed = __now - (r)->start; \
	X_ASSERT(__elapsed >= 0); \
	X_NODED_HISTOGRAM_UPDATE_((r)->in_node_requ.opcode, __elapsed / 1000); \
} while (0)

static void x_noded_reply(x_noded_conn_t *noded_conn,
		x_noded_requ_t *noded_requ,
		NTSTATUS status,
		x_out_buf_t &out_buf)
{
	if (noded_requ->interim_state == x_nxfsd_requ_t::INTERIM_S_SCHEDULED &&
			x_nxfsd_del_timer(&noded_requ->interim_timer)) {
		noded_requ->decref();
	}
	x_noded_set_reply_hdr(noded_requ, status, out_buf);
	noded_requ->interim_state = x_nxfsd_requ_t::INTERIM_S_NONE;
}

static int x_noded_reply_error(x_noded_requ_t *noded_requ,
		NTSTATUS status,
		x_out_buf_t &out_buf,
		const char *file, unsigned int line)
{
	X_LOG(NODED, OP, "%ld RESP 0x%x at %s:%d", noded_requ->in_node_requ.mid,
			NT_STATUS_V(status), file, line);

	out_buf.head = out_buf.tail = x_node_alloc_resp(sizeof(x_node_error_t));
	out_buf.length = out_buf.head->length;

	uint8_t *out_hdr = out_buf.head->get_data();
	auto node_err = (x_node_error_t *)(out_hdr + sizeof(x_node_error_t));
	node_err->unused = 0;

	return 0;
}

#define X_NODED_REPLY_ERROR(noded_requ, status, out_buf) \
	x_noded_reply_error((noded_requ), (status), (out_buf), __FILE__, __LINE__)

static int x_noded_reply_interim(x_noded_conn_t *noded_conn, x_noded_requ_t *noded_requ,
		const char *file, unsigned int line)
{
	X_LOG(NODED, OP, "%ld RESP ASYNC at %s:%d", noded_requ->in_node_requ.mid,
			file, line);

	x_out_buf_t out_buf;
	out_buf.head = out_buf.tail = x_node_alloc_resp(sizeof(x_node_interim_t));
	out_buf.length = out_buf.head->length;

	auto out_resp = (x_node_interim_t *)(out_buf.head->get_data() +
			sizeof(x_node_resp_t));

	noded_requ->interim_state = x_nxfsd_requ_t::INTERIM_S_SENT;
	out_resp->async_id = X_H2LE64(x_nxfsd_requ_get_async_id(noded_requ));

	x_noded_set_reply_hdr(noded_requ, NT_STATUS_PENDING, out_buf);
	X_NODED_COUNTER_INC(noded_reply_interim, 1);

	noded_requ->compound_out_buf.append(out_buf);

	return 0;
}

#define X_NODED_REPLY_INTERIM(noded_conn, noded_requ) \
	x_noded_reply_interim((noded_conn), (noded_requ), __FILE__, __LINE__)

static bool is_success(NTSTATUS status)
{
	return NT_STATUS_IS_OK(status) ||
		NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED) ||
		NT_STATUS_EQUAL(status, NT_STATUS_NOTIFY_ENUM_DIR);
}

static void noded_requ_done(x_noded_conn_t *noded_conn, x_noded_requ_t *noded_requ,
		x_noded_requ_context_t &requ_ctx, NTSTATUS status)
{
	X_ASSERT(status != NT_STATUS_PENDING);

	auto out_buf = std::move(noded_requ->requ_out_buf);
	if (!out_buf.head) {
		X_ASSERT(!is_success(status));
		X_NODED_REPLY_ERROR(noded_requ, status, out_buf);
		X_ASSERT(out_buf.head);
	}
	noded_requ->status = status;

	X_NODED_REQU_LOG(DBG, noded_requ, " done %s status=%s at %s",
			x_tostr(noded_conn->base).c_str(),
			x_ntstatus_str(status),
			noded_requ->location);
	x_noded_reply(noded_conn, noded_requ, status, out_buf);
	X_NODED_UPDATE_OP_HISTOGRAM(noded_requ);

	requ_ctx.proto = noded_requ->proto;
	requ_ctx.compound_id = noded_requ->compound_id;
	requ_ctx.in_buf = std::move(noded_requ->requ_in_buf);
	requ_ctx.in_buf.offset += requ_ctx.in_buf.length;
	requ_ctx.in_msgsize = noded_requ->in_msgsize;
	requ_ctx.status = noded_requ->status;
	requ_ctx.smbd_open = std::exchange(noded_requ->smbd_open, nullptr);
	requ_ctx.out_buf = std::move(noded_requ->compound_out_buf);
	requ_ctx.out_buf.append(out_buf);

	x_nxfsd_conn_done_requ(noded_requ);
	noded_requ->decref();
}

static int noded_conn_process_msg(x_noded_conn_t *noded_conn, x_noded_requ_context_t &requ_ctx)
{
	uint32_t in_requ_len = 0;
	auto &in_buf = requ_ctx.in_buf;
	auto proto = requ_ctx.proto;

	for (; in_buf.offset < requ_ctx.in_msgsize; ) {
		in_requ_len = requ_ctx.in_msgsize - in_buf.offset;
		if (in_requ_len < sizeof(x_node_requ_t)) {
			return -EBADMSG;
		}

		auto in_node_requ = (const x_node_requ_t *)(in_buf.get_data());
		uint32_t next_command = X_LE2H32(in_node_requ->next_command);
		if (next_command != 0) {
			if (next_command < sizeof(x_node_requ_t) || next_command + sizeof(x_node_requ_t) >= in_requ_len) {
				return -EBADMSG;
			}
			in_requ_len = next_command;
		}

		uint16_t opcode = in_node_requ->opcode;
		if (opcode >= proto->num_ops) {
			return -EBADMSG;
		}

		in_buf.length = in_requ_len;
		x_noded_requ_t *noded_requ = nullptr;
		NTSTATUS status = proto->ops[opcode].parse_func(noded_conn, &noded_requ, in_buf);
		if (!status.ok()) {
			X_TODO;
		}

		noded_requ->requ_in_buf = std::move(requ_ctx.in_buf);
		noded_requ->in_msgsize = requ_ctx.in_msgsize;

		noded_requ->in_node_requ.mid = X_LE2H64(in_node_requ->mid);
		noded_requ->in_node_requ.opcode = in_node_requ->opcode;
		noded_requ->in_node_requ.flags = X_LE2H32(in_node_requ->flags);
		noded_requ->in_node_requ.next_command = next_command;

		noded_requ->proto = proto;
		noded_requ->compound_id = requ_ctx.compound_id;
		noded_requ->smbd_open = std::exchange(requ_ctx.smbd_open, nullptr);
		noded_requ->status = requ_ctx.status;

		X_NODED_REQU_LOG(DBG, noded_requ, " start %s",
				x_tostr(noded_conn->base).c_str());

		if (!x_nxfsd_conn_start_requ(&noded_conn->base, noded_requ)) {
			X_TODO;
		}

		status = noded_requ->process(noded_conn);
		if (status == NT_STATUS_PENDING) {
			if (x_nxfsd_requ_schedule_interim(noded_requ)) {
				X_NODED_REPLY_INTERIM(noded_conn, noded_requ);
				noded_conn_queue(noded_conn, noded_requ);
			}
			break;
		} else if (status == X_NT_STATUS_INTERNAL_TERMINATE) {
			x_nxfsd_conn_done_requ(noded_requ);
			noded_requ->decref();
			return -EBADMSG;
		} else if (status == X_NT_STATUS_INTERNAL_BLOCKED) {
			return 0;
		}

		status = noded_requ->done_node(noded_conn, status);
		noded_requ_done(noded_conn, noded_requ, requ_ctx, status);
	}

	/* CANCEL request do not have response */
	if (requ_ctx.out_buf.length > 0) {
		noded_conn_queue(noded_conn, requ_ctx);
	}
	return 0;
}

static ssize_t noded_conn_cb_check_header(x_nxfsd_conn_t *nxfsd_conn)
{
	x_noded_conn_t *noded_conn = noded_conn_from_base(nxfsd_conn);
	X_LOG(SMB, CONN, "%p", noded_conn);

	uint32_t magic = ntohl(noded_conn->node_hdr.magic);
	const x_noded_proto_t *proto = nullptr;
	for (size_t i = 0; i < std::size(x_noded_protos); i++) {
		if (x_noded_protos[i].magic == magic) {
			proto = &x_noded_protos[i];
			break;
		}
	}
	if (!proto) {
		X_LOG(NODED, WARN, "invalid magic 0x%08x", magic);
		return -EBADMSG;
	}
	uint32_t size = ntohl(noded_conn->node_hdr.length);
	if (size > X_NODE_MAX_MSG) {
		X_LOG(NODED, WARN, "invalid node msg size 0x%08x", size);
		return -EMSGSIZE;
	}
	noded_conn->proto = proto;
	return size;
}

static int noded_conn_cb_process_msg(x_nxfsd_conn_t *nxfsd_conn, x_buf_t *buf, uint32_t msgsize)
{
	x_noded_conn_t *noded_conn = noded_conn_from_base(nxfsd_conn);
	x_noded_requ_context_t requ_ctx;
	requ_ctx.compound_id = ++noded_conn->num_msg;
	requ_ctx.in_buf.buf = buf;
	requ_ctx.in_buf.offset = 0;
	requ_ctx.in_buf.length = 0;
	requ_ctx.in_msgsize = msgsize;
	requ_ctx.proto = noded_conn->proto;

	return noded_conn_process_msg(noded_conn, requ_ctx);
}

static void noded_conn_cb_destroy(x_nxfsd_conn_t *nxfsd_conn)
{
	x_noded_conn_t *noded_conn = noded_conn_from_base(nxfsd_conn);
	X_LOG(NODED, CONN, "%p", noded_conn);
	delete noded_conn;
}

/* this function is in the noded_conn work thread context */
static void noded_conn_cb_close(x_nxfsd_conn_t *nxfsd_conn)
{
	x_noded_conn_t *noded_conn = noded_conn_from_base(nxfsd_conn);
	X_LOG(NODED, CONN, "%p", noded_conn);
	x_dlink_t *link;
	while ((link = noded_conn->open_list.get_front()) != nullptr) {
		noded_conn->open_list.remove(link);
		x_smbd_open_unlinked(link, true);
	}
}

static bool noded_conn_cb_can_remove(x_nxfsd_conn_t *nxfsd_conn, x_nxfsd_requ_t *nxfsd_requ)
{
	x_noded_conn_t *noded_conn = noded_conn_from_base(nxfsd_conn);
	x_noded_requ_t *noded_requ = dynamic_cast<x_noded_requ_t *>(nxfsd_requ);
	X_LOG(NODED, CONN, "%p %p", noded_conn, noded_requ);
	return true;
}

static void noded_conn_cb_reply_interim(x_nxfsd_conn_t *nxfsd_conn, x_nxfsd_requ_t *nxfsd_requ)
{
	x_noded_conn_t *noded_conn = noded_conn_from_base(nxfsd_conn);
	x_noded_requ_t *noded_requ = dynamic_cast<x_noded_requ_t *>(nxfsd_requ);
	X_LOG(NODED, CONN, "%p %p", noded_conn, noded_requ);
	X_NODED_REPLY_INTERIM(noded_conn, noded_requ);
	noded_conn_queue(noded_conn, noded_requ);
}

static const x_nxfsd_conn_cbs_t noded_conn_upcall_cbs = {
	noded_conn_cb_check_header,
	noded_conn_cb_process_msg,
	noded_conn_cb_destroy,
	noded_conn_cb_close,
	noded_conn_cb_can_remove,
	noded_conn_cb_reply_interim,
};

static inline x_noded_conn_t *noded_conn_from_base(x_nxfsd_conn_t *base)
{
	X_ASSERT(base->cbs == &noded_conn_upcall_cbs);
	return X_CONTAINER_OF(base, x_noded_conn_t, base);
}

x_noded_conn_t::x_noded_conn_t(int fd, const x_sockaddr_t &saddr)
	: base(&noded_conn_upcall_cbs, fd, saddr, x_noded_conn_t::MAX_MSG,
			sizeof(node_hdr), &node_hdr)
{
	X_NODED_COUNTER_INC_CREATE(noded_conn, 1);
}

x_noded_conn_t::~x_noded_conn_t()
{
	X_LOG(NODED, DBG, "x_noded_conn_t %p destroy", this);
	X_NODED_COUNTER_INC_DELETE(noded_conn, 1);
}

static inline x_noded_t *x_noded_from_strm_srv(x_strm_srv_t *strm_srv)
{
	return X_CONTAINER_OF(strm_srv, x_noded_t, base);
}

static void x_noded_cb_accepted(x_strm_srv_t *strm_srv, int fd,
			const struct sockaddr *sa, socklen_t slen)
{
	x_sockaddr_t *saddr = (x_sockaddr_t *)sa;
	X_ASSERT(slen <= sizeof(*saddr));
	set_nbio(fd, 1);
	saddr->normalize();
	x_noded_conn_t *noded_conn = new x_noded_conn_t(fd, *saddr);
	X_ASSERT(noded_conn != NULL);
	X_LOG(SMB, CONN, "accepted noded_conn %p %s", noded_conn,
			x_tostr(noded_conn->base).c_str());

	x_nxfsd_conn_start(&noded_conn->base);
}

static void x_noded_cb_shutdown(x_strm_srv_t *strm_srv)
{
	x_noded_t *noded = x_noded_from_strm_srv(strm_srv);
	X_LOG(NODED, CONN, "%p", noded);
	/* TODO may close all accepted client, and notify it is freed */
}

static const x_strm_srv_cbs_t noded_cbs = {
	x_noded_cb_accepted,
	x_noded_cb_shutdown,
};

static x_noded_t g_noded;
int x_noded_init()
{
	auto nxfsd_conf = x_smbd_conf_get();
	return x_tcp_srv_init(&g_noded.base, nxfsd_conf->node_port, &noded_cbs);
}

int x_noded_register_proto(uint32_t magic, uint32_t num_ops, const x_noded_op_t *ops)
{
	for (size_t i = 0; i < std::size(x_noded_protos); i++) {
		if (x_noded_protos[i].magic == 0) {
			x_noded_protos[i].magic = magic;
			x_noded_protos[i].num_ops = num_ops;
			x_noded_protos[i].ops = ops;
			return 0;
		}
	}
	return -ENOSPC;
}

void x_noded_requ_t::async_done(void *ctx_conn, NTSTATUS status)
{
	X_ASSERT(status != NT_STATUS_PENDING);
	if (!ctx_conn) {
		x_nxfsd_conn_done_requ(this);
		this->decref();
		return;
	}

	auto noded_conn = (x_noded_conn_t *)ctx_conn;
	NTSTATUS status1 = this->done_node(noded_conn, status);
	x_noded_requ_context_t requ_ctx;
	noded_requ_done(noded_conn, this, requ_ctx, status1);

	int err = noded_conn_process_msg(noded_conn, requ_ctx);
	if (err < 0) {
		X_TODO; // x_smbd_conn_reset(smbd_conn);
	}
}

enum {
	SMBD_OPEN_S_INIT,
	SMBD_OPEN_S_ACTIVE,
	SMBD_OPEN_S_DISCONNECTED, /* durable handle waiting reconnect */
	SMBD_OPEN_S_DONE,
};

void x_noded_conn_link_open(x_nxfsd_conn_t *nxfsd_conn, x_smbd_open_t *smbd_open)
{
	x_noded_conn_t *noded_conn = noded_conn_from_base(nxfsd_conn);
	noded_conn->open_list.push_back(&smbd_open->tcon_link);
	X_ASSERT(smbd_open->state == SMBD_OPEN_S_INIT);
	smbd_open->state = SMBD_OPEN_S_ACTIVE;
	x_ref_inc(smbd_open);

}


#undef X_NODED_COUNTER_DECL
#define X_NODED_COUNTER_DECL(x) # x,
static const char *noded_counter_names[] = {
	X_NODED_COUNTER_ENUM
};

#undef X_NODED_PAIR_COUNTER_DECL
#define X_NODED_PAIR_COUNTER_DECL(x) # x,
static const char *noded_pair_counter_names[] = {
	X_NODED_PAIR_COUNTER_ENUM
};

#undef X_NODED_HISTOGRAM_DECL
#define X_NODED_HISTOGRAM_DECL(x) # x,
static const char *noded_histogram_names[] = {
	X_NODED_HISTOGRAM_ENUM
};

x_stats_module_t x_noded_stats = {
	"noded",
	X_NODED_COUNTER_ID_MAX,
	X_NODED_PAIR_COUNTER_ID_MAX,
	X_NODED_HISTOGRAM_ID_MAX,
	noded_counter_names,
	noded_pair_counter_names,
	noded_histogram_names,
};

void x_noded_stats_init()
{
	x_stats_register_module(x_noded_stats);
}
