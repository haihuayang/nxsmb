
#ifndef __noded__hxx__
#define __noded__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "nxfsd.hxx"
#include "node.hxx"
#include "smbd.hxx"
#include "smbd_file.hxx"
#include <memory>

struct x_noded_conn_t;
struct x_noded_requ_t;

struct x_noded_op_t
{
	NTSTATUS (* const parse_func)(x_noded_conn_t *noded_conn,
			x_noded_requ_t **p_noded_requ,
			x_in_buf_t &in_buf);
};

struct x_noded_proto_t
{
	uint32_t magic;
	uint32_t num_ops;
	const x_noded_op_t *ops;
};

int x_noded_register_proto(uint32_t magic, uint32_t num_ops, const x_noded_op_t *ops);

struct x_noded_requ_t : x_nxfsd_requ_t
{
	explicit x_noded_requ_t(x_noded_conn_t *noded_conn);
	~x_noded_requ_t();

	void async_done(void *ctx_conn, NTSTATUS status) override;

	virtual NTSTATUS done_node(x_noded_conn_t *noded_conn, NTSTATUS status)
	{
		X_ASSERT(false);
		return NT_STATUS_INTERNAL_ERROR;
	}

	bool can_async() const override {
		return !is_compound_followed();
	}
	std::ostream &tostr(std::ostream &os) const override;

	bool is_compound_followed() const {
		return in_node_requ.next_command != 0;
	}

	const x_noded_proto_t *proto;
	uint32_t magic;
	x_node_requ_t in_node_requ;
};


#define X_NODED_REQU_SUB_DBG_FMT "mid=%lu f=0x%x op=%d"
#define X_NODED_REQU_SUB_DBG_ARG(noded_requ) \
		(noded_requ)->in_node_requ.mid, (noded_requ)->in_node_requ.flags, \
		(noded_requ)->in_node_requ.opcode

#define X_NODED_REQU_DBG_FMT "requ(%p 0x%lx " X_NODED_REQU_SUB_DBG_FMT ")"
#define X_NODED_REQU_DBG_ARG(noded_requ) (noded_requ), (noded_requ)->id, \
		X_NODED_REQU_SUB_DBG_ARG(noded_requ)

#define X_NODED_REQU_RETURN_STATUS(noded_requ, status) do { \
	X_LOG(NODED, OP, X_NODED_REQU_DBG_FMT " %s", \
			X_NODED_REQU_DBG_ARG(noded_requ), \
			x_ntstatus_str(status)); \
	return (status); \
} while (0)

#define X_NODED_REQU_LOG(level, noded_requ, fmt, ...) \
	X_LOG(NODED, level, X_NODED_REQU_DBG_FMT fmt, X_NODED_REQU_DBG_ARG(noded_requ), ##__VA_ARGS__)

int x_noded_init();

uint64_t x_noded_conn_get_epid(const x_noded_conn_t *noded_conn);

void x_noded_conn_requ_done(x_noded_conn_t *noded_conn, x_noded_requ_t *noded_requ,
		NTSTATUS status);

void x_noded_conn_send_unsolicited(x_noded_conn_t *noded_conn, x_bufref_t *buf,
		uint8_t opcode, uint32_t magic);

void x_noded_conn_link_open(x_nxfsd_conn_t *nxfsd_conn, x_smbd_open_t *smbd_open);

x_noded_requ_t *x_noded_requ_create(x_nxfsd_conn_t *nxfsd_conn,
		x_buf_t *in_buf, uint32_t in_msgsize);

NTSTATUS x_noded_requ_init_open(x_noded_requ_t *noded_requ,
		uint64_t id_persistent, uint64_t id_volatile,
		bool modify_call);

void x_noded_reply(x_noded_conn_t *noded_conn,
		x_noded_requ_t *noded_requ,
		x_bufref_t *buf_head,
		x_bufref_t *buf_tail,
		NTSTATUS status,
		size_t reply_size);

/* Declare counter id below, e.g., X_NODED_COUNTER_DECL(name) */
#define X_NODED_COUNTER_ENUM \
	X_NODED_COUNTER_DECL(noded_reply_interim) \

enum {
#undef X_NODED_COUNTER_DECL
#define X_NODED_COUNTER_DECL(x) X_NODED_COUNTER_ID_ ## x,
	X_NODED_COUNTER_ENUM
	X_NODED_COUNTER_ID_MAX,
};

/* Declare pair counter id below, e.g., X_NODED_PAIR_COUNTER_DECL(name) */
#define X_NODED_PAIR_COUNTER_ENUM \
	X_NODED_PAIR_COUNTER_DECL(noded_conn) \
	X_NODED_PAIR_COUNTER_DECL(noded_requ) \

enum {
#undef X_NODED_PAIR_COUNTER_DECL
#define X_NODED_PAIR_COUNTER_DECL(x) X_NODED_PAIR_COUNTER_ID_ ## x,
	X_NODED_PAIR_COUNTER_ENUM
	X_NODED_PAIR_COUNTER_ID_MAX,
};

/* Declare histogram id below, e.g., X_NODED_HISTOGRAM_DECL(name) */
#define X_NODED_HISTOGRAM_ENUM \
	X_NODED_HISTOGRAM_DECL(noded_op_ping) \

enum {
#undef X_NODED_HISTOGRAM_DECL
#define X_NODED_HISTOGRAM_DECL(x) X_NODED_HISTOGRAM_ID_ ## x,
	X_NODED_HISTOGRAM_ENUM
	X_NODED_HISTOGRAM_ID_MAX,
};

extern x_stats_module_t x_noded_stats;

#define X_NODED_COUNTER_INC(id, num) \
	X_STATS_COUNTER_INC(x_noded_stats.counter_base + X_NODED_COUNTER_ID_##id, (num))

#define X_NODED_COUNTER_INC_CREATE(id, num) \
	X_STATS_COUNTER_INC_CREATE(x_noded_stats.pair_counter_base + X_NODED_PAIR_COUNTER_ID_##id, (num))

#define X_NODED_COUNTER_INC_DELETE(id, num) \
	X_STATS_COUNTER_INC_DELETE(x_noded_stats.pair_counter_base + X_NODED_PAIR_COUNTER_ID_##id, (num))

#define X_NODED_HISTOGRAM_UPDATE_(id, elapsed) do { \
	local_stats.histograms[x_noded_stats.histogram_base + id].update(elapsed); \
} while (0)

#define X_NODED_HISTOGRAM_UPDATE(id, elapsed) \
	X_NODED_HISTOGRAM_UPDATE_(X_NODED_HISTOGRAM_ID_ ## id, elapsed)

void x_noded_stats_init();

#endif /* __noded__hxx__ */

