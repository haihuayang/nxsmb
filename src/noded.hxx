
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
			x_in_buf_t &in_buf, uint32_t in_msgsize);
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
	explicit x_noded_requ_t(x_noded_conn_t *noded_conn,
			x_in_buf_t &in_buf, uint32_t in_msgsize);
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
	uint64_t compound_id;
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


#endif /* __noded__hxx__ */

