
#ifndef __node__hxx__
#define __node__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/ntstatus.hxx"
#include "smb2.hxx"
#include "buf.hxx"

enum {
	X_NODE_MAX_MSG = 0xffffff,
};

struct x_node_hdr_t
{
	uint32_t magic;
	uint32_t length;
};

struct x_node_requ_t
{
	uint64_t mid;
	uint32_t next_command;
	uint8_t opcode;
	uint8_t unused;
	uint16_t flags;
};

#define X_NODE_REQU_DBG_FMT "mid=%lu f=0x%x op=%d"
#define X_NODE_REQU_DBG_ARG(node_requ) \
		X_LE2H64((node_requ)->mid), X_LE2H16((node_requ)->flags), \
		((node_requ)->opcode)

struct x_node_resp_t
{
	uint64_t mid;
	uint32_t next_command;
	uint8_t opcode;
	uint8_t unused0;
	uint16_t flags;
	uint32_t status;
	uint32_t unused1;
};

struct x_node_interim_t
{
	uint64_t async_id;
};

struct x_node_error_t
{
	uint64_t unused;
};

static inline x_bufref_t *x_node_alloc_requ(size_t body_size)
{
	X_ASSERT(body_size + sizeof(x_node_requ_t) < 0x100000000ul);
	x_buf_t *out_buf = x_buf_alloc(sizeof(x_node_hdr_t) + sizeof(x_node_requ_t) + body_size);
	x_bufref_t *bufref = new x_bufref_t{out_buf, 8,
		x_convert_assert<uint32_t>(sizeof(x_node_requ_t) + body_size)};
	return bufref;
}

static inline x_bufref_t *x_node_alloc_resp(size_t body_size)
{
	size_t resp_size = sizeof(x_node_resp_t) + body_size;
	X_ASSERT(resp_size < 0x100000000ul);
	x_buf_t *out_buf = x_buf_alloc(sizeof(x_node_hdr_t) + resp_size);
	return new x_bufref_t{out_buf, x_convert<uint32_t>(sizeof(x_node_hdr_t)),
		x_convert<uint32_t>(resp_size)};
}

#endif /* __node__hxx__ */

