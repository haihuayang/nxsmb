
#include "smbd.hxx"
#include "include/charset.hxx"
#include "include/librpc/ndr_dcerpc.hxx"
#include "include/librpc/ndr_wkssvc.hxx"
#include "include/librpc/ndr_srvsvc.hxx"

namespace {

/* this guid indicates NDR encoding in a protocol tower */
static const idl::ndr_syntax_id ndr_transfer_syntax_ndr = {
	{ 0x8a885d04, 0x1ceb, 0x11c9, {0x9f, 0xe8}, {0x08,0x00,0x2b,0x10,0x48,0x60} },
	2
};

static const idl::ndr_syntax_id PNIO = {
	{ 0x0, 0x0, 0x0, {0x0, 0x0}, {0x0,0x0,0x0,0x0,0x0,0x0} },
	0
};

static struct x_rpc_iface_t {
	idl::ndr_syntax_id syntax_id;
	std::u16string iface_name;
} rpc_lookup[] = {
	{ { NDR_WKSSVC_UUID, NDR_WKSSVC_VERSION }, u"wkssvc", },
	{ { NDR_SRVSVC_UUID, NDR_SRVSVC_VERSION }, u"srvsvc", },
};

//static std::map<std::u16string, int> rpc_lookup;

static const x_rpc_iface_t *find_rpc_by_name(const std::u16string &name)
{
	for (const auto &rpc: rpc_lookup) {
		if (rpc.iface_name == name) {
			return &rpc;
		}
	}
	return nullptr;
}

static inline const x_rpc_iface_t *find_rpc_by_syntax(const idl::ndr_syntax_id &syntax)
{
	for (const auto &rpc: rpc_lookup) {
		if (rpc.syntax_id == syntax) {
			return &rpc;
		}
	}
	return nullptr;
}

struct x_ncacn_packet_t
{
	bool little_endian() const {
		return (drep[0] & idl::DCERPC_DREP_LE);
	}
	uint8_t rpc_vers;
	uint8_t rpc_vers_minor;
	uint8_t type;
	uint8_t pfc_flags;
	uint8_t drep[4];
	uint16_t frag_length;
	uint16_t auth_length;
	uint32_t call_id;
};

struct x_bind_context_t
{
	uint32_t context_id;
	const x_rpc_iface_t *rpc_iface;
};

struct x_smbd_name_pipe_t
{
	x_smbd_open_t base;
	const x_rpc_iface_t *rpc_iface;
	std::vector<x_bind_context_t> bind_contexts;
	x_ncacn_packet_t pkt;
	uint16_t packet_read = 0;
	uint32_t offset = 0;
	std::vector<uint8_t> input;
	std::vector<uint8_t> output;
};
}

static inline x_smbd_name_pipe_t *from_smbd_open(x_smbd_open_t *smbd_open)
{
	return X_CONTAINER_OF(smbd_open, x_smbd_name_pipe_t, base);
}

static NTSTATUS x_smbd_name_pipe_read(x_smbd_open_t *smbd_open, const x_smb2_requ_read_t &requ,
			std::vector<uint8_t> &output)
{
	x_smbd_name_pipe_t *name_pipe = from_smbd_open(smbd_open);
	if (name_pipe->output.size() == 0) {
		X_TODO;
		return STATUS_PENDING; // should keep the original request
	}
	uint32_t data_copy = name_pipe->output.size() - name_pipe->offset;
	if (data_copy > requ.length) {
		data_copy = requ.length;
	}
	output.assign(name_pipe->output.data() + name_pipe->offset, name_pipe->output.data() + name_pipe->offset + data_copy);
	name_pipe->offset += data_copy;
	if (name_pipe->offset == name_pipe->output.size()) {
		name_pipe->output.clear();
		name_pipe->offset = 0;
	}
	return name_pipe->output.size() == 0 ? NT_STATUS_OK : STATUS_BUFFER_OVERFLOW;
}

static inline bool process_ncacn_header(x_ncacn_packet_t &header)
{
	if (header.rpc_vers != 5 || header.rpc_vers_minor != 0) {
		return false;
	}

	if (!(header.little_endian())) {
		header.frag_length = ntohs(header.frag_length);
		header.auth_length = ntohs(header.auth_length);
	}
	if (header.frag_length < sizeof(x_ncacn_packet_t)) {
		return false;
	}
	if (header.auth_length > header.frag_length) {
		return false;
	}
	const uint8_t required_flags = idl::DCERPC_PFC_FLAG_FIRST | idl::DCERPC_PFC_FLAG_LAST;
	if ((header.pfc_flags & required_flags) != required_flags) {
		X_TODO; // dont know how the spec use the flags
		return false;
	}
	return true;
}

static bool x_smbd_name_pipe_bind(x_smbd_name_pipe_t *name_pipe,
		const idl::dcerpc_ctx_list &ctx,
		idl::dcerpc_ack_ctx &ack_ctx)
{
	// api_pipe_bind_req
	if (ctx.transfer_syntaxes.val.size() == 0) {
		ack_ctx.result = idl::DCERPC_BIND_ACK_RESULT_USER_REJECTION;
		ack_ctx.reason.value = idl::DCERPC_BIND_ACK_REASON_NOT_SPECIFIED;
		ack_ctx.syntax = PNIO;
		return false;
	}
	if (std::find(std::begin(ctx.transfer_syntaxes.val), std::end(ctx.transfer_syntaxes.val), ndr_transfer_syntax_ndr) == std::end(ctx.transfer_syntaxes.val)) {
		ack_ctx.result = idl::DCERPC_BIND_ACK_RESULT_USER_REJECTION;
		ack_ctx.reason.value = idl::DCERPC_BIND_ACK_REASON_TRANSFER_SYNTAXES_NOT_SUPPORTED;
		ack_ctx.syntax = PNIO;
		return false;
	}

	for (auto &bc: name_pipe->bind_contexts) {
		if (ctx.context_id != bc.context_id) {
			continue;
		}
		if (ctx.abstract_syntax == bc.rpc_iface->syntax_id) {
			X_TODO; // should insert context_id??
			ack_ctx.result = idl::DCERPC_BIND_ACK_RESULT_ACCEPTANCE;
			ack_ctx.reason.value = idl::DCERPC_BIND_ACK_REASON_NOT_SPECIFIED;
			ack_ctx.syntax = ndr_transfer_syntax_ndr;
			return true;
		}

		// not support change abstract syntax
		return false;
	}

	/* rpc_srv_pipe_exists_by_id,
	 * should we just compare the syntax_id of this pipe or find globally?
		const x_rpc_iface_t *rpc = find_rpc_by_syntax(ctx.abstract);
	 */
	if (!(ctx.abstract_syntax == name_pipe->rpc_iface->syntax_id)) {
		ack_ctx.result = idl::DCERPC_BIND_ACK_RESULT_USER_REJECTION;
		ack_ctx.reason.value = idl::DCERPC_BIND_ACK_REASON_ABSTRACT_SYNTAX_NOT_SUPPORTED;
		ack_ctx.syntax = PNIO;
		return false;
	}

	name_pipe->bind_contexts.push_back(x_bind_context_t{ctx.context_id, name_pipe->rpc_iface});
	ack_ctx.result = idl::DCERPC_BIND_ACK_RESULT_ACCEPTANCE;
	ack_ctx.reason.value = idl::DCERPC_BIND_ACK_REASON_NOT_SPECIFIED;
	ack_ctx.syntax = ndr_transfer_syntax_ndr;
	return true;
}

static NTSTATUS process_dcerpc_bind(x_smbd_name_pipe_t *name_pipe, std::vector<uint8_t> &output)
{
	idl::dcerpc_bind bind;
	uint32_t ndr_flags = name_pipe->pkt.little_endian() ? 0 : LIBNDR_FLAG_BIGENDIAN;
	idl::x_ndr_off_t ndr_ret = x_ndr_pull(bind, name_pipe->input.data(), name_pipe->input.size(), ndr_flags);
	if (ndr_ret < 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	if (bind.ctx_list.val.size() == 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	idl::dcerpc_bind_ack bind_ack;
	bind_ack.ctx_list.resize(bind.ctx_list.val.size());
	unsigned int ok_count = 0;
	for (size_t i = 0; i < bind.ctx_list.val.size(); ++i) {
		if (x_smbd_name_pipe_bind(name_pipe, bind.ctx_list.val[i], bind_ack.ctx_list.val[i])) {
			++ok_count;
		}
	}
	bind_ack.max_xmit_frag = 4280;
	bind_ack.max_recv_frag = 4280;
	if (bind.assoc_group_id != 0) {
		bind_ack.assoc_group_id = bind.assoc_group_id;
	} else {
		bind_ack.assoc_group_id = 0x53f0;
	}
	bind_ack.secondary_address.val = "\\PIPE\\" + x_convert_utf16_to_utf8(name_pipe->rpc_iface->iface_name);


	std::vector<uint8_t> body_output;
	x_ndr_push(bind_ack, body_output, ndr_flags);
	x_ncacn_packet_t resp_header = name_pipe->pkt;
	resp_header.type = idl::DCERPC_PKT_BIND_ACK;
	resp_header.pfc_flags = idl::DCERPC_PFC_FLAG_FIRST | idl::DCERPC_PFC_FLAG_LAST;
	resp_header.frag_length = sizeof(x_ncacn_packet_t) + body_output.size();
	resp_header.auth_length = 0;

	name_pipe->output.resize(resp_header.frag_length);

	if (!name_pipe->pkt.little_endian()) {
		resp_header.frag_length = htons(resp_header.frag_length);
	}
	memcpy(name_pipe->output.data(), &resp_header, sizeof(resp_header));
	memcpy(name_pipe->output.data() + sizeof(resp_header), body_output.data(), body_output.size());
	return NT_STATUS_OK;
}

static inline NTSTATUS process_ncacn_pdu(x_smbd_name_pipe_t *name_pipe)
{
	std::vector<uint8_t> output;
	switch (name_pipe->pkt.type) {
		case idl::DCERPC_PKT_BIND:
			process_dcerpc_bind(name_pipe, output);
			break;
		default:
			X_TODO;
	}

	/* TODO */
	name_pipe->packet_read = 0;
	name_pipe->input.clear();
	return NT_STATUS_OK;
}

static NTSTATUS x_smbd_name_pipe_write(x_smbd_open_t *smbd_open,
		const x_smb2_requ_write_t &requ,
		const uint8_t *data, x_smb2_resp_write_t &resp)
{
	x_smbd_name_pipe_t *name_pipe = from_smbd_open(smbd_open);
	uint32_t input_size = requ.data_length;
	const uint8_t *input_data = data;
	if (name_pipe->packet_read < sizeof(x_ncacn_packet_t)) {
		X_ASSERT(name_pipe->input.size() == 0);
		uint32_t copy_len = sizeof(x_ncacn_packet_t) - name_pipe->packet_read;
		if (copy_len > input_size) {
			copy_len = input_size;
		}
		memcpy((uint8_t *)&name_pipe->pkt + name_pipe->packet_read,
				data, copy_len);
		name_pipe->packet_read += copy_len;
		if (name_pipe->packet_read < sizeof(x_ncacn_packet_t)) {
			resp.write_count = input_size;
			resp.write_remaining = 0;
			return NT_STATUS_OK;
		}
		if (!process_ncacn_header(name_pipe->pkt)) {
			return NT_STATUS_RPC_PROTOCOL_ERROR;
		}

		input_size -= copy_len;
		input_data += copy_len;
	}

	X_ASSERT(name_pipe->packet_read <= name_pipe->pkt.frag_length);
	if (input_size) {
		uint32_t copy_len = name_pipe->pkt.frag_length - name_pipe->packet_read;
		if (copy_len > input_size) {
			copy_len = input_size;
		}
		name_pipe->input.insert(name_pipe->input.end(),
				input_data, input_data + copy_len);
		name_pipe->packet_read += copy_len;
		input_size -= copy_len;
		input_data += copy_len;
	}

	if (name_pipe->packet_read < name_pipe->pkt.frag_length) {
		resp.write_count = requ.data_length;
		resp.write_remaining = 0;
		return NT_STATUS_OK;
	}

	NTSTATUS status = process_ncacn_pdu(name_pipe);
	if (NT_STATUS_IS_OK(status)) {
		resp.write_count = requ.data_length - input_size;
		resp.write_remaining = 0;
	}
	return status;
}

static NTSTATUS x_smbd_name_pipe_getinfo(x_smbd_open_t *smbd_open, const x_smb2_requ_getinfo_t &requ, std::vector<uint8_t> &output)
{
	/* SMB2_GETINFO_FILE, SMB2_FILE_STANDARD_INFO */
	if (requ.info_class == 0x01 && requ.info_level == 0x05) {
		/* only little endian */
		struct {
			uint64_t allocation_size;
			uint64_t end_of_file;
			uint32_t link_count;
			uint8_t delete_pending;
			uint8_t is_directory;
			uint16_t reserve;
		} standard_info = {
			4096, 0, 1, 1, 0, 0
		};
		output.assign((const uint8_t *)&standard_info, (const uint8_t *)(&standard_info + 1));
		return NT_STATUS_OK;
	} else {
		return NT_STATUS_NOT_SUPPORTED;
	}
}

static NTSTATUS x_smbd_name_pipe_close(x_smbd_open_t *smbd_open,
		const x_smb2_requ_close_t &requ, x_smb2_resp_close_t &resp)
{
	memset(&resp, 0, sizeof resp);
	resp.struct_size = 0x3c;
	return NT_STATUS_OK;
}

static void x_smbd_name_pipe_destroy(x_smbd_open_t *smbd_open)
{
	x_smbd_name_pipe_t *name_pipe = from_smbd_open(smbd_open);
	delete name_pipe;
}

static const x_smbd_open_ops_t x_smbd_name_pipe_ops = {
	x_smbd_name_pipe_read,
	x_smbd_name_pipe_write,
	x_smbd_name_pipe_getinfo,
	nullptr,
	x_smbd_name_pipe_close,
	x_smbd_name_pipe_destroy,
};

static inline x_smbd_name_pipe_t *x_smbd_name_pipe_create(std::shared_ptr<x_smbd_tcon_t> &smbd_tcon, const x_rpc_iface_t *rpc)
{
	x_smbd_name_pipe_t *name_pipe = new x_smbd_name_pipe_t;
	name_pipe->base.ops = &x_smbd_name_pipe_ops;
	name_pipe->base.smbd_tcon = smbd_tcon;
	name_pipe->rpc_iface = rpc;
	return name_pipe;
}

static x_smbd_open_t *x_smbd_tcon_ipc_op_create(std::shared_ptr<x_smbd_tcon_t> &smbd_tcon,
		NTSTATUS &status, x_smb2_requ_create_t &requ_create)
{
	std::u16string in_name;
	in_name.reserve(requ_create.in_name.size());
	std::transform(std::begin(requ_create.in_name), std::end(requ_create.in_name),
			std::back_inserter(in_name), tolower);

	const x_rpc_iface_t *rpc = find_rpc_by_name(in_name);
	if (!rpc) {
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		return nullptr;
	}

	x_smbd_name_pipe_t *name_pipe = x_smbd_name_pipe_create(smbd_tcon, rpc);
	x_smbd_open_insert_local(&name_pipe->base);

	requ_create.out_create_ts.val = 0;
	requ_create.out_last_access_ts.val = 0;
	requ_create.out_last_write_ts.val = 0;
	requ_create.out_change_ts.val = 0;
	requ_create.out_allocation_size = 4096;
	requ_create.out_end_of_file = 0;
	requ_create.out_file_attributes = FILE_ATTRIBUTE_NORMAL;
	requ_create.out_oplock_level = 0;
	requ_create.out_create_flags = 0;
	requ_create.out_create_action = FILE_WAS_OPENED;

	//status = x_smbd_open_np_file(smbd_open);
	status = NT_STATUS_OK;
	return &name_pipe->base;
}

static const x_smbd_tcon_ops_t x_smbd_tcon_ipc_ops = {
	x_smbd_tcon_ipc_op_create,
};

void x_smbd_tcon_init_ipc(x_smbd_tcon_t *smbd_tcon)
{
	smbd_tcon->ops = &x_smbd_tcon_ipc_ops;
}

int x_smbd_ipc_init()
{
	return 0;
}

