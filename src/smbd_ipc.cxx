
#include "smbd_open.hxx"
#include "include/charset.hxx"
#include "smbd_dcerpc.hxx"
#if 0
#include "include/librpc/dcerpc_ndr.hxx"
#endif
#include "include/librpc/wkssvc.hxx"
#include "include/librpc/srvsvc.hxx"
// #include "include/librpc/dcerpc_x.hxx"

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
	const x_dcerpc_iface_t *iface;
};

struct x_smbd_named_pipe_t
{
	x_smbd_open_t base;
	const x_dcerpc_iface_t *iface;
	std::vector<x_bind_context_t> bind_contexts;
	x_ncacn_packet_t pkt;
	NTSTATUS return_status{NT_STATUS_OK};
	uint16_t packet_read = 0;
	uint32_t offset = 0;
	std::vector<uint8_t> input;
	std::vector<uint8_t> output;
};
}


static const x_dcerpc_iface_t *rpc_lookup[] = {
	// { { WKSSVC_UUID, WKSSVC_VERSION }, u"wkssvc", 0, nullptr, /*WKSSVC_RPCGEN_N_CMD, x_dcerpc_wkssvc */},
	&x_smbd_dcerpc_srvsvc,
};

static const x_dcerpc_iface_t *find_rpc_by_name(const std::u16string &name)
{
	for (const auto rpc: rpc_lookup) {
		if (rpc->iface_name == name) {
			return rpc;
		}
	}
	return nullptr;
}

static inline const x_dcerpc_iface_t *find_rpc_by_syntax(const idl::ndr_syntax_id &syntax)
{
	for (const auto rpc: rpc_lookup) {
		if (rpc->syntax_id == syntax) {
			return rpc;
		}
	}
	return nullptr;
}


static inline x_smbd_named_pipe_t *from_smbd_open(x_smbd_open_t *smbd_open)
{
	return X_CONTAINER_OF(smbd_open, x_smbd_named_pipe_t, base);
}

static NTSTATUS named_pipe_read(x_smbd_conn_t *smbd_conn,
		x_smbd_named_pipe_t *named_pipe, uint32_t requ_length,
		std::vector<uint8_t> &output)
{
	if (named_pipe->output.size() == 0) {
		X_TODO;
		return STATUS_PENDING; // should keep the original request
	}
	uint32_t data_copy = named_pipe->output.size() - named_pipe->offset;
	if (data_copy > requ_length) {
		data_copy = requ_length;
	}
	output.assign(named_pipe->output.data() + named_pipe->offset, named_pipe->output.data() + named_pipe->offset + data_copy);
	named_pipe->offset += data_copy;
	if (named_pipe->offset == named_pipe->output.size()) {
		named_pipe->output.clear();
		named_pipe->offset = 0;
	}
	return named_pipe->output.size() == 0 ? NT_STATUS_OK : STATUS_BUFFER_OVERFLOW;
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

static bool x_smbd_named_pipe_bind(x_smbd_named_pipe_t *named_pipe,
		const idl::dcerpc_ctx_list &ctx,
		idl::dcerpc_ack_ctx &ack_ctx)
{
	// api_pipe_bind_req
	if (ctx.transfer_syntaxes.size() == 0) {
		ack_ctx.result = idl::DCERPC_BIND_ACK_RESULT_USER_REJECTION;
		ack_ctx.reason.value = idl::DCERPC_BIND_ACK_REASON_NOT_SPECIFIED;
		ack_ctx.syntax = PNIO;
		return false;
	}
	if (std::find(std::begin(ctx.transfer_syntaxes), std::end(ctx.transfer_syntaxes), ndr_transfer_syntax_ndr) == std::end(ctx.transfer_syntaxes)) {
		ack_ctx.result = idl::DCERPC_BIND_ACK_RESULT_USER_REJECTION;
		ack_ctx.reason.value = idl::DCERPC_BIND_ACK_REASON_TRANSFER_SYNTAXES_NOT_SUPPORTED;
		ack_ctx.syntax = PNIO;
		return false;
	}

	for (auto &bc: named_pipe->bind_contexts) {
		if (ctx.context_id != bc.context_id) {
			continue;
		}
		if (ctx.abstract_syntax == bc.iface->syntax_id) {
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
	if (!(ctx.abstract_syntax == named_pipe->iface->syntax_id)) {
		ack_ctx.result = idl::DCERPC_BIND_ACK_RESULT_USER_REJECTION;
		ack_ctx.reason.value = idl::DCERPC_BIND_ACK_REASON_ABSTRACT_SYNTAX_NOT_SUPPORTED;
		ack_ctx.syntax = PNIO;
		return false;
	}

	named_pipe->bind_contexts.push_back(x_bind_context_t{ctx.context_id, named_pipe->iface});
	ack_ctx.result = idl::DCERPC_BIND_ACK_RESULT_ACCEPTANCE;
	ack_ctx.reason.value = idl::DCERPC_BIND_ACK_REASON_NOT_SPECIFIED;
	ack_ctx.syntax = ndr_transfer_syntax_ndr;
	return true;
}

static NTSTATUS process_dcerpc_bind(x_smbd_named_pipe_t *named_pipe,
		uint8_t &resp_type, std::vector<uint8_t> &body_output)
{
	idl::dcerpc_bind bind;
	uint32_t ndr_flags = named_pipe->pkt.little_endian() ? 0 : LIBNDR_FLAG_BIGENDIAN;
	idl::x_ndr_off_t ndr_ret = x_ndr_pull(bind, named_pipe->input.data(), named_pipe->input.size(), ndr_flags);
	if (ndr_ret < 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	if (bind.ctx_list.size() == 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	idl::dcerpc_bind_ack bind_ack;
	bind_ack.ctx_list.resize(bind.ctx_list.size());
	unsigned int ok_count = 0;
	for (size_t i = 0; i < bind.ctx_list.size(); ++i) {
		if (x_smbd_named_pipe_bind(named_pipe, bind.ctx_list[i], bind_ack.ctx_list[i])) {
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
	bind_ack.secondary_address= "\\PIPE\\" + x_convert_utf16_to_utf8(named_pipe->iface->iface_name);

	x_ndr_push(bind_ack, body_output, ndr_flags);
	resp_type = idl::DCERPC_PKT_BIND_ACK;
	
#if 0
	std::vector<uint8_t> body_output;
	x_ndr_push(bind_ack, body_output, ndr_flags);
	x_ncacn_packet_t resp_header = named_pipe->pkt;
	resp_header.type = idl::DCERPC_PKT_BIND_ACK;
	resp_header.pfc_flags = idl::DCERPC_PFC_FLAG_FIRST | idl::DCERPC_PFC_FLAG_LAST;
	resp_header.frag_length = sizeof(x_ncacn_packet_t) + body_output.size();
	resp_header.auth_length = 0;

	named_pipe->output.resize(resp_header.frag_length);

	if (!named_pipe->pkt.little_endian()) {
		resp_header.frag_length = htons(resp_header.frag_length);
	}
	memcpy(named_pipe->output.data(), &resp_header, sizeof(resp_header));
	memcpy(named_pipe->output.data() + sizeof(resp_header), body_output.data(), body_output.size());
#endif
	return NT_STATUS_OK;
}

static const x_dcerpc_iface_t *find_context(x_smbd_named_pipe_t *named_pipe, uint32_t context_id)
{
	for (const auto ctx: named_pipe->bind_contexts) {
		if (ctx.context_id == context_id) {
			return ctx.iface;
		}
	}
	return nullptr;
}

static NTSTATUS process_dcerpc_request(x_smbd_conn_t *smbd_conn,
		x_smbd_named_pipe_t *named_pipe,
		uint8_t &resp_type, std::vector<uint8_t> &body_output)
{
	idl::dcerpc_request request;
	uint32_t ndr_flags = named_pipe->pkt.little_endian() ? 0 : LIBNDR_FLAG_BIGENDIAN;
	idl::x_ndr_off_t ndr_ret = x_ndr_pull(request, named_pipe->input.data(), named_pipe->input.size(), ndr_flags);
	if (ndr_ret < 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	X_ASSERT(named_pipe->pkt.auth_length == 0); // TODO

	// api_pipe_request
	const x_dcerpc_iface_t *iface = find_context(named_pipe, request.context_id);
	if (!iface) {
		return NT_STATUS_PIPE_DISCONNECTED;
	}

	uint32_t opnum = request.opnum;
	if (opnum >= iface->n_cmd) {
		x_smbd_dcerpc_fault(resp_type, body_output, ndr_flags);
	} else {
		std::vector<uint8_t> output;
		idl::dcerpc_nca_status dce_status = iface->cmds[opnum](smbd_conn,
				request, resp_type, output, ndr_flags);
		X_TODO_ASSERT(resp_type == idl::DCERPC_PKT_RESPONSE);
		X_TODO_ASSERT(dce_status == 0);
		idl::dcerpc_response response;
		response.alloc_hint = output.size();
		response.context_id = 0;
		response.cancel_count = 0;
		response.stub_and_verifier.val.swap(output);

		x_ndr_push(response, body_output, ndr_flags);
	}
	return NT_STATUS_OK;
}

static inline NTSTATUS process_ncacn_pdu(x_smbd_conn_t *smbd_conn, x_smbd_named_pipe_t *named_pipe)
{
	std::vector<uint8_t> body_output;
	uint8_t resp_type;
	NTSTATUS status = NT_STATUS_INTERNAL_ERROR;
	switch (named_pipe->pkt.type) {
		case idl::DCERPC_PKT_BIND:
			status = process_dcerpc_bind(named_pipe, resp_type, body_output);
			break;
		case idl::DCERPC_PKT_REQUEST:
			status = process_dcerpc_request(smbd_conn, named_pipe, resp_type, body_output);
			break;
		default:
			X_TODO;
	}

	if (NT_STATUS_IS_OK(status)) {
		x_ncacn_packet_t resp_header = named_pipe->pkt;
		resp_header.type = resp_type;
		resp_header.pfc_flags = idl::DCERPC_PFC_FLAG_FIRST | idl::DCERPC_PFC_FLAG_LAST;
		resp_header.frag_length = sizeof(x_ncacn_packet_t) + body_output.size();
		resp_header.auth_length = 0;

		named_pipe->output.resize(resp_header.frag_length);

		if (!named_pipe->pkt.little_endian()) {
			resp_header.frag_length = htons(resp_header.frag_length);
		}
		memcpy(named_pipe->output.data(), &resp_header, sizeof(resp_header));
		memcpy(named_pipe->output.data() + sizeof(resp_header), body_output.data(), body_output.size());
		/* TODO */
	}
	named_pipe->packet_read = 0;
	named_pipe->input.clear();
	return status;
}

static int named_pipe_write(x_smbd_conn_t *smbd_conn,
		x_smbd_named_pipe_t *named_pipe,
		const uint8_t *_input_data,
		uint32_t input_size)
{
	if (!NT_STATUS_IS_OK(named_pipe->return_status)) {
		return input_size;
	}

	/* TODO flow control */
	const uint8_t *data = _input_data;
	if (named_pipe->packet_read < sizeof(x_ncacn_packet_t)) {
		X_ASSERT(named_pipe->input.size() == 0);
		uint32_t copy_len = sizeof(x_ncacn_packet_t) - named_pipe->packet_read;
		if (copy_len > input_size) {
			copy_len = input_size;
		}
		memcpy((uint8_t *)&named_pipe->pkt + named_pipe->packet_read,
				data, copy_len);
		named_pipe->packet_read += copy_len;
		if (named_pipe->packet_read < sizeof(x_ncacn_packet_t)) {
			return input_size;
		}
		if (!process_ncacn_header(named_pipe->pkt)) {
			named_pipe->return_status = NT_STATUS_RPC_PROTOCOL_ERROR;
			return input_size;
		}

		input_size -= copy_len;
		data += copy_len;
	}

	X_ASSERT(named_pipe->packet_read <= named_pipe->pkt.frag_length);
	if (input_size) {
		uint32_t copy_len = named_pipe->pkt.frag_length - named_pipe->packet_read;
		if (copy_len > input_size) {
			copy_len = input_size;
		}
		named_pipe->input.insert(named_pipe->input.end(),
				data, data + copy_len);
		named_pipe->packet_read += copy_len;
		input_size -= copy_len;
		data += copy_len;
	}

	if (named_pipe->packet_read == named_pipe->pkt.frag_length) {
		/* complete pdu */
		named_pipe->return_status = process_ncacn_pdu(smbd_conn, named_pipe);
	}
	return data - _input_data;
}

static NTSTATUS x_smbd_named_pipe_read(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_read_t> &state)
{
	return named_pipe_read(smbd_conn, from_smbd_open(smbd_requ->smbd_open),
			state->in_length, state->out_data);
}

static NTSTATUS x_smbd_named_pipe_write(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_write_t> &state)
{
	int ret = named_pipe_write(smbd_conn, from_smbd_open(smbd_requ->smbd_open),
			state->in_data.data(), state->in_data.size());
	state->out_count = ret;
	state->out_remaining = 0;
	return NT_STATUS_OK;
}

static NTSTATUS x_smbd_named_pipe_getinfo(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_getinfo_t> &state)
{
	/* SMB2_GETINFO_FILE, SMB2_FILE_STANDARD_INFO */
	if (state->in_info_class == SMB2_GETINFO_FILE &&
			state->in_info_level == SMB2_FILE_INFO_FILE_STANDARD_INFORMATION) {
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
		state->out_data.assign((const uint8_t *)&standard_info, (const uint8_t *)(&standard_info + 1));
		return NT_STATUS_OK;
	} else {
		return NT_STATUS_NOT_SUPPORTED;
	}
}

static NTSTATUS x_smbd_named_pipe_setinfo(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_setinfo_t> &state)
{
	return NT_STATUS_NOT_SUPPORTED;
}

static NTSTATUS x_smbd_named_pipe_ioctl(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_ioctl_t> &state)
{
	x_smbd_named_pipe_t *named_pipe = from_smbd_open(smbd_requ->smbd_open);
	switch (state->ctl_code) {
	case FSCTL_PIPE_TRANSCEIVE:
		named_pipe_write(smbd_conn, named_pipe, state->in_data.data(),
				state->in_data.size());
		return named_pipe_read(smbd_conn, named_pipe,
				state->in_max_output_length, state->out_data);
	default:
		X_TODO;
		return NT_STATUS_NOT_SUPPORTED;
	}
}

static NTSTATUS x_smbd_named_pipe_find(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_find_t> &state)
{
	return NT_STATUS_INVALID_PARAMETER;
}

static NTSTATUS x_smbd_named_pipe_notify(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_notify_t> &state)
{
	return NT_STATUS_INVALID_PARAMETER;
}

static NTSTATUS x_smbd_named_pipe_close(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_close_t> &state)
{
	state->out_flags = 0;
	return NT_STATUS_OK;
}

static void x_smbd_named_pipe_destroy(x_smbd_open_t *smbd_open)
{
	x_smbd_named_pipe_t *named_pipe = from_smbd_open(smbd_open);
	delete named_pipe;
}

static const x_smbd_open_ops_t x_smbd_named_pipe_ops = {
	x_smbd_named_pipe_read,
	x_smbd_named_pipe_write,
	x_smbd_named_pipe_getinfo,
	x_smbd_named_pipe_setinfo,
	x_smbd_named_pipe_find,
	x_smbd_named_pipe_ioctl,
	x_smbd_named_pipe_notify,
	x_smbd_named_pipe_close,
	x_smbd_named_pipe_destroy,
};

static inline x_smbd_named_pipe_t *x_smbd_named_pipe_create(x_smbd_tcon_t *smbd_tcon, const x_dcerpc_iface_t *iface)
{
	x_smbd_named_pipe_t *named_pipe = new x_smbd_named_pipe_t;
	named_pipe->base.ops = &x_smbd_named_pipe_ops;
	named_pipe->base.smbd_tcon = smbd_tcon;
	named_pipe->iface = iface;
	return named_pipe;
}

static x_smbd_open_t *x_smbd_tcon_ipc_op_create(x_smbd_tcon_t *smbd_tcon,
		NTSTATUS &status, x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state)
{
	std::u16string in_name;
	in_name.reserve(state->in_name.size());
	std::transform(std::begin(state->in_name), std::end(state->in_name),
			std::back_inserter(in_name), tolower);

	const x_dcerpc_iface_t *rpc = find_rpc_by_name(in_name);
	if (!rpc) {
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		return nullptr;
	}

	x_smbd_named_pipe_t *named_pipe = x_smbd_named_pipe_create(smbd_tcon, rpc);

	state->out_info.out_allocation_size = 4096;
	state->out_info.out_file_attributes = FILE_ATTRIBUTE_NORMAL;
	state->out_oplock_level = 0;
	state->out_create_flags = 0;
	state->out_create_action = FILE_WAS_OPENED;

	//status = x_smbd_open_np_file(smbd_open);
	status = NT_STATUS_OK;
	return &named_pipe->base;
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

