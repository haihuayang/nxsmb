
#include "smbd_open.hxx"
#include "include/charset.hxx"
#include "smbd_dcerpc.hxx"
#if 0
#include "include/librpc/dcerpc_ndr.hxx"
#endif
#include "include/librpc/wkssvc.hxx"
#include "include/librpc/srvsvc.hxx"
#include "include/librpc/security.hxx"
#include "smbd_share.hxx"

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

struct named_pipe_t
{
	named_pipe_t(x_smbd_object_t *so, x_smbd_tcon_t *st,
			uint32_t am, uint32_t sa)
		: base(so, nullptr, st, am, sa, 0) { }
	x_smbd_open_t base;
	// const x_dcerpc_iface_t *iface;
	std::vector<x_bind_context_t> bind_contexts;
	x_dcerpc_pipe_t rpc_pipe;
	x_ncacn_packet_t pkt;
	NTSTATUS return_status{NT_STATUS_OK};
	uint32_t packet_read = 0;
	uint32_t offset = 0;
	std::vector<uint8_t> input;
	std::vector<uint8_t> output;
};

struct x_smbd_ipc_object_t
{
	x_smbd_ipc_object_t(const std::u16string &name, const x_dcerpc_iface_t *iface);
	x_smbd_object_t base;
	const x_dcerpc_iface_t * const iface;
};

static const x_dcerpc_iface_t *find_iface_by_syntax(
		const idl::ndr_syntax_id &syntax);

static inline x_smbd_ipc_object_t *from_smbd_object(x_smbd_object_t *smbd_object)
{
	return X_CONTAINER_OF(smbd_object, x_smbd_ipc_object_t, base);
}

static inline const x_smbd_ipc_object_t *from_smbd_object(const x_smbd_object_t *smbd_object)
{
	return X_CONTAINER_OF(smbd_object, x_smbd_ipc_object_t, base);
}

static inline named_pipe_t *from_smbd_open(x_smbd_open_t *smbd_open)
{
	return X_CONTAINER_OF(smbd_open, named_pipe_t, base);
}

static NTSTATUS named_pipe_read(
		x_smbd_ipc_object_t *ipc_object,
		named_pipe_t *named_pipe,
		x_smbd_conn_t *smbd_conn,
		uint32_t requ_length,
		x_buf_t *&out_buf,
		uint32_t &out_buf_length)
{
	if (named_pipe->output.size() == 0) {
		X_TODO;
		return STATUS_PENDING; // should keep the original request
	}
	uint32_t data_copy = x_convert_assert<uint32_t>(named_pipe->output.size()) - named_pipe->offset;
	if (data_copy > requ_length) {
		data_copy = requ_length;
	}
	out_buf = x_buf_alloc(data_copy);
	memcpy(out_buf->data, named_pipe->output.data() + named_pipe->offset, data_copy);
	out_buf_length = data_copy;
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

static bool x_smbd_named_pipe_bind(named_pipe_t *named_pipe,
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
	if (!(ctx.abstract_syntax == named_pipe->iface->syntax_id)) {
	 */
	const x_dcerpc_iface_t *iface = find_iface_by_syntax(ctx.abstract_syntax);
	if (!iface) {
		ack_ctx.result = idl::DCERPC_BIND_ACK_RESULT_USER_REJECTION;
		ack_ctx.reason.value = idl::DCERPC_BIND_ACK_REASON_ABSTRACT_SYNTAX_NOT_SUPPORTED;
		ack_ctx.syntax = PNIO;
		return false;
	}

	named_pipe->bind_contexts.push_back(x_bind_context_t{ctx.context_id, iface});
	ack_ctx.result = idl::DCERPC_BIND_ACK_RESULT_ACCEPTANCE;
	ack_ctx.reason.value = idl::DCERPC_BIND_ACK_REASON_NOT_SPECIFIED;
	ack_ctx.syntax = ndr_transfer_syntax_ndr;
	return true;
}

static NTSTATUS process_dcerpc_bind(
		const x_smbd_ipc_object_t *ipc_object,
		named_pipe_t *named_pipe,
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
	bind_ack.secondary_address= "\\PIPE\\" + x_convert_utf16_to_utf8(ipc_object->base.path);

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

static const x_dcerpc_iface_t *find_context(named_pipe_t *named_pipe, uint32_t context_id)
{
	for (const auto ctx: named_pipe->bind_contexts) {
		if (ctx.context_id == context_id) {
			return ctx.iface;
		}
	}
	return nullptr;
}

static NTSTATUS process_dcerpc_request(
		const x_smbd_ipc_object_t* ipc_object,
		named_pipe_t *named_pipe,
		x_smbd_sess_t *smbd_sess,
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
		idl::dcerpc_nca_status dce_status = iface->cmds[opnum](
				named_pipe->rpc_pipe, smbd_sess,
				request, resp_type, output, ndr_flags);
		X_TODO_ASSERT(resp_type == idl::DCERPC_PKT_RESPONSE);
		X_TODO_ASSERT(dce_status == 0);
		idl::dcerpc_response response;
		response.alloc_hint = x_convert_assert<uint32_t>(output.size());
		response.context_id = 0;
		response.cancel_count = 0;
		response.stub_and_verifier.val.swap(output);

		x_ndr_push(response, body_output, ndr_flags);
	}
	return NT_STATUS_OK;
}

static inline NTSTATUS process_ncacn_pdu(
		const x_smbd_ipc_object_t *ipc_object,
		named_pipe_t *named_pipe,
		x_smbd_sess_t *smbd_sess)
{
	std::vector<uint8_t> body_output;
	uint8_t resp_type;
	NTSTATUS status = NT_STATUS_INTERNAL_ERROR;
	switch (named_pipe->pkt.type) {
		case idl::DCERPC_PKT_BIND:
			status = process_dcerpc_bind(ipc_object, named_pipe, resp_type, body_output);
			break;
		case idl::DCERPC_PKT_REQUEST:
			status = process_dcerpc_request(ipc_object, named_pipe, smbd_sess, resp_type, body_output);
			break;
		default:
			X_TODO;
	}

	if (NT_STATUS_IS_OK(status)) {
		x_ncacn_packet_t resp_header = named_pipe->pkt;
		resp_header.type = resp_type;
		resp_header.pfc_flags = idl::DCERPC_PFC_FLAG_FIRST | idl::DCERPC_PFC_FLAG_LAST;
		resp_header.frag_length = x_convert_assert<uint16_t>(sizeof(x_ncacn_packet_t) + body_output.size());
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

static int named_pipe_write(
		x_smbd_ipc_object_t *ipc_object,
		named_pipe_t *named_pipe,
		x_smbd_sess_t *smbd_sess,
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
		uint32_t copy_len = x_convert_assert<uint32_t>(sizeof(x_ncacn_packet_t)) - named_pipe->packet_read;
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
		named_pipe->return_status = process_ncacn_pdu(ipc_object, named_pipe, smbd_sess);
	}
	return x_convert_assert<uint32_t>(data - _input_data);
}

static NTSTATUS ipc_object_op_read(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_read_t> &state)
{
	return named_pipe_read(from_smbd_object(smbd_object),
			from_smbd_open(smbd_requ->smbd_open),
			smbd_conn,
			state->in_length, state->out_buf,
			state->out_buf_length);
}

static NTSTATUS ipc_object_op_write(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_write_t> &state)
{
	int ret = named_pipe_write(from_smbd_object(smbd_object),
			from_smbd_open(smbd_requ->smbd_open),
			smbd_requ->smbd_sess,
			state->in_buf->data + state->in_buf_offset,
			state->in_buf_length);
	state->out_count = ret;
	state->out_remaining = 0;
	return NT_STATUS_OK;
}

static NTSTATUS ipc_object_op_getinfo(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_getinfo_t> &state)
{
	/* TODO should access check ? */
	/* SMB2_GETINFO_FILE, SMB2_FILE_STANDARD_INFO */
	if (state->in_info_class == SMB2_GETINFO_FILE) {
		if (state->in_info_level == SMB2_FILE_INFO_FILE_STANDARD_INFORMATION) {
			if (state->in_output_buffer_length < sizeof(x_smb2_file_standard_info_t)) {
				return STATUS_BUFFER_OVERFLOW;
			}
			state->out_data.resize(sizeof(x_smb2_file_standard_info_t));
			x_smb2_file_standard_info_t *info =
				(x_smb2_file_standard_info_t *)state->out_data.data();
			
			info->allocation_size = X_H2LE64(4096);
			info->end_of_file = 0;
			info->nlinks = X_H2LE32(1);
			info->delete_pending = 1; // not sure why samba assign 1
			info->directory = 0;
			info->unused = 0;
			return NT_STATUS_OK;
		} else if (state->in_info_level == SMB2_FILE_INFO_FILE_STREAM_INFORMATION) {
			return NT_STATUS_INVALID_PARAMETER;
		}
	} 
	return NT_STATUS_NOT_SUPPORTED;
}

static NTSTATUS ipc_object_op_setinfo(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_setinfo_t> &state,
		std::vector<x_smb2_change_t> &changes)
{
	return NT_STATUS_NOT_SUPPORTED;
}

static NTSTATUS ipc_object_op_ioctl(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_ioctl_t> &state)
{
	x_smbd_ipc_object_t *ipc_object = from_smbd_object(smbd_object);
	named_pipe_t *named_pipe = from_smbd_open(smbd_requ->smbd_open);
	switch (state->ctl_code) {
	case FSCTL_PIPE_TRANSCEIVE:
		named_pipe_write(ipc_object, named_pipe,
				smbd_requ->smbd_sess,
				state->in_buf->data + state->in_buf_offset,
				state->in_buf_length);
		return named_pipe_read(ipc_object, named_pipe,
				smbd_conn,
				state->in_max_output_length,
				state->out_buf,
				state->out_buf_length);
	default:
		X_TODO;
		return NT_STATUS_NOT_SUPPORTED;
	}
}

static NTSTATUS ipc_object_op_qdir(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_qdir_t> &state)
{
	return NT_STATUS_INVALID_PARAMETER;
}

static NTSTATUS ipc_object_op_notify(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_notify_t> &state)
{
	return NT_STATUS_INVALID_PARAMETER;
}

static NTSTATUS ipc_object_op_close(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_close_t> &state,
		std::vector<x_smb2_change_t> &changes)
{
	if (smbd_requ) {
		state->out_flags = 0;
	}
	return NT_STATUS_OK;
}

static void ipc_object_op_destroy(x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open)
{
	named_pipe_t *named_pipe = from_smbd_open(smbd_open);
	delete named_pipe;
}

#define USTR(x) u##x
#define DECL_RPC(x) { USTR(#x), &x_smbd_dcerpc_##x }
static x_smbd_ipc_object_t ipc_object_tbl[] = {
	DECL_RPC(srvsvc),
	DECL_RPC(wkssvc),
	DECL_RPC(dssetup),
	DECL_RPC(lsarpc),
};

static x_smbd_ipc_object_t *find_ipc_object_by_name(const std::u16string &path)
{
	for (auto &ipc: ipc_object_tbl) {
		if (path == ipc.base.path) {
			return &ipc;
		}
	}
	return nullptr;
}

static const x_dcerpc_iface_t *find_iface_by_syntax(
		const idl::ndr_syntax_id &syntax)
{
	for (const auto &ipc: ipc_object_tbl) {
		if (ipc.iface->syntax_id == syntax) {
			return ipc.iface;
		}
	}
	return nullptr;
}

static x_smbd_object_t *ipc_open_object(NTSTATUS *pstatus,
		std::shared_ptr<x_smbd_topdir_t> &topdir,
		const std::u16string &path,
		long path_priv_data,
		bool create_if)
{
	X_ASSERT(path_priv_data == 0);
	std::u16string in_name;
	in_name.reserve(path.size());
	std::transform(std::begin(path), std::end(path),
			std::back_inserter(in_name), tolower);

	x_smbd_ipc_object_t *ipc_object = find_ipc_object_by_name(in_name);
	if (!ipc_object) {
		*pstatus = NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}
	return &ipc_object->base;
}

static NTSTATUS ipc_create_open(x_smbd_open_t **psmbd_open,
			x_smbd_requ_t *smbd_requ,
			const std::string &volume,
			std::unique_ptr<x_smb2_state_create_t> &state)
{
	X_ASSERT(state->open_priv_data == 0);
	if (state->end_with_sep) {
		return NT_STATUS_OBJECT_NAME_INVALID;
	}

	if (state->in_ads_name.size() > 0 || state->is_dollar_data) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (state->in_desired_access & idl::SEC_STD_DELETE) {
		*psmbd_open = nullptr;
		return NT_STATUS_ACCESS_DENIED;
	}

	x_smbd_ipc_object_t *ipc_object = from_smbd_object(state->smbd_object);
	named_pipe_t *named_pipe = new named_pipe_t(&ipc_object->base,
			smbd_requ->smbd_tcon,
			state->in_desired_access,
			state->in_share_access);
	if (!x_smbd_open_store(&named_pipe->base)) {
		delete named_pipe;
		*psmbd_open = nullptr;
		return NT_STATUS_INSUFFICIENT_RESOURCES;
	}

	state->out_info.out_allocation_size = 4096;
	state->out_info.out_file_attributes = FILE_ATTRIBUTE_NORMAL;
	state->out_oplock_level = 0;
	state->out_create_flags = 0;
	state->out_create_action = FILE_WAS_OPENED;
	state->contexts = 0;

	// x_smbd_open_init(&named_pipe->base, &ipc_object->base, smbd_requ->smbd_tcon,

	*psmbd_open = &named_pipe->base;
	return NT_STATUS_OK;
}

static void ipc_op_release_object(x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream)
{
	X_ASSERT(!smbd_stream);
	// do nothing
}
#if 0
static uint32_t ipc_op_get_attributes(const x_smbd_object_t *smbd_object)
{
	return FILE_ATTRIBUTE_NORMAL;
}
#endif
static std::u16string ipc_op_get_path(const x_smbd_object_t *smbd_object,
		const x_smbd_open_t *smbd_open)
{
	return smbd_object->path;
}

static const x_smbd_object_ops_t x_smbd_ipc_object_ops = {
	ipc_open_object,
	ipc_object_op_close,
	ipc_object_op_read,
	ipc_object_op_write,
	nullptr, // op_lock
	ipc_object_op_getinfo,
	ipc_object_op_setinfo,
	ipc_object_op_ioctl,
	ipc_object_op_qdir,
	ipc_object_op_notify,
	nullptr, // op_lease_break
	nullptr, // op_oplock_break
	nullptr, // op_rename
	nullptr, // op_set_delete_on_close
	nullptr, // notify_fname
	ipc_object_op_destroy,
	ipc_op_release_object,
	ipc_op_get_path,
};

static std::shared_ptr<x_smbd_topdir_t> ipc_get_topdir()
{
	static std::shared_ptr<x_smbd_topdir_t> topdir = 
		x_smbd_topdir_create("", &x_smbd_ipc_object_ops);
	return topdir;
}

x_smbd_ipc_object_t::x_smbd_ipc_object_t(const std::u16string &path,
		const x_dcerpc_iface_t *iface)
		: base(ipc_get_topdir(), 0, path), iface(iface)
{
	base.flags = x_smbd_object_t::flag_initialized;
	base.type = x_smbd_object_t::type_file;
}

struct ipc_share_t : x_smbd_share_t
{
	ipc_share_t() : x_smbd_share_t("ipc$")
			, topdir(ipc_get_topdir()) {
	}
	uint8_t get_type() const override {
		return SMB2_SHARE_TYPE_PIPE;
	}
	bool is_dfs() const override {
		return false;
	}
	bool abe_enabled() const override {
		return false;
	}

	NTSTATUS resolve_path(std::shared_ptr<x_smbd_topdir_t> &topdir,
			std::u16string &out_path,
			long &path_priv_data,
			long &open_priv_data,
			bool dfs,
			const char16_t *in_path_begin,
			const char16_t *in_path_end,
			const std::string &volume) override {
		topdir = this->topdir;
		out_path.assign(in_path_begin, in_path_end);
		path_priv_data = 0;
		open_priv_data = 0;
		return NT_STATUS_OK;
	}
	NTSTATUS get_dfs_referral(x_dfs_referral_resp_t &dfs_referral,
			const char16_t *in_full_path_begin,
			const char16_t *in_full_path_end,
			const char16_t *in_server_begin,
			const char16_t *in_server_end,
			const char16_t *in_share_begin,
			const char16_t *in_share_end) const override
	{
		return NT_STATUS_FS_DRIVER_REQUIRED;
	}

	NTSTATUS create_open(x_smbd_open_t **psmbd_open,
			x_smbd_requ_t *smbd_requ,
			const std::string &volume,
			std::unique_ptr<x_smb2_state_create_t> &state,
			std::vector<x_smb2_change_t> &changes) override {
		return ipc_create_open(psmbd_open, smbd_requ,
				volume, state);
	}

	virtual NTSTATUS delete_object(x_smbd_object_t *smbd_object,
			x_smbd_open_t *smbd_open, int fd,
			std::vector<x_smb2_change_t> &changes) override
	{
		X_ASSERT(false);
		return NT_STATUS_UNSUCCESSFUL;
	}
	const std::shared_ptr<x_smbd_topdir_t> topdir;
};

std::shared_ptr<x_smbd_share_t> x_smbd_ipc_share_create()
{
	return std::make_shared<ipc_share_t>();
}

int x_smbd_ipc_init()
{
	return 0;
}
#if 0
static std::unique_lock<std::mutex> ipc_lock_object(x_smbd_object_t *psmbd_object)
{
	return {};
}
#endif

