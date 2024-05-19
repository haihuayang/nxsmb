
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
#include "smbd_conf.hxx"
#include "smbd_stats.hxx"

/* this guid indicates NDR encoding in a protocol tower */
static const idl::ndr_syntax_id ndr_transfer_syntax_ndr = {
	{ 0x8a885d04, 0x1ceb, 0x11c9, {0x9f, 0xe8}, {0x08,0x00,0x2b,0x10,0x48,0x60} },
	2
};

static const idl::ndr_syntax_id ndr_transfer_syntax_ndr64 = {
	{ 0x71710533, 0xbeba, 0x4937, {0x83, 0x19}, {0xb5,0xdb,0xef,0x9c,0xcc,0x36} },
	1
};

static const idl::ndr_syntax_id PNIO = {
	{ 0x0, 0x0, 0x0, {0x0, 0x0}, {0x0,0x0,0x0,0x0,0x0,0x0} },
	0
};

static const x_smbd_object_meta_t ipc_object_meta{0, 0, 1, 0, 0, 0, 0, 
	X_SMB2_FILE_ATTRIBUTE_NORMAL};

static const x_smbd_stream_meta_t ipc_stream_meta{0, 4096, false};

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
	const uint32_t context_id;
	const uint32_t ndr_flags;
	const x_dcerpc_iface_t *const iface;
};

struct named_pipe_t
{
	named_pipe_t(x_smbd_object_t *so, x_smbd_tcon_t *st,
			const x_smbd_open_state_t &open_state)
		: base(so, nullptr, st, open_state) { }
	x_smbd_open_t base;
	// const x_dcerpc_iface_t *iface;
	std::vector<x_bind_context_t> bind_contexts;
	x_dcerpc_pipe_t rpc_pipe;
	x_ncacn_packet_t pkt;
	NTSTATUS return_status{NT_STATUS_OK};
	bool is_transceive = false;
	bool got_first = false;

	bool allow_bind = true;
	bool allow_alter = false;

	uint32_t packet_read = 0;
	uint32_t offset = 0;
	std::vector<uint8_t> input;
	std::vector<uint8_t> output;
};

struct x_smbd_ipc_root_t
{
	x_smbd_ipc_root_t(const std::shared_ptr<x_smbd_volume_t> &smbd_volume)
		: base(smbd_volume, nullptr, 0, 0, u"")
	{
		base.type = x_smbd_object_t::type_dir;
		base.flags = x_smbd_object_t::flag_initialized;
	}

	x_smbd_object_t base;
};

struct x_smbd_ipc_object_t
{
	x_smbd_ipc_object_t(const std::shared_ptr<x_smbd_volume_t> &smbd_volume,
			long priv_data, uint64_t hash,
			x_smbd_object_t *parent_object,
			const std::u16string &name,
			const x_dcerpc_iface_t *iface,
			std::string secondary_address);
	x_smbd_object_t base;
	const x_dcerpc_iface_t * const iface;
	const std::string secondary_address;
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
		uint32_t requ_length,
		x_buf_t *&out_buf,
		uint32_t &out_buf_length)
{
	if (named_pipe->output.size() == 0) {
		X_TODO;
		return NT_STATUS_PENDING; // should keep the original request
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
	named_pipe->got_first = false;
	if (named_pipe->output.size() == 0) {
		named_pipe->is_transceive = false;
		return NT_STATUS_OK;
	} else if (!named_pipe->is_transceive) {
		return NT_STATUS_OK;
	} else {
		return NT_STATUS_BUFFER_OVERFLOW;
	}
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
	return true;
}

static std::tuple<const x_dcerpc_iface_t *, unsigned int, idl::dcerpc_bind_ack_reason_values>
smbd_named_pipe_match_ctx(named_pipe_t *named_pipe,
		const idl::dcerpc_ctx_list &ctx,
		idl::dcerpc_ack_ctx &ack_ctx)
{
	// api_pipe_bind_req
	unsigned int weight = 0;
	for (auto &transfer_syntax: ctx.transfer_syntaxes) {
		if (x_smbd_conf_get_curr().ndr64 && transfer_syntax == ndr_transfer_syntax_ndr64) {
			weight = 2;
			break;
		} else if (transfer_syntax == ndr_transfer_syntax_ndr) {
			weight = 1;
		}
	}

	if (weight == 0) {
		return {nullptr, 0, idl::DCERPC_BIND_ACK_REASON_TRANSFER_SYNTAXES_NOT_SUPPORTED};
	}

	/* rpc_srv_pipe_exists_by_id,
	 * should we just compare the syntax_id of this pipe or find globally?
		const x_rpc_iface_t *rpc = find_rpc_by_syntax(ctx.abstract);
	if (!(ctx.abstract_syntax == named_pipe->iface->syntax_id)) {
	 */
	const x_dcerpc_iface_t *iface = find_iface_by_syntax(ctx.abstract_syntax);
	if (!iface) {
		return {nullptr, 0, idl::DCERPC_BIND_ACK_REASON_ABSTRACT_SYNTAX_NOT_SUPPORTED};
	}

	return {iface, weight, idl::DCERPC_BIND_ACK_REASON_NOT_SPECIFIED};
}

static const x_bind_context_t *find_context(named_pipe_t *named_pipe, uint32_t context_id)
{
	for (auto &ctx: named_pipe->bind_contexts) {
		if (ctx.context_id == context_id) {
			return &ctx;
		}
	}
	return nullptr;
}

static bool pull_dcerpc_bind(named_pipe_t *named_pipe,
		idl::dcerpc_bind &bind)
{
	uint32_t ndr_flags = named_pipe->pkt.little_endian() ? 0 : LIBNDR_FLAG_BIGENDIAN;
	idl::x_ndr_off_t ndr_ret = x_ndr_pull(bind, named_pipe->input.data(), named_pipe->input.size(), ndr_flags);
	if (ndr_ret < 0) {
		return false;
	}
	if (bind.ctx_list.size() == 0) {
		return false;
	}

	for (const auto &ctx: bind.ctx_list) {
		if (ctx.transfer_syntaxes.empty()) {
			return false;
		}
	}

	return true;
}

/* looks like windows client only expect 1 ctx accepted, otherwise it report rpc
 * protocol error
 */
static bool dcesrv_negotiate_contexts(named_pipe_t *named_pipe,
		const idl::dcerpc_bind &bind,
		idl::dcerpc_bind_ack &bind_ack)
{
	size_t matched_idx = bind.ctx_list.size();
	bool syntax_match = false;
	for (size_t i = 0; i < bind.ctx_list.size(); ++i) {
		auto &ctx = bind.ctx_list[i];
		auto bc = find_context(named_pipe, ctx.context_id);
		if (bc) {
			matched_idx = i;
			syntax_match = ctx.abstract_syntax == bc->iface->syntax_id;
			if (!syntax_match) {
				return false;
			}
			break;
		}
	}

	bind_ack.ctx_list.resize(bind.ctx_list.size());

	if (matched_idx < bind.ctx_list.size()) {
		for (size_t i = 0; i < bind.ctx_list.size(); ++i) {
			auto &ctx = bind.ctx_list[i];
			auto &ack_ctx = bind_ack.ctx_list[i];
			if (i != matched_idx) {
				ack_ctx.result = idl::DCERPC_BIND_ACK_RESULT_PROVIDER_REJECTION;
				ack_ctx.reason.value = idl::DCERPC_BIND_ACK_REASON_ABSTRACT_SYNTAX_NOT_SUPPORTED;
				ack_ctx.syntax = PNIO;
			} else if (syntax_match) {
				ack_ctx.result = idl::DCERPC_BIND_ACK_RESULT_ACCEPTANCE;
				ack_ctx.reason.value = idl::DCERPC_BIND_ACK_REASON_NOT_SPECIFIED;
				ack_ctx.syntax = ctx.transfer_syntaxes[0];
			} else {
				ack_ctx.result = idl::DCERPC_BIND_ACK_RESULT_PROVIDER_REJECTION;
				ack_ctx.reason.value = idl::DCERPC_BIND_ACK_REASON_ABSTRACT_SYNTAX_NOT_SUPPORTED;
				ack_ctx.syntax = PNIO;
			}
		}
		return true;
	}

	size_t id_max = 0;
	unsigned int weight_max = 0;
	const x_dcerpc_iface_t *iface_max = nullptr;
	for (size_t i = 0; i < bind.ctx_list.size(); ++i) {
		auto [iface, weight, reason] = smbd_named_pipe_match_ctx(
				named_pipe, bind.ctx_list[i], bind_ack.ctx_list[i]);
		if (weight > weight_max) {
			if (weight_max != 0) {
				auto &ack_ctx = bind_ack.ctx_list[id_max];
				ack_ctx.result = idl::DCERPC_BIND_ACK_RESULT_PROVIDER_REJECTION;
				ack_ctx.reason.value = idl::DCERPC_BIND_ACK_REASON_TRANSFER_SYNTAXES_NOT_SUPPORTED;
				ack_ctx.syntax = PNIO;
			}
			weight_max = weight;
			id_max = i;
			iface_max = iface;
		} else if (weight == 0) {
			auto &ack_ctx = bind_ack.ctx_list[i];
			ack_ctx.result = idl::DCERPC_BIND_ACK_RESULT_PROVIDER_REJECTION;
			ack_ctx.reason.value = idl::DCERPC_BIND_ACK_REASON_TRANSFER_SYNTAXES_NOT_SUPPORTED;
			ack_ctx.syntax = PNIO;
		} else {
			auto &ack_ctx = bind_ack.ctx_list[i];
			ack_ctx.result = idl::DCERPC_BIND_ACK_RESULT_PROVIDER_REJECTION;
			ack_ctx.reason.value = idl::DCERPC_BIND_ACK_REASON_TRANSFER_SYNTAXES_NOT_SUPPORTED;
			ack_ctx.syntax = PNIO;
		}
	}
	if (weight_max == 0) {
		return true;
	}

	auto &ack_ctx = bind_ack.ctx_list[id_max];
	auto &ctx = bind.ctx_list[id_max];
	ack_ctx.result = idl::DCERPC_BIND_ACK_RESULT_ACCEPTANCE;
	ack_ctx.reason.value = idl::DCERPC_BIND_ACK_REASON_NOT_SPECIFIED;
	uint32_t ndr_flags = 0;
	if (weight_max == 2) {
		ack_ctx.syntax = ndr_transfer_syntax_ndr64;
		ndr_flags = LIBNDR_FLAG_NDR64;
	} else {
		ack_ctx.syntax = ndr_transfer_syntax_ndr;
		ndr_flags = 0;
	}
	named_pipe->bind_contexts.push_back(x_bind_context_t{ctx.context_id, ndr_flags, iface_max});
	return true;
}

static bool process_dcerpc_bind_intl(
		const x_smbd_ipc_object_t *ipc_object,
		named_pipe_t *named_pipe,
		uint8_t &resp_type, std::vector<uint8_t> &body_output)
{
	if (!named_pipe->allow_bind) {
		return false;
	}

	named_pipe->allow_bind = false;

	idl::dcerpc_bind bind;
	if (!pull_dcerpc_bind(named_pipe, bind)) {
		return false;
	}

	idl::dcerpc_bind_ack bind_ack;
	dcesrv_negotiate_contexts(named_pipe, bind, bind_ack);

	// TODO handle auth

	bind_ack.max_xmit_frag = 4280;
	bind_ack.max_recv_frag = 4280;
	if (bind.assoc_group_id != 0) {
		bind_ack.assoc_group_id = bind.assoc_group_id;
	} else {
		bind_ack.assoc_group_id = 0x53f0;
	}
	bind_ack.secondary_address = ipc_object->secondary_address;
		//"\\PIPE\\" + x_convert_utf16_to_utf8_assert(ipc_object->base.path);

	uint32_t ndr_flags = named_pipe->pkt.little_endian() ? 0 : LIBNDR_FLAG_BIGENDIAN;
	x_ndr_push(bind_ack, body_output, ndr_flags);
	resp_type = idl::DCERPC_PKT_BIND_ACK;

	named_pipe->allow_alter = true;
	return true;
}

static NTSTATUS setup_bind_nak(named_pipe_t *named_pipe,
		uint8_t &resp_type, std::vector<uint8_t> &body_output)
{
	uint32_t ndr_flags = named_pipe->pkt.little_endian() ? 0 : LIBNDR_FLAG_BIGENDIAN;
	idl::dcerpc_bind_nak bind_nak;
	bind_nak.reject_reason = idl::DCERPC_BIND_NAK_REASON_NOT_SPECIFIED;
	x_ndr_push(bind_nak, body_output, ndr_flags);
	resp_type = idl::DCERPC_PKT_BIND_NAK;
	return NT_STATUS_OK;
}

static NTSTATUS process_dcerpc_bind(
		const x_smbd_ipc_object_t *ipc_object,
		named_pipe_t *named_pipe,
		uint8_t &resp_type, std::vector<uint8_t> &body_output)
{
	if (!process_dcerpc_bind_intl(ipc_object, named_pipe, resp_type, body_output)) {
		setup_bind_nak(named_pipe, resp_type, body_output);
	}
	return NT_STATUS_OK;
}

static void dcesrv_reply_fault(named_pipe_t *named_pipe,
		idl::dcerpc_nca_status nca_status,
		uint8_t &resp_type, std::vector<uint8_t> &body_output)
{
	uint32_t ndr_flags = named_pipe->pkt.little_endian() ? 0 : LIBNDR_FLAG_BIGENDIAN;
	idl::dcerpc_fault fault;
	fault.alloc_hint = 0;
	fault.context_id = 0;
	fault.cancel_count = 0;
	fault.status = nca_status;
	x_ndr_push(fault, body_output, ndr_flags);
	resp_type = idl::DCERPC_PKT_FAULT;
}

static NTSTATUS dcesrv_fault_disconnect(
		named_pipe_t *named_pipe,
		idl::dcerpc_nca_status nca_status,
		uint8_t &resp_type, std::vector<uint8_t> &body_output)
{
	named_pipe->allow_bind = false;
	named_pipe->allow_alter = false;

	dcesrv_reply_fault(named_pipe, nca_status, resp_type, body_output);
	return NT_STATUS_CONNECTION_DISCONNECTED;
}

/* samba dcesrv_alter */
static NTSTATUS process_dcerpc_alter(
		const x_smbd_ipc_object_t *ipc_object,
		named_pipe_t *named_pipe,
		x_smbd_sess_t *smbd_sess,
		uint8_t &resp_type, std::vector<uint8_t> &body_output)
{
	if (!named_pipe->allow_alter) {
		return dcesrv_fault_disconnect(named_pipe, idl::DCERPC_NCA_S_PROTO_ERROR,
				resp_type, body_output);
	}

	idl::dcerpc_bind bind;
	if (!pull_dcerpc_bind(named_pipe, bind)) {
		return dcesrv_fault_disconnect(named_pipe, idl::DCERPC_NCA_S_PROTO_ERROR,
				resp_type, body_output);
	}

	// TODO auth
	
	idl::dcerpc_bind_ack bind_ack;
#if 0
	NTSTATUS status = dcesrv_negotiate_contexts(named_pipe, bind, bind_ack);
	if (NT_STATUS_EQUAL(status, NT_STATUS_RPC_PROTOCOL_ERROR)) {
		return dcesrv_fault_disconnect(call, DCERPC_NCA_S_PROTO_ERROR);
	}
#endif
	if (!dcesrv_negotiate_contexts(named_pipe, bind, bind_ack)) {
		return dcesrv_fault_disconnect(named_pipe, idl::DCERPC_NCA_S_PROTO_ERROR,
				resp_type, body_output);
	}

	bind_ack.max_xmit_frag = 4280;
	bind_ack.max_recv_frag = 4280;
	if (bind.assoc_group_id != 0) {
		bind_ack.assoc_group_id = bind.assoc_group_id;
	} else {
		bind_ack.assoc_group_id = 0x53f0;
	}
	bind_ack.secondary_address = "";

	uint32_t ndr_flags = named_pipe->pkt.little_endian() ? 0 : LIBNDR_FLAG_BIGENDIAN;
	x_ndr_push(bind_ack, body_output, ndr_flags);
	resp_type = idl::DCERPC_PKT_ALTER_RESP;

	return NT_STATUS_OK;
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
	const auto ctx = find_context(named_pipe, request.context_id);
	if (!ctx) {
		return NT_STATUS_PIPE_DISCONNECTED;
	}

	uint32_t opnum = request.opnum;
	const auto iface = ctx->iface;
	idl::dcerpc_nca_status dce_status = idl::DCERPC_NCA_S_OP_RNG_ERROR;
	if (opnum < iface->n_cmd) {
		ndr_flags |= ctx->ndr_flags;
		std::vector<uint8_t> output;
		dce_status = iface->cmds[opnum](
				named_pipe->rpc_pipe, smbd_sess,
				request, resp_type, output, ndr_flags);
		if (dce_status == X_SMBD_DCERPC_NCA_STATUS_OK) {
			X_TODO_ASSERT(resp_type == idl::DCERPC_PKT_RESPONSE);
			idl::dcerpc_response response;
			response.alloc_hint = x_convert_assert<uint32_t>(output.size());
			response.context_id = 0;
			response.cancel_count = 0;
			response.stub_and_verifier.val.swap(output);

			x_ndr_push(response, body_output, ndr_flags);
		}
	}

	if (dce_status != X_SMBD_DCERPC_NCA_STATUS_OK) {
		idl::dcerpc_fault fault;
		fault.alloc_hint = 0;
		fault.context_id = 0;
		fault.cancel_count = 0;
		fault.status = dce_status;
		x_ndr_push(fault, body_output, ndr_flags);
		resp_type = idl::DCERPC_PKT_FAULT;
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
		case idl::DCERPC_PKT_ALTER:
			status = process_dcerpc_alter(ipc_object, named_pipe, smbd_sess, resp_type, body_output);
			break;
		default:
			X_TODO;
	}

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

	auto pfc_flags = named_pipe->pkt.pfc_flags;
	if ((pfc_flags & idl::DCERPC_PFC_FLAG_FIRST)) {
		if (named_pipe->got_first) {
			X_TODO;
			named_pipe->return_status = NT_STATUS_RPC_PROTOCOL_ERROR;
			return input_size;
		}
		named_pipe->got_first = true;
	} else {
		if (!named_pipe->got_first) {
			X_TODO;
			named_pipe->return_status = NT_STATUS_RPC_PROTOCOL_ERROR;
			return input_size;
		}
	}

	if (!(pfc_flags & idl::DCERPC_PFC_FLAG_LAST)) {
		named_pipe->return_status = NT_STATUS_OK;
		return input_size;
	}
	X_TODO_ASSERT(named_pipe->packet_read <= named_pipe->pkt.frag_length);
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
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smbd_requ_state_read_t> &state,
		uint32_t delay_ms,
		bool all)
{
	return named_pipe_read(from_smbd_object(smbd_object),
			from_smbd_open(smbd_requ->smbd_open),
			state->in_length, state->out_buf,
			state->out_buf_length);
}

static NTSTATUS ipc_object_op_write(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smbd_requ_state_write_t> &state,
		uint32_t delay_ms)
{
	named_pipe_t *named_pipe = from_smbd_open(smbd_requ->smbd_open);
	if (!NT_STATUS_IS_OK(named_pipe->return_status)) {
		return named_pipe->return_status;
	}

	int ret = named_pipe_write(from_smbd_object(smbd_object),
			named_pipe,
			smbd_requ->smbd_sess,
			state->in_buf->data + state->in_buf_offset,
			state->in_buf_length);
	state->out_count = ret;
	state->out_remaining = 0;
	return NT_STATUS_OK;
}

static NTSTATUS ipc_object_op_flush(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS ipc_object_op_getinfo(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smbd_requ_state_getinfo_t> &state)
{
	/* TODO should access check ? */
	/* SMB2_GETINFO_FILE, SMB2_FILE_STANDARD_INFO */
	if (state->in_info_class == x_smb2_info_class_t::FILE) {
		if (state->in_info_level == x_smb2_info_level_t::FILE_STANDARD_INFORMATION) {
			if (state->in_output_buffer_length < sizeof(x_smb2_file_standard_info_t)) {
				return NT_STATUS_BUFFER_OVERFLOW;
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
		} else if (state->in_info_level == x_smb2_info_level_t::FILE_STREAM_INFORMATION) {
			return NT_STATUS_INVALID_PARAMETER;
		}
	} 
	return NT_STATUS_NOT_SUPPORTED;
}

static NTSTATUS ipc_object_op_setinfo(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smbd_requ_state_setinfo_t> &state)
{
	return NT_STATUS_NOT_SUPPORTED;
}

static NTSTATUS ipc_object_op_ioctl(
		x_smbd_object_t *smbd_object,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smbd_requ_state_ioctl_t> &state)
{
	x_smbd_ipc_object_t *ipc_object = from_smbd_object(smbd_object);
	named_pipe_t *named_pipe = from_smbd_open(smbd_requ->smbd_open);
	if (!NT_STATUS_IS_OK(named_pipe->return_status)) {
		return named_pipe->return_status;
	}

	switch (state->ctl_code) {
	case X_SMB2_FSCTL_PIPE_TRANSCEIVE:
		named_pipe->is_transceive = true;
		named_pipe_write(ipc_object, named_pipe,
				smbd_requ->smbd_sess,
				state->in_buf->data + state->in_buf_offset,
				state->in_buf_length);
		return named_pipe_read(ipc_object, named_pipe,
				state->in_max_output_length,
				state->out_buf,
				state->out_buf_length);
	default:
		X_TODO;
		return NT_STATUS_NOT_SUPPORTED;
	}
}

static NTSTATUS ipc_object_op_query_allocated_ranges(
		x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream,
		std::vector<x_smb2_file_range_t> &ranges,
		uint64_t offset, uint64_t max_offset)
{
	return NT_STATUS_NOT_SUPPORTED;
}

static NTSTATUS ipc_object_op_set_zero_data(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		uint64_t begin_offset, uint64_t end_offset)
{
	return NT_STATUS_NOT_SUPPORTED;
}

static NTSTATUS ipc_object_op_set_attribute(x_smbd_object_t *smbd_object,
			x_smbd_stream_t *smbd_stream,
			uint32_t attributes_modify,
			uint32_t attributes_value,
			bool &modified)
{
	return NT_STATUS_NOT_SUPPORTED;
}

static NTSTATUS ipc_object_op_update_mtime(x_smbd_object_t *smbd_object)
{
	return NT_STATUS_NOT_SUPPORTED;
}

static struct x_smbd_ipc_iface_t
{
	const std::u16string name;
	const x_dcerpc_iface_t * const iface;
	const std::string secondary_address;
	x_smbd_ipc_object_t *ipc_object;
} ipc_tbl[] = {
#define USTR(x) u##x
#define X_SMBD_DCERPC_IFACE_DECL(x) { USTR(#x), &x_smbd_dcerpc_##x, "\\PIPE\\" #x, nullptr, },
X_SMBD_DCERPC_IFACE_ENUM
#undef X_SMBD_DCERPC_IFACE_DECL
};

static const x_dcerpc_iface_t *find_iface_by_syntax(
		const idl::ndr_syntax_id &syntax)
{
	for (const auto &ipc: ipc_tbl) {
		if (ipc.iface->syntax_id == syntax) {
			return ipc.iface;
		}
	}
	return nullptr;
}

static NTSTATUS ipc_create_object(x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream,
		const x_smbd_user_t &smbd_user,
		x_smbd_requ_state_create_t &state,
		uint32_t file_attributes,
		uint64_t allocation_size)
{
	X_ASSERT(false);
	return NT_STATUS_ACCESS_DENIED;
}

static NTSTATUS ipc_create_open(x_smbd_open_t **psmbd_open,
		x_smbd_requ_t *smbd_requ,
		x_smbd_share_t &smbd_share,
		std::unique_ptr<x_smbd_requ_state_create_t> &state,
		bool overwrite,
		x_smb2_create_action_t create_action,
		uint8_t oplock_level)
{
	X_ASSERT(!overwrite);
	X_ASSERT(state->open_priv_data == 0);
	X_ASSERT(oplock_level == X_SMB2_OPLOCK_LEVEL_NONE);
	X_ASSERT(create_action == x_smb2_create_action_t::WAS_OPENED);
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
			x_smbd_open_state_t{
				state->in_desired_access,
				state->in_share_access,
				x_smbd_conn_curr_client_guid(),
				state->in_create_guid,
				state->in_context_app_instance_id,
				state->in_context_app_instance_version_high,
				state->in_context_app_instance_version_low,
				state->lease.parent_key,
				0l,
				x_smbd_tcon_get_user(smbd_requ->smbd_tcon)->get_owner_sid(),
				state->valid_flags,
				0,
				x_smb2_create_action_t::WAS_OPENED,
				X_SMB2_OPLOCK_LEVEL_NONE});
	ipc_object->base.incref();
	if (!x_smbd_open_store(&named_pipe->base)) {
		X_SMBD_COUNTER_INC(toomany_open, 1);
		delete named_pipe;
		*psmbd_open = nullptr;
		return NT_STATUS_INSUFFICIENT_RESOURCES;
	}

	// x_smbd_open_init(&named_pipe->base, &ipc_object->base, smbd_requ->smbd_tcon,

	*psmbd_open = &named_pipe->base;
	return NT_STATUS_OK;
}

static NTSTATUS ipc_op_delete_object(x_smbd_object_t *smbd_object,
			x_smbd_stream_t *smbd_stream,
			x_smbd_open_t *smbd_open)
{
	X_ASSERT(false);
	return NT_STATUS_INTERNAL_ERROR;
}
#if 0
static uint32_t ipc_op_get_attributes(const x_smbd_object_t *smbd_object)
{
	return FILE_ATTRIBUTE_NORMAL;
}
#endif

static NTSTATUS ipc_op_access_check(x_smbd_object_t *smbd_object,
		uint32_t &granted_access,
		uint32_t &maximal_access,
		x_smbd_tcon_t *smbd_tcon,
		const x_smbd_user_t &smbd_user,
		uint32_t desired_access,
		bool overwrite)
{
	X_ASSERT(0);
	return NT_STATUS_INTERNAL_ERROR;
}

static void ipc_op_lease_granted(x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream)
{
	X_ASSERT(0);
}

static int ipc_op_init_volume(std::shared_ptr<x_smbd_volume_t> &smbd_volume)
{
	auto ipc_root = new x_smbd_ipc_root_t(smbd_volume);
	smbd_volume->root_object = &ipc_root->base;

	long priv_data = 0;
	/* TODO create root_object */
	x_smbd_object_t *parent_object = smbd_volume->root_object;
	for (auto &item: ipc_tbl) {
		auto [ ok, hash ] = x_smbd_hash_path(*smbd_volume,
				parent_object, item.name);
		X_ASSERT(ok);
		x_smbd_object_t *smbd_object;
		NTSTATUS status = x_smbd_object_lookup(&smbd_object,
				smbd_volume, parent_object, item.name,
				priv_data, true, hash, true);
		X_ASSERT(NT_STATUS_IS_OK(status));
		x_smbd_release_object(parent_object);
		++priv_data;
	}
	return 0;
}

static NTSTATUS ipc_op_allocate_object(
		x_smbd_object_t **p_smbd_object,
		const std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		long priv_data,
		uint64_t hash,
		x_smbd_object_t *parent_object,
		const std::u16string &path_base)
{
	if (priv_data >= (long)std::size(ipc_tbl)) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}
	auto &item = ipc_tbl[priv_data];
	if (item.ipc_object) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}
	x_smbd_ipc_object_t *ipc_object = new x_smbd_ipc_object_t(
			smbd_volume, priv_data, hash,
			parent_object, path_base,
			item.iface, item.secondary_address);
	X_ASSERT(ipc_object);
	item.ipc_object = ipc_object;
	*p_smbd_object = &ipc_object->base;
	return NT_STATUS_OK;
}

static void ipc_op_destroy_object(x_smbd_object_t *smbd_object)
{
	X_ASSERT(false);
}

static NTSTATUS ipc_op_initialize_object(x_smbd_object_t *smbd_object)
{
	return NT_STATUS_OK;
}

static NTSTATUS ipc_op_rename_object(
		x_smbd_object_t *smbd_object,
		bool replace_if_exists,
		x_smbd_object_t *new_parent_object,
		const std::u16string &new_path_base)
{
	X_ASSERT(false);
	return NT_STATUS_INTERNAL_ERROR;
}

static NTSTATUS ipc_op_open_stream(x_smbd_object_t *smbd_object,
		x_smbd_stream_t **p_smbd_stream,
		const std::u16string &ads_name)
{
	return NT_STATUS_OBJECT_NAME_NOT_FOUND;
}

static NTSTATUS ipc_op_rename_stream(
		x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream,
		bool replace_if_exists,
		const std::u16string &new_stream_name)
{
	X_ASSERT(false);
	return NT_STATUS_INTERNAL_ERROR;
}

static void ipc_op_release_stream(x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream)
{
	X_ASSERT(false);
}

static void ipc_op_destroy_open(x_smbd_open_t *smbd_open)
{
	named_pipe_t *named_pipe = from_smbd_open(smbd_open);
	delete named_pipe;
}


static const x_smbd_object_ops_t x_smbd_ipc_object_ops = {
	ipc_create_object,
	ipc_create_open,
	nullptr,
	ipc_object_op_read,
	ipc_object_op_write,
	ipc_object_op_flush,
	ipc_object_op_getinfo,
	ipc_object_op_setinfo,
	ipc_object_op_ioctl,
	ipc_object_op_query_allocated_ranges,
	ipc_object_op_set_zero_data,
	ipc_object_op_set_attribute,
	ipc_object_op_update_mtime,
	nullptr, // op_qdir_create
	nullptr, // op_set_delete_on_close
	nullptr, // notify_fname
	ipc_op_delete_object,
	ipc_op_access_check,
	ipc_op_lease_granted,
	ipc_op_init_volume,
	ipc_op_allocate_object,
	ipc_op_destroy_object,
	ipc_op_initialize_object,
	ipc_op_rename_object,
	ipc_op_open_stream,
	ipc_op_rename_stream,
	ipc_op_release_stream,
	ipc_op_destroy_open,
};

static std::shared_ptr<x_smbd_volume_t> ipc_create_volume()
{
	std::shared_ptr<x_smbd_volume_t> smbd_volume = 
		x_smbd_volume_create({0, 0}, "IPC$", u"IPC$", {}, {}, 0);
	x_smbd_volume_init(smbd_volume, &x_smbd_ipc_object_ops);
	return smbd_volume;
}

static std::shared_ptr<x_smbd_volume_t> ipc_get_volume()
{
	static std::shared_ptr<x_smbd_volume_t> ipc_volume = ipc_create_volume();
	return ipc_volume;
}

x_smbd_ipc_object_t::x_smbd_ipc_object_t(const std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		long priv_data, uint64_t hash,
		x_smbd_object_t *parent_object,
		const std::u16string &path_base,
		const x_dcerpc_iface_t *iface,
		std::string secondary_address)
	: base(smbd_volume, parent_object, priv_data, hash, path_base), iface(iface)
	, secondary_address(std::move(secondary_address))
{
	base.flags = x_smbd_object_t::flag_initialized;
	base.type = x_smbd_object_t::type_pipe;
	base.meta = ipc_object_meta;
	base.sharemode.meta = ipc_stream_meta;
}

struct ipc_share_t : x_smbd_share_t
{
	ipc_share_t()
		: x_smbd_share_t({0, 0}, "ipc$", u"IPC$", u"ipc$", 0,
				x_smbd_feature_option_t::disabled)
		, smbd_volume(ipc_get_volume())
	{
	}
	uint8_t get_type() const override {
		return X_SMB2_SHARE_TYPE_PIPE;
	}
	bool is_dfs() const override {
		return false;
	}

	NTSTATUS resolve_path(std::shared_ptr<x_smbd_volume_t> &smbd_volume,
			std::u16string &out_path,
			long &path_priv_data,
			long &open_priv_data,
			bool dfs,
			const char16_t *in_path_begin,
			const char16_t *in_path_end,
			const std::shared_ptr<x_smbd_volume_t> &tcon_volume) override
	{
		smbd_volume = this->smbd_volume;
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
	std::shared_ptr<x_smbd_volume_t> find_volume(const char16_t *in_share_s, const char16_t *in_share_e) const override
	{
		if (in_share_s[0] == u'-') {
			return nullptr;
		}
		return smbd_volume;
	}

	const std::shared_ptr<x_smbd_volume_t> smbd_volume;
};

std::shared_ptr<x_smbd_share_t> x_smbd_ipc_share_create()
{
	return std::make_shared<ipc_share_t>();
}

int x_smbd_ipc_init()
{
	return 0;
}
