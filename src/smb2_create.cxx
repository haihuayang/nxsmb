
#include "smbd.hxx"
#include "smbd_open.hxx"
#include "smbd_replay.hxx"
#include "smbd_ntacl.hxx"
#include "nxfsd_stats.hxx"
#include "include/charset.hxx"
#include "include/nttime.hxx"


static const char16_t SEP = u'\\';
static bool pop_comp(std::u16string &path)
{
	auto length = path.length();
	if (length == 0) {
		return true;
	}
	if (path[length - 1] != u'.') {
		return true;
	}
	if (length == 1) {
		return true;
	}
	if (path[length - 2] == SEP) {
		/* convert '\.\' to '\' */
		path.resize(length - 2);
		return true;
	}
	if (length == 2) {
		return true;
	}
	if (path[length - 2] != u'.') {
		return true;
	}
	if (path[length - 3] != SEP) {
		return true;
	}
	if (length == 3) {
		return false;
	}
	/* TODO cannot pop if previous component is .. too */
	auto pos = path.rfind(SEP, length - 4);
	if (pos == std::u16string::npos) {
		return false;
	}
	path.resize(pos);
	return true;
}

/* TODO windows does not allow path starting with '.' or '\' */
static bool normalize_path(std::u16string &path,
		const char16_t *path_begin, const char16_t *path_end)
{
	std::u16string ret;
	for (; path_begin < path_end; ++path_begin) {
		char16_t curr = *path_begin;
		if (!curr) {
			return false;
		}
		if (curr != SEP) {
			ret.push_back(curr);
			continue;
		}
		if (!pop_comp(ret)) {
			return false;
		}

		if (ret.length() == 0 || ret[ret.length() - 1] != SEP) {
			ret.push_back(curr);
		}
	}
	if (!pop_comp(ret)) {
		return false;
	}
	path = std::move(ret);
	return true;
}

static NTSTATUS decode_in_create(uint16_t dialect, x_smbd_requ_state_create_t &state,
		const uint8_t *in_hdr, uint32_t in_len)
{
	const x_smb2_create_requ_t *in_create = (const x_smb2_create_requ_t *)(in_hdr + sizeof(x_smb2_header_t));
	uint16_t in_struct_size		 = X_LE2H16(in_create->struct_size);
	if (in_struct_size != sizeof(*in_create) + 1) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	uint16_t in_name_offset          = X_LE2H16(in_create->name_offset);
	uint16_t in_name_length          = X_LE2H16(in_create->name_length);
	uint32_t in_context_offset       = X_LE2H32(in_create->context_offset);
	uint32_t in_context_length       = X_LE2H32(in_create->context_length);

	if (in_name_length % 2 != 0 || !x_check_range<uint32_t>(in_name_offset, in_name_length, 
				sizeof(x_smb2_header_t) + sizeof(x_smb2_create_requ_t), in_len)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!x_check_range<uint32_t>(in_context_offset, in_context_length, 
				sizeof(x_smb2_header_t) + sizeof(x_smb2_create_requ_t), in_len)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	state.in_oplock_level         = in_create->oplock_level;
	state.in_impersonation_level  = X_LE2H32(in_create->impersonation_level);
	state.in_desired_access       = X_LE2H32(in_create->desired_access);
	state.in_file_attributes      = X_LE2H32(in_create->file_attributes);
	state.in_share_access         = X_LE2H32(in_create->share_access);
	state.in_create_disposition   = x_smb2_create_disposition_t(X_LE2H32(in_create->create_disposition));
	state.in_create_options       = X_LE2H32(in_create->create_options);

	/* TODO check_path_syntax_internal() */
	const char16_t *in_name_begin = (const char16_t *)(in_hdr + in_name_offset);
	const char16_t *in_name_end = (const char16_t *)(in_hdr + in_name_offset + in_name_length);
	const char16_t *in_path_end = x_next_sep(in_name_begin, in_name_end, u':');

	if (in_path_end != in_name_end) {
		NTSTATUS status = x_smb2_parse_stream_name(state.in_ads_name,
				state.is_dollar_data,
				in_path_end + 1, in_name_end);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}
	const char16_t *in_path_end_trimed = x_rskip_sep(in_path_end,
			in_name_begin, u'\\');
	state.end_with_sep = in_path_end_trimed != in_path_end;
	if (!normalize_path(state.in_path, in_name_begin, in_path_end)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (in_context_length != 0 && !state.in_context.decode(dialect,
				in_hdr + in_context_offset,
				in_context_length)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (state.in_context.lease.version != 0) {
		if (state.in_oplock_level != X_SMB2_OPLOCK_LEVEL_LEASE) {
			X_LOG(SMB, WARN, "inconsistenct oplock_level %d with RqLs",
					state.in_oplock_level);
			state.in_oplock_level = X_SMB2_OPLOCK_LEVEL_LEASE;
		}
	} else {
		if (state.in_oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE) {
			X_LOG(SMB, WARN, "missing RqLs");
			state.in_oplock_level = X_SMB2_OPLOCK_LEVEL_NONE;
		}
	}

#if 0
	if (state.in_context.bits & (X_SMB2_CONTEXT_FLAG_DHNQ | X_SMB2_CONTEXT_FLAG_DH2Q)) {
		if (state.in_oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE) {
			if ((state.lease.state & X_SMB2_LEASE_HANDLE) == 0) {
				state.in_context.bits &= ~(X_SMB2_CONTEXT_FLAG_DHNQ
						| X_SMB2_CONTEXT_FLAG_DH2Q);
				state.in_create_guid = { 0, 0 };
			}
		} else if (state.in_oplock_level != X_SMB2_OPLOCK_LEVEL_BATCH) {
			state.in_context.bits &= ~(X_SMB2_CONTEXT_FLAG_DHNQ
					| X_SMB2_CONTEXT_FLAG_DH2Q);
			state.in_create_guid = { 0, 0 };
		}
	}
#endif
	return NT_STATUS_OK;
}

/* it assume output has enough space */
static uint32_t encode_out_create(const x_smbd_requ_state_create_t &state,
		x_smbd_open_t *smbd_open, uint8_t *out_hdr)
{
	/* TODO we assume max output context 256 */
	x_smb2_create_resp_t *out_create = (x_smb2_create_resp_t *)(out_hdr + sizeof(x_smb2_header_t));

	auto [object_meta, stream_meta] = x_smbd_open_op_get_meta(smbd_open);

	out_create->struct_size = X_H2LE16(sizeof(x_smb2_create_resp_t) + 1);
	out_create->oplock_level = state.out_oplock_level;
	out_create->create_flags = state.out_create_flags;
	out_create->create_action = X_H2LE32(uint32_t(smbd_open->open_state.create_action));
	out_create->create_ts = X_H2LE64(x_timespec_to_nttime_val(object_meta->creation));
	out_create->last_access_ts = X_H2LE64(x_timespec_to_nttime_val(object_meta->last_access));
	out_create->last_write_ts = X_H2LE64(x_timespec_to_nttime_val(object_meta->last_write));
	out_create->change_ts = X_H2LE64(x_timespec_to_nttime_val(object_meta->change));
	out_create->allocation_size = X_H2LE64(stream_meta->allocation_size);
	out_create->end_of_file = X_H2LE64(stream_meta->end_of_file);
	out_create->file_attributes = X_H2LE32(object_meta->file_attributes);
	out_create->reserved0 = 0;
	auto [id_persistent, id_volatile] = x_smbd_open_get_id(smbd_open);
	out_create->file_id_persistent = X_H2LE64(id_persistent);
	out_create->file_id_volatile = X_H2LE64(id_volatile);

	static_assert((sizeof(x_smb2_create_resp_t) % 8) == 0);
	uint32_t out_context_length = state.out_context.encode(
			(uint8_t *)(out_create + 1), 256);
	if (out_context_length == 0) {
		out_create->context_offset = out_create->context_length = 0;
	} else {
		out_create->context_offset = X_H2LE32(sizeof(x_smb2_header_t) + sizeof(x_smb2_create_resp_t));
		out_create->context_length = X_H2LE32(out_context_length);
	}

	return x_convert_assert<uint32_t>(sizeof(x_smb2_create_resp_t) + out_context_length);
}

static void x_smb2_reply_create(x_smbd_requ_t *smbd_requ,
		const x_smbd_requ_state_create_t &state)
{
#if 1
	/* TODO we assume max output context 256 */
	size_t out_context_length = 256;
#else
	size_t out_context_length = 0;
	if (state.oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE) {
		out_context_length += 0x18 + 56;
	}
#endif
	auto &out_buf = smbd_requ->get_requ_out_buf();
	out_buf.head = out_buf.tail = x_smb2_bufref_alloc(sizeof(x_smb2_create_resp_t) +
			out_context_length);
	uint8_t *out_hdr = out_buf.head->get_data();
	uint32_t out_length = encode_out_create(state, smbd_requ->smbd_open, out_hdr);
	out_buf.length = out_buf.head->length = x_convert_assert<uint32_t>(sizeof(x_smb2_header_t) + out_length);
}

static void smb2_create_success(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		x_smbd_requ_state_create_t &state)
{
	x_smbd_open_t *smbd_open = smbd_requ->smbd_open;
	auto &open_state = smbd_requ->smbd_open->open_state;
	if (smbd_open->open_type != x_smbd_open_type_t::proxy) {
		if (state.replay_reserved) {
			/* TODO atomic */
			x_smbd_replay_cache_set(state.client_guid,
					state.in_context.create_guid,
					smbd_open);
			open_state.flags |= x_smbd_open_state_t::F_REPLAY_CACHED;
			state.replay_reserved = false;
		}

		if (smbd_open->id_persistent == 0xffffffffu) {
			auto &smbd_volume = *smbd_open->smbd_object->smbd_volume;
			smbd_open->id_persistent = x_smbd_volume_non_durable_id(smbd_volume);
		}
		x_smbd_save_durable(smbd_open, smbd_requ->smbd_tcon, state);

		if (open_state.dhmode != x_smbd_dhmode_t::NONE &&
				(state.out_oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE ||
				 state.out_oplock_level == X_SMB2_OPLOCK_LEVEL_BATCH)) {
			state.out_context.bits |= (state.in_context.bits &
				(X_SMB2_CONTEXT_FLAG_DHNQ | X_SMB2_CONTEXT_FLAG_DH2Q));
		}
	}

	if (state.out_oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE) {
		state.out_context.bits |= X_SMB2_CONTEXT_FLAG_RQLS;
		state.out_context.lease = state.in_context.lease;
	}
	state.out_context.durable_flags = open_state.dhmode ==
		x_smbd_dhmode_t::PERSISTENT ?  X_SMB2_DHANDLE_FLAG_PERSISTENT : 0,
	state.out_context.durable_timeout_msec = open_state.durable_timeout_msec;

	x_smb2_reply_create(smbd_requ, state);
}
#if 0
void x_smbd_requ_state_create_t::async_done(void *ctx_conn,
		x_nxfsd_requ_t *nxfsd_requ,
		NTSTATUS status)
{
	x_smbd_requ_t *smbd_requ = x_smbd_requ_from_base(nxfsd_requ);
	X_SMBD_REQU_LOG(OP, smbd_requ, " %s open=0x%lx,0x%lx",
			x_ntstatus_str(status),
			smbd_requ->smbd_open ? smbd_requ->smbd_open->id_persistent : 0,
			smbd_requ->smbd_open ? smbd_requ->smbd_open->id_volatile : 0);
	if (!ctx_conn) {
		return;
	}
	x_smbd_conn_t *smbd_conn = (x_smbd_conn_t *)ctx_conn;
	if (NT_STATUS_IS_OK(status)) {
		auto &open_state = nxfsd_requ->smbd_open->open_state;
		out_oplock_level = open_state.oplock_level;
		smb2_create_success(smbd_conn, smbd_requ, *this);
	}

	x_smbd_conn_requ_done(smbd_conn, smbd_requ, status);
}

#endif
static bool oplock_valid_for_durable(const x_smbd_requ_state_create_t &state)
{
	if (state.in_oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE) {
		return state.in_context.lease.state & X_SMB2_LEASE_HANDLE;
	} else {
		return state.in_oplock_level == X_SMB2_OPLOCK_LEVEL_BATCH;
	}
}

static NTSTATUS smb2_process_create(x_smbd_requ_t *smbd_requ,
		x_smbd_requ_state_create_t &state)
{
	if (state.in_context.bits & (X_SMB2_CONTEXT_FLAG_DHNQ | X_SMB2_CONTEXT_FLAG_DH2Q)) {
		if (!oplock_valid_for_durable(state)) {
			state.in_context.bits &= ~(X_SMB2_CONTEXT_FLAG_DHNQ
					| X_SMB2_CONTEXT_FLAG_DH2Q);
		}
	}

	if (state.in_impersonation_level >= X_SMB2_IMPERSONATION_MAX) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_BAD_IMPERSONATION_LEVEL);
	}

	if (state.in_create_options & (X_SMB2_CREATE_OPTION_CREATE_TREE_CONNECTION
				| X_SMB2_CREATE_OPTION_OPEN_BY_FILE_ID
				| X_SMB2_CREATE_OPTION_RESERVER_OPFILTER)) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_NOT_SUPPORTED);
	}

	if (state.in_create_options & (0xff000000u)) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	if ((state.in_create_options & (X_SMB2_CREATE_OPTION_DIRECTORY_FILE
					| X_SMB2_CREATE_OPTION_NON_DIRECTORY_FILE))
			== (X_SMB2_CREATE_OPTION_DIRECTORY_FILE
				| X_SMB2_CREATE_OPTION_NON_DIRECTORY_FILE)) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	if ((state.in_create_options & X_SMB2_CREATE_OPTION_DIRECTORY_FILE) &&
			(state.in_ads_name.size() || state.is_dollar_data)) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_NOT_A_DIRECTORY);
	}

	if (state.in_desired_access & idl::SEC_MASK_INVALID) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_ACCESS_DENIED);
	}

	if (state.in_file_attributes & (X_SMB2_FILE_ATTRIBUTE_DEVICE
				| X_SMB2_FILE_ATTRIBUTE_VOLUME
				| ~X_SMB2_FILE_ATTRIBUTE_ALL_MASK)) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	state.in_file_attributes &= X_NXSMB_FILE_ATTRIBUTE_MASK;

	/* windows server deny in_desired_access == 0 */
	if (state.in_desired_access == 0) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_ACCESS_DENIED);
	}

	if ((state.in_create_options & X_SMB2_CREATE_OPTION_DELETE_ON_CLOSE) &&
			!(state.in_desired_access & (idl::SEC_STD_DELETE |
					0xee000000u))) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	uint32_t orig_access = state.in_desired_access;
	state.in_desired_access = se_file_map_generic(orig_access);
	X_LOG(SMB, DBG, "map access 0x%x to 0x%x", orig_access, state.in_desired_access);

	if (!state.in_path.empty()) {
		auto ch = state.in_path[0];
		if (ch == u'\\') {
			X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
		}
	}

	x_smbd_tcon_t *smbd_tcon = smbd_requ->smbd_tcon;

	if (!x_smbd_tcon_access_check(smbd_tcon,
				state.in_desired_access & ~idl::SEC_FLAG_MAXIMUM_ALLOWED)) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_ACCESS_DENIED);
	}

	X_SMBD_REQU_LOG(OP, smbd_requ,  " '%s:%s'",
			x_str_todebug(state.in_path).c_str(),
			x_str_todebug(state.in_ads_name).c_str());

	if (x_str_has_wild(state.in_path)) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_OBJECT_NAME_INVALID);
	}

	// smbd_requ->async_done_fn = x_smb2_create_async_done;
	if (state.in_oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE) {
		state.smbd_lease = x_smbd_lease_find(state.client_guid,
				state.in_context.lease, true);
	}

	state.smbd_share = x_smbd_tcon_get_share(smbd_tcon);
	state.smbd_object = state.smbd_share->root_object;
	state.smbd_object->incref();
	state.unresolved_path = state.in_path.c_str();

	NTSTATUS status = x_smbd_open_op_create(smbd_requ, smbd_tcon, state);
	if (status == NT_STATUS_PENDING) {
		/* TODO does it need a timer? can break timer always wake up it? */
		X_SMBD_REQU_LOG(DBG, smbd_requ, " interim_state %d",
				smbd_requ->interim_state);
	}
	return status;
}

struct x_smbd_requ_create_t : x_smbd_requ_t
{
	x_smbd_requ_create_t(x_smbd_conn_t *smbd_conn, x_in_buf_t &in_buf,
			uint32_t in_msgsize, bool encrypted,
			x_smbd_requ_state_create_t &state)
		: x_smbd_requ_t(smbd_conn, in_buf, in_msgsize, encrypted)
		, state(std::move(state))
	{
		interim_timeout_ns = 0;
	}
	std::tuple<bool, bool, bool> get_properties() const override
	{
		return { true, true, false };
	}
	NTSTATUS process(void *ctx_conn) override;
	NTSTATUS done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status) override;
	NTSTATUS cancelled(void *ctx_conn, int reason) override
	{
		return NT_STATUS_CANCELLED;
	}

	x_smbd_requ_state_create_t state;
	int attempt = 0;
};

static NTSTATUS smbd_process_create_first(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		x_smbd_requ_state_create_t &state)
{
	X_ASSERT(smbd_requ->smbd_chan && smbd_requ->smbd_sess);
	X_ASSERT(!smbd_requ->smbd_open);
	const auto &negprot = x_smbd_conn_get_negprot(smbd_conn);
	state.client_guid = negprot.client_guid;
	state.server_capabilities = negprot.server_capabilities;
	state.smbd_user = x_smbd_sess_get_user(smbd_requ->smbd_sess);

	if (negprot.dialect < X_SMB2_DIALECT_210 &&
			state.in_oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE) {
		state.in_oplock_level = X_SMB2_OPLOCK_LEVEL_NONE;
	}

	state.replay_operation = smbd_requ->in_smb2_hdr.flags & X_SMB2_HDR_FLAG_REPLAY_OPERATION;

	NTSTATUS status = NT_STATUS_OK;

	if (state.in_context.bits & X_SMB2_CONTEXT_FLAG_DH2Q) {
		if (!state.in_context.create_guid.is_valid()) {
			X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
		}

		status = x_smbd_replay_cache_lookup(
				&smbd_requ->smbd_open,
				state.client_guid,
				state.in_context.create_guid,
				state.replay_operation);
		if (NT_STATUS_EQUAL(status, NT_STATUS_FWP_RESERVED)) {
			state.replay_operation = false;
			state.replay_reserved = true;
		} else if (NT_STATUS_IS_OK(status)) {
			X_ASSERT(state.replay_operation);
			X_ASSERT(smbd_requ->smbd_open);
		} else {
			X_SMBD_REQU_RETURN_STATUS(smbd_requ, status);
		}
	}

	if (smbd_requ->smbd_open) {
		// TODO create state
		auto smbd_open = smbd_requ->smbd_open;
		auto &open_state = smbd_open->open_state;
		if (state.replay_operation) {
			if (smbd_open->smbd_lease) {
				if (!x_smbd_open_match_get_lease(smbd_open,
							state.client_guid,
							state.in_context.lease)) {
					X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_ACCESS_DENIED);
				}
			} else {
				if (state.in_oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE) {
					X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_ACCESS_DENIED);
				}
			}

		} else if (state.in_oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE &&
				(open_state.oplock_level != X_SMB2_OPLOCK_LEVEL_LEASE ||
				 !x_smbd_open_match_get_lease(smbd_open,
					 state.client_guid,
					 state.in_context.lease))) {
			X_REF_DEC(smbd_open);
			X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_ACCESS_DENIED);
		}

		state.out_oplock_level = state.in_oplock_level;
	} else {
		if (x_bit_any<uint32_t>(state.in_context.bits, X_SMB2_CONTEXT_FLAG_DHNC |
					X_SMB2_CONTEXT_FLAG_DH2C)) {
			if (!x_smbd_tcon_get_durable_handle(smbd_requ->smbd_tcon)) {
				X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_OBJECT_NAME_NOT_FOUND);
			}
			status = x_smbd_open_op_reconnect(smbd_requ, state);
		} else {
			status = smb2_process_create(smbd_requ, state);
		}

		if (NT_STATUS_IS_OK(status)) {
			auto &open_state = smbd_requ->smbd_open->open_state;
			state.out_oplock_level = open_state.oplock_level;
		}
	}

	return status;
}

NTSTATUS x_smbd_requ_create_t::process(void *ctx_conn)
{
	if (attempt++ == 0) {
		return smbd_process_create_first((x_smbd_conn_t *)ctx_conn, this, state);
	} else {
		auto status = x_smbd_open_op_create(this, this->smbd_tcon, this->state);
		if (status.ok()) {
			state.out_oplock_level = smbd_open->open_state.oplock_level;
		}
		return status;
	}
}

NTSTATUS x_smbd_requ_create_t::done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status)
{
	if (status.ok()) {
		X_SMBD_REQU_LOG(OP, this, " STATUS_SUCCESS 0x%lx,0x%lx",
			smbd_open->id_persistent,
			smbd_open->id_volatile);
		smb2_create_success(smbd_conn, this, state);
	}
	return status;
}

NTSTATUS x_smb2_parse_CREATE(x_smbd_conn_t *smbd_conn, x_smbd_requ_t **p_smbd_requ,
		x_in_buf_t &in_buf, uint32_t in_msgsize,
		bool encrypted)
{
	X_TRACE_LOC;
	auto in_smb2_hdr = (const x_smb2_header_t *)(in_buf.get_data());

	if (in_buf.length < sizeof(x_smb2_header_t) + sizeof(x_smb2_create_requ_t) + 1) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}

	const auto &negprot = x_smbd_conn_get_negprot(smbd_conn);
	/* TODO check limit of open for both total and per conn*/
	x_smbd_requ_state_create_t state(negprot.client_guid, negprot.server_capabilities);
	NTSTATUS status = decode_in_create(negprot.dialect, state,
			(const uint8_t *)in_smb2_hdr, in_buf.length);
	if (!status.ok()) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, status);
	}
	*p_smbd_requ = new x_smbd_requ_create_t(smbd_conn, in_buf,
			in_msgsize, encrypted, state);

	return NT_STATUS_OK;
}

