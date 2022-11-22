
#include "smbd.hxx"
#include "smbd_open.hxx"
#include "smbd_ntacl.hxx"
#include "include/charset.hxx"

enum {
	X_SMB2_CREATE_REQU_BODY_LEN = 0x38,
	X_SMB2_CREATE_RESP_BODY_LEN = 0x58,
};

struct x_smb2_in_create_t
{
	uint16_t struct_size;
	uint8_t reserved0;
	uint8_t oplock_level;
	uint32_t impersonation_level;
	uint64_t create_flags;
	uint64_t reserved1;
	uint32_t desired_access;
	uint32_t file_attributes;
	uint32_t share_access;
	uint32_t create_disposition;
	uint32_t create_options;
	uint16_t name_offset;
	uint16_t name_length;
	uint32_t context_offset;
	uint32_t context_length;
};

static bool decode_smb2_lease(x_smb2_lease_t &lease,
		const uint8_t *data, uint32_t length)
{
	const x_smb2_lease_t *in_lease = (const x_smb2_lease_t *)data;
	if (length == 52) {
		lease.key = in_lease->key;
		lease.state = X_LE2H32(in_lease->state);
		lease.flags = X_LE2H32(in_lease->flags);
		lease.duration = X_LE2H32(in_lease->duration);
		lease.parent_key = in_lease->parent_key;
		lease.epoch = X_LE2H16(in_lease->epoch);
		lease.version = 2;
	} else if (length == 32) {
		lease.key = in_lease->key;
		lease.state = X_LE2H32(in_lease->state);
		lease.flags = X_LE2H32(in_lease->flags);
		lease.duration = X_LE2H32(in_lease->duration);
		lease.version = 1;
	} else {
		return false;
	}
	return true;
}

static uint32_t encode_smb2_lease(const x_smb2_lease_t &lease,
		uint8_t *data)
{
	x_smb2_lease_t *out_lease = (x_smb2_lease_t *)data;
	out_lease->key = lease.key;
	out_lease->state = X_H2LE32(lease.state);
	out_lease->flags = X_H2LE32(lease.flags);
	out_lease->duration = X_H2LE64(lease.duration);
	if (lease.version == 2) {
		out_lease->parent_key = lease.parent_key;
		out_lease->epoch = X_H2LE16(lease.epoch);
		out_lease->version = 0;
		return 52;
	} else {
		return 32;
	}
}

struct x_smb2_create_context_header_t
{
	uint32_t chain_offset;
	uint16_t tag_offset;
	uint16_t tag_length;
	uint16_t unused0;
	uint16_t data_offset;
	uint32_t data_length;
	// uint32_t tag;
	// uint32_t unused1;
};

static bool decode_contexts(x_smb2_state_create_t &state,
		const uint8_t *data, uint32_t length)
{
	bool has_RqLs = false;
	for (;;) {
		if (length < sizeof(x_smb2_create_context_header_t)) {
			return false;
		}

		const x_smb2_create_context_header_t *ch = (const x_smb2_create_context_header_t *)data;
		uint32_t chain_off = X_LE2H32(ch->chain_offset);
		uint16_t tag_off = X_LE2H16(ch->tag_offset);
		uint16_t tag_len = X_LE2H16(ch->tag_length); // we assume tag_len is 2 bytes
		uint16_t data_off = X_LE2H16(ch->data_offset);
		uint32_t data_len = X_LE2H32(ch->data_length);

		uint32_t clen;
		if (chain_off != 0) {
			if (chain_off + 0x10 > length) {
				return false;
			}
			clen = chain_off;
		} else {
			clen = length;
		}

		if (!x_check_range<uint32_t>(tag_off, tag_len, 0, clen)) {
			return false;
		}

		if (!x_check_range<uint32_t>(data_off, data_len, 0, clen)) {
			return false;
		}

		if (tag_len == 4) {
			uint32_t tag = x_get_be32(data + tag_off);
			if (tag == X_SMB2_CREATE_TAG_RQLS) {
				if (state.in_oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE) {
					has_RqLs = decode_smb2_lease(state.lease,
							data + data_off,
							data_len);
				}
			} else if (tag == X_SMB2_CREATE_TAG_QFID) {
				state.contexts |= X_SMB2_CONTEXT_FLAG_QFID;
			} else if (tag == X_SMB2_CREATE_TAG_ALSI) {
				if (data_len != sizeof(uint64_t)) {
					return false;
				}
				const uint64_t *pdata = (uint64_t *)(data + data_off);
				state.in_allocation_size = X_LE2H64(*pdata);
				state.contexts |= X_SMB2_CONTEXT_FLAG_ALSI;
			} else if (tag == X_SMB2_CREATE_TAG_TWRP) {
				if (data_len != sizeof(uint64_t)) {
					return false;
				}
				const uint64_t *pdata = (uint64_t *)(data + data_off);
				state.in_timestamp = X_LE2H64(*pdata);
			} else if (tag == X_SMB2_CREATE_TAG_MXAC) {
				state.contexts |= X_SMB2_CONTEXT_FLAG_MXAC;
			} else if (tag == X_SMB2_CREATE_TAG_SECD) {
				auto sd = std::make_shared<idl::security_descriptor>();
				idl::x_ndr_off_t ret = idl::x_ndr_pull(*sd,
						data + data_off, data_len, 0);
				if (ret <= 0) {
					X_LOG_WARN("failed parsing TAG_SECD, ndr %d", ret);
					return false;
				}
				state.in_security_descriptor = sd;
			} else if (tag == X_SMB2_CREATE_TAG_EXTA) {
				// TODO;
			} else if (tag == X_SMB2_CREATE_TAG_DHNQ) {
				// TODO
			} else if (tag == X_SMB2_CREATE_TAG_DHNC) {
				// TODO
			} else if (tag == X_SMB2_CREATE_TAG_DH2Q) {
				// TODO
			} else if (tag == X_SMB2_CREATE_TAG_DH2C) {
				// TODO
			} else if (tag == X_SMB2_CREATE_TAG_AAPL) {
				// TODO
			} else {
#if 0
				// TODO
				contexts.resize(contexts.size() + 1);
				auto &ctx = contexts.back();
				ctx.tag = x_get_be32(data + tag_off);
				ctx.data.assign(data + data_off, data + data_off + data_len);
#endif
			}
		} else if (tag_len < 4) {
			return false;
		} else {
			/* ignore */
		}

		data += clen;
		length -= clen;

		if (length == 0) {
			break;
		}
	}
	if (state.in_oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE && !has_RqLs) {
		X_LOG_WARN("missing RqLs");
		state.in_oplock_level = X_SMB2_OPLOCK_LEVEL_NONE;
	}
	return true;
}

static uint32_t encode_contexts(const x_smb2_state_create_t &state,
		uint8_t *out_ptr)
{
	uint8_t *p = out_ptr;
	x_smb2_create_context_header_t *ch = nullptr;

	if (state.out_oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE) {
		if (ch) {
			uint8_t *np = out_ptr + x_pad_len(p - out_ptr, 8);
			while (p != np) {
				*p++ = 0;
			}
			ch->chain_offset = X_H2LE32(x_convert_assert<uint32_t>(p - (uint8_t *)ch));
		}

		ch = (x_smb2_create_context_header_t *)p;
		ch->tag_offset = X_H2LE16(0x10);
		ch->tag_length = X_H2LE16(0x4);
		ch->unused0 = 0;
		ch->data_offset = X_H2LE16(0x18);

		p = (uint8_t *)(ch + 1);
		*(uint32_t *)p = X_H2BE32(X_SMB2_CREATE_TAG_RQLS);
		p += 4;
		*(uint32_t *)p = 0;
		p += 4;

		uint32_t data_len = encode_smb2_lease(state.lease, p);
		ch->data_length = X_H2LE32(data_len);
		p += data_len;
	}

	if (state.contexts & X_SMB2_CONTEXT_FLAG_MXAC) {
		if (ch) {
			uint8_t *np = out_ptr + x_pad_len(p - out_ptr, 8);
			while (p != np) {
				*p++ = 0;
			}
			ch->chain_offset = X_H2LE32(x_convert_assert<uint32_t>(p - (uint8_t *)ch));
		}

		ch = (x_smb2_create_context_header_t *)p;
		ch->tag_offset = X_H2LE16(0x10);
		ch->tag_length = X_H2LE16(0x4);
		ch->unused0 = 0;
		ch->data_offset = X_H2LE16(0x18);

		p = (uint8_t *)(ch + 1);
		*(uint32_t *)p = X_H2BE32(X_SMB2_CREATE_TAG_MXAC);
		p += 4;
		*(uint32_t *)p = 0;
		p += 4;

		*(uint32_t *)p = 0; /* MxAc INFO, query status */
		p += 4;
		*(uint32_t *)p = X_H2LE32(state.out_maximal_access);
		p += 4;
		ch->data_length = X_H2LE32(8);
	}

	if (state.contexts & X_SMB2_CONTEXT_FLAG_QFID) {
		if (ch) {
			uint8_t *np = out_ptr + x_pad_len(p - out_ptr, 8);
			while (p != np) {
				*p++ = 0;
			}
			ch->chain_offset = X_H2LE32(x_convert_assert<uint32_t>(p - (uint8_t *)ch));
		}

		ch = (x_smb2_create_context_header_t *)p;
		ch->tag_offset = X_H2LE16(0x10);
		ch->tag_length = X_H2LE16(0x4);
		ch->unused0 = 0;
		ch->data_offset = X_H2LE16(0x18);

		p = (uint8_t *)(ch + 1);
		*(uint32_t *)p = X_H2BE32(X_SMB2_CREATE_TAG_QFID);
		p += 4;
		*(uint32_t *)p = 0;
		p += 4;

		memcpy(p, state.out_qfid_info, sizeof state.out_qfid_info);
		ch->data_length = X_H2LE32(sizeof state.out_qfid_info);
		p += sizeof state.out_qfid_info;
	}

	if (ch) {
		ch->chain_offset = 0;
	}
	return x_convert_assert<uint32_t>(p - out_ptr);
}

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

static NTSTATUS decode_in_create(x_smb2_state_create_t &state,
		const uint8_t *in_hdr, uint32_t in_len)
{
	const x_smb2_in_create_t *in_create = (const x_smb2_in_create_t *)(in_hdr + SMB2_HDR_BODY);
	uint16_t in_name_offset          = X_LE2H16(in_create->name_offset);
	uint16_t in_name_length          = X_LE2H16(in_create->name_length);
	uint32_t in_context_offset       = X_LE2H32(in_create->context_offset);
	uint32_t in_context_length       = X_LE2H32(in_create->context_length);

	if (in_name_length % 2 != 0 || !x_check_range<uint32_t>(in_name_offset, in_name_length, 
				SMB2_HDR_BODY + sizeof(x_smb2_in_create_t), in_len)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!x_check_range<uint32_t>(in_context_offset, in_context_length, 
				SMB2_HDR_BODY + sizeof(x_smb2_in_create_t), in_len)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	state.in_oplock_level         = in_create->oplock_level;
	state.in_impersonation_level  = X_LE2H32(in_create->impersonation_level);
	state.in_desired_access       = X_LE2H32(in_create->desired_access);
	state.in_file_attributes      = X_LE2H32(in_create->file_attributes);
	state.in_share_access         = X_LE2H32(in_create->share_access);
	state.in_create_disposition   = X_LE2H32(in_create->create_disposition);
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

	if (in_context_length != 0 && !decode_contexts(state,
				in_hdr + in_context_offset,
				in_context_length)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return NT_STATUS_OK;
}

struct x_smb2_out_create_t
{
	uint16_t struct_size;
	uint8_t oplock_level;
	uint8_t create_flags;
	uint32_t create_action;
	uint64_t create_ts;
	uint64_t last_access_ts;
	uint64_t last_write_ts;
	uint64_t change_ts;
	uint64_t allocation_size;
	uint64_t end_of_file;
	uint32_t file_attributes;
	uint32_t reserved0;
	uint64_t file_id_persistent;
	uint64_t file_id_volatile;
	uint32_t context_offset;
	uint32_t context_length;
};

/* it assume output has enough space */
static uint32_t encode_out_create(const x_smb2_state_create_t &state,
		x_smbd_open_t *smbd_open, uint8_t *out_hdr)
{
	/* TODO we assume max output context 256 */
	x_smb2_out_create_t *out_create = (x_smb2_out_create_t *)(out_hdr + SMB2_HDR_BODY);

	out_create->struct_size = X_H2LE16(sizeof(x_smb2_out_create_t) + 1);
	out_create->oplock_level = state.out_oplock_level;
	out_create->create_flags = state.out_create_flags;
	out_create->create_action = X_H2LE32(state.out_create_action);
	out_create->create_ts = X_H2LE64(state.out_info.out_create_ts.val);
	out_create->last_access_ts = X_H2LE64(state.out_info.out_last_access_ts.val);
	out_create->last_write_ts = X_H2LE64(state.out_info.out_last_write_ts.val);
	out_create->change_ts = X_H2LE64(state.out_info.out_change_ts.val);
	out_create->allocation_size = X_H2LE64(state.out_info.out_allocation_size);
	out_create->end_of_file = X_H2LE64(state.out_info.out_end_of_file);
	out_create->file_attributes = X_H2LE32(state.out_info.out_file_attributes);
	out_create->reserved0 = 0;
	auto [id_persistent, id_volatile] = x_smbd_open_get_id(smbd_open);
	out_create->file_id_persistent = X_H2LE64(id_persistent);
	out_create->file_id_volatile = X_H2LE64(id_volatile);

	static_assert((sizeof(x_smb2_out_create_t) % 8) == 0);
	uint32_t out_context_length = encode_contexts(state, (uint8_t *)(out_create + 1));
	if (out_context_length == 0) {
		out_create->context_offset = out_create->context_length = 0;
	} else {
		out_create->context_offset = X_H2LE32(SMB2_HDR_BODY + sizeof(x_smb2_out_create_t));
		out_create->context_length = X_H2LE32(out_context_length);
	}

	return x_convert_assert<uint32_t>(sizeof(x_smb2_out_create_t) + out_context_length);
}

static void x_smb2_reply_create(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		const x_smb2_state_create_t &state)
{
	X_LOG_OP("%ld RESP SUCCESS 0x%lx,0x%lx", smbd_requ->in_smb2_hdr.mid,
			smbd_requ->smbd_open->id, smbd_requ->smbd_open->id);

#if 1
	/* TODO we assume max output context 256 */
	size_t out_context_length = 256;
#else
	size_t out_context_length = 0;
	if (state.oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE) {
		out_context_length += 0x18 + 56;
	}
#endif
	x_bufref_t *bufref = x_bufref_alloc(sizeof(x_smb2_out_create_t) + out_context_length);

	uint8_t *out_hdr = bufref->get_data();

	uint32_t out_length = encode_out_create(state, smbd_requ->smbd_open, out_hdr);
	bufref->length = SMB2_HDR_BODY + out_length;
	x_smb2_reply(smbd_conn, smbd_requ, bufref, bufref, NT_STATUS_OK, 
			bufref->length);
}

static void x_smb2_create_async_done(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		NTSTATUS status)
{
	X_LOG_DBG("status=0x%x", status.v);
	auto state = smbd_requ->release_state<x_smb2_state_create_t>();
	if (!smbd_conn) {
		return;
	}
	if (NT_STATUS_IS_OK(status)) {
		x_smb2_reply_create(smbd_conn, smbd_requ, *state);
	}
	x_smbd_conn_requ_done(smbd_conn, smbd_requ, status);
}

NTSTATUS x_smb2_process_create(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	X_ASSERT(smbd_requ->smbd_chan && smbd_requ->smbd_sess);
	if (smbd_requ->in_requ_len < SMB2_HDR_BODY + sizeof(x_smb2_in_create_t) + 1) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	const uint8_t *in_hdr = smbd_requ->get_in_data();

	/* TODO check limit of open for both total and per conn*/

	auto state = std::make_unique<x_smb2_state_create_t>();
	NTSTATUS status = decode_in_create(*state, in_hdr, smbd_requ->in_requ_len);
	if (!NT_STATUS_IS_OK(status)) {
		RETURN_OP_STATUS(smbd_requ, status);
	}

	if (state->in_impersonation_level >= X_SMB2_IMPERSONATION_MAX) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_BAD_IMPERSONATION_LEVEL);
	}

	if (state->in_create_options & (FILE_CREATE_TREE_CONNECTION
				| FILE_OPEN_BY_FILE_ID
				| FILE_RESERVER_OPFILTER)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_NOT_SUPPORTED);
	}

	if (state->in_create_options & (0xff000000u)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	if ((state->in_create_options & (FILE_DIRECTORY_FILE | FILE_NON_DIRECTORY_FILE)) == (FILE_DIRECTORY_FILE | FILE_NON_DIRECTORY_FILE)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	if ((state->in_create_options & FILE_DIRECTORY_FILE) &&
			(state->in_ads_name.size() || state->is_dollar_data)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_NOT_A_DIRECTORY);
	}

	if (state->in_desired_access & idl::SEC_MASK_INVALID) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_ACCESS_DENIED);
	}

	if (state->in_file_attributes & (X_SMB2_FILE_ATTRIBUTE_DEVICE
				| X_SMB2_FILE_ATTRIBUTE_VOLUME
				| ~X_SMB2_FILE_ATTRIBUTE_ALL_MASK)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	state->in_file_attributes &= X_NXSMB_FILE_ATTRIBUTE_MASK;

	/* windows server deny in_desired_access == 0 */
	if (state->in_desired_access == 0) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_ACCESS_DENIED);
	}

	uint32_t orig_access = state->in_desired_access;
	state->in_desired_access = se_file_map_generic(orig_access);
	X_LOG_DBG("map access 0x%x to 0x%x", orig_access, state->in_desired_access);

	if ((state->in_create_options & FILE_DELETE_ON_CLOSE) &&
			!(state->in_desired_access & idl::SEC_STD_DELETE)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	if (!state->in_path.empty()) {
		auto ch = state->in_path[0];
		if (ch == u'\\') {
			RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
		}
	}

	if (!x_smbd_tcon_access_check(smbd_requ->smbd_tcon, state->in_desired_access & ~idl::SEC_FLAG_MAXIMUM_ALLOWED)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_ACCESS_DENIED);
	}

	/* TODO log stream too */
	X_LOG_OP("%ld CREATE '%s':'%s'", smbd_requ->in_smb2_hdr.mid,
			x_convert_utf16_to_utf8_safe(state->in_path).c_str(),
			x_convert_utf16_to_utf8_safe(state->in_ads_name).c_str());

	if (x_str_has_wild(state->in_path)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_OBJECT_NAME_INVALID);
	}

	smbd_requ->async_done_fn = x_smb2_create_async_done;
	if (state->in_oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE) {
		state->smbd_lease = x_smbd_lease_find(x_smbd_conn_curr_client_guid(),
				state->lease.key, state->lease.version, true);
	}

	status = x_smbd_tcon_op_create(smbd_requ, state);
	if (NT_STATUS_IS_OK(status)) {
		x_smb2_reply_create(smbd_conn, smbd_requ, *state);
		return status;
	} else {
		RETURN_OP_STATUS(smbd_requ, status);
	}
}
