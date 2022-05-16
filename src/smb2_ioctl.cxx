
#include "smbd.hxx"
#include "include/charset.hxx"
#include "smbd_open.hxx"
#include "smb2.hxx"

enum {
	X_SMB2_IOCTL_REQU_BODY_LEN = 0x38,
	X_SMB2_IOCTL_RESP_BODY_LEN = 0x30,
};

struct x_smb2_in_ioctl_t
{
	uint16_t struct_size;
	uint16_t reserved0;
	uint32_t ctl_code;
	uint64_t file_id_persistent;
	uint64_t file_id_volatile;
	uint32_t input_offset;
	uint32_t input_length;
	uint32_t max_input_length;
	uint32_t output_offset;
	uint32_t output_length;
	uint32_t max_output_length;
	uint32_t flags;
	uint32_t reserved1;
};

static bool decode_in_ioctl(x_smb2_state_ioctl_t &state,
		x_buf_t *in_buf, uint32_t in_offset, uint32_t in_len)
{
	const uint8_t *in_hdr = in_buf->data + in_offset;
	const x_smb2_in_ioctl_t *in_ioctl = (const x_smb2_in_ioctl_t *)(in_hdr + SMB2_HDR_BODY);
	uint32_t in_input_offset = X_LE2H16(in_ioctl->input_offset);
	uint32_t in_input_length = X_LE2H32(in_ioctl->input_length);

	if (!x_check_range<uint32_t>(in_input_offset, in_input_length,
				SMB2_HDR_BODY + sizeof(x_smb2_in_ioctl_t), in_len)) {
		return false;
	}

	state.ctl_code = X_LE2H32(in_ioctl->ctl_code);
	state.file_id_persistent = X_LE2H64(in_ioctl->file_id_persistent);
	state.file_id_volatile = X_LE2H64(in_ioctl->file_id_volatile);
	state.in_max_input_length = X_LE2H32(in_ioctl->max_input_length);
	state.in_max_output_length = X_LE2H32(in_ioctl->max_output_length);
	state.in_flags = X_LE2H32(in_ioctl->flags);

	if (in_input_length > 0) {
		state.in_buf = x_buf_get(in_buf);
		state.in_buf_offset = in_offset + in_input_offset;
		state.in_buf_length = in_input_length;
	}
	return true;
}

struct x_smb2_out_ioctl_t
{
	uint16_t struct_size;
	uint16_t reserved0;
	uint32_t ctl_code;
	uint64_t file_id_persistent;
	uint64_t file_id_volatile;
	uint32_t input_offset;
	uint32_t input_length;
	uint32_t output_offset;
	uint32_t output_length;
	uint64_t reserved1;
};

static void encode_out_ioctl(const x_smb2_state_ioctl_t &state,
		uint8_t *out_hdr)
{
	x_smb2_out_ioctl_t *out_ioctl = (x_smb2_out_ioctl_t *)(out_hdr + SMB2_HDR_BODY);
	out_ioctl->struct_size = X_H2LE16(sizeof(x_smb2_out_ioctl_t) +
			(state.out_buf_length != 0));

	out_ioctl->reserved0 = 0;
	out_ioctl->ctl_code = X_H2LE32(state.ctl_code);
	out_ioctl->file_id_persistent = X_H2LE64(state.file_id_persistent);
	out_ioctl->file_id_volatile = X_H2LE64(state.file_id_volatile);
	out_ioctl->input_offset = X_H2LE32(SMB2_HDR_BODY + sizeof(x_smb2_out_ioctl_t));
	out_ioctl->input_length = 0;
	out_ioctl->output_offset = X_H2LE32(SMB2_HDR_BODY + sizeof(x_smb2_out_ioctl_t));
	out_ioctl->output_length = X_H2LE32(state.out_buf_length);
	out_ioctl->reserved1 = 0;
}

static void x_smb2_reply_ioctl(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		const x_smb2_state_ioctl_t &state)
{
	X_LOG_OP("%ld IOCTL SUCCESS", smbd_requ->in_mid);

	x_bufref_t *bufref = x_bufref_alloc(sizeof(x_smb2_out_ioctl_t));
	x_bufref_t *out_data;
	if (state.out_buf_length) {
		out_data = new x_bufref_t(x_buf_get(state.out_buf), 0, state.out_buf_length);
		bufref->next = out_data;
	} else {
		out_data = bufref;
	}

	uint8_t *out_hdr = bufref->get_data();
	encode_out_ioctl(state, out_hdr);

	x_smb2_reply(smbd_conn, smbd_requ, bufref, out_data, NT_STATUS_OK, 
			SMB2_HDR_BODY + sizeof(x_smb2_out_ioctl_t) + state.out_buf_length);
}


static inline bool file_id_is_nul(const x_smb2_state_ioctl_t &state)
{
	/*
	 * Some SMB2 specific CtlCodes like FSCTL_DFS_GET_REFERRALS or
	 * FSCTL_PIPE_WAIT does not take a file handle.
	 *
	 * If FileId in the SMB2 Header of the request is not
	 * 0xFFFFFFFFFFFFFFFF, then the server MUST fail the request
	 * with STATUS_INVALID_PARAMETER.
	 */
	return state.file_id_persistent == UINT64_MAX
		&& state.file_id_volatile == UINT64_MAX;
}

static NTSTATUS parse_dfs_path(const std::string &in_file_name,
		std::string &host, std::string &share, std::string &relpath)
{
	// TODO NT_STATUS_ILLEGAL_CHARACTER
	const char *str = in_file_name.c_str();
	while (*str == '\\') {
		++str;
	}
	const char *sep = strchr(str, '\\');
	if (!sep) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	host = std::string(str, sep);
	str = sep + 1;
	sep = strchr(str, '\\');
	if (!sep) {
		share = str;
	} else {
		share = std::string(str, sep);
		relpath = sep + 1;
	}
	return NT_STATUS_OK;
}

struct x_referral_t
{
	uint32_t proximity;
	uint32_t ttl;
	std::u16string path;
	std::u16string node;
};

#define DFS_HEADER_FLAG_REFERAL_SVR ( 0x00000001 )
#define DFS_HEADER_FLAG_STORAGE_SVR ( 0x00000002 )
#define DFS_HEADER_FLAG_TARGET_BCK ( 0x00000004 )

#define DFS_SERVER_ROOT 1

struct x_dfs_referral_resp_t
{
	uint16_t path_consumed;
	uint32_t header_flags;
	std::vector<x_referral_t> referrals;
};

static idl::x_ndr_off_t push_referral_v3(const x_referral_t &referral, idl::x_ndr_push_t &ndr,
		idl::x_ndr_off_t bpos, idl::x_ndr_off_t epos, uint32_t ndr_flags)
{
	idl::x_ndr_off_t base_pos = bpos;
	bpos = X_NDR_CHECK(idl::x_ndr_push_uint16(3, ndr, bpos, epos, ndr_flags)); // TODO version to be max_referral_level
	idl::x_ndr_off_t size_pos = bpos;
	bpos = X_NDR_CHECK(idl::x_ndr_push_uint16(0, ndr, bpos, epos, ndr_flags));
	bpos = X_NDR_CHECK(idl::x_ndr_push_uint16(DFS_SERVER_ROOT, ndr, bpos, epos, ndr_flags));
	bpos = X_NDR_CHECK(idl::x_ndr_push_uint16(0, ndr, bpos, epos, ndr_flags)); // TODO entry_flags
	bpos = X_NDR_CHECK(idl::x_ndr_push_uint32(referral.ttl, ndr, bpos, epos, ndr_flags));
	idl::x_ndr_off_t path_pos = bpos;
	bpos = X_NDR_CHECK(idl::x_ndr_push_uint16(0, ndr, bpos, epos, ndr_flags));
	bpos = X_NDR_CHECK(idl::x_ndr_push_uint16(0, ndr, bpos, epos, ndr_flags));
	bpos = X_NDR_CHECK(idl::x_ndr_push_uint16(0, ndr, bpos, epos, ndr_flags));
	const uint8_t zeroes[16] = {0, };
	bpos = X_NDR_CHECK(idl::x_ndr_push_bytes(zeroes, ndr, bpos, epos, 16));

	uint16_t size = x_convert_assert<uint16_t>(bpos - base_pos);
	idl::x_ndr_push_uint16(size, ndr, size_pos, epos, ndr_flags);
	for (uint32_t i = 0; i < 2; ++i) {
		path_pos = idl::x_ndr_push_uint16(x_convert_assert<uint16_t>(bpos - base_pos), ndr, path_pos, epos, ndr_flags);
		bpos = X_NDR_CHECK(idl::x_ndr_scalars_string(referral.path, ndr, bpos, epos, ndr_flags, false));
	}

	path_pos = idl::x_ndr_push_uint16(x_convert_assert<uint16_t>(bpos - base_pos), ndr, path_pos, epos, ndr_flags);
	bpos = X_NDR_CHECK(idl::x_ndr_scalars_string(referral.node, ndr, bpos, epos, ndr_flags, false));

	return bpos;
}

static idl::x_ndr_off_t push_dfs_referral_resp(const x_dfs_referral_resp_t &resp,
		idl::x_ndr_push_t &ndr, idl::x_ndr_off_t bpos, idl::x_ndr_off_t epos,
		uint32_t flags)
{
	bpos = X_NDR_CHECK(idl::x_ndr_push_uint16(resp.path_consumed, ndr, bpos, epos, flags));
	bpos = X_NDR_CHECK(idl::x_ndr_push_uint16(x_convert_assert<uint16_t>(resp.referrals.size()), ndr, bpos, epos, flags));
	bpos = X_NDR_CHECK(idl::x_ndr_push_uint32(DFS_HEADER_FLAG_REFERAL_SVR | DFS_HEADER_FLAG_STORAGE_SVR, ndr, bpos, epos, flags));
	for (const auto& ref: resp.referrals) {
		bpos = X_NDR_CHECK(push_referral_v3(ref, ndr, bpos, epos, idl::x_ndr_set_flags(flags, LIBNDR_FLAG_NOALIGN)));
	}
	return bpos;
}

static NTSTATUS push_ref_resp(const x_dfs_referral_resp_t &resp, size_t in_max_output,
		x_buf_t *&out_buf, uint32_t &out_buf_length)
{
	idl::x_ndr_push_buff_t ndr_data{};
	idl::x_ndr_push_t ndr{ndr_data, 0};
	idl::x_ndr_off_t ndr_ret = push_dfs_referral_resp(resp, ndr, 0, in_max_output, 0);
	if (ndr_ret < 0) {
		return STATUS_BUFFER_OVERFLOW;
	}
	out_buf = x_buf_alloc(ndr_data.data.size());
	memcpy(out_buf->data, ndr_data.data.data(), ndr_data.data.size());
	out_buf_length = x_convert_assert<uint32_t>(ndr_data.data.size());
	return NT_STATUS_OK;
}

static NTSTATUS fsctl_dfs_get_refers_internal(
		x_smbd_conn_t *smbd_conn,
		x_smb2_state_ioctl_t &state,
		uint16_t in_max_referral_level,
		const uint8_t *in_file_name_data,
		uint32_t in_file_name_size)
{
	NTSTATUS status;

	if (in_file_name_size % 2 != 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	const char16_t *in_file_name_ptr = (const char16_t *)in_file_name_data;
	const char16_t *in_file_name_end = (const char16_t *)(in_file_name_data + in_file_name_size);
	for ( ; in_file_name_ptr < in_file_name_end; ++in_file_name_ptr) {
		if (*in_file_name_ptr != u'\\' && *in_file_name_ptr != u'/') {
			break;
		}
	}

	if (in_file_name_ptr != in_file_name_end && in_file_name_end[-1] == 0) {
		--in_file_name_end;
	}

	if (in_file_name_ptr != (const char16_t *)in_file_name_data) {
		--in_file_name_ptr;
	}

	std::string in_file_name = x_convert_utf16_to_lower_utf8(in_file_name_ptr,
			in_file_name_end);
	std::string host, share, reqpath;
	status = parse_dfs_path(in_file_name, host, share, reqpath);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	auto smbd_conf = x_smbd_conf_get();
	for (auto const& node: smbd_conf->cluster_nodes) {
		if (host == node) {
			return NT_STATUS_NOT_FOUND;
		}
	}

	std::shared_ptr<x_smbd_share_t> smbd_share = x_smbd_find_share(share);
	if (!smbd_share) {
		X_TODO;
		// find_service user_share
		return NT_STATUS_NOT_FOUND;
	}

	if (smbd_share->msdfs_proxy.size() == 0) {
		return NT_STATUS_FS_DRIVER_REQUIRED;
	}

	x_dfs_referral_resp_t dfs_referral_resp;
	dfs_referral_resp.path_consumed = x_convert_assert<uint16_t>((in_file_name_end - in_file_name_ptr) * 2);
	if (true || reqpath.size() == 0) {
		std::u16string in_file_name{in_file_name_ptr, in_file_name_end};
#if 1
		dfs_referral_resp.referrals.push_back(x_referral_t{0, smbd_conf->max_referral_ttl, in_file_name, in_file_name});
#else
		TODO
		if (smbd_share->msdfs_proxy.size() == 0) {
			dfs_referral_resp.referrals.push_back(x_referral_t{0, smbd_conf->max_referral_ttl, in_file_name, in_file_name});
		} else {
			std::string alt_path = "\\";
			alt_path += smbd_share->msdfs_proxy;
			if (!smbd_conf->dns_domain.empty()) {
				alt_path += '.';
				alt_path += smbd_conf->dns_domain;
			}
			alt_path += '\\';
			alt_path += share;
			if (reqpath.size()) {
				alt_path += '\\';
				alt_path += reqpath;
			}
			dfs_referral_resp.referrals.push_back(x_referral_t{0, smbd_conf->max_referral_ttl, in_file_name, x_convert_utf8_to_utf16(alt_path)});
		}
#endif
	} else {
		X_TODO; // department share
	}

	return push_ref_resp(dfs_referral_resp, state.in_max_output_length, state.out_buf, state.out_buf_length);
}

/* FSCTL_DFS_GET_REFERRALS_EX References: [MS-DFSC]: 2.2.3
 */
	/* TODO should check IPC ?
	if (smbd_tcon->smbshare->type != TYPE_IPC) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	if (!smbd_conf->host_msdfs) {
		return NT_STATUS_FS_DRIVER_REQUIRED;
	}
	*/
static NTSTATUS x_smb2_fsctl_dfs_get_referrals(
		x_smbd_conn_t *smbd_conn,
		x_smb2_state_ioctl_t &state)
{
	if (!file_id_is_nul(state)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (state.in_buf_length < (2 + 2)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	const uint8_t *in_data = state.in_buf->data + state.in_buf_offset;
	uint16_t in_max_referral_level = x_get_le16(in_data);

	return fsctl_dfs_get_refers_internal(smbd_conn, state,
			in_max_referral_level,
			in_data + 2, state.in_buf_length - 2);
}

struct x_smb2_in_refers_ex_t
{
	uint16_t max_referral_level;
	uint16_t request_flags;
	uint32_t request_size;
};

static NTSTATUS x_smb2_fsctl_dfs_get_referrals_ex(
		x_smbd_conn_t *smbd_conn,
		x_smb2_state_ioctl_t &state)
{
	if (!file_id_is_nul(state)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (state.in_buf_length < sizeof(x_smb2_in_refers_ex_t) + 2) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	const uint8_t *in_data = state.in_buf->data + state.in_buf_offset;
	x_smb2_in_refers_ex_t in_refers_ex;
	memcpy(&in_refers_ex, in_data, sizeof(in_refers_ex));

	in_refers_ex.max_referral_level = X_LE2H16(in_refers_ex.max_referral_level);
	in_refers_ex.request_size = X_LE2H16(in_refers_ex.request_size);

	if (in_refers_ex.request_size < 2) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (in_refers_ex.request_size > state.in_buf_length - sizeof(x_smb2_in_refers_ex_t)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	uint16_t in_file_name_size = x_get_le16(in_data + sizeof(in_refers_ex));
	/* Skip check site_name here since referrals are not site dependent */
	if (in_file_name_size > in_refers_ex.request_size - 2) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return fsctl_dfs_get_refers_internal(smbd_conn, state,
			in_refers_ex.max_referral_level,
			in_data + sizeof(x_smb2_in_refers_ex_t) + 2,
			in_file_name_size);
}

static NTSTATUS x_smb2_fsctl_pipe_wait(
		x_smbd_conn_t *smbd_conn,
		x_smb2_state_ioctl_t &state)
{
	if (!file_id_is_nul(state)) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	X_TODO;
	return NT_STATUS_INTERNAL_ERROR;
}

static NTSTATUS x_smb2_fsctl_validate_negotiate_info_224(
		x_smbd_conn_t *smbd_conn,
		x_smb2_state_ioctl_t &state)
{
	if (!file_id_is_nul(state)) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	X_TODO;
	return NT_STATUS_INTERNAL_ERROR;
}

struct x_smb2_fsctl_validate_negotiate_info_in_t
{
	uint32_t capabilities;
	x_smb2_uuid_bytes_t client_guid;
	uint16_t security_mode;
	uint16_t num_dialects;
};

struct x_smb2_fsctl_validate_negotiate_info_out_t
{
	uint32_t capabilities;
	x_smb2_uuid_bytes_t server_guid;
	uint16_t security_mode;
	uint16_t dialect;
};

static NTSTATUS x_smb2_fsctl_validate_negotiate_info(
		x_smbd_conn_t *smbd_conn,
		x_smb2_state_ioctl_t &state)
{
	if (!file_id_is_nul(state)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	uint32_t in_input_size = state.in_buf_length;

	if (in_input_size < sizeof(x_smb2_fsctl_validate_negotiate_info_in_t)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (state.in_max_output_length < sizeof(x_smb2_fsctl_validate_negotiate_info_out_t)) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	struct x_smb2_fsctl_validate_negotiate_info_state_t fsctl_state;
	const struct x_smb2_fsctl_validate_negotiate_info_in_t *in = (x_smb2_fsctl_validate_negotiate_info_in_t *)(state.in_buf->data + state.in_buf_offset);

	fsctl_state.in_capabilities = X_LE2H32(in->capabilities);
	memcpy(&fsctl_state.in_guid, &in->client_guid, sizeof(in->client_guid));
	fsctl_state.in_security_mode = X_LE2H16(in->security_mode);
	fsctl_state.in_num_dialects = X_LE2H16(in->num_dialects);
	if (in_input_size < (sizeof(x_smb2_fsctl_validate_negotiate_info_in_t)
				+ fsctl_state.in_num_dialects * 2)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	NTSTATUS status = x_smbd_conn_validate_negotiate_info(smbd_conn, fsctl_state);
	if (NT_STATUS_IS_OK(status)) {
		state.out_buf = x_buf_alloc(sizeof(x_smb2_fsctl_validate_negotiate_info_out_t));
		x_smb2_fsctl_validate_negotiate_info_out_t *out = (x_smb2_fsctl_validate_negotiate_info_out_t *)state.out_buf->data;
		out->capabilities = X_H2LE32(fsctl_state.out_capabilities);
		memcpy(&out->server_guid, &fsctl_state.out_guid, sizeof(out->server_guid));
		out->security_mode = X_H2LE16(fsctl_state.out_security_mode);
		out->dialect = X_H2LE16(fsctl_state.out_dialect);
		state.out_buf_length = sizeof(x_smb2_fsctl_validate_negotiate_info_out_t);
	}

	return status;
}

struct fsctl_net_iface_info_t
{
	uint32_t next;
	uint32_t ifindex;
	uint32_t capability;
	uint32_t rss_queue;
	uint64_t linkspeed;
	struct sockaddr_storage sockaddr;
};

static NTSTATUS x_smb2_fsctl_query_network_interface_info(
		x_smbd_conn_t *smbd_conn,
		x_smbd_tcon_t *smbd_tcon,
		x_smb2_state_ioctl_t &state)
{
	if (!file_id_is_nul(state)) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	if (!(x_smbd_conn_get_capabilities(smbd_conn) & SMB2_CAP_MULTI_CHANNEL)) {
		if (x_smbd_tcon_get_share(smbd_tcon)->type == TYPE_IPC) {
			return NT_STATUS_FS_DRIVER_REQUIRED;
		} else {
			return NT_STATUS_INVALID_DEVICE_REQUEST;
		}
	}

	const auto smbd_conf = x_smbd_conf_get();
	const auto &local_ifaces = smbd_conf->local_ifaces;
	if (state.in_max_output_length < sizeof(fsctl_net_iface_info_t) * local_ifaces.size()) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	state.out_buf = x_buf_alloc(sizeof(fsctl_net_iface_info_t) * local_ifaces.size());
	uint8_t *p = state.out_buf->data;
	fsctl_net_iface_info_t *last_info = nullptr;
	for (auto &iface: local_ifaces) {
		fsctl_net_iface_info_t *info = (fsctl_net_iface_info_t *)p;
		if (last_info) {
			last_info->next = X_H2LE32(sizeof(fsctl_net_iface_info_t));
		}
		info->next = 0;
		info->ifindex = X_H2LE32(iface.if_index);
		info->capability = X_H2LE32(iface.capability);
		info->rss_queue = 0; // samba always set to 0
		info->linkspeed = X_H2LE64(iface.linkspeed);
		info->sockaddr = iface.ip;
		last_info = info;
	}
	state.out_buf_length = x_convert_assert<uint32_t>(sizeof(fsctl_net_iface_info_t) * local_ifaces.size());

	return NT_STATUS_OK;
}

NTSTATUS x_smb2_process_ioctl(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	if (smbd_requ->in_requ_len < SMB2_HDR_BODY + sizeof(x_smb2_in_ioctl_t)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	auto state = std::make_unique<x_smb2_state_ioctl_t>();
	if (!decode_in_ioctl(*state, smbd_requ->in_buf, smbd_requ->in_offset, smbd_requ->in_requ_len)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	X_LOG_OP("%ld IOCTL 0x%lx, 0x%lx", smbd_requ->in_mid,
			state->file_id_persistent, state->file_id_volatile);

	if (state->in_flags != SMB2_IOCTL_FLAG_IS_FSCTL) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_NOT_SUPPORTED);
	}

	NTSTATUS status;
	switch (state->ctl_code) {
	default:
		if (!smbd_requ->smbd_open) {
			smbd_requ->smbd_open = x_smbd_open_lookup(state->file_id_persistent,
					state->file_id_volatile,
					smbd_requ->smbd_tcon);
			if (!smbd_requ->smbd_open) {
				RETURN_OP_STATUS(smbd_requ, NT_STATUS_FILE_CLOSED);
			}
		}

		status = x_smbd_open_op_ioctl(smbd_requ->smbd_open,
				smbd_conn, smbd_requ, state);
		break;
	case FSCTL_DFS_GET_REFERRALS:
		status = x_smb2_fsctl_dfs_get_referrals(smbd_conn, *state);
		break;
	case FSCTL_DFS_GET_REFERRALS_EX:
		status = x_smb2_fsctl_dfs_get_referrals_ex(smbd_conn, *state);
		break;
	case FSCTL_PIPE_WAIT:
		status = x_smb2_fsctl_pipe_wait(smbd_conn, *state);
		break;
	case FSCTL_VALIDATE_NEGOTIATE_INFO_224:
		status = x_smb2_fsctl_validate_negotiate_info_224(smbd_conn, *state);
		break;
	case FSCTL_VALIDATE_NEGOTIATE_INFO:
		status = x_smb2_fsctl_validate_negotiate_info(smbd_conn, *state);
		break;
	case FSCTL_QUERY_NETWORK_INTERFACE_INFO:
		status = x_smb2_fsctl_query_network_interface_info(smbd_conn,
				smbd_requ->smbd_tcon, *state);
		break;
	}

	if (NT_STATUS_IS_OK(status)) {
		x_smb2_reply_ioctl(smbd_conn, smbd_requ, *state);
	}
	return status;
}
#if 0
// FSCTL_NAMED_PIPE
static NTSTATUS x_smb2_ioctl_named_pipe(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_ioctl_t> &state)
{
	switch (state->ctl_code) {
	case FSCTL_PIPE_WAIT:
		if (!file_id_is_nul(*state)) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		/* TODO */
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (smbd_requ->smbd_open) {
	} else if (smbd_requ->smbd_tcon) {
		smbd_requ->smbd_open = x_smbd_open_find(state->file_id_persistent,
				state->file_id_volatile,
				smbd_requ->smbd_tcon);
	} else {
		smbd_requ->smbd_open = x_smbd_open_find(state->file_id_persistent,
				state->file_id_volatile, smbd_requ->in_tid, smbd_requ->smbd_sess);
	}

	/* TODO check tcon is IPC? */
	if (!smbd_requ->smbd_open) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_FILE_CLOSED);
	}

	return x_smbd_open_op_ioctl(smbd_conn, smbd_requ, state);
}

// FSCTL_FILESYSTEM
static NTSTATUS x_smb2_ioctl_filesys(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_ioctl_t> &state)
{
	if (smbd_requ->smbd_open) {
	} else if (smbd_requ->smbd_tcon) {
		smbd_requ->smbd_open = x_smbd_open_find(state->file_id_persistent,
				state->file_id_volatile,
				smbd_requ->smbd_tcon);
	} else {
		smbd_requ->smbd_open = x_smbd_open_find(state->file_id_persistent,
				state->file_id_volatile, smbd_requ->in_tid, smbd_requ->smbd_sess);
	}

	/* TODO check tcon is not IPC? */
	if (!smbd_requ->smbd_open) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_FILE_CLOSED);
	}

	return x_smbd_open_op_ioctl(smbd_conn, smbd_requ, state);
}

static NTSTATUS x_smb2_ioctl_network_fs(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_ioctl_t> &state)
{
	NTSTATUS status = NT_STATUS_INTERNAL_ERROR;

	switch (state->ctl_code) {
#if 0
	/*
	 * [MS-SMB2] 2.2.31
	 * FSCTL_SRV_COPYCHUNK is issued when a handle has
	 * FILE_READ_DATA and FILE_WRITE_DATA access to the file;
	 * FSCTL_SRV_COPYCHUNK_WRITE is issued when a handle only has
	 * FILE_WRITE_DATA access.
	 */
	case FSCTL_SRV_COPYCHUNK_WRITE:	/* FALL THROUGH */
	case FSCTL_SRV_COPYCHUNK:
		subreq = fsctl_srv_copychunk_send(state, ev,
						  ctl_code,
						  state->fsp,
						  &state->in_input,
						  state->in_max_output,
						  state->smb2req);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq,
					smb2_ioctl_network_fs_copychunk_done,
					req);
		return req;
		break;
#endif
	case FSCTL_VALIDATE_NEGOTIATE_INFO:
		if (!file_id_is_nul(*state)) {
			return NT_STATUS_NOT_SUPPORTED;
		}
		status = fsctl_validate_neg_info(smbd_conn, *state);
		break;
	case FSCTL_VALIDATE_NEGOTIATE_INFO_224:
		if (!file_id_is_nul(*state)) {
			return NT_STATUS_NOT_SUPPORTED;
		}
		/* TODO */
		break;
	case FSCTL_QUERY_NETWORK_INTERFACE_INFO:
		if (!file_id_is_nul(*state)) {
			return NT_STATUS_NOT_SUPPORTED;
		}
		/* server_multi_channel_enabled */
		/* check if IS_IPC */
		status = fsctl_network_iface_info(smbd_conn, *state);
		break;
#if 0
	case FSCTL_SRV_REQUEST_RESUME_KEY:
		status = fsctl_srv_req_resume_key(state, ev, state->fsp,
						  state->in_max_output,
						  &state->out_output);
		if (!tevent_req_nterror(req, status)) {
			tevent_req_done(req);
		}
		return tevent_req_post(req, ev);
		break;
#endif
	default: {
		X_TODO;
#if 0
		uint8_t *out_data = NULL;
		uint32_t out_data_len = 0;

		if (state->fsp == NULL) {
			status = NT_STATUS_NOT_SUPPORTED;
		} else {
			status = SMB_VFS_FSCTL(state->fsp,
					       state,
					       ctl_code,
					       state->smbreq->flags2,
					       state->in_input.data,
					       state->in_input.length,
					       &out_data,
					       state->in_max_output,
					       &out_data_len);
			state->out_output = data_blob_const(out_data, out_data_len);
			if (NT_STATUS_IS_OK(status)) {
				tevent_req_done(req);
				return tevent_req_post(req, ev);
			}
		}

		if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED)) {
			if (IS_IPC(state->smbreq->conn)) {
				status = NT_STATUS_FS_DRIVER_REQUIRED;
			} else {
				status = NT_STATUS_INVALID_DEVICE_REQUEST;
			}
		}

		tevent_req_nterror(req, status);
		return tevent_req_post(req, ev);
		break;
#endif
	}
	}

	return status;
}
static NTSTATUS x_smb2_ioctl_open(
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_ioctl_t> &state)
{
	if (smbd_requ->smbd_open) {
	} else if (smbd_requ->smbd_tcon) {
		smbd_requ->smbd_open = x_smbd_open_find(state->file_id_persistent,
				state->file_id_volatile,
				smbd_requ->smbd_tcon);
	} else {
		uint32_t tid = x_get_le32(in_hdr + SMB2_HDR_TID);
		smbd_requ->smbd_open = x_smbd_open_find(state->file_id_persistent,
				state->file_id_volatile, tid, smbd_requ->smbd_sess);
	}

	if (!smbd_requ->smbd_open) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_FILE_CLOSED);
	}

	auto smbd_object = smbd_requ->smbd_open->smbd_object;
	return x_smbd_object_op_ioctl(smbd_object, smbd_conn, smbd_requ,
			state);
}

#endif

