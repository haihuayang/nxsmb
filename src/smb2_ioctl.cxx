
#include "smbd.hxx"
#include "core.hxx"
#include "include/charset.hxx"

enum {
	X_SMB2_IOCTL_REQU_BODY_LEN = 0x38,
	X_SMB2_IOCTL_RESP_BODY_LEN = 0x30,
};

static int x_smb2_reply_ioctl(x_smbd_conn_t *smbd_conn,
		x_smbd_sess_t *smbd_sess,
		x_msg_t *msg, NTSTATUS status,
		uint32_t tid,
		uint32_t ctl_code,
		uint64_t file_id_persistent, uint64_t file_id_volatile,
		const std::vector<uint8_t> &output)
{
	X_LOG_OP("%ld RESP SUCCESS", msg->mid);

	uint8_t *outbuf = new uint8_t[8 + 0x40 + X_SMB2_IOCTL_RESP_BODY_LEN + output.size()];
	uint8_t *outhdr = outbuf + 8;
	uint8_t *outbody = outhdr + 0x40;

	if (output.size()) {
		SSVAL(outbody, 0x00, X_SMB2_IOCTL_RESP_BODY_LEN + 1);
	} else {
		SSVAL(outbody, 0x00, X_SMB2_IOCTL_RESP_BODY_LEN);
	}
	SSVAL(outbody, 0x02, 0);
	SIVAL(outbody, 0x04, ctl_code);
	SBVAL(outbody, 0x08, file_id_persistent);
	SBVAL(outbody, 0x10, file_id_volatile);
	SIVAL(outbody, 0x18, 0x40 + X_SMB2_IOCTL_RESP_BODY_LEN);
	SIVAL(outbody, 0x1c, 0);
	SIVAL(outbody, 0x20, 0x40 + X_SMB2_IOCTL_RESP_BODY_LEN);
	SIVAL(outbody, 0x24, output.size());
	SBVAL(outbody, 0x28, 0);

	memcpy(outbody + X_SMB2_IOCTL_RESP_BODY_LEN, output.data(), output.size());

	//smbd_smb2_request_setup_out
	memset(outhdr, 0, 0x40);
	SIVAL(outhdr, SMB2_HDR_PROTOCOL_ID,     SMB2_MAGIC);
	SSVAL(outhdr, SMB2_HDR_LENGTH,	  SMB2_HDR_BODY);
	SSVAL(outhdr, SMB2_HDR_CREDIT_CHARGE, 1); // TODO
	SIVAL(outhdr, SMB2_HDR_STATUS, NT_STATUS_V(status));
	SIVAL(outhdr, SMB2_HDR_OPCODE, SMB2_OP_IOCTL);
	SSVAL(outhdr, SMB2_HDR_CREDIT, 1); // TODO
	SIVAL(outhdr, SMB2_HDR_FLAGS, SMB2_HDR_FLAG_REDIRECT); // TODO
	SIVAL(outhdr, SMB2_HDR_NEXT_COMMAND, 0);
	SBVAL(outhdr, SMB2_HDR_MESSAGE_ID, msg->mid);
	SIVAL(outhdr, SMB2_HDR_TID, tid);
	SBVAL(outhdr, SMB2_HDR_SESSION_ID, smbd_sess->id);

	uint8_t *outnbt = outbuf + 4;
	x_put_be32(outnbt, 0x40 + X_SMB2_IOCTL_RESP_BODY_LEN + output.size());

	msg->out_buf = outbuf;
	msg->out_off = 4;
	msg->out_len = 4 + 0x40 + X_SMB2_IOCTL_RESP_BODY_LEN + output.size();

	msg->state = x_msg_t::STATE_COMPLETE;
	x_smbd_conn_reply(smbd_conn, msg, smbd_sess);
	return 0;
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
	bpos = X_NDR_CHECK(idl::x_ndr_push_uint16(4, ndr, bpos, epos, ndr_flags)); // TODO version to be max_referral_level
	idl::x_ndr_off_t size_pos = bpos;
	bpos = X_NDR_CHECK(idl::x_ndr_skip<uint16_t>(ndr, bpos, epos, ndr_flags));
	bpos = X_NDR_CHECK(idl::x_ndr_push_uint16(DFS_SERVER_ROOT, ndr, bpos, epos, ndr_flags));
	bpos = X_NDR_CHECK(idl::x_ndr_push_uint16(4, ndr, bpos, epos, ndr_flags)); // entry_flags
	bpos = X_NDR_CHECK(idl::x_ndr_push_uint32(referral.ttl, ndr, bpos, epos, ndr_flags));
	idl::x_ndr_off_t path_pos = bpos;
	bpos = X_NDR_CHECK(idl::x_ndr_skip<uint16_t>(ndr, bpos, epos, ndr_flags));
	bpos = X_NDR_CHECK(idl::x_ndr_skip<uint16_t>(ndr, bpos, epos, ndr_flags));
	bpos = X_NDR_CHECK(idl::x_ndr_skip<uint16_t>(ndr, bpos, epos, ndr_flags));
	const uint8_t zeroes[16] = {0, };
	bpos = X_NDR_CHECK(idl::x_ndr_push_bytes(zeroes, ndr, bpos, epos, 16));

	uint16_t size = bpos - base_pos;
	idl::x_ndr_push_uint16(size, ndr, size_pos, epos, ndr_flags);
	for (uint32_t i = 0; i < 2; ++i) {
		path_pos = idl::x_ndr_push_uint16(bpos - base_pos, ndr, path_pos, epos, ndr_flags);
		bpos = X_NDR_CHECK(idl::x_ndr_push_u16string(referral.path, ndr, bpos, epos, ndr_flags));
		bpos = X_NDR_CHECK(idl::x_ndr_push_uint16(0, ndr, bpos, epos, ndr_flags));
	}

	path_pos = idl::x_ndr_push_uint16(bpos - base_pos, ndr, path_pos, epos, ndr_flags);
	bpos = X_NDR_CHECK(idl::x_ndr_push_u16string(referral.node, ndr, bpos, epos, ndr_flags));
	bpos = X_NDR_CHECK(idl::x_ndr_push_uint16(0, ndr, bpos, epos, ndr_flags));

	return bpos;
}

static idl::x_ndr_off_t push_dfs_referral_resp(const x_dfs_referral_resp_t &resp,
		idl::x_ndr_push_t &ndr, idl::x_ndr_off_t bpos, idl::x_ndr_off_t epos,
		uint32_t flags)
{
	bpos = X_NDR_CHECK(idl::x_ndr_push_uint16(resp.path_consumed, ndr, bpos, epos, flags));
	bpos = X_NDR_CHECK(idl::x_ndr_push_uint16(resp.referrals.size(), ndr, bpos, epos, flags));
	bpos = X_NDR_CHECK(idl::x_ndr_push_uint32(DFS_HEADER_FLAG_REFERAL_SVR | DFS_HEADER_FLAG_STORAGE_SVR, ndr, bpos, epos, flags));
	for (const auto& ref: resp.referrals) {
		bpos = X_NDR_CHECK(push_referral_v3(ref, ndr, bpos, epos, idl::x_ndr_set_flags(flags, LIBNDR_FLAG_NOALIGN)));
	}
	return bpos;
}

static NTSTATUS push_ref_resp(const x_dfs_referral_resp_t &resp, size_t in_max_output, std::vector<uint8_t> &output)
{
	idl::x_ndr_push_buff_t ndr_data{};
	idl::x_ndr_push_t ndr{ndr_data, 0};
	idl::x_ndr_off_t ndr_ret = push_dfs_referral_resp(resp, ndr, 0, in_max_output, 0);
	if (ndr_ret < 0) {
		return STATUS_BUFFER_OVERFLOW;
	}
	std::swap(output, ndr_data.data);
	return NT_STATUS_OK;
}

static NTSTATUS fsctl_dfs_get_refers_internal(x_smbd_tcon_t *smbd_tcon,
		uint16_t in_max_referral_level,
		const uint8_t *in_file_name_data,
		uint32_t in_file_name_size,
		uint32_t in_max_output,
		std::vector<uint8_t> &output)
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

	for (auto const& node: lpcfg_cluster_nodes()) {
		if (host == node) {
			return NT_STATUS_NOT_FOUND;
		}
	}

	std::shared_ptr<x_smbd_share_t> smbd_share = x_smbd_share_find(share);
	if (!smbd_share) {
		X_TODO;
		// find_service user_share
		return NT_STATUS_NOT_FOUND;
	}

	x_dfs_referral_resp_t dfs_referral_resp;
	dfs_referral_resp.path_consumed = (in_file_name_end - in_file_name_ptr) * 2;
	if (true || reqpath.size() == 0) {
		std::u16string in_file_name{in_file_name_ptr, in_file_name_end};
		if (smbd_share->msdfs_proxy.size() == 0) {
			dfs_referral_resp.referrals.push_back(x_referral_t{0, lpcfg_max_referral_ttl(), in_file_name, in_file_name});
		} else {
			std::string alt_path = "\\";
			alt_path += smbd_share->msdfs_proxy;
			if (lpcfg_dns_domain()) {
				alt_path += '.';
				alt_path += lpcfg_dns_domain();
			}
			alt_path += '\\';
			alt_path += share;
			if (reqpath.size()) {
				alt_path += '\\';
				alt_path += reqpath;
			}
			dfs_referral_resp.referrals.push_back(x_referral_t{0, lpcfg_max_referral_ttl(), in_file_name, x_convert_utf8_to_utf16(alt_path)});
		}

	} else {
		X_TODO; // department share
	}

	return push_ref_resp(dfs_referral_resp, in_max_output, output);
}

static NTSTATUS fsctl_dfs_get_refers(x_smbd_tcon_t *smbd_tcon,
		const uint8_t *in_input_data,
		uint32_t in_input_size,
		uint32_t in_max_output,
		std::vector<uint8_t>& output)
{
	if (in_input_size < (2 + 2)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	uint16_t in_max_referral_level = SVAL(in_input_data, 0);
	const uint8_t *in_file_name_data = in_input_data + 2;
	uint32_t in_file_name_size = in_input_size - 2;

	return fsctl_dfs_get_refers_internal(smbd_tcon, in_max_referral_level,
			in_file_name_data, in_file_name_size, in_max_output, output);
}

static NTSTATUS fsctl_dfs_get_refers_ex(x_smbd_tcon_t *smbd_tcon,
		const uint8_t *in_input_data,
		uint32_t in_input_size,
		uint32_t in_max_output,
		std::vector<uint8_t>& output)
{
	/* 2 bytes in_max_referral_level + 2 bytes in_site_name_present +
	 * 4 bytes in_request_data_length
	 */
#define DFS_GET_REFERS_EX_HEADER (2 + 2 + 4)
	if (in_input_size < DFS_GET_REFERS_EX_HEADER) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	uint16_t in_max_referral_level = SVAL(in_input_data, 0);
	uint16_t in_request_flags = SVAL(in_input_data, 2);
	(void)in_request_flags; // unused
	uint32_t in_request_size = IVAL(in_input_data, 4);

	if (in_request_size < 2) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (in_request_size > in_input_size - DFS_GET_REFERS_EX_HEADER) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	uint16_t in_file_name_size = SVAL(in_input_data, DFS_GET_REFERS_EX_HEADER);
	/* Skip check site_name here since referrals are not site dependent */
	if (in_file_name_size > in_request_size - 2) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return fsctl_dfs_get_refers_internal(smbd_tcon, in_max_referral_level,
			in_input_data + DFS_GET_REFERS_EX_HEADER + 2,
			in_file_name_size, in_max_output, output);
}

/* FSCTL_DFS_GET_REFERRALS_EX References: [MS-DFSC]: 2.2.3
 */
static NTSTATUS x_smb2_ioctl_dfs(x_smbd_tcon_t *smbd_tcon,
		x_smbd_open_t *smbd_open,
		uint32_t ctl_code,
		const uint8_t *in_input_data,
		uint32_t in_input_size,
		uint32_t in_max_output,
		std::vector<uint8_t>& output)
{
	if (smbd_tcon->smbd_share->type != TYPE_IPC) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	if (!lpcfg_host_msdfs()) {
		return NT_STATUS_FS_DRIVER_REQUIRED;
	}

	NTSTATUS status = NT_STATUS_INTERNAL_ERROR;

	switch (ctl_code) {
	case FSCTL_DFS_GET_REFERRALS:
		X_ASSERT(!smbd_open);
		status = fsctl_dfs_get_refers(smbd_tcon, in_input_data, in_input_size, in_max_output, output);
		break;
	case FSCTL_DFS_GET_REFERRALS_EX:
		X_ASSERT(!smbd_open);
		status = fsctl_dfs_get_refers_ex(smbd_tcon, in_input_data, in_input_size, in_max_output, output);
		break;
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

// FSCTL_NETWORK_FILESYSTEM
static NTSTATUS x_smb2_ioctl_named_pipe(x_smbd_open_t *smbd_open,
		uint32_t ctl_code,
		const uint8_t *in_input_data,
		uint32_t in_input_size,
		uint32_t in_max_output,
		std::vector<uint8_t>& output)
{
	if (!smbd_open) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	return x_smbd_open_op_ioctl(smbd_open, ctl_code, in_input_data, in_input_size, in_max_output, output);
}

// FSCTL_NETWORK_FILESYSTEM
static NTSTATUS fsctl_validate_neg_info(x_smbd_conn_t *smbd_conn,
		const uint8_t *in_input_data,
		uint32_t in_input_size,
		uint32_t in_max_output,
		std::vector<uint8_t>& output)
{
	if (in_input_size < 0x18) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	uint32_t in_capabilities = IVAL(in_input_data, 0x00);
	if (in_capabilities != smbd_conn->client_capabilities) {
		return X_NT_STATUS_INTERNAL_TERMINATE;
	}

	idl::GUID client_guid;
	idl::x_ndr_pull(client_guid, in_input_data + 4, 0x10, 0);
	if (memcmp(&client_guid, &smbd_conn->client_guid, 0x10) != 0) {
		return X_NT_STATUS_INTERNAL_TERMINATE;
	}

	uint16_t in_security_mode = SVAL(in_input_data, 0x14);
	if (in_security_mode != smbd_conn->client_security_mode) {
		return X_NT_STATUS_INTERNAL_TERMINATE;
	}

	uint16_t in_num_dialects = SVAL(in_input_data, 0x16);
	if (in_input_size < (0x18u + in_num_dialects*2)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/*
	 * From: [MS-SMB2]
	 * 3.3.5.15.12 Handling a Validate Negotiate Info Request
	 *
	 * The server MUST determine the greatest common dialect
	 * between the dialects it implements and the Dialects array
	 * of the VALIDATE_NEGOTIATE_INFO request. If no dialect is
	 * matched, or if the value is not equal to Connection.Dialect,
	 * the server MUST terminate the transport connection
	 * and free the Connection object.
	 */
	uint16_t dialect = x_smb2_dialect_match(smbd_conn, 
			in_input_data + 0x18,
			in_num_dialects);

	if (dialect != smbd_conn->dialect) {
		return X_NT_STATUS_INTERNAL_TERMINATE;
	}

	if (in_max_output < 0x18) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	output.resize(0x18);
	uint8_t *outbody = output.data();
	x_put_le32(outbody + 0x00, smbd_conn->server_capabilities);
	memcpy(outbody + 4, smbd_conn->smbd->conf.guid, 16);
	x_put_le16(outbody + 0x14, smbd_conn->server_security_mode);
	x_put_le16(outbody + 0x16, smbd_conn->dialect);

	return NT_STATUS_OK;
}

static NTSTATUS x_smb2_ioctl_network_fs(x_smbd_conn_t *smbd_conn,
		x_smbd_tcon_t *smbd_tcon,
		x_smbd_open_t *smbd_open,
		uint32_t ctl_code,
		const uint8_t *in_input_data,
		uint32_t in_input_size,
		uint32_t in_max_output,
		std::vector<uint8_t>& output)
{
	NTSTATUS status = NT_STATUS_INTERNAL_ERROR;

	switch (ctl_code) {
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
		X_ASSERT(!smbd_open);
		status = fsctl_validate_neg_info(smbd_conn, in_input_data, in_input_size, in_max_output, output);
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

	return NT_STATUS_OK;
}

int x_smb2_process_IOCTL(x_smbd_conn_t *smbd_conn, x_msg_t *msg,
		const uint8_t *in_buf, size_t in_len)
{
	if (in_len < 0x40 + X_SMB2_IOCTL_REQU_BODY_LEN + 1) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, nullptr, NT_STATUS_INVALID_PARAMETER);
	}

	const uint8_t *inhdr = in_buf;
	const uint8_t *inbody = in_buf + 0x40;

	uint64_t in_session_id = BVAL(inhdr, SMB2_HDR_SESSION_ID);
	if (in_session_id == 0) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, nullptr, NT_STATUS_USER_SESSION_DELETED);
	}
	x_auto_ref_t<x_smbd_sess_t> smbd_sess{x_smbd_sess_find(in_session_id, smbd_conn)};
	if (smbd_sess == nullptr) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, nullptr, NT_STATUS_USER_SESSION_DELETED);
	}
	if (smbd_sess->state != x_smbd_sess_t::S_ACTIVE) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, NT_STATUS_INVALID_PARAMETER);
	}
	/* TODO signing/encryption */

	uint32_t in_tid = IVAL(inhdr, SMB2_HDR_TID);
	auto it = smbd_sess->tcon_table.find(in_tid);
	if (it == smbd_sess->tcon_table.end()) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, NT_STATUS_NETWORK_NAME_DELETED);
	}
	std::shared_ptr<x_smbd_tcon_t> smbd_tcon = it->second;

	x_smb2_requ_ioctl_t requ_ioctl;
	memcpy(&requ_ioctl, inbody, sizeof(requ_ioctl));

	X_LOG_OP("%ld IOCTL 0x%x 0x%lx,0x%lx", msg->mid, requ_ioctl.ctl_code,
			requ_ioctl.file_id_persistent, requ_ioctl.file_id_volatile);

	/*
	 * InputOffset (4 bytes): The offset, in bytes, from the beginning of
	 * the SMB2 header to the input data buffer. If no input data is
	 * required for the FSCTL/IOCTL command being issued, the client SHOULD
	 * set this value to 0.<49>
	 * <49> If no input data is required for the FSCTL/IOCTL command being
	 * issued, Windows-based clients set this field to any value.
	 */
	// allowed_length_in = 0;
	if (!x_check_range(requ_ioctl.input_offset, requ_ioctl.input_length,
			0x40 + X_SMB2_IOCTL_REQU_BODY_LEN, in_len)) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, NT_STATUS_INVALID_PARAMETER);
	}

	if (!x_check_range(requ_ioctl.output_offset, requ_ioctl.output_length,
			0x40 + X_SMB2_IOCTL_REQU_BODY_LEN, in_len)) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, NT_STATUS_INVALID_PARAMETER);
	}
#if 0
	if (in_output_length > 0) {
		uint32_t tmp_ofs;

		if (in_output_offset < min_output_offset) {
			return smbd_smb2_request_error(req,
					NT_STATUS_INVALID_PARAMETER);
		}

		tmp_ofs = in_output_offset - min_buffer_offset;
		in_output_buffer.data = SMBD_SMB2_IN_DYN_PTR(req);
		in_output_buffer.data += tmp_ofs;
		in_output_buffer.length = in_output_length;
	}

	/*
	 * verify the credits and avoid overflows
	 * in_input_buffer.length and in_output_buffer.length
	 * are already verified.
	 */
	data_length_in = in_input_buffer.length + in_output_buffer.length;

	data_length_out = in_max_input_length;
	data_length_tmp = UINT32_MAX - data_length_out;
	if (data_length_tmp < in_max_output_length) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}
	data_length_out += in_max_output_length;

	data_length_max = MAX(data_length_in, data_length_out);

	status = smbd_smb2_request_verify_creditcharge(req, data_length_max);
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(req, status);
	}
#endif
	x_auto_ref_t<x_smbd_open_t> smbd_open;
	/*
	 * If the Flags field of the request is not SMB2_0_IOCTL_IS_FSCTL the
	 * server MUST fail the request with STATUS_NOT_SUPPORTED.
	 */
	if (requ_ioctl.flags != SMB2_IOCTL_FLAG_IS_FSCTL) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, NT_STATUS_NOT_SUPPORTED);
	}

	switch (requ_ioctl.ctl_code) {
	case FSCTL_DFS_GET_REFERRALS:
	case FSCTL_DFS_GET_REFERRALS_EX:
	case FSCTL_PIPE_WAIT:
	case FSCTL_VALIDATE_NEGOTIATE_INFO_224:
	case FSCTL_VALIDATE_NEGOTIATE_INFO:
	case FSCTL_QUERY_NETWORK_INTERFACE_INFO:
		/*
		 * Some SMB2 specific CtlCodes like FSCTL_DFS_GET_REFERRALS or
		 * FSCTL_PIPE_WAIT does not take a file handle.
		 *
		 * If FileId in the SMB2 Header of the request is not
		 * 0xFFFFFFFFFFFFFFFF, then the server MUST fail the request
		 * with STATUS_INVALID_PARAMETER.
		 */
		if (requ_ioctl.file_id_persistent != UINT64_MAX ||
				requ_ioctl.file_id_volatile != UINT64_MAX) {
			return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess,
					NT_STATUS_INVALID_PARAMETER);
		}
		break;
	default:
		smbd_open.set(x_smbd_open_find(requ_ioctl.file_id_volatile,
				smbd_tcon.get()));
		if (!smbd_open) {
			return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess,
					NT_STATUS_FILE_CLOSED);
		}
		break;
	}

	std::vector<uint8_t> output;
	NTSTATUS status;
	switch (requ_ioctl.ctl_code & IOCTL_DEV_TYPE_MASK) {
	case FSCTL_DFS:
		status = x_smb2_ioctl_dfs(smbd_tcon.get(), smbd_open,
				requ_ioctl.ctl_code,
				in_buf + requ_ioctl.input_offset,
				requ_ioctl.input_length,
				requ_ioctl.max_output_length, output);
		break;
#if 0
	case FSCTL_FILESYSTEM:
		return smb2_ioctl_filesys(in_ctl_code, ev, req, state);
		break;
#endif
	case FSCTL_NAMED_PIPE:
		status = x_smb2_ioctl_named_pipe(smbd_open,
				requ_ioctl.ctl_code, in_buf + requ_ioctl.input_offset,
				requ_ioctl.input_length,
				requ_ioctl.max_output_length, output);
		break;
	case FSCTL_NETWORK_FILESYSTEM:
		status = x_smb2_ioctl_network_fs(smbd_conn, smbd_tcon.get(),
				smbd_open,
			       	requ_ioctl.ctl_code, in_buf + requ_ioctl.input_offset,
				requ_ioctl.input_length,
				requ_ioctl.max_output_length, output);
		break;
	default:
		X_TODO;
#if 0
		if (IS_IPC(smbreq->conn)) {
			tevent_req_nterror(req, NT_STATUS_FS_DRIVER_REQUIRED);
		} else {
			tevent_req_nterror(req, NT_STATUS_INVALID_DEVICE_REQUEST);
		}

		return tevent_req_post(req, ev);
#endif
		break;
	}

	if (NT_STATUS_EQUAL(status, X_NT_STATUS_INTERNAL_TERMINATE)) {
		return -EACCES;
	}
	/* TODO return error */
	return x_smb2_reply_ioctl(smbd_conn, smbd_sess, msg, status, in_tid,
			requ_ioctl.ctl_code,
			requ_ioctl.file_id_persistent, requ_ioctl.file_id_volatile, output);
#if 0
	subreq = smbd_smb2_ioctl_send(req, req->sconn->ev_ctx,
				      req, in_fsp,
				      in_ctl_code,
				      in_input_buffer,
				      in_max_output_length,
				      in_flags);
	if (subreq == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
	}
	tevent_req_set_callback(subreq, smbd_smb2_request_ioctl_done, req);

	return smbd_smb2_request_pending_queue(req, subreq, 1000);
#endif
}


