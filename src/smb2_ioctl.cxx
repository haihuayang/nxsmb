
#include "smbd.hxx"

enum {
	X_SMB2_IOCTL_BODY_LEN = 0x38,
};

int x_smb2_process_IOCTL(x_smbdconn_t *smbdconn, x_msg_t *msg,
		const uint8_t *in_buf, size_t in_len)
{
	X_TODO;
	return 0;
}
#if 0
static inline bool check_input_range(uint32_t offset, uint32_t length,
		uint32_t min_offset, uint32_t max_offset)
{
	if (offset < min_offset) {
		return false;
	}
	uint32_t end = offset + length;
	if (end < offset) {
		return false;
	}
	if (end > max_offset) {
		return false;
	}
	return true;
}

static NTSTATUS fsctl_dfs_get_refers_internal(TALLOC_CTX *mem_ctx,
		struct connection_struct *conn,
		uint16_t in_max_referral_level,
		uint32_t in_max_output,
		DATA_BLOB in_file_name_buffer,
		DATA_BLOB *out_output)
{
	char *in_file_name_string;
	size_t in_file_name_string_size;
	bool ok;
	bool overflow = false;
	NTSTATUS status;
	int dfs_size;
	char *dfs_data = NULL;
	DATA_BLOB output;

	ok = convert_string_talloc(mem_ctx, CH_UTF16, CH_UNIX,
				   in_file_name_buffer.data,
				   in_file_name_buffer.length,
				   &in_file_name_string,
				   &in_file_name_string_size);
	if (!ok) {
		return NT_STATUS_ILLEGAL_CHARACTER;
	}

	dfs_size = setup_dfs_referral(conn,
				      in_file_name_string,
				      in_max_referral_level,
				      &dfs_data, &status);
	if (dfs_size < 0) {
		return status;
	}

	if (dfs_size > in_max_output) {
		/*
		 * TODO: we need a testsuite for this
		 */
		overflow = true;
		dfs_size = in_max_output;
	}

	output = data_blob_talloc(mem_ctx, (uint8_t *)dfs_data, dfs_size);
	SAFE_FREE(dfs_data);
	if ((dfs_size > 0) && (output.data == NULL)) {
		return NT_STATUS_NO_MEMORY;
	}
	*out_output = output;

	if (overflow) {
		return STATUS_BUFFER_OVERFLOW;
	}
	return NT_STATUS_OK;
}

static NTSTATUS fsctl_dfs_get_refers(
		x_smbdconn_t *smbdconn,
				     struct tevent_context *ev,
				     struct connection_struct *conn,
				     DATA_BLOB *in_input,
				     uint32_t in_max_output,
				     DATA_BLOB *out_output)
{
	uint16_t in_max_referral_level;
	DATA_BLOB in_file_name_buffer;

	if (!IS_IPC(conn)) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}

	if (!lp_host_msdfs()) {
		return NT_STATUS_FS_DRIVER_REQUIRED;
	}

	if (in_input->length < (2 + 2)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	in_max_referral_level = SVAL(in_input->data, 0);
	in_file_name_buffer.data = in_input->data + 2;
	in_file_name_buffer.length = in_input->length - 2;

	return fsctl_dfs_get_refers_internal(mem_ctx, conn, in_max_referral_level,
			in_max_output, in_file_name_buffer, out_output);
}

static NTSTATUS fsctl_dfs_get_refers_ex(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct connection_struct *conn,
				     DATA_BLOB *in_input,
				     uint32_t in_max_output,
				     DATA_BLOB *out_output)
{
	uint16_t in_max_referral_level;
	uint16_t in_request_flags, in_file_name_length;
	DATA_BLOB in_file_name_buffer;
	uint32_t in_request_data_length;

	if (!IS_IPC(conn)) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}

	if (!lp_host_msdfs()) {
		return NT_STATUS_FS_DRIVER_REQUIRED;
	}

	/* 2 bytes in_max_referral_level + 2 bytes in_site_name_present +
	 * 4 bytes in_request_data_length
	 */
#define DFS_GET_REFERS_EX_HEADER (2 + 2 + 4)
	if (in_input->length < DFS_GET_REFERS_EX_HEADER) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	in_max_referral_level = SVAL(in_input->data, 0);
	in_request_flags = SVAL(in_input->data, 2);
	in_request_data_length = IVAL(in_input->data, 4);

	if (in_input->length < (DFS_GET_REFERS_EX_HEADER + in_request_data_length)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (in_request_data_length < 2) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	in_file_name_length = SVAL(in_input->data, DFS_GET_REFERS_EX_HEADER);
	/* Skip check site_name here since referrals are not site dependent */
	if (in_request_data_length < (2 + in_file_name_length)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	in_file_name_buffer.data = in_input->data + DFS_GET_REFERS_EX_HEADER + 2;
	in_file_name_buffer.length = in_file_name_length;

	return fsctl_dfs_get_refers_internal(mem_ctx, conn, in_max_referral_level,
			in_max_output, in_file_name_buffer, out_output);
}

/* FSCTL_DFS_GET_REFERRALS_EX References: [MS-DFSC]: 2.2.3
 */
struct tevent_req *x_smb2_ioctl_dfs(uint32_t ctl_code,
				  struct tevent_context *ev,
				  struct tevent_req *req,
				  struct smbd_smb2_ioctl_state *state)
{
	NTSTATUS status;

	switch (ctl_code) {
	case FSCTL_DFS_GET_REFERRALS:
		status = fsctl_dfs_get_refers(state, ev, state->smbreq->conn,
					      &state->in_input,
					      state->in_max_output,
					      &state->out_output);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(2, ("FSCTL_DFS_GET_REFERRALS error %s\n",
						nt_errstr(status)));
		}
		if (!tevent_req_nterror(req, status)) {
			tevent_req_done(req);
		}
		return tevent_req_post(req, ev);
		break;
	case FSCTL_DFS_GET_REFERRALS_EX:
		status = fsctl_dfs_get_refers_ex(state, ev, state->smbreq->conn,
					      &state->in_input,
					      state->in_max_output,
					      &state->out_output);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(2, ("FSCTL_DFS_GET_REFERRALS_EX error %s\n",
						nt_errstr(status)));
		}
		if (!tevent_req_nterror(req, status)) {
			tevent_req_done(req);
		}
		return tevent_req_post(req, ev);
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

	tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
	return tevent_req_post(req, ev);
}

static struct tevent_req *smbd_smb2_ioctl_send(TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       struct smbd_smb2_request *smb2req,
					       struct files_struct *fsp,
					       uint32_t in_ctl_code,
					       DATA_BLOB in_input,
					       uint32_t in_max_output,
					       uint32_t in_flags)
{
	struct tevent_req *req;
	struct smbd_smb2_ioctl_state *state;
	struct smb_request *smbreq;

	req = tevent_req_create(mem_ctx, &state,
				struct smbd_smb2_ioctl_state);
	if (req == NULL) {
		return NULL;
	}
	state->smb2req = smb2req;
	state->smbreq = NULL;
	state->fsp = fsp;
	state->in_input = in_input;
	state->in_max_output = in_max_output;
	state->out_output = data_blob_null;

	DEBUG(10, ("smbd_smb2_ioctl: ctl_code[0x%08x] %s, %s\n",
		   (unsigned)in_ctl_code,
		   fsp ? fsp_str_dbg(fsp) : "<no handle>",
		   fsp_fnum_dbg(fsp)));

	smbreq = smbd_smb2_fake_smb_request(smb2req);
	if (tevent_req_nomem(smbreq, req)) {
		return tevent_req_post(req, ev);
	}
	state->smbreq = smbreq;

	switch (in_ctl_code & IOCTL_DEV_TYPE_MASK) {
	case FSCTL_DFS:
		return smb2_ioctl_dfs(in_ctl_code, ev, req, state);
		break;
	case FSCTL_FILESYSTEM:
		return smb2_ioctl_filesys(in_ctl_code, ev, req, state);
		break;
	case FSCTL_NAMED_PIPE:
		return smb2_ioctl_named_pipe(in_ctl_code, ev, req, state);
		break;
	case FSCTL_NETWORK_FILESYSTEM:
		return smb2_ioctl_network_fs(in_ctl_code, ev, req, state);
		break;
	default:
		if (IS_IPC(smbreq->conn)) {
			tevent_req_nterror(req, NT_STATUS_FS_DRIVER_REQUIRED);
		} else {
			tevent_req_nterror(req, NT_STATUS_INVALID_DEVICE_REQUEST);
		}

		return tevent_req_post(req, ev);
		break;
	}

	tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
	return tevent_req_post(req, ev);
}

int x_smb2_process_IOCTL(x_smbdconn_t *smbdconn, x_msg_t *msg,
		const uint8_t *in_buf, size_t in_len)
{
	if (in_len < 0x40 + X_SMB2_IOCTL_BODY_LEN + 1) {
		return x_smb2_reply_error(smbdconn, msg, nullptr, NT_STATUS_INVALID_PARAMETER);
	}

	const uint8_t *inhdr = in_buf;
	const uint8_t *inbody = in_buf + 0x40;

	uint64_t in_session_id = BVAL(inhdr, SMB2_HDR_SESSION_ID);
	if (in_session_id == 0) {
		return x_smb2_reply_error(smbdconn, msg, nullptr, NT_STATUS_USER_SESSION_DELETED);
	}
	
	x_ref_t<x_smbdsess_t> smbdsess{x_smbdsess_find(in_session_id, smbdconn)};
	if (smbdsess == nullptr) {
		return x_smb2_reply_error(smbdconn, msg, nullptr, NT_STATUS_USER_SESSION_DELETED);
	}
	if (smbdsess->state != x_smbdsess_t::S_ACTIVE) {
		return x_smb2_reply_error(smbdconn, msg, smbdsess, NT_STATUS_INVALID_PARAMETER);
	}
	/* TODO signing/encryption */

	uint32_t in_ctl_code = IVAL(inbody, 0x04);
	uint64_t in_file_id_persistent   = BVAL(inbody, 0x08);
	uint64_t in_file_id_volatile     = BVAL(inbody, 0x10);
	uint32_t in_input_offset         = IVAL(inbody, 0x18);
	uint32_t in_input_length         = IVAL(inbody, 0x1C);
	uint32_t in_max_input_length     = IVAL(inbody, 0x20);
	uint32_t in_output_offset        = IVAL(inbody, 0x24);
	uint32_t in_output_length        = IVAL(inbody, 0x28);
	uint32_t in_max_output_length    = IVAL(inbody, 0x2C);
	uint32_t in_flags                = IVAL(inbody, 0x30);

	min_buffer_offset = SMB2_HDR_BODY + SMBD_SMB2_IN_BODY_LEN(req);
	max_buffer_offset = min_buffer_offset + SMBD_SMB2_IN_DYN_LEN(req);
	min_output_offset = min_buffer_offset;

	/*
	 * InputOffset (4 bytes): The offset, in bytes, from the beginning of
	 * the SMB2 header to the input data buffer. If no input data is
	 * required for the FSCTL/IOCTL command being issued, the client SHOULD
	 * set this value to 0.<49>
	 * <49> If no input data is required for the FSCTL/IOCTL command being
	 * issued, Windows-based clients set this field to any value.
	 */
	allowed_length_in = 0;
	if ((in_input_offset > 0) && (in_input_length > 0)) {
		if (!check_input_range(in_input_offset, in_input_length,
					0x40 + X_SMB2_IOCTL_BODY_LEN, in_len)) {
			return x_smb2_reply_error(smbdconn, msg, smbdsess, NT_STATUS_INVALID_PARAMETER);
		}
	}

	if (in_output_offset > 0) {
		if (!check_output_range(in_output_offset, in_output_length,
					0x40 + X_SMB2_IOCTL_BODY_LEN, in_len)) {
			return x_smb2_reply_error(smbdconn, msg, smbdsess, NT_STATUS_INVALID_PARAMETER);
		}
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
	/*
	 * If the Flags field of the request is not SMB2_0_IOCTL_IS_FSCTL the
	 * server MUST fail the request with STATUS_NOT_SUPPORTED.
	 */
	if (in_flags != SMB2_IOCTL_FLAG_IS_FSCTL) {
		return x_smb2_reply_error(smbdconn, msg, smbdsess, NT_STATUS_NOT_SUPPORTED);
	}

	switch (in_ctl_code) {
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
		if (in_file_id_persistent != UINT64_MAX ||
		    in_file_id_volatile != UINT64_MAX) {
			return smbd_smb2_request_error(req,
				NT_STATUS_INVALID_PARAMETER);
		}
		break;
	default:
		X_TODO;
#if 0
		in_fsp = file_fsp_smb2(req, in_file_id_persistent,
				       in_file_id_volatile);
		if (in_fsp == NULL) {
			return smbd_smb2_request_error(req, NT_STATUS_FILE_CLOSED);
		}
#endif
		break;
	}

	switch (in_ctl_code & IOCTL_DEV_TYPE_MASK) {
	case FSCTL_DFS:
		return smb2_ioctl_dfs(in_ctl_code, ev, req, state);
		break;
	case FSCTL_FILESYSTEM:
		return smb2_ioctl_filesys(in_ctl_code, ev, req, state);
		break;
	case FSCTL_NAMED_PIPE:
		return smb2_ioctl_named_pipe(in_ctl_code, ev, req, state);
		break;
	case FSCTL_NETWORK_FILESYSTEM:
		return smb2_ioctl_network_fs(in_ctl_code, ev, req, state);
		break;
	default:
		if (IS_IPC(smbreq->conn)) {
			tevent_req_nterror(req, NT_STATUS_FS_DRIVER_REQUIRED);
		} else {
			tevent_req_nterror(req, NT_STATUS_INVALID_DEVICE_REQUEST);
		}

		return tevent_req_post(req, ev);
		break;
	}	subreq = smbd_smb2_ioctl_send(req, req->sconn->ev_ctx,
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
}
#endif

