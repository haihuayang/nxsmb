
#include "smbd.hxx"
#include "core.hxx"

namespace {
enum {
	X_SMB2_READ_REQU_BODY_LEN = 0x30,
	X_SMB2_READ_RESP_BODY_LEN = 0x10,
};
}

static int x_smb2_reply_read(x_smbd_conn_t *smbd_conn,
		x_smbd_sess_t *smbd_sess,
		x_msg_t *msg, uint32_t tid,
		x_smb2_resp_read_t &resp,
		const std::vector<uint8_t> &output)
{
	X_LOG_OP("%ld RESP SUCCESS", msg->mid);

	uint8_t *outbuf = new uint8_t[8 + 0x40 + X_SMB2_READ_RESP_BODY_LEN + output.size()];
	uint8_t *outhdr = outbuf + 8;
	uint8_t *outbody = outhdr + 0x40;

	memcpy(outbody, &resp, sizeof(resp));
	memcpy(outbody + X_SMB2_READ_RESP_BODY_LEN, output.data(), output.size());
	x_smbd_conn_reply(smbd_conn, msg, smbd_sess, outbuf, tid, NT_STATUS_OK,
			X_SMB2_READ_RESP_BODY_LEN + output.size());
	return 0;
}

int x_smb2_process_READ(x_smbd_conn_t *smbd_conn, x_msg_t *msg,
		const uint8_t *in_buf, size_t in_len)
{
	if (in_len < 0x40 + X_SMB2_READ_REQU_BODY_LEN) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, nullptr, 0, NT_STATUS_INVALID_PARAMETER);
	}

	const uint8_t *inhdr = in_buf;
	const uint8_t *inbody = in_buf + 0x40;

	uint64_t in_session_id = BVAL(inhdr, SMB2_HDR_SESSION_ID);
	uint32_t in_tid = IVAL(inhdr, SMB2_HDR_TID);
	if (in_session_id == 0) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, nullptr, in_tid, NT_STATUS_USER_SESSION_DELETED);
	}
	x_auto_ref_t<x_smbd_sess_t> smbd_sess{x_smbd_sess_find(in_session_id, smbd_conn)};
	if (smbd_sess == nullptr) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, nullptr, in_tid, NT_STATUS_USER_SESSION_DELETED);
	}
	if (smbd_sess->state != x_smbd_sess_t::S_ACTIVE) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, in_tid, NT_STATUS_INVALID_PARAMETER);
	}
	/* TODO signing/encryption */

	auto it = smbd_sess->tcon_table.find(in_tid);
	if (it == smbd_sess->tcon_table.end()) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, in_tid, NT_STATUS_NETWORK_NAME_DELETED);
	}
	std::shared_ptr<x_smbd_tcon_t> smbd_tcon = it->second;

	/* TODO only for little-endian */
	x_smb2_requ_read_t requ_read;
	memcpy(&requ_read, inbody, X_SMB2_READ_REQU_BODY_LEN);

	X_LOG_OP("%ld READ %x,%lx %lx,%lx", msg->mid, 
			requ_read.length, requ_read.offset,
			requ_read.file_id_persistent, requ_read.file_id_volatile);

	// TODO smbd_smb2_request_verify_creditcharge
	x_auto_ref_t<x_smbd_open_t> smbd_open{x_smbd_open_find(requ_read.file_id_volatile,
			smbd_tcon.get())};
	if (!smbd_open) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, in_tid, NT_STATUS_FILE_CLOSED);
	}

	std::vector<uint8_t> output;
	NTSTATUS status = x_smbd_open_op_read(smbd_conn, smbd_open, requ_read, output);
	if (NT_STATUS_IS_OK(status)) {
		x_smb2_resp_read_t resp_read;
		resp_read.struct_size = 0x11;
		resp_read.data_offset = 0x50;
		resp_read.data_length = output.size();
		resp_read.read_remaining = 0;
		resp_read.reserved = 0;
		return x_smb2_reply_read(smbd_conn, smbd_sess, msg, in_tid,
				resp_read, output);
	} else {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, in_tid, status);
	}
}
