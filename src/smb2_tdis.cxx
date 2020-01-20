
#include "smbd.hxx"
#include "core.hxx"

enum {
	X_SMB2_TDIS_REQU_BODY_LEN = 0x04,
	X_SMB2_TDIS_RESP_BODY_LEN = 0x04,
};

static int x_smb2_reply_tdis(x_smbd_conn_t *smbd_conn,
		x_smbd_sess_t *smbd_sess,
		x_msg_t *msg, NTSTATUS status,
		uint32_t tid)
{
	X_LOG_OP("%ld RESP SUCCESS %x", msg->mid, tid);

	uint8_t *outbuf = new uint8_t[8 + 0x40 + X_SMB2_TDIS_RESP_BODY_LEN];
	uint8_t *outhdr = outbuf + 8;
	uint8_t *outbody = outhdr + 0x40;

	SSVAL(outbody, 0x00, X_SMB2_TDIS_RESP_BODY_LEN);
	SSVAL(outbody, 0x02, 0);

	//smbd_smb2_request_setup_out
	memset(outhdr, 0, 0x40);
	SIVAL(outhdr, SMB2_HDR_PROTOCOL_ID,     SMB2_MAGIC);
	SSVAL(outhdr, SMB2_HDR_LENGTH,	  SMB2_HDR_BODY);
	SSVAL(outhdr, SMB2_HDR_CREDIT_CHARGE, 1); // TODO
	SIVAL(outhdr, SMB2_HDR_STATUS, NT_STATUS_V(status));
	SIVAL(outhdr, SMB2_HDR_OPCODE, SMB2_OP_TDIS);
	SSVAL(outhdr, SMB2_HDR_CREDIT, 1); // TODO
	SIVAL(outhdr, SMB2_HDR_FLAGS, SMB2_HDR_FLAG_REDIRECT); // TODO
	SIVAL(outhdr, SMB2_HDR_NEXT_COMMAND, 0);
	SBVAL(outhdr, SMB2_HDR_MESSAGE_ID, msg->mid);
	SIVAL(outhdr, SMB2_HDR_TID, tid);
	SBVAL(outhdr, SMB2_HDR_SESSION_ID, smbd_sess->id);

	uint8_t *outnbt = outbuf + 4;
	x_put_be32(outnbt, 0x40 + X_SMB2_TDIS_RESP_BODY_LEN);

	msg->out_buf = outbuf;
	msg->out_off = 4;
	msg->out_len = 4 + 0x40 + X_SMB2_TDIS_RESP_BODY_LEN;

	msg->state = x_msg_t::STATE_COMPLETE;
	x_smbd_conn_reply(smbd_conn, msg, smbd_sess);
	return 0;
}

int x_smb2_process_TDIS(x_smbd_conn_t *smbd_conn, x_msg_t *msg,
		const uint8_t *in_buf, size_t in_len)
{
	if (in_len < 0x40 + X_SMB2_TDIS_REQU_BODY_LEN) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, nullptr, NT_STATUS_INVALID_PARAMETER);
	}

	const uint8_t *inhdr = in_buf;

	uint64_t in_session_id = BVAL(inhdr, SMB2_HDR_SESSION_ID);
	uint32_t in_tid = IVAL(inhdr, SMB2_HDR_TID);

	X_LOG_OP("%ld TDIS 0x%lx, 0x%x", msg->mid, in_session_id, in_tid);

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

	auto it = smbd_sess->tcon_table.find(in_tid);
	if (it == smbd_sess->tcon_table.end()) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, NT_STATUS_NETWORK_NAME_DELETED);
	}
	smbd_sess->tcon_table.erase(it);

	return x_smb2_reply_tdis(smbd_conn, smbd_sess, msg, NT_STATUS_OK, in_tid);
}
