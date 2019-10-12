#include "smbd.hxx"

enum {
	X_SMB2_SESSSETUP_BODY_LEN = 0x18,
};

static x_smbsess_ptr_t x_smbconn_lookup_session(const x_smbconn_t *smbconn,
		uint64_t session_id)
{
	for (auto &sess: smbconn->sessions) {
		if (sess->id == session_id) {
			return sess;
		}
	}
	return nullptr;
}

static uint64_t g_sess_id = 0x1234;
static x_smbsess_ptr_t x_smbconn_create_session(x_smbconn_t *smbconn)
{
	x_smbsess_ptr_t sess = std::make_shared<x_smbsess_t>();
	sess->id = g_sess_id++;
	sess->gensec.reset(x_smbsrv_create_gensec(smbconn->smbsrv));
	smbconn->sessions.push_back(sess);
	return sess;
}

static int x_smb2_reply_sesssetup(x_smbconn_t *smbconn, x_smbsess_t *sess,
		x_msg_t *msg, NTSTATUS status,
		const std::vector<uint8_t> &out_security)
{
#if 0
	const x_smbsrv_t *smbsrv = smbconn->smbsrv;
	const x_smbconf_t &conf = smbconn->get_conf();
	nttime_t now = nttime_current();
#endif
	uint8_t *outbuf = new uint8_t[8 + 0x40 + 0x8 + out_security.size()];
	uint8_t *outhdr = outbuf + 8;
	uint8_t *outbody = outhdr + 0x40;

	uint16_t out_session_flags = 0; // TODO
	uint16_t out_security_offset = SMB2_HDR_BODY + 0x08;
	SSVAL(outbody, 0x00, 0x08 + 1);
	SSVAL(outbody, 0x02, out_session_flags);
	SSVAL(outbody, 0x04, out_security_offset);
	SSVAL(outbody, 0x06, out_security.size());

	memcpy(outbody + 0x08, out_security.data(), out_security.size());

	//smbd_smb2_request_setup_out
	memset(outhdr, 0, 0x40);
	SIVAL(outhdr, SMB2_HDR_PROTOCOL_ID,     SMB2_MAGIC);
	SSVAL(outhdr, SMB2_HDR_LENGTH,          SMB2_HDR_BODY);
	SSVAL(outhdr, SMB2_HDR_CREDIT_CHARGE, 1); // TODO
	SIVAL(outhdr, SMB2_HDR_STATUS, NT_STATUS_V(status));
	SIVAL(outhdr, SMB2_HDR_OPCODE, SMB2_OP_SESSSETUP);
	SSVAL(outhdr, SMB2_HDR_CREDIT, 1); // TODO
	SIVAL(outhdr, SMB2_HDR_FLAGS, SMB2_HDR_FLAG_REDIRECT); // TODO
	SIVAL(outhdr, SMB2_HDR_NEXT_COMMAND, 0);
	SBVAL(outhdr, SMB2_HDR_MESSAGE_ID, msg->mid);
	// SIVAL(outhdr, SMB2_HDR_PID, );
	SBVAL(outhdr, SMB2_HDR_SESSION_ID, sess->id);

	uint8_t *outnbt = outbuf + 4;
	put_be32(outnbt, 0x40 + 0x8 + out_security.size());

	msg->out_buf = outbuf;
	msg->out_off = 4;
	msg->out_len = 4 + 0x40 + 0x8 + out_security.size();

	msg->state = x_msg_t::STATE_COMPLETE;
	x_smbconn_reply(smbconn, msg);
	return 0;
}

int x_smb2_process_SESSSETUP(x_smbconn_t *smbconn, x_msg_t *msg,
		const uint8_t *in_buf, size_t in_len)
{
	// x_smb2_verify_size(msg, X_SMB2_NEGPROT_BODY_LEN);
	if (in_len < 0x40 + 0x19) {
		return -EBADMSG;
	}

	const uint8_t *inhdr = in_buf;
	const uint8_t *inbody = in_buf + 0x40;
	uint64_t in_session_id = BVAL(inhdr, SMB2_HDR_SESSION_ID);
	uint8_t in_flags = CVAL(inbody, 0x02);
	// TODO uint8_t in_security_mode = CVAL(inbody, 0x03);
	uint16_t in_security_offset = SVAL(inbody, 0x0C);
	uint16_t in_security_length = SVAL(inbody, 0x0E);
	// TODO uint64_t in_previous_session_id = BVAL(inbody, 0x10);

	if (in_security_offset != (SMB2_HDR_BODY + X_SMB2_SESSSETUP_BODY_LEN)) {
		return x_smb2_reply_error(smbconn, msg, NT_STATUS_INVALID_PARAMETER);
	}
	
	if (in_security_offset + in_security_length > in_len) {
		return x_smb2_reply_error(smbconn, msg, NT_STATUS_INVALID_PARAMETER);
	}

	if (in_flags & SMB2_SESSION_FLAG_BINDING) {
		if (smbconn->dialect < SMB2_DIALECT_REVISION_222) {
			return x_smb2_reply_error(smbconn, msg, NT_STATUS_REQUEST_NOT_ACCEPTED);
		}
		return x_smb2_reply_error(smbconn, msg, NT_STATUS_NOT_SUPPORTED);
	}

	x_smbsess_ptr_t sess;
	if (in_session_id == 0) {
		sess = x_smbconn_create_session(smbconn);
	} else {
		sess = x_smbconn_lookup_session(smbconn, in_session_id);
		if (sess == nullptr) {
			return x_smb2_reply_error(smbconn, msg, NT_STATUS_USER_SESSION_DELETED);
		}
	}

	std::vector<uint8_t> out_security;
	NTSTATUS status = sess->gensec->update(in_buf + in_security_offset, in_security_length, out_security);
	if (NT_STATUS_IS_OK(status)) {
	} else if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		return x_smb2_reply_sesssetup(smbconn, sess.get(), msg, status, out_security);
//	} else if (NT_STATUS_EQUAL(status, INTERNAL_BLOCKING)) {
//		return;
	} else {
		return x_smb2_reply_error(smbconn, msg, status);
	}
}


