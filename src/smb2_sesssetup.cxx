#include "smbd.hxx"
#include "core.hxx"

enum {
	X_SMB2_SESSSETUP_BODY_LEN = 0x18,
};

enum {
	SESSSETUP_TIMEOUT = 60 * 1000000000l,
};

static int x_smb2_reply_sesssetup(x_smbdconn_t *smbdconn,
		x_smbdsess_t *smbdsess,
		x_msg_t *msg, NTSTATUS status,
		const std::vector<uint8_t> &out_security)
{
#if 0
	const x_smbsrv_t *smbsrv = smbdconn->smbsrv;
	const x_smbconf_t &conf = smbdconn->get_conf();
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
	SBVAL(outhdr, SMB2_HDR_SESSION_ID, smbdsess->id);

	uint8_t *outnbt = outbuf + 4;
	x_put_be32(outnbt, 0x40 + 0x8 + out_security.size());

	msg->out_buf = outbuf;
	msg->out_off = 4;
	msg->out_len = 4 + 0x40 + 0x8 + out_security.size();

	msg->state = x_msg_t::STATE_COMPLETE;
	x_smbdconn_reply(smbdconn, msg);
	return 0;
}

static inline NTSTATUS x_smbdsess_update_auth(x_smbdsess_t *smbdsess, const uint8_t *inbuf, size_t inlen,
		std::vector<uint8_t> &outbuf)
{
	return smbdsess->auth->update(inbuf, inlen, outbuf, smbdsess);
}

static void smbdsess_auth_updated(x_smbdsess_t *smbdsess, NTSTATUS status,
		std::vector<uint8_t> &out_security)
{
	x_msg_t *msg = smbdsess->authmsg;
	smbdsess->authmsg = nullptr;
	x_smbdconn_t *smbdconn = smbdsess->smbdconn;
	if (NT_STATUS_IS_OK(status)) {
		smbdsess->state = x_smbdsess_t::S_ACTIVE;
		smbdconn->session_list.push_back(smbdsess);
		/* TODO set user token ... */
		x_smb2_reply_sesssetup(smbdconn, smbdsess, msg, status, out_security);
	} else if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		smbdsess->state = x_smbdsess_t::S_WAIT_INPUT;
		smbdsess->timeout = x_tick_add(tick_now, SESSSETUP_TIMEOUT);
		smbdconn->session_wait_input_list.push_back(smbdsess);
		x_smb2_reply_sesssetup(smbdconn, smbdsess, msg, status, out_security);
	} else if (NT_STATUS_EQUAL(status, X_NT_STATUS_INTERNAL_BLOCKED)) {
		smbdsess->state = x_smbdsess_t::S_BLOCKED;
		smbdsess->incref();
		smbdconn->session_list.push_back(smbdsess);
	} else {
		x_smb2_reply_error(smbdconn, msg, status);
	}
}

int x_smb2_process_SESSSETUP(x_smbdconn_t *smbdconn, x_msg_t *msg,
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
		return x_smb2_reply_error(smbdconn, msg, NT_STATUS_INVALID_PARAMETER);
	}
	
	if (in_security_offset + in_security_length > in_len) {
		return x_smb2_reply_error(smbdconn, msg, NT_STATUS_INVALID_PARAMETER);
	}

	if (in_flags & SMB2_SESSION_FLAG_BINDING) {
		if (smbdconn->dialect < SMB2_DIALECT_REVISION_222) {
			return x_smb2_reply_error(smbdconn, msg, NT_STATUS_REQUEST_NOT_ACCEPTED);
		}
		return x_smb2_reply_error(smbdconn, msg, NT_STATUS_NOT_SUPPORTED);
	}

	x_smbdsess_t *smbdsess;
	if (in_session_id == 0) {
		smbdsess = x_smbdsess_create(smbdconn);
		smbdsess->auth = x_smbd_create_auth(smbdconn->smbd);
	} else {
		smbdsess = x_smbdsess_find(in_session_id, smbdconn);
		if (smbdsess == nullptr) {
			return x_smb2_reply_error(smbdconn, msg, NT_STATUS_USER_SESSION_DELETED);
		}
		if (smbdsess->state != x_smbdsess_t::S_WAIT_INPUT) {
			smbdsess->decref();
			/* TODO just drop the message, should we reply something for this unexpected message */
			return x_smb2_reply_error(smbdconn, msg, NT_STATUS_INVALID_PARAMETER);
		}
		smbdsess->decref();
		smbdconn->session_wait_input_list.remove(smbdsess);
	}

	X_ASSERT(smbdsess->authmsg == nullptr);
	smbdsess->authmsg = msg;
	std::vector<uint8_t> out_security;
	NTSTATUS status = x_smbdsess_update_auth(smbdsess, in_buf + in_security_offset, in_security_length, out_security);
	smbdsess_auth_updated(smbdsess, status, out_security);
	smbdsess->decref();
	return 0;
}

struct smbdsess_auth_updated_evt_t
{
	x_fdevt_user_t base;
	x_smbdsess_t *smbdsess;
	NTSTATUS status;
	std::vector<uint8_t> out_security;
};

static void smbdsess_auth_updated_func(x_smbdconn_t *smbdconn, x_fdevt_user_t *fdevt_user)
{
	smbdsess_auth_updated_evt_t *evt = X_CONTAINER_OF(fdevt_user, smbdsess_auth_updated_evt_t, base);

	X_ASSERT(!NT_STATUS_EQUAL(evt->status, X_NT_STATUS_INTERNAL_BLOCKED));
	x_smbdsess_t *smbdsess = evt->smbdsess;

	if (smbdsess->state == x_smbdsess_t::S_BLOCKED) {
		smbdconn->session_list.remove(smbdsess);
		smbdsess_auth_updated(smbdsess, evt->status, evt->out_security);
		smbdsess->decref();
	}

	smbdsess->decref();
	delete evt;
}

void x_smbdsess_auth_updated(x_smbdsess_t *smbdsess, NTSTATUS status, std::vector<uint8_t> &out_security)
{
	smbdsess->incref();
	smbdsess_auth_updated_evt_t *updated_evt = new smbdsess_auth_updated_evt_t;
	updated_evt->base.func = smbdsess_auth_updated_func;
	updated_evt->smbdsess = smbdsess;
	updated_evt->status = status;
	std::swap(updated_evt->out_security, out_security);
	x_smbdconn_post_user(smbdsess->smbdconn, &updated_evt->base);
}

