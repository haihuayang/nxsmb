#include "smbd.hxx"
#include "smbd_requ.hxx"
#include "misc.hxx"
#include "smbd_ntacl.hxx"
#include "smbd_stats.hxx"

enum {
	SESSSETUP_TIMEOUT = 60 * 1000000000l,
};

struct x_smb2_sesssetup_requ_t
{
	uint16_t struct_size;
	uint8_t flags;
	uint8_t security_mode;
	uint32_t capabilities;
	uint32_t channel;
	uint16_t security_buffer_offset;
	uint16_t security_buffer_length;
	uint64_t previous_session;
};

struct x_smb2_sesssetup_resp_t
{
	uint16_t struct_size;
	uint16_t session_flags;
	uint16_t security_buffer_offset;
	uint16_t security_buffer_length;
};


static void x_smb2_reply_sesssetup(x_smbd_conn_t *smbd_conn,
		x_smbd_chan_t *smbd_chan,
		x_smbd_requ_t *smbd_requ,
		uint16_t dialect,
		NTSTATUS status,
		const std::vector<uint8_t> &out_security)
{
	x_bufref_t *bufref = x_smb2_bufref_alloc(sizeof(x_smb2_sesssetup_resp_t) +
			out_security.size());
	uint8_t *out_hdr = bufref->get_data();
	uint8_t *out_body = out_hdr + sizeof(x_smb2_header_t);

	uint16_t out_session_flags = 0; // TODO
	uint16_t out_security_offset = sizeof(x_smb2_header_t) + 0x08;
	x_put_le16(out_body, 0x08 + 1);
	x_put_le16(out_body + 0x02, out_session_flags);
	x_put_le16(out_body + 0x04, out_security_offset);
	x_put_le16(out_body + 0x06, x_convert_assert<uint16_t>(out_security.size()));

	memcpy(out_body + sizeof(x_smb2_sesssetup_resp_t), out_security.data(), out_security.size());

	if (NT_STATUS_IS_OK(status)) {
		smbd_requ->out_hdr_flags |= X_SMB2_HDR_FLAG_SIGNED;
	}

	x_smb2_reply(smbd_conn, smbd_requ, bufref, bufref, status, 
			sizeof(x_smb2_header_t) + sizeof(x_smb2_sesssetup_resp_t) + out_security.size());

	if (dialect >= X_SMB2_DIALECT_310 && NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		x_smbd_chan_update_preauth(smbd_chan, 
				out_hdr, sizeof(x_smb2_header_t) + sizeof(x_smb2_sesssetup_resp_t) + out_security.size());
	}
}

static void smb2_sesssetup_done(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
		uint16_t dialect, NTSTATUS status,
		const x_smbd_requ_state_sesssetup_t &state,
		const std::vector<uint8_t> &out_security)
{
	X_LOG(SMB, DBG, "smbd_chan=%p, smbd_requ=%p, status=0x%x", smbd_requ->smbd_chan, smbd_requ, NT_STATUS_V(status));
	if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		x_smb2_reply_sesssetup(smbd_conn, smbd_requ->smbd_chan, smbd_requ,
				dialect, status, out_security);
	} else if (NT_STATUS_IS_OK(status)) {
		/* TODO (state->session->global->session_wire_id != state->in_previous_session_id)
		 */
		if (state.in_previous_session_id != 0) {
			x_smbd_sess_close_previous(smbd_requ->smbd_sess, state.in_previous_session_id);
		}
		x_smb2_reply_sesssetup(smbd_conn, smbd_requ->smbd_chan, smbd_requ,
				dialect, status, out_security);
	} else {
		if (!(state.in_flags & X_SMB2_SESSION_FLAG_BINDING)) {
			x_smbd_sess_logoff(smbd_requ->smbd_sess);
		}
	}
}

void x_smbd_requ_state_sesssetup_t::async_done(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ, NTSTATUS status)
{
	smb2_sesssetup_done(smbd_conn, smbd_requ,
			x_smbd_conn_get_dialect(smbd_conn),
			status, *this, out_security);
	x_smbd_conn_requ_done(smbd_conn, smbd_requ, status);
}
#if 0
void x_smb2_sesssetup_done(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ, NTSTATUS status,
		const std::vector<uint8_t> &out_security)
{
	auto state = smbd_requ->release_state<x_smbd_requ_state_sesssetup_t>();
	/* async done */
	smb2_sesssetup_done(smbd_conn, smbd_requ,
			x_smbd_conn_get_dialect(smbd_conn),
			status, *state, out_security);
	x_smbd_conn_requ_done(smbd_conn, smbd_requ, status);
}
#endif
NTSTATUS x_smb2_process_sesssetup(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	X_SMBD_REQU_LOG(OP, smbd_requ,  "");

	if (smbd_requ->in_requ_len < sizeof(x_smb2_header_t) + sizeof(x_smb2_sesssetup_requ_t) + 1) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	const uint8_t *in_hdr = smbd_requ->get_in_data();
	x_smb2_sesssetup_requ_t *requ = (x_smb2_sesssetup_requ_t *)(in_hdr + sizeof(x_smb2_header_t));

	uint16_t in_security_offset = X_LE2H16(requ->security_buffer_offset);
	uint16_t in_security_length = X_LE2H16(requ->security_buffer_length);

	if (!x_check_range<uint32_t>(in_security_offset, in_security_length, sizeof(x_smb2_header_t) + sizeof(x_smb2_sesssetup_requ_t), smbd_requ->in_requ_len)) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}
	
	auto state = std::make_unique<x_smbd_requ_state_sesssetup_t>();
	state->in_flags = requ->flags;
	state->in_security_mode = requ->security_mode;
	state->in_previous_session_id = X_LE2H64(requ->previous_session);

	bool new_auth = false;
	/* smbd_sess must be valid if smbd_chan is */
	X_ASSERT(!smbd_requ->smbd_chan || smbd_requ->smbd_sess);
	uint16_t dialect = x_smbd_conn_get_dialect(smbd_conn);

	if (state->in_flags & X_SMB2_SESSION_FLAG_BINDING) {
		if (!smbd_requ->is_signed()) {
			X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
		}
		X_ASSERT(smbd_requ->smbd_sess);

		uint16_t curr_signing_algo = x_smbd_conn_curr_get_signing_algo();
		uint16_t sess_signing_algo;
		X_ASSERT(x_smbd_sess_get_signing_key(smbd_requ->smbd_sess, &sess_signing_algo));
		
		if (sess_signing_algo >= X_SMB2_SIGNING_AES128_GMAC &&
				curr_signing_algo != sess_signing_algo) {
			X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_REQUEST_OUT_OF_SEQUENCE);
		}

		if (curr_signing_algo >= X_SMB2_SIGNING_AES128_GMAC &&
				curr_signing_algo != sess_signing_algo) {
			X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_NOT_SUPPORTED);
		}

		if (dialect < X_SMB2_DIALECT_300) {
			X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_REQUEST_NOT_ACCEPTED);
		}

		if (x_smbd_sess_get_cryption_algo(smbd_requ->smbd_sess) != x_smbd_conn_curr_get_cryption_algo()) {
			X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
		}

		if (!(x_smbd_conn_get_capabilities(smbd_conn) & X_SMB2_CAP_MULTI_CHANNEL)) {
			X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_REQUEST_NOT_ACCEPTED);
		}

		if (x_smbd_sess_get_dialect(smbd_requ->smbd_sess) != x_smbd_conn_curr_dialect()) {
			X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
		}

		if (smbd_requ->smbd_chan) {
			if (x_smbd_chan_is_active(smbd_requ->smbd_chan)) {
				/* the chan is already setup */
				X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_REQUEST_NOT_ACCEPTED);
			}
		} else {
			/* TODO does it allow previous session in session binding */
			smbd_requ->smbd_chan = x_smbd_chan_create(smbd_requ->smbd_sess, smbd_conn);
			if (!smbd_requ->smbd_chan) {
				X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INSUFFICIENT_RESOURCES);
			}
			X_SMBD_COUNTER_INC(sess_bind, 1);
			new_auth = true;
		}
	} else if (!smbd_requ->smbd_sess) {
		smbd_requ->smbd_sess = x_smbd_sess_create();
		if (!smbd_requ->smbd_sess) {
			X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INSUFFICIENT_RESOURCES);
		}
		smbd_requ->smbd_chan = x_smbd_chan_create(smbd_requ->smbd_sess, smbd_conn);
		if (!smbd_requ->smbd_chan) {
			X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INSUFFICIENT_RESOURCES);
		}
		new_auth = true;
	} else if (!smbd_requ->smbd_chan) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_USER_SESSION_DELETED);
	}


#if 0
	if (!smbd_requ->smbd_chan) {
		smbd_requ->smbd_chan = x_smbd_chan_create(smbd_requ->smbd_sess);
		if (
		status = x_smbd_sess_create(&smbd_requ->smbd_sess, &smbd_requ->smbd_chan);
		if (!NT_STATUS_IS_OK(status)) {
		/* TODO too many session */
		smbd_requ->smbd_chan->auth = x_smbd_create_auth();
		smbd_sess->auth_upcall.cbs = &smbd_sess_auth_upcall_cbs;
		if (smbd_conn->dialect >= X_SMB2_DIALECT_310) {
			smbd_sess->preauth = smbd_conn->preauth;
		}

	} else {
		if (smbd_sess->state != x_smbd_sess_t::S_WAIT_INPUT) {
			smbd_sess->decref();
			/* TODO just drop the message, should we reply something for this unexpected message */
			X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
		}
		smbd_sess->decref();
		smbd_conn->session_wait_input_list.remove(smbd_sess);
	}
#endif

	x_smbd_chan_update_preauth(smbd_requ->smbd_chan, in_hdr, smbd_requ->in_requ_len);

	std::vector<uint8_t> out_security;
	NTSTATUS status = x_smbd_chan_update_auth(smbd_requ->smbd_chan, smbd_requ,
			in_hdr + in_security_offset, in_security_length,
			out_security,
			state->in_flags & X_SMB2_SESSION_FLAG_BINDING,
			x_convert<uint8_t>(state->in_security_mode |
				x_smbd_conn_curr_negprot().server_security_mode),
			new_auth);
	if (!NT_STATUS_EQUAL(status, X_NT_STATUS_INTERNAL_BLOCKED)) {
		smb2_sesssetup_done(smbd_conn, smbd_requ, dialect, status,
				*state, out_security);
	} else {
		smbd_requ->save_requ_state(state);
	}
	return status;
}

