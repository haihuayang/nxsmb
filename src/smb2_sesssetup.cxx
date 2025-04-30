#include "smbd.hxx"
#include "smbd_requ.hxx"
#include "misc.hxx"
#include "smbd_ntacl.hxx"
#include "nxfsd_stats.hxx"

enum {
	SESSSETUP_TIMEOUT = 60 * 1000000000l,
};

struct x_smbd_requ_sesssetup_t : x_smbd_requ_t
{
	x_smbd_requ_sesssetup_t(x_smbd_conn_t *smbd_conn,
			x_smbd_requ_state_sesssetup_t &state)
		: x_smbd_requ_t(smbd_conn)
		, state(std::move(state))
	{
	}

	std::tuple<bool, bool, bool> get_properties() const override
	{
		return { false, false, true };
	}

	NTSTATUS cancelled(void *ctx_conn, int reason)
	{
		return NT_STATUS_CANCELLED;
	}

	NTSTATUS process(void *ctx_conn) override;
	NTSTATUS done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status) override;

	x_smbd_requ_state_sesssetup_t state;
};


static void x_smb2_reply_sesssetup(
		x_smbd_requ_t *smbd_requ,
		uint16_t dialect,
		NTSTATUS status,
		const std::vector<uint8_t> &out_security)
{
	auto &out_buf = smbd_requ->get_requ_out_buf();
	out_buf.head = out_buf.tail = x_smb2_bufref_alloc(sizeof(x_smb2_sesssetup_resp_t) +
			out_security.size());
	out_buf.length = out_buf.head->length;

	uint8_t *out_hdr = out_buf.head->get_data();
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

	if (dialect >= X_SMB2_DIALECT_310 && NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		smbd_requ->preauth = x_smbd_chan_get_preauth(smbd_requ->smbd_chan);
	}
#if 0
		x_smbd_chan_t *smbd_chan,
	x_smb2_reply(smbd_conn, smbd_requ, status, out_buf);

	if (dialect >= X_SMB2_DIALECT_310 && NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		x_smbd_chan_update_preauth(smbd_chan, 
				out_hdr, sizeof(x_smb2_header_t) + sizeof(x_smb2_sesssetup_resp_t) + out_security.size());
	}
#endif
}

NTSTATUS x_smbd_requ_sesssetup_t::process(void *ctx_conn)
{
	auto smbd_conn = (x_smbd_conn_t *)ctx_conn;
	bool new_auth = false;
	/* smbd_sess must be valid if smbd_chan is */
	X_ASSERT(!this->smbd_chan || this->smbd_sess);
	const x_smbd_negprot_t &negprot = x_smbd_conn_get_negprot(smbd_conn);

	if (state.in_flags & X_SMB2_SESSION_FLAG_BINDING) {
		if (!this->is_signed()) {
			X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_INVALID_PARAMETER);
		}
		X_ASSERT(this->smbd_sess);

		uint16_t curr_signing_algo = negprot.signing_algo;
		uint16_t sess_signing_algo;
		X_ASSERT(x_smbd_sess_get_signing_key(this->smbd_sess, &sess_signing_algo));
		
		if (sess_signing_algo >= X_SMB2_SIGNING_AES128_GMAC &&
				curr_signing_algo != sess_signing_algo) {
			X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_REQUEST_OUT_OF_SEQUENCE);
		}

		if (curr_signing_algo >= X_SMB2_SIGNING_AES128_GMAC &&
				curr_signing_algo != sess_signing_algo) {
			X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_NOT_SUPPORTED);
		}

		if (negprot.dialect < X_SMB2_DIALECT_300) {
			X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_REQUEST_NOT_ACCEPTED);
		}

		if (x_smbd_sess_get_cryption_algo(this->smbd_sess) != negprot.cryption_algo) {
			X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_INVALID_PARAMETER);
		}

		if (!(x_smbd_conn_get_capabilities(smbd_conn) & X_SMB2_CAP_MULTI_CHANNEL)) {
			X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_REQUEST_NOT_ACCEPTED);
		}

		if (x_smbd_sess_get_dialect(this->smbd_sess) != negprot.dialect) {
			X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_INVALID_PARAMETER);
		}

		if (this->smbd_chan) {
			if (x_smbd_chan_is_active(this->smbd_chan)) {
				/* the chan is already setup */
				X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_REQUEST_NOT_ACCEPTED);
			}
		} else {
			/* TODO does it allow previous session in session binding */
			this->smbd_chan = x_smbd_chan_create(this->smbd_sess, smbd_conn);
			if (!this->smbd_chan) {
				X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_INSUFFICIENT_RESOURCES);
			}
			X_SMBD_COUNTER_INC(smbd_sess_bind, 1);
			new_auth = true;
		}
	} else if (!this->smbd_sess) {
		this->smbd_sess = x_smbd_sess_create(smbd_conn);
		if (!this->smbd_sess) {
			X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_INSUFFICIENT_RESOURCES);
		}
		this->smbd_chan = x_smbd_chan_create(this->smbd_sess, smbd_conn);
		if (!this->smbd_chan) {
			X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_INSUFFICIENT_RESOURCES);
		}
		new_auth = true;
	} else if (!this->smbd_chan) {
		x_ref_dec(this->smbd_sess);
		this->smbd_sess = nullptr;
		X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_USER_SESSION_DELETED);
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

	auto in_hdr = requ_in_buf.get_data();
	auto preauth = x_smbd_chan_get_preauth(this->smbd_chan);
	if (preauth) {
		preauth->update(in_hdr, requ_in_buf.length);
	}

	std::vector<uint8_t> out_security;
	state.in_security_mode = x_convert<uint8_t>(state.in_security_mode | negprot.server_security_mode);
	return x_smbd_chan_update_auth(this->smbd_chan, this,
			&state, in_hdr + state.in_security_offset, state.in_security_length,
			new_auth);
}

static void smb2_sesssetup_done(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_sesssetup_t *requ,
		uint16_t dialect, NTSTATUS status,
		x_smbd_requ_state_sesssetup_t &state)
{
	X_LOG(SMB, DBG, "smbd_chan=%p, smbd_requ=%p, status=0x%x", requ->smbd_chan, requ, NT_STATUS_V(status));
	if (status == NT_STATUS_MORE_PROCESSING_REQUIRED) {
		x_smb2_reply_sesssetup(requ, dialect, status, state.out_security);
	} else if (status.ok()) {
		/* TODO (state->session->global->session_wire_id != state->in_previous_session_id)
		 */
		if (state.in_previous_session != 0) {
			x_smbd_sess_close_previous(requ->smbd_sess,
					state.in_previous_session);
		}
		x_smb2_reply_sesssetup(requ, dialect, status, state.out_security);
	} else {
		if (!(state.in_flags & X_SMB2_SESSION_FLAG_BINDING) && requ->smbd_sess) {
			x_smbd_sess_logoff(requ->smbd_sess);
		}
	}
}

NTSTATUS x_smbd_requ_sesssetup_t::done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status)
{
	smb2_sesssetup_done(smbd_conn, this,
			x_smbd_conn_get_dialect(smbd_conn),
			status, state);
	return status;
}

NTSTATUS x_smb2_parse_SESSSETUP(x_smbd_conn_t *smbd_conn, x_smbd_requ_t **p_smbd_requ,
		x_in_buf_t &in_buf)
{
	auto in_smb2_hdr = (const x_smb2_header_t *)(in_buf.get_data());

	if (in_buf.length < sizeof(x_smb2_header_t) + sizeof(x_smb2_sesssetup_requ_t) + 1) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}

	auto in_body = (x_smb2_sesssetup_requ_t *)(in_smb2_hdr + 1);

	x_smbd_requ_state_sesssetup_t state;
	state.in_security_offset = X_LE2H16(in_body->security_buffer_offset);
	state.in_security_length = X_LE2H16(in_body->security_buffer_length);

	if (!x_check_range<uint32_t>(state.in_security_offset, state.in_security_length,
				sizeof(x_smb2_header_t) + sizeof(x_smb2_sesssetup_requ_t),
				in_buf.length)) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}
	
	state.in_flags = in_body->flags;
	state.in_security_mode = in_body->security_mode;
	state.in_previous_session = X_LE2H64(in_body->previous_session);

	auto smbd_requ = new x_smbd_requ_sesssetup_t(smbd_conn,
			state);
	*p_smbd_requ = smbd_requ;
	return NT_STATUS_OK;
}

