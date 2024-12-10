
#include "smbd_open.hxx"
#include "smbd_lease.hxx"

static void decode_in_lease_break(x_smbd_requ_state_lease_break_t &state,
		const x_smb2_lease_break_t *in_lease_break)
{
	state.in_flags = X_LE2H32(in_lease_break->flags);
	state.in_key = {in_lease_break->key[0], in_lease_break->key[1]};
	state.in_state = X_LE2H32(in_lease_break->state);
	uint64_t duration_low = X_LE2H32(in_lease_break->duration_low);
	uint64_t duration_high = X_LE2H32(in_lease_break->duration_high);
	state.in_duration = (duration_high << 32 | duration_low);
}
	
static void encode_lease_break_resp(const x_smbd_requ_state_lease_break_t &state,
		uint8_t *out_hdr)
{
	x_smb2_lease_break_t *resp = (x_smb2_lease_break_t *)(out_hdr + sizeof(x_smb2_header_t));
	resp->struct_size = X_H2LE16(sizeof(x_smb2_lease_break_t));
	resp->reserved0 = 0;
	resp->flags = X_H2LE32(state.in_flags);
	resp->key[0] = state.in_key.data[0];
	resp->key[1] = state.in_key.data[1];
	resp->state = X_H2LE32(state.in_state); // TODO should have out_state
	resp->duration_low = 0;
	resp->duration_high = 0;
}

static void decode_in_oplock_break(x_smbd_requ_state_oplock_break_t &state,
		const x_smb2_oplock_break_t *in_oplock_break)
{
	state.in_oplock_level = X_LE2H8(in_oplock_break->oplock_level);
	state.in_file_id_persistent = X_LE2H64(in_oplock_break->file_id_persistent);
	state.in_file_id_volatile = X_LE2H64(in_oplock_break->file_id_volatile);
}

static void encode_oplock_break_resp(const x_smbd_requ_state_oplock_break_t &state,
		uint8_t *out_hdr)
{
	x_smb2_oplock_break_t *resp = (x_smb2_oplock_break_t *)(out_hdr + sizeof(x_smb2_header_t));
	resp->struct_size = X_H2LE16(sizeof(x_smb2_oplock_break_t));
	resp->oplock_level = state.out_oplock_level;
	resp->reserved0 = 0;
	resp->reserved1 = 0;
	resp->file_id_persistent = X_H2LE64(state.in_file_id_persistent);
	resp->file_id_volatile = X_H2LE64(state.in_file_id_volatile);
}

static void x_smb2_reply_oplock_break(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		const x_smbd_requ_state_oplock_break_t &state)
{
	x_out_buf_t out_buf;
	out_buf.head = out_buf.tail = x_smb2_bufref_alloc(sizeof(x_smb2_oplock_break_t));
	out_buf.length = out_buf.head->length;

	uint8_t *out_hdr = out_buf.head->get_data();
	encode_oplock_break_resp(state, out_hdr);
	x_smb2_reply(smbd_conn, smbd_requ, NT_STATUS_OK, out_buf);
}

static NTSTATUS x_smb2_process_oplock_break(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		const x_smb2_oplock_break_t *in_oplock_break)
{
	auto state = std::make_unique<x_smbd_requ_state_oplock_break_t>();
	decode_in_oplock_break(*state, in_oplock_break);

	X_SMBD_REQU_LOG(OP, smbd_requ,  " open=0x%lx,0x%lx %d",
			state->in_file_id_persistent, state->in_file_id_volatile,
			state->in_oplock_level);

	NTSTATUS status = x_smbd_requ_init_open(smbd_requ,
			state->in_file_id_persistent,
			state->in_file_id_volatile,
			false);
	if (!NT_STATUS_IS_OK(status)) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, status);
	}

	status = x_smbd_break_oplock(smbd_requ->smbd_open,
			smbd_requ, *state);

	X_SMBD_REQU_LOG(OP, smbd_requ,  " %s", x_ntstatus_str(status));

	if (NT_STATUS_IS_OK(status)) {
		x_smb2_reply_oplock_break(smbd_conn, smbd_requ, *state);
	}

	return status;
}

static void x_smb2_reply_lease_break(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		const x_smbd_requ_state_lease_break_t &state)
{
	x_out_buf_t out_buf;
	out_buf.head = out_buf.tail = x_smb2_bufref_alloc(sizeof(x_smb2_lease_break_t));
	out_buf.length = out_buf.head->length;

	uint8_t *out_hdr = out_buf.head->get_data();
	encode_lease_break_resp(state, out_hdr);
	x_smb2_reply(smbd_conn, smbd_requ, NT_STATUS_OK, out_buf);
	if (state.more_break) {
		x_smb2_send_lease_break(smbd_conn, smbd_requ->smbd_sess,
				&state.in_key,
				x_convert<uint8_t>(state.more_break_from),
				x_convert<uint8_t>(state.more_break_to),
				state.more_epoch, state.more_flags);
	}
}

static NTSTATUS x_smb2_process_lease_break(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		const x_smb2_lease_break_t *in_lease_break)
{
	x_smbd_requ_state_lease_break_t state{x_smbd_conn_get_client_guid(smbd_conn)};
	decode_in_lease_break(state, in_lease_break);

	X_SMBD_REQU_LOG(OP, smbd_requ,  " lease=%s",
			x_tostr(state.in_key).c_str());

	NTSTATUS status = x_smbd_lease_process_break(state);

	X_SMBD_REQU_LOG(OP, smbd_requ,  " %s", x_ntstatus_str(status));

	if (NT_STATUS_IS_OK(status)) {
		x_smb2_reply_lease_break(smbd_conn, smbd_requ, state);
	}

	return status;
}

NTSTATUS x_smb2_process_break(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	auto [ in_hdr, in_requ_len ] = smbd_requ->get_in_data();
	if (in_requ_len < sizeof(x_smb2_header_t) + sizeof(x_smb2_oplock_break_t)) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	if (smbd_requ->smbd_chan == nullptr) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_USER_SESSION_DELETED);
	}
#if 0
	if (!smbd_requ->smbd_sess) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_USER_SESSION_DELETED);
	}

	if (smbd_requ->smbd_sess->state != x_smbd_sess_t::S_ACTIVE) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}
#endif
	const x_smb2_oplock_break_t *in_break = (const x_smb2_oplock_break_t *)(in_hdr + sizeof(x_smb2_header_t));
	if (in_break->struct_size >= sizeof(x_smb2_lease_break_t)) {
		if (in_requ_len < sizeof(x_smb2_header_t) + sizeof(x_smb2_lease_break_t)) {
			X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
		}
		return x_smb2_process_lease_break(smbd_conn, smbd_requ,
				(const x_smb2_lease_break_t *)in_break);
	} else {
		if (in_requ_len < sizeof(x_smb2_header_t) + sizeof(x_smb2_oplock_break_t)) {
			X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
		}
		return x_smb2_process_oplock_break(smbd_conn, smbd_requ,
				in_break);
	}
}

void x_smb2_send_lease_break(x_smbd_conn_t *smbd_conn, x_smbd_sess_t *smbd_sess,
		const x_smb2_lease_key_t *lease_key,
		uint8_t current_state, uint8_t new_state,
		uint16_t new_epoch,
		uint32_t flags)
{
	x_bufref_t *bufref = x_smb2_bufref_alloc(sizeof(x_smb2_lease_break_noti_t));
	uint8_t *out_hdr = bufref->get_data();

	x_smb2_lease_break_noti_t *noti = (x_smb2_lease_break_noti_t *)(out_hdr + sizeof(x_smb2_header_t));
	noti->struct_size = X_H2LE16(sizeof(x_smb2_lease_break_noti_t));
	noti->new_epoch = X_H2LE16(new_epoch);
	// noti->flags = X_H2LE32(SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED); // TODO
	noti->flags = X_H2LE32(flags);
	noti->key[0] = lease_key->data[0];
	noti->key[1] = lease_key->data[1];
	noti->current_state = X_H2LE32(current_state);
	noti->new_state = X_H2LE32(new_state);
	noti->reason = 0;
	noti->access_mask_hint = 0;
	noti->access_mask_hint = 0;
	noti->share_mask_hint = 0;

	x_smbd_conn_send_unsolicited(smbd_conn, nullptr, bufref, X_SMB2_OP_BREAK);
}

void x_smb2_send_oplock_break(x_smbd_conn_t *smbd_conn, x_smbd_sess_t *smbd_sess,
		uint64_t id_persistent, uint64_t id_volatile, uint8_t oplock_level)
{
	x_bufref_t *bufref = x_smb2_bufref_alloc(sizeof(x_smb2_oplock_break_t));
	uint8_t *out_hdr = bufref->get_data();

	x_smb2_oplock_break_t *noti = (x_smb2_oplock_break_t *)(out_hdr + sizeof(x_smb2_header_t));
	noti->struct_size = X_H2LE16(sizeof(x_smb2_oplock_break_t));
	noti->oplock_level = X_H2LE16(oplock_level);
	noti->reserved0 = 0;
	noti->reserved1 = 0;
	noti->file_id_persistent = X_H2LE64(id_persistent);
	noti->file_id_volatile = X_H2LE64(id_volatile);

	x_smbd_conn_send_unsolicited(smbd_conn, nullptr, bufref, X_SMB2_OP_BREAK);
}

#if 0
	auto state = std::make_unique<x_smb2_state_create_t>();
	if (!decode_in_create(*state, in_hdr, smbd_requ->in_requ_len)) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	X_LOG(SMB, OP, "%ld BREAK '%s'", smbd_requ->in_mid, x_convert_utf16_to_utf8(state->in_name).c_str());
	X_TODO;
	return NT_STATUS_NOT_SUPPORTED;
#endif
