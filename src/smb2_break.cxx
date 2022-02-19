
#include "smbd.hxx"

struct x_smb2_in_oplock_break_t
{
	uint16_t struct_size;
	uint8_t oplock_level;
	uint8_t reserved0;
	uint32_t reserved1;
	uint64_t file_id_persistent;
	uint64_t file_id_volatile;
};

struct x_smb2_in_lease_break_t
{
	uint16_t struct_size;
	uint8_t oplock_level;
	uint8_t reserved0;
	uint32_t flags;
	x_smb2_lease_key_t key;
	uint32_t state;
	uint64_t duration; // not 8-byte aligned
}; // TODO pack

static void decode_in_lease_break(x_smb2_state_lease_break_t &state,
		const x_smb2_in_lease_break_t *in_lease_break)
{
	state.in_oplock_level = X_LE2H8(in_lease_break->oplock_level);
	state.in_flags = X_LE2H32(in_lease_break->flags);
	state.in_state = X_LE2H32(in_lease_break->state);
	memcpy(&state.in_key, &in_lease_break->key, sizeof(state.in_key));
	state.in_state = x_get_le64((const uint8_t *)&in_lease_break->duration);
}
	
static void decode_in_oplock_break(x_smb2_state_oplock_break_t &state,
		const x_smb2_in_oplock_break_t *in_oplock_break)
{
	state.in_oplock_level = X_LE2H8(in_oplock_break->oplock_level);
	state.in_file_id_persistent = X_LE2H64(in_oplock_break->file_id_persistent);
	state.in_file_id_volatile = X_LE2H64(in_oplock_break->file_id_volatile);
}

static NTSTATUS x_smb2_process_oplock_break(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		const x_smb2_in_oplock_break_t *in_oplock_break)
{
	auto state = std::make_unique<x_smb2_state_oplock_break_t>();
	decode_in_oplock_break(*state, in_oplock_break);

	if (!smbd_requ->smbd_open) {
		assert(smbd_requ->smbd_tcon);
		smbd_requ->smbd_open = x_smbd_open_find(state->in_file_id_persistent,
				state->in_file_id_volatile,
				smbd_requ->smbd_tcon);

		if (!smbd_requ->smbd_open) {
			RETURN_OP_STATUS(smbd_requ, NT_STATUS_FILE_CLOSED);
		}
	}

#if 0
	NTSTATUS status = x_smbd_object_op_oplock_break(smbd_requ->smbd_open->smbd_object,
			smbd_conn, smbd_requ, state);
	if (NT_STATUS_IS_OK(status)) {
		x_smb2_reply_setinfo(smbd_conn, smbd_requ, *state);
		return status;
	}
#endif
	X_TODO;
	return NT_STATUS_INVALID_PARAMETER;
}

static NTSTATUS x_smb2_process_lease_break(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		const x_smb2_in_lease_break_t *in_lease_break)
{
	auto state = std::make_unique<x_smb2_state_lease_break_t>();
	decode_in_lease_break(*state, in_lease_break);
	X_TODO;
	return NT_STATUS_INVALID_PARAMETER;
}

NTSTATUS x_smb2_process_BREAK(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	X_LOG_OP("%ld BREAK", smbd_requ->in_mid);

	if (smbd_requ->in_requ_len < SMB2_HDR_BODY + sizeof(x_smb2_in_oplock_break_t)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	if (!smbd_requ->smbd_sess) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_USER_SESSION_DELETED);
	}

	if (smbd_requ->smbd_sess->state != x_smbd_sess_t::S_ACTIVE) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	const uint8_t *in_hdr = smbd_requ->get_in_data();
	/* TODO signing/encryption */
	if (!smbd_requ->smbd_tcon) {
		uint32_t in_tid = IVAL(in_hdr, SMB2_HDR_TID);
		smbd_requ->smbd_tcon = x_smbd_tcon_find(in_tid, smbd_requ->smbd_sess);
		if (!smbd_requ->smbd_tcon) {
			RETURN_OP_STATUS(smbd_requ, NT_STATUS_NETWORK_NAME_DELETED);
		}
	}

	const x_smb2_in_lease_break_t *in_lease_break = (const x_smb2_in_lease_break_t *)(in_hdr + SMB2_HDR_BODY);
	if (in_lease_break->struct_size >= sizeof(x_smb2_in_lease_break_t)) {
		if (smbd_requ->in_requ_len < SMB2_HDR_BODY + sizeof(x_smb2_in_lease_break_t)) {
			RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
		}
		return x_smb2_process_lease_break(smbd_conn, smbd_requ, in_lease_break);
	} else {
		if (smbd_requ->in_requ_len < SMB2_HDR_BODY + sizeof(x_smb2_in_oplock_break_t)) {
			RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
		}
		return x_smb2_process_oplock_break(smbd_conn, smbd_requ,
				(const x_smb2_in_oplock_break_t *)in_lease_break);
	}
}
#if 0
	auto state = std::make_unique<x_smb2_state_create_t>();
	if (!decode_in_create(*state, in_hdr, smbd_requ->in_requ_len)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	X_LOG_OP("%ld BREAK '%s'", smbd_requ->in_mid, x_convert_utf16_to_utf8(state->in_name).c_str());
	X_TODO;
	return NT_STATUS_NOT_SUPPORTED;
#endif
