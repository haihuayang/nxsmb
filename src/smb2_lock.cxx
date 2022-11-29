
#include "smbd_open.hxx"

struct x_smb2_in_lock_t
{
	uint16_t struct_size;
	uint16_t lock_count;
	uint32_t lock_sequence_index;
	uint64_t file_id_persistent;
	uint64_t file_id_volatile;
	x_smb2_lock_element_t lock_elements[1];
};

struct x_smb2_out_lock_t
{
	uint16_t struct_size;
	uint16_t reserved0;
};

static bool decode_in_lock(x_smb2_state_lock_t &state,
		const uint8_t *in_hdr, uint32_t in_len)
{
	const x_smb2_in_lock_t *in_lock = (const x_smb2_in_lock_t *)(in_hdr + sizeof(x_smb2_header_t));

	uint16_t lock_count = X_LE2H16(in_lock->lock_count);
	if (lock_count == 0) {
		return false;
	}
	
	if ((lock_count - 1) * sizeof(x_smb2_lock_element_t) + sizeof(x_smb2_in_lock_t) + sizeof(x_smb2_header_t) > in_len) {
		return false;
	}

	state.in_lock_sequence_index = X_LE2H32(in_lock->lock_sequence_index);
	state.in_file_id_persistent = X_LE2H64(in_lock->file_id_persistent);
	state.in_file_id_volatile = X_LE2H64(in_lock->file_id_volatile);
	state.in_lock_elements.resize(lock_count);
	const x_smb2_lock_element_t *in_elem = in_lock->lock_elements;
	for (auto &elem: state.in_lock_elements) {
		elem.offset = X_LE2H64(in_elem->offset);
		elem.length = X_LE2H64(in_elem->length);
		elem.flags = X_LE2H32(in_elem->flags);
	}
	return true;
}

static void encode_out_lock(uint8_t *out_hdr)
{
	x_smb2_out_lock_t *out_lock = (x_smb2_out_lock_t *)(out_hdr + sizeof(x_smb2_header_t));

	out_lock->struct_size = X_H2LE16(sizeof(x_smb2_out_lock_t));
	out_lock->reserved0 = 0;
}

static void x_smb2_reply_lock(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		const x_smb2_state_lock_t &state)
{
	X_LOG_OP("%ld RESP SUCCESS", smbd_requ->in_smb2_hdr.mid);

	x_bufref_t *bufref = x_bufref_alloc(sizeof(x_smb2_out_lock_t));

	uint8_t *out_hdr = bufref->get_data();
	encode_out_lock(out_hdr);
	x_smb2_reply(smbd_conn, smbd_requ, bufref, bufref, NT_STATUS_OK, 
			sizeof(x_smb2_header_t) + sizeof(x_smb2_out_lock_t));
}

static void x_smb2_lock_async_done(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		NTSTATUS status)
{
	X_LOG_DBG("status=0x%x", status.v);
	auto state = smbd_requ->release_state<x_smb2_state_lock_t>();
	if (!smbd_conn) {
		return;
	}
	if (NT_STATUS_IS_OK(status)) {
		x_smb2_reply_lock(smbd_conn, smbd_requ, *state);
	}
	x_smbd_conn_requ_done(smbd_conn, smbd_requ, status);
}

NTSTATUS x_smb2_process_lock(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	if (smbd_requ->in_requ_len < sizeof(x_smb2_header_t) + sizeof(x_smb2_in_lock_t)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	const uint8_t *in_hdr = smbd_requ->get_in_data();

	auto state = std::make_unique<x_smb2_state_lock_t>();
	if (!decode_in_lock(*state, in_hdr, smbd_requ->in_requ_len)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	X_LOG_OP("%ld LOCK 0x%lx, 0x%lx", smbd_requ->in_smb2_hdr.mid,
			state->in_file_id_persistent, state->in_file_id_volatile);

	bool is_unlock = state->in_lock_elements[0].flags & X_SMB2_LOCK_FLAG_UNLOCK;
	uint32_t async_count = 0;
	if (is_unlock) {
		uint32_t flags = ~(X_SMB2_LOCK_FLAG_UNLOCK|X_SMB2_LOCK_FLAG_FAIL_IMMEDIATELY);
		for (const auto &le: state->in_lock_elements) {
			if ((le.flags & flags) != 0) {
				RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
			}
		}
	} else {
		for (const auto &le: state->in_lock_elements) {
			if ((le.flags & X_SMB2_LOCK_FLAG_FAIL_IMMEDIATELY) == 0) {
				if (++async_count > 0 && state->in_lock_elements.size() > 1) {
					RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
				}
			}
			auto f = le.flags & ~X_SMB2_LOCK_FLAG_FAIL_IMMEDIATELY;
			if (f != X_SMB2_LOCK_FLAG_SHARED && f != X_SMB2_LOCK_FLAG_EXCLUSIVE) {
				RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
			}
			if (le.length != 0 && (le.offset + le.length - 1) < le.offset) {
				RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_LOCK_RANGE);
			}
		}
	}
	
	NTSTATUS status = x_smbd_requ_init_open(smbd_requ,
			state->in_file_id_persistent,
			state->in_file_id_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		RETURN_OP_STATUS(smbd_requ, status);
	}

	smbd_requ->async_done_fn = x_smb2_lock_async_done;
	status = x_smbd_open_op_lock(smbd_requ->smbd_open,
			smbd_conn, smbd_requ, state);
	if (NT_STATUS_IS_OK(status)) {
		x_smb2_reply_lock(smbd_conn, smbd_requ, *state);
		return status;
	}

	RETURN_OP_STATUS(smbd_requ, status);
}
