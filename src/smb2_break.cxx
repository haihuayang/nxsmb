
#include "smbd_open.hxx"
#include "smbd_lease.hxx"
#include "nxfsd_sched.hxx"

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

struct x_smbd_requ_oplock_break_t : x_smbd_requ_t
{
	using x_smbd_requ_t::x_smbd_requ_t;

	std::tuple<bool, bool, bool> get_properties() const override
	{
		return { true, true, false };
	}
	NTSTATUS process(void *ctx_conn) override;
	NTSTATUS done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status) override;

	x_smbd_requ_state_oplock_break_t state;
};

NTSTATUS x_smbd_requ_oplock_break_t::process(void *ctx_conn)
{
	X_SMBD_REQU_LOG(OP, this, " open=0x%lx,0x%lx %d",
			state.in_file_id_persistent, state.in_file_id_volatile,
			state.in_oplock_level);

	if (this->smbd_chan == nullptr) {
		X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_USER_SESSION_DELETED);
	}

	NTSTATUS status = x_smbd_requ_init_open(this,
			state.in_file_id_persistent,
			state.in_file_id_volatile,
			false);
	if (!NT_STATUS_IS_OK(status)) {
		X_SMBD_REQU_RETURN_STATUS(this, status);
	}

	return x_smbd_break_oplock(smbd_open, this, state);
}

NTSTATUS x_smbd_requ_oplock_break_t::done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status)
{
	if (status.ok()) {
		auto &out_buf = get_requ_out_buf();
		out_buf.head = out_buf.tail = x_smb2_bufref_alloc(sizeof(x_smb2_oplock_break_t));
		out_buf.length = out_buf.head->length;

		uint8_t *out_hdr = out_buf.head->get_data();
		encode_oplock_break_resp(state, out_hdr);
	}
	return status;
}

struct x_smbd_requ_lease_break_t : x_smbd_requ_t
{
	using x_smbd_requ_t::x_smbd_requ_t;

	std::tuple<bool, bool, bool> get_properties() const override
	{
		return { true, true, false };
	}
	NTSTATUS process(void *ctx_conn) override;
	NTSTATUS done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status) override;

	x_smbd_requ_state_lease_break_t state;
};

NTSTATUS x_smbd_requ_lease_break_t::process(void *ctx_conn)
{
	X_SMBD_REQU_LOG(OP, this,  " lease=%s",
			x_tostr(state.in_key).c_str());

	if (this->smbd_chan == nullptr) {
		X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_USER_SESSION_DELETED);
	}

	return x_smbd_lease_process_break(state);
}

NTSTATUS x_smb2_parse_BREAK(x_smbd_conn_t *smbd_conn, x_smbd_requ_t **p_smbd_requ,
		x_in_buf_t &in_buf, uint32_t in_msgsize,
		bool encrypted)
{
	auto in_smb2_hdr = (const x_smb2_header_t *)(in_buf.get_data());

	if (in_buf.length < sizeof(x_smb2_header_t) + sizeof(x_smb2_oplock_break_t)) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}

	auto in_break = (const x_smb2_oplock_break_t *)(in_smb2_hdr + 1);
	if (in_break->struct_size >= sizeof(x_smb2_lease_break_t)) {
		if (in_buf.length < sizeof(x_smb2_header_t) + sizeof(x_smb2_lease_break_t)) {
			X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
		}
		auto in_lease_break = (const x_smb2_lease_break_t *)in_break;
		auto requ = new x_smbd_requ_lease_break_t(smbd_conn, in_buf,
				in_msgsize, encrypted);
		decode_in_lease_break(requ->state, in_lease_break);
		requ->state.in_client_guid = x_smbd_conn_get_client_guid(smbd_conn);
		*p_smbd_requ = requ;
		return NT_STATUS_OK;

	} else {
		auto requ = new x_smbd_requ_oplock_break_t(smbd_conn, in_buf,
				in_msgsize, encrypted);
		decode_in_oplock_break(requ->state, in_break);
		*p_smbd_requ = requ;
		return NT_STATUS_OK;
	}
}

static void x_smb2_send_lease_break(x_smbd_conn_t *smbd_conn, x_smbd_sess_t *smbd_sess,
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

struct send_lease_break_evt_t
{
	static void func(void *ctx_conn, x_fdevt_user_t *fdevt_user)
	{
		x_smbd_conn_t *smbd_conn = (x_smbd_conn_t *)ctx_conn;
		send_lease_break_evt_t *evt = X_CONTAINER_OF(fdevt_user,
				send_lease_break_evt_t, base);
		X_LOG(SMB, DBG, "send_lease_break_evt=%p curr_state=%d new_state=%d "
				"new_epoch=%u flags=0x%x",
				evt, evt->curr_state, evt->new_state, evt->new_epoch,
				evt->flags);

		if (smbd_conn) {
			x_smb2_send_lease_break(smbd_conn,
					evt->smbd_sess,
					&evt->lease_key,
					evt->curr_state,
					evt->new_state,
					evt->new_epoch,
					evt->flags);
		}
		delete evt;
	}

	send_lease_break_evt_t(x_smbd_sess_t *smbd_sess,
			const x_smb2_lease_key_t &lease_key,
			uint8_t curr_state,
			uint8_t new_state,
			uint16_t new_epoch,
			uint32_t flags)
		: base(func), smbd_sess(smbd_sess)
		, lease_key(lease_key)
		, curr_state(curr_state)
		, new_state(new_state)
		, new_epoch(new_epoch)
		, flags(flags)
	{
	}

	~send_lease_break_evt_t()
	{
		x_ref_dec(smbd_sess);
	}

	x_fdevt_user_t base;
	x_smbd_sess_t * const smbd_sess;
	const x_smb2_lease_key_t lease_key;
	const uint8_t curr_state, new_state;
	const uint16_t new_epoch;
	const uint32_t flags;
};

NTSTATUS x_smbd_requ_lease_break_t::done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status)
{
	if (status.ok()) {
		auto &out_buf = get_requ_out_buf();
		out_buf.head = out_buf.tail = x_smb2_bufref_alloc(sizeof(x_smb2_lease_break_t));
		out_buf.length = out_buf.head->length;

		uint8_t *out_hdr = out_buf.head->get_data();
		encode_lease_break_resp(state, out_hdr);
		if (state.more_break) {
			send_lease_break_evt_t *evt = new send_lease_break_evt_t(
					x_ref_inc(this->smbd_sess), state.in_key,
					x_convert<uint8_t>(state.more_break_from),
					x_convert<uint8_t>(state.more_break_to),
					state.more_epoch, state.more_flags);
			x_nxfsd_schedule(&evt->base);
		}
	}
	return status;
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

void x_smbd_post_lease_break(x_smbd_sess_t *smbd_sess,
		x_smb2_lease_key_t lease_key,
		uint8_t curr_state, uint8_t new_state,
		uint16_t new_epoch, uint32_t flags)
{
	X_SMBD_SESS_POST_USER(smbd_sess, new send_lease_break_evt_t(
				smbd_sess, lease_key, curr_state, new_state,
				new_epoch, flags));
}

