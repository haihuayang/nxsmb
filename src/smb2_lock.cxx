
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
		++in_elem;
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

static void smb2_lock_set_sequence(x_smbd_open_t *smbd_open,
		const x_smb2_state_lock_t &state)
{
	auto lock_sequence_bucket = state.in_lock_sequence_index >> 4;
	if (lock_sequence_bucket > 0 &&
			lock_sequence_bucket <= x_smbd_open_t::LOCK_SEQUENCE_MAX) {
		smbd_open->lock_sequence_array[lock_sequence_bucket - 1] =
			state.in_lock_sequence_index & 0xf;
	}
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
	X_ASSERT(!NT_STATUS_EQUAL(status, NT_STATUS_PENDING));
	if (NT_STATUS_IS_OK(status)) {
		smb2_lock_set_sequence(smbd_requ->smbd_open, *state);
		x_smb2_reply_lock(smbd_conn, smbd_requ, *state);
	}
	x_smbd_conn_requ_done(smbd_conn, smbd_requ, status);
}

static bool byte_range_overlap(uint64_t ofs1,
		uint64_t len1,
		uint64_t ofs2,
		uint64_t len2)
{
	uint64_t last1;
	uint64_t last2;

	/*
	 * This is based on [MS-FSA] 2.1.4.10
	 * Algorithm for Determining If a Range Access
	 * Conflicts with Byte-Range Locks
	 */

	/*
	 * The {0, 0} range doesn't conflict with any byte-range lock
	 */
	if (ofs1 == 0 && len1 == 0) {
		return false;
	}
	if (ofs2 == 0 && len2 == 0) {
		return false;
	}

	/*
	 * The caller should have checked that the ranges are
	 * valid.
	 */
	last1 = ofs1 + len1 - 1;
	last2 = ofs2 + len2 - 1;

	/*
	 * If one range starts after the last
	 * byte of the other range there's
	 * no conflict.
	 */
	if (ofs1 > last2) {
		return false;
	}
	if (ofs2 > last1) {
		return false;
	}

	return true;
}

/* SMB2_LOCK */
static bool brl_overlap(const x_smb2_lock_element_t &le1, const x_smb2_lock_element_t &le2)
{
	return byte_range_overlap(le1.offset, le1.length, le2.offset, le2.length);
}

static bool brl_conflict(const x_smbd_sharemode_t *sharemode,
		const x_smbd_open_t *smbd_open,
		const x_smb2_lock_element_t &le)
{
	auto &open_list = sharemode->open_list;
	const x_smbd_open_t *curr_open;
	for (curr_open = open_list.get_front(); curr_open; curr_open = open_list.next(curr_open)) {
		for (auto &l: curr_open->locks) {
			if (!(le.flags & X_SMB2_LOCK_FLAG_EXCLUSIVE) &&
					!(l.flags & X_SMB2_LOCK_FLAG_EXCLUSIVE)) {
				continue;
			}

			/* A READ lock can stack on top of a WRITE lock if they are
			 * the same open */
			if ((l.flags & X_SMB2_LOCK_FLAG_EXCLUSIVE) &&
					!(le.flags & X_SMB2_LOCK_FLAG_EXCLUSIVE) &&
					curr_open == smbd_open) {
				continue;
			}

			if (brl_overlap(le, l)) {
				return true;
			}
		}
	}
	return false;
}

static bool brl_conflict(const x_smbd_sharemode_t *sharemode,
		const x_smbd_open_t *smbd_open,
		const std::vector<x_smb2_lock_element_t> &locks)
{
	for (auto &le: locks) {
		if (brl_conflict(sharemode, smbd_open, le)) {
			return true;
		}
	}
	return false;
}

static bool brl_conflict_other(const x_smbd_sharemode_t *sharemode,
		const x_smbd_open_t *smbd_open,
		const x_smb2_lock_element_t &le)
{
	auto &open_list = sharemode->open_list;
	const x_smbd_open_t *curr_open;
	for (curr_open = open_list.get_front(); curr_open; curr_open = open_list.next(curr_open)) {
		for (auto &l: curr_open->locks) {
			if (!(le.flags & X_SMB2_LOCK_FLAG_EXCLUSIVE) &&
					!(l.flags & X_SMB2_LOCK_FLAG_EXCLUSIVE)) {
				continue;
			}

			if (!brl_overlap(le, l)) {
				continue;
			}

			if (curr_open != smbd_open) {
				return true;
			}

			/*
			 * Incoming WRITE locks conflict with existing READ locks even
			 * if the context is the same. JRA. See LOCKTEST7 in
			 * smbtorture.
			 */
			if (!(l.flags & X_SMB2_LOCK_FLAG_EXCLUSIVE) &&
					(le.flags & X_SMB2_LOCK_FLAG_EXCLUSIVE)) {
				return true;
			}
		}
	}
	return false;
}

bool x_smbd_check_io_brl_conflict(x_smbd_object_t *smbd_object,
		const x_smbd_open_t *smbd_open,
		uint64_t offset, uint64_t length, bool is_write)
{
	struct x_smb2_lock_element_t le;
	le.offset = offset;
	le.length = length;
	le.flags = is_write ? X_SMB2_LOCK_FLAG_EXCLUSIVE : X_SMB2_LOCK_FLAG_SHARED;
	return brl_conflict_other(x_smbd_open_get_sharemode(smbd_open),
			smbd_open, le);
}

struct lock_evt_t
{
	static void func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user)
	{
		lock_evt_t *evt = X_CONTAINER_OF(fdevt_user, lock_evt_t, base);
		x_smbd_requ_t *smbd_requ = evt->smbd_requ;
		X_LOG_DBG("evt=%p, requ=%p, smbd_conn=%p", evt, smbd_requ, smbd_conn);
		x_smbd_requ_async_done(smbd_conn, smbd_requ, NT_STATUS_OK);
		delete evt;
	}

	explicit lock_evt_t(x_smbd_requ_t *requ)
		: base(func), smbd_requ(requ)
	{
	}
	~lock_evt_t()
	{
		x_smbd_ref_dec(smbd_requ);
	}
	x_fdevt_user_t base;
	x_smbd_requ_t * const smbd_requ;
};

void x_smbd_lock_retry(x_smbd_sharemode_t *sharemode)
{
	/* TODO it is not fair, it always scan the lock from open_list */
	x_smbd_open_t *curr_open;
	auto &open_list = sharemode->open_list;
	for (curr_open = open_list.get_front(); curr_open; curr_open = open_list.next(curr_open)) {
		x_smbd_requ_t *smbd_requ = curr_open->pending_requ_list.get_front();
		/* TODO show it post retry to smbd_conn */
		while (smbd_requ) {
			x_smbd_requ_t *next_requ = curr_open->pending_requ_list.next(smbd_requ);
			if (smbd_requ->in_smb2_hdr.opcode == X_SMB2_OP_LOCK) {
				auto state = smbd_requ->get_requ_state<x_smb2_state_lock_t>();
				if (!brl_conflict(sharemode, curr_open, state->in_lock_elements)) {
					curr_open->pending_requ_list.remove(smbd_requ);
					curr_open->locks.insert(curr_open->locks.end(),
							state->in_lock_elements.begin(),
							state->in_lock_elements.end());
					X_SMBD_CHAN_POST_USER(smbd_requ->smbd_chan, 
							new lock_evt_t(smbd_requ));
				}
			}
			smbd_requ = next_requ;
		}
	}
}

static void smbd_lock_cancel(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	x_smbd_open_t *smbd_open = smbd_requ->smbd_open;
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;

	{
		std::lock_guard<std::mutex> lock(smbd_object->mutex);
		smbd_open->pending_requ_list.remove(smbd_requ);
	}
	x_smbd_conn_post_cancel(smbd_conn, smbd_requ, NT_STATUS_CANCELLED);
}

static NTSTATUS smbd_open_lock(
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_lock_t> &state)
{
	if (state->in_lock_elements.size() > 1) {
		for (const auto &le: state->in_lock_elements) {
			if (le.flags != (X_SMB2_LOCK_FLAG_SHARED | X_SMB2_LOCK_FLAG_FAIL_IMMEDIATELY) &&
					le.flags != (X_SMB2_LOCK_FLAG_EXCLUSIVE | X_SMB2_LOCK_FLAG_FAIL_IMMEDIATELY)) {
				RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
			}
			if (le.length != 0 && (le.offset + le.length - 1) < le.offset) {
				RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_LOCK_RANGE);
			}
		}
	} else {
		for (const auto &le: state->in_lock_elements) {
			if (le.flags != X_SMB2_LOCK_FLAG_SHARED &&
					le.flags != X_SMB2_LOCK_FLAG_EXCLUSIVE &&
					le.flags != (X_SMB2_LOCK_FLAG_SHARED | X_SMB2_LOCK_FLAG_FAIL_IMMEDIATELY) &&
					le.flags != (X_SMB2_LOCK_FLAG_EXCLUSIVE | X_SMB2_LOCK_FLAG_FAIL_IMMEDIATELY)) {
				RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
			}
			if (le.length != 0 && (le.offset + le.length - 1) < le.offset) {
				RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_LOCK_RANGE);
			}
		}
	}

	x_smbd_sharemode_t *sharemode = x_smbd_open_get_sharemode(
			smbd_open);
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	auto first_flags = state->in_lock_elements[0].flags;

	std::lock_guard<std::mutex> lock(smbd_object->mutex);

	bool conflict = brl_conflict(sharemode, smbd_open,
			state->in_lock_elements);
	if (!conflict) {
		smbd_open->locks.insert(smbd_open->locks.end(),
				state->in_lock_elements.begin(),
				state->in_lock_elements.end());
	} else if (first_flags & X_SMB2_LOCK_FLAG_FAIL_IMMEDIATELY) {
		return NT_STATUS_LOCK_NOT_GRANTED;
	} else {
		X_ASSERT(state->in_lock_elements.size() == 1);
		X_LOG_DBG("lock conflict");
		smbd_requ->save_requ_state(state);
		x_smbd_ref_inc(smbd_requ);
		smbd_open->pending_requ_list.push_back(smbd_requ);
		x_smbd_requ_async_insert(smbd_requ, smbd_lock_cancel);
		return NT_STATUS_PENDING;
	}

	/* when lock success, it break oplock */
	x_smbd_break_others_to_none(smbd_object, sharemode,
			smbd_open->smbd_lease,
			smbd_open->open_state.oplock_level);
	return NT_STATUS_OK;
}

static NTSTATUS smbd_open_unlock(
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_lock_t> &state)
{
	x_smbd_sharemode_t *sharemode = x_smbd_open_get_sharemode(
			smbd_open);
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	uint32_t unlocked = 0;
	NTSTATUS status = NT_STATUS_OK;

	std::lock_guard<std::mutex> lock(smbd_object->mutex);

	for (auto &l1: state->in_lock_elements) {
		if (l1.flags != X_SMB2_LOCK_FLAG_UNLOCK) {
			status = NT_STATUS_INVALID_PARAMETER;
			break;
		}
		auto it = smbd_open->locks.begin();
		for (; it != smbd_open->locks.end(); ++it) {
			if (it->offset == l1.offset && it->length == l1.length) {
				break;
			}
		}
		if (it == smbd_open->locks.end()) {
			X_LOG_NOTICE("failed to unlock");
			status = NT_STATUS_RANGE_NOT_LOCKED;
			break;
		}
		smbd_open->locks.erase(it);
		++unlocked;
	}
	if (unlocked > 0) {
		x_smbd_lock_retry(sharemode);
	}
	return status;
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

	bool is_unlock = state->in_lock_elements[0].flags == X_SMB2_LOCK_FLAG_UNLOCK;
	if (!is_unlock && NT_STATUS_EQUAL(smbd_requ->sess_status,
				NT_STATUS_NETWORK_SESSION_EXPIRED)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_NETWORK_SESSION_EXPIRED);
	}

	NTSTATUS status = x_smbd_requ_init_open(smbd_requ,
			state->in_file_id_persistent,
			state->in_file_id_volatile,
			false);
	if (!NT_STATUS_IS_OK(status)) {
		RETURN_OP_STATUS(smbd_requ, status);
	}

	auto smbd_open = smbd_requ->smbd_open;

	if (!x_smbd_open_is_data(smbd_open)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	if (smbd_open->open_state.dhmode != x_smbd_dhmode_t::NONE ||
			(x_smbd_conn_get_capabilities(smbd_conn) & X_SMB2_CAP_MULTI_CHANNEL)) {
		auto lock_sequence_bucket = state->in_lock_sequence_index >> 4;
		if (lock_sequence_bucket > 0 &&
				lock_sequence_bucket <= x_smbd_open_t::LOCK_SEQUENCE_MAX) {
			if (smbd_open->lock_sequence_array[lock_sequence_bucket - 1] ==
					(state->in_lock_sequence_index & 0xf)) {
				X_LOG_NOTICE("replayed smb2 lock request detected, sequence = 0x%x",
						state->in_lock_sequence_index);
				x_smb2_reply_lock(smbd_conn, smbd_requ, *state);
				return NT_STATUS_OK;
			}
			/* not a replay, mark it invalid */
			smbd_open->lock_sequence_array[lock_sequence_bucket - 1] = 0xff;
		}
	} else {
		/* disable check_lock_sequence */
		state->in_lock_sequence_index = 0;
	}

	if (is_unlock) {
		status = smbd_open_unlock(smbd_requ->smbd_open,
				smbd_requ, state);
	} else {
		smbd_requ->status = NT_STATUS_RANGE_NOT_LOCKED;
		smbd_requ->async_done_fn = x_smb2_lock_async_done;
		status = smbd_open_lock(smbd_requ->smbd_open,
				smbd_requ, state);
	}
	

	if (NT_STATUS_IS_OK(status)) {
		smb2_lock_set_sequence(smbd_requ->smbd_open, *state);
		x_smb2_reply_lock(smbd_conn, smbd_requ, *state);
		return status;
	}

	RETURN_OP_STATUS(smbd_requ, status);
}
