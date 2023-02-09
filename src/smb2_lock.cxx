
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
		x_smbd_requ_t *smbd_requ = curr_open->lock_requ_list.get_front();
		/* TODO show it post retry to smbd_conn */
		while (smbd_requ) {
			x_smbd_requ_t *next_requ = curr_open->lock_requ_list.next(smbd_requ);
			auto state = smbd_requ->get_state<x_smb2_state_lock_t>();
			if (!brl_conflict(sharemode, curr_open, state->in_lock_elements)) {
				curr_open->lock_requ_list.remove(smbd_requ);
				curr_open->locks.insert(curr_open->locks.end(),
						state->in_lock_elements.begin(),
						state->in_lock_elements.end());
				X_SMBD_CHAN_POST_USER(smbd_requ->smbd_chan, 
						new lock_evt_t(smbd_requ));
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
		smbd_open->lock_requ_list.remove(smbd_requ);
	}
	x_smbd_conn_post_cancel(smbd_conn, smbd_requ, NT_STATUS_CANCELLED);
}

static NTSTATUS smbd_open_lock(
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_lock_t> &state)
{
	x_smbd_sharemode_t *sharemode = x_smbd_open_get_sharemode(
			smbd_open);
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;

	std::lock_guard<std::mutex> lock(smbd_object->mutex);

	if (state->in_lock_elements[0].flags & X_SMB2_LOCK_FLAG_UNLOCK) {
		for (auto &l1: state->in_lock_elements) {
			auto it = smbd_open->locks.begin();
			for (; it != smbd_open->locks.end(); ++it) {
				if (it->offset == l1.offset && it->length == l1.length) {
					break;
				}
			}
			if (it == smbd_open->locks.end()) {
				X_LOG_NOTICE("failed to unlock");
				return NT_STATUS_RANGE_NOT_LOCKED;
			}
			smbd_open->locks.erase(it);
		}
		x_smbd_lock_retry(sharemode);
		return NT_STATUS_OK;
	} else {
		bool conflict = brl_conflict(sharemode, smbd_open,
				state->in_lock_elements);
		if (!conflict) {
			smbd_open->locks.insert(smbd_open->locks.end(),
					state->in_lock_elements.begin(),
					state->in_lock_elements.end());
		} else if (state->in_lock_elements[0].flags & X_SMB2_LOCK_FLAG_FAIL_IMMEDIATELY) {
			return NT_STATUS_LOCK_NOT_GRANTED;
		} else {
			X_ASSERT(state->in_lock_elements.size() == 1);
			X_LOG_DBG("lock conflict");
			smbd_requ->save_state(state);
			x_smbd_ref_inc(smbd_requ);
			smbd_open->lock_requ_list.push_back(smbd_requ);
			x_smbd_requ_async_insert(smbd_requ, smbd_lock_cancel);
			return NT_STATUS_PENDING;
		}
	}
	/* when lock success, it break oplock */
	x_smbd_break_others_to_none(smbd_object, sharemode,
			smbd_open->smbd_lease,
			smbd_open->open_state.oplock_level);
	return NT_STATUS_OK;
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

	if (!x_smbd_open_is_data(smbd_requ->smbd_open)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	smbd_requ->async_done_fn = x_smb2_lock_async_done;

	status = smbd_open_lock(smbd_requ->smbd_open,
			smbd_requ, state);
	if (NT_STATUS_IS_OK(status)) {
		x_smb2_reply_lock(smbd_conn, smbd_requ, *state);
		return status;
	}

	RETURN_OP_STATUS(smbd_requ, status);
}
