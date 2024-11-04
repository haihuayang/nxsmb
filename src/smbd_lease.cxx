
#include "smbd_hashtable.hxx"
#include "smbd_lease.hxx"
#include "smbd_stats.hxx"
#include "smbd_open.hxx"
#include "smbd_ctrl.hxx"

static long smbd_lease_break_timeout(x_timer_job_t *timer);
struct x_smbd_lease_t
{
	x_smbd_lease_t(const x_smb2_uuid_t &client_guid,
			const x_smb2_lease_key_t &lease_key,
			uint32_t hash, uint8_t version,
			uint16_t epoch);
	x_dqlink_t hash_link;
	x_timer_job_t timer{smbd_lease_break_timeout};
	const x_smb2_uuid_t client_guid;
	x_smbd_object_t * smbd_object{}; // protected by bucket mutex
	x_smbd_stream_t * smbd_stream{}; // protected by bucket mutex
	x_smbd_lease_data_t data;
	const uint32_t hash;
	uint32_t refcnt{1}; // protected by bucket mutex
	uint32_t open_cnt{0};
	x_smbd_requ_id_list_t pending_requ_list;
};

X_DECLARE_MEMBER_TRAITS(smbd_lease_hash_traits, x_smbd_lease_t, hash_link)

static uint32_t lease_hash(const x_smb2_uuid_t &client_guid, const x_smb2_lease_key_t &lease_key)
{
	uint64_t hash = client_guid.data[0];
	hash = hash * 31 + client_guid.data[1];
	hash = hash * 31 + lease_key.data[0];
	hash = hash * 31 + lease_key.data[1];
	return uint32_t((hash >> 32) ^ hash);
}


using smbd_lease_pool_t = x_smbd_hashtable_t<smbd_lease_hash_traits>;

static smbd_lease_pool_t g_smbd_lease_pool;

x_smbd_lease_data_t x_smbd_lease_get_data(const x_smbd_lease_t *smbd_lease)
{
	return smbd_lease->data;
}

uint8_t x_smbd_lease_get_state(const x_smbd_lease_t *smbd_lease)
{
	return smbd_lease->data.state;
}

static inline auto smbd_lease_lock(uint32_t hash)
{
	return std::lock_guard<std::mutex>(g_smbd_lease_pool.mutex[hash % g_smbd_lease_pool.mutex.size()]);
}

#define SMBD_LEASE_EPOCH_INC(smbd_lease) \
	smbd_lease_epoch_inc((smbd_lease), __FILE__, __LINE__)
static inline void smbd_lease_epoch_inc(x_smbd_lease_t *smbd_lease,
		const char *file, unsigned int line)
{
	X_LOG(SMB, DBG, "smbd_lease=%p epoch=%u at %s:%u", smbd_lease,
			smbd_lease->data.epoch,
			file, line);
	++smbd_lease->data.epoch;
}

static inline auto smbd_lease_lock(const x_smbd_lease_t *smbd_lease)
{
	return smbd_lease_lock(smbd_lease->hash);
}

bool x_smbd_lease_match(const x_smbd_lease_t *smbd_lease,
		x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream)
{
	auto lock = smbd_lease_lock(smbd_lease);
	if (smbd_lease->smbd_object) {
		return smbd_lease->smbd_object == smbd_object &&
			smbd_lease->smbd_stream == smbd_stream;
	}
	return true;
}

static bool smbd_lease_match(const x_smbd_lease_t *smbd_lease,
		const x_smb2_uuid_t &client_guid,
		const x_smb2_lease_key_t &lkey)
{
	return smbd_lease->client_guid == client_guid && smbd_lease->data.key == lkey;
}

static inline void smbd_lease_incref(x_smbd_lease_t *smbd_lease)
{
	X_ASSERT(smbd_lease->refcnt > 0);
	++smbd_lease->refcnt;
}

static void smbd_lease_decref(x_smbd_lease_t *smbd_lease)
{
	{
		auto lock = smbd_lease_lock(smbd_lease);
		if (--smbd_lease->refcnt == 0) {
			g_smbd_lease_pool.hashtable.remove(smbd_lease);
		}
	}

	if (smbd_lease->refcnt == 0) {
		X_ASSERT(smbd_lease->open_cnt == 0);
		X_ASSERT(!smbd_lease->data.breaking);
		if (smbd_lease->smbd_object) {
			x_smbd_release_object_and_stream(smbd_lease->smbd_object, smbd_lease->smbd_stream);
		}
		X_SMBD_COUNTER_INC_DELETE(lease, 1);
		delete smbd_lease;
	}
}

void x_smbd_lease_release(x_smbd_lease_t *smbd_lease)
{
	smbd_lease_decref(smbd_lease);
}

static inline void smbd_lease_cancel_timer(x_smbd_lease_t *smbd_lease)
{
	if (x_nxfsd_del_timer(&smbd_lease->timer)) {
		X_ASSERT(--smbd_lease->refcnt > 0);
	}
}

void x_smbd_lease_close(x_smbd_lease_t *smbd_lease)
{
	x_smbd_requ_id_list_t requ_list;
	{
		auto lock = smbd_lease_lock(smbd_lease);
		X_ASSERT(smbd_lease->open_cnt > 0);
		if (--smbd_lease->open_cnt == 0) {
			if (smbd_lease->data.breaking) {
				smbd_lease_cancel_timer(smbd_lease);
				smbd_lease->data.breaking = false;
				smbd_lease->data.state = 0;
			}
			std::swap(requ_list, smbd_lease->pending_requ_list);
		}
	}
	smbd_lease_decref(smbd_lease);
	x_smbd_wakeup_requ_list(requ_list);
}

static x_smbd_lease_t *smbd_lease_find(uint32_t hash,
		const x_smb2_uuid_t &client_guid,
		const x_smb2_lease_key_t &lease_key)
{
	return g_smbd_lease_pool.hashtable.find(hash,
			[client_guid, lease_key](const x_smbd_lease_t &smbd_lease) {
				return smbd_lease_match(&smbd_lease, client_guid, lease_key);
			});
}

/* TODO lease should ref smbd_object */
x_smbd_lease_t *x_smbd_lease_find(
		const x_smb2_uuid_t &client_guid,
		const x_smb2_lease_t &smb2_lease,
		bool create_if)
{
	uint32_t hash = lease_hash(client_guid, smb2_lease.key);

	auto lock = smbd_lease_lock(hash);
	x_smbd_lease_t *smbd_lease = smbd_lease_find(hash, client_guid, smb2_lease.key);
	if (smbd_lease) {
		++smbd_lease->refcnt;
	} else if (create_if) {
		smbd_lease = new x_smbd_lease_t(client_guid, smb2_lease.key,
				hash, smb2_lease.version, smb2_lease.epoch);
		g_smbd_lease_pool.hashtable.insert(smbd_lease, hash);
	}
	return smbd_lease;
}

bool x_smbd_lease_match_get(const x_smbd_lease_t *smbd_lease,
		const x_smb2_uuid_t &client_guid,
		x_smb2_lease_t &lease)
{
	if (lease.version != smbd_lease->data.version) {
		return false;
	}
	if (!smbd_lease_match(smbd_lease, client_guid, lease.key)) {
		return false;
	}
	lease.state = smbd_lease->data.state;
	lease.epoch = smbd_lease->data.epoch;
	if (smbd_lease->data.breaking) {
		lease.flags = X_SMB2_LEASE_FLAG_BREAK_IN_PROGRESS;
	} else {
		lease.flags = 0;
	}
	return true;
}

bool x_smbd_lease_grant(x_smbd_lease_t *smbd_lease,
		x_smb2_lease_t &lease,
		uint8_t granted, uint8_t requested,
		x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream,
		bool &new_lease)
{
	auto lock = smbd_lease_lock(smbd_lease);

	if (!smbd_lease->smbd_object) {
		smbd_lease->smbd_object = smbd_object;
		smbd_lease->smbd_stream = smbd_stream;
		lease.state = smbd_lease->data.state = granted;
		lease.epoch = smbd_lease->data.epoch;
		new_lease = true;
		++smbd_lease->open_cnt;
		++smbd_lease->refcnt;
		return true;
	}

	if (smbd_object != smbd_lease->smbd_object
			|| smbd_stream != smbd_lease->smbd_stream) {
		return false;
	}

	uint32_t existing = smbd_lease->data.state;

	/*
	 * Tricky: This test makes sure that "requested" is a
	 * strict bitwise superset of "existing".
	 */
	bool do_upgrade = ((existing & requested) == existing);

	/*
	 * Upgrade only if there's a change.
	 */
	do_upgrade &= (granted != existing);

	/*
	 * Upgrade only if other leases don't prevent what was asked
	 * for.
	 */
	do_upgrade &= (granted == requested);

	/*
	 * only upgrade if we are not in breaking state
	 */
	do_upgrade &= !smbd_lease->data.breaking;

	if (do_upgrade) {
		smbd_lease->data.state = granted;
		SMBD_LEASE_EPOCH_INC(smbd_lease);
	}

	lease.version = smbd_lease->data.version;
	lease.state = smbd_lease->data.state;
	lease.epoch = smbd_lease->data.epoch;

	if (smbd_lease->data.breaking) {
		lease.flags |= X_SMB2_LEASE_FLAG_BREAK_IN_PROGRESS;
	} else {
		lease.flags &= ~X_SMB2_LEASE_FLAG_BREAK_IN_PROGRESS;
	}

	++smbd_lease->open_cnt;
	++smbd_lease->refcnt;
	return true;
}

static bool require_break(x_smbd_lease_t *smbd_lease,
		uint8_t break_to,
		uint8_t delay_mask,
		uint16_t &epoch,
		uint32_t &flags)
{
	epoch = (smbd_lease->data.version > 1) ? smbd_lease->data.epoch : 0;
	if (smbd_lease->data.state == X_SMB2_LEASE_READ) {
		smbd_lease->data.state = X_SMB2_LEASE_NONE;
		smbd_lease->data.breaking = false;
		smbd_lease->data.breaking_to_required = 0;
		smbd_lease->data.breaking_to_requested = 0;
		flags = 0;
		return false;
	} else {
		smbd_lease->data.breaking = true;
		smbd_lease->data.breaking_to_required = break_to;
		smbd_lease->data.breaking_to_requested = break_to;
		smbd_lease_incref(smbd_lease);
		flags = X_SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED;
		x_smbd_add_timer(&smbd_lease->timer, x_smbd_timer_id_t::BREAK);
		return smbd_lease->data.state & delay_mask;
	}
}

static inline void smbd_lease_add_pending_requ(
		x_smbd_lease_t *smbd_lease,
		x_smbd_requ_t *smbd_requ)
{
	int32_t count = smbd_requ->async_pending.fetch_add(1, std::memory_order_relaxed);
	X_ASSERT(count >= 0);
	X_LOG(SMB, DBG, "add requ 0x%lx %p pending %d", smbd_requ->id, smbd_requ,
			count + 1);
	smbd_lease->pending_requ_list.push_back(smbd_requ->id);
}

/* samba process_oplock_break_message */
uint32_t x_smbd_lease_require_break(x_smbd_lease_t *smbd_lease,
		const x_smb2_lease_key_t *ignore_lease_key,
		const x_smb2_uuid_t *client_guid,
		x_smb2_lease_key_t &lease_key,
		uint8_t break_mask,
		uint8_t delay_mask,
		uint8_t &curr_state,
		uint8_t &new_state,
		uint16_t &epoch,
		uint32_t &flags,
		x_smbd_requ_t *smbd_requ,
		bool block_breaking)
{
	if (ignore_lease_key && smbd_lease_match(smbd_lease, *client_guid,
				*ignore_lease_key)) {
		return 0;
	}

	auto lock = smbd_lease_lock(smbd_lease);
	X_LOG(SMB, DBG, "lease=%p %c state=%d epoch=%u break_mask=%u",
			smbd_lease, smbd_lease->data.breaking ? 'B' : '-',
			smbd_lease->data.state, smbd_lease->data.epoch,
			break_mask);

	uint8_t break_from = smbd_lease->data.state;
	uint8_t break_to = break_from & x_convert<uint8_t>(~break_mask);
	if (smbd_lease->data.breaking) {
		break_to &= smbd_lease->data.breaking_to_required;
		if (smbd_lease->data.breaking_to_required != break_to) {
			/*
			 * Note we don't increment the epoch
			 * here, which might be a bug in
			 * Windows too...
			 */
			smbd_lease->data.breaking_to_required = break_to;
		}
		if (smbd_requ && ((smbd_lease->data.state & delay_mask) ||
					block_breaking)) {
			smbd_lease_add_pending_requ(smbd_lease, smbd_requ);
			return X_SMBD_BREAK_ACTION_BLOCKED;
		}
		return 0;
	} else if (smbd_lease->data.state == break_to) {
		return 0;
	}
	
	/* Need to increment the epoch */
	SMBD_LEASE_EPOCH_INC(smbd_lease);
	/* Ensure we're in sync with current lease state. */
	// fsp_lease_update(lck, fsp);

	if (break_from == X_SMB2_LEASE_NONE) {
		X_LOG(SMB, NOTICE, "Already downgraded oplock to none");
		return 0;
	}

	X_LOG(SMB, DBG, "break from=%u to=%u", break_from, break_to);
	if (break_from == break_to) {
		X_LOG(SMB, NOTICE, "Already downgraded oplock to %u", break_to);
		return 0;
	}

	bool block = require_break(smbd_lease, break_to, delay_mask, epoch, flags);
	lease_key = smbd_lease->data.key;
	new_state = break_to;
	curr_state = break_from;
	if (block && smbd_requ != 0) {
		smbd_lease_add_pending_requ(smbd_lease, smbd_requ);
		return X_SMBD_BREAK_ACTION_SEND | X_SMBD_BREAK_ACTION_BLOCKED;
	} else {
		return X_SMBD_BREAK_ACTION_SEND;
	}
}

/* downgrade_lease() */
static NTSTATUS smbd_lease_process_break(x_smbd_lease_t *smbd_lease,
		x_smbd_requ_state_lease_break_t &state,
		x_smbd_requ_id_list_t &requ_list)
{
	bool modified = false;
	auto lock = smbd_lease_lock(smbd_lease);
	if (!smbd_lease->data.breaking) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	if ((state.in_state & smbd_lease->data.breaking_to_requested) != state.in_state) {
		X_LOG(SMB, DBG, "Attempt to upgrade from %d to %d - expected %d",
				(int)smbd_lease->data.state, (int)state.in_state,
				(int)smbd_lease->data.breaking_to_requested);
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}

	smbd_lease_cancel_timer(smbd_lease);

	X_LOG(SMB, DBG, "breaking from %d to %d - expected %d required %d",
			(int)smbd_lease->data.state, (int)state.in_state,
			(int)smbd_lease->data.breaking_to_requested,
			(int)smbd_lease->data.breaking_to_required);

	if (smbd_lease->data.state != state.in_state) {
		/* TODO should not assert with invalid client in_state */
		smbd_lease->data.state = x_convert_assert<uint8_t>(state.in_state);
		modified = true;
	}

	if ((state.in_state & (~smbd_lease->data.breaking_to_required)) != 0) {
		X_LOG(SMB, DBG, "lease state %d not fully broken from %d to %d",
				(int)state.in_state,
				(int)smbd_lease->data.state,
				(int)smbd_lease->data.breaking_to_required);
		uint8_t break_to = smbd_lease->data.breaking_to_required;
		if (smbd_lease->data.state & (~X_SMB2_LEASE_READ)) {
			/*
			 * Here we break in steps, as windows does
			 * see the breaking3 and v2_breaking3 tests.
			 */
			break_to |= X_SMB2_LEASE_READ;
		}
		/* for unknown reason windows server does not increase epoch
		 * when it break RH -> R, see v2_breaking3
		 */
		if (smbd_lease->data.state & X_SMB2_LEASE_WRITE) {
			SMBD_LEASE_EPOCH_INC(smbd_lease);
		}
		state.more_break_from = smbd_lease->data.state;
		state.more_break_to = break_to;
		require_break(smbd_lease, break_to, 0,
				state.more_epoch, state.more_flags);
		state.more_break = true;
		modified = true;
	} else {
		smbd_lease->data.breaking_to_requested = 0;
		smbd_lease->data.breaking_to_required = 0;
		smbd_lease->data.breaking = false;
	}
	if (modified) {
		std::swap(requ_list, smbd_lease->pending_requ_list);
	}
	return NT_STATUS_OK;
}

NTSTATUS x_smbd_lease_process_break(x_smbd_requ_state_lease_break_t &state)
{
	auto &lease_key = state.in_key;

	x_smbd_lease_t *smbd_lease;
	NTSTATUS status;
	uint32_t hash = lease_hash(state.in_client_guid, lease_key);

	{
		auto lock = smbd_lease_lock(hash);

		smbd_lease = smbd_lease_find(hash, state.in_client_guid, lease_key);
		if (!smbd_lease) {
			X_LOG(SMB, DBG, "smbd_lease_find failed client %s lease_key %s",
					x_tostr(state.in_client_guid).c_str(),
					x_tostr(lease_key).c_str());
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}
		
		if (!smbd_lease->smbd_object) {
			/* not yet granted */
			X_LOG(SMB, DBG, "smbd_lease_find not granted %s lease_key %s",
					x_tostr(state.in_client_guid).c_str(),
					x_tostr(lease_key).c_str());
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}

		++smbd_lease->refcnt;
	}

	x_smbd_requ_id_list_t requ_list;
	status = smbd_lease_process_break(smbd_lease, state, requ_list);
	smbd_lease_decref(smbd_lease);

	x_smbd_wakeup_requ_list(requ_list);
	return status;
}

static long smbd_lease_break_timeout(x_timer_job_t *timer)
{
	/* we already have a ref on smbd_chan when adding timer */
	x_smbd_lease_t *smbd_lease = X_CONTAINER_OF(timer, x_smbd_lease_t, timer);
	x_smbd_requ_id_list_t requ_list;
	{
		auto lock = smbd_lease_lock(smbd_lease);
		/* down grade lease  TODO */
		smbd_lease->data.breaking_to_requested = 0;
		smbd_lease->data.breaking_to_required = 0;
		smbd_lease->data.breaking = false;
		if (smbd_lease->data.state != X_SMB2_LEASE_NONE) {
			smbd_lease->data.state = X_SMB2_LEASE_NONE;
			std::swap(requ_list, smbd_lease->pending_requ_list);
		}
	}
	smbd_lease_decref(smbd_lease);

	x_smbd_wakeup_requ_list(requ_list);
	return -1;
}

inline x_smbd_lease_t::x_smbd_lease_t(const x_smb2_uuid_t &client_guid,
		const x_smb2_lease_key_t &lease_key,
		uint32_t hash, uint8_t version,
		uint16_t epoch)
	: client_guid(client_guid), data{lease_key, version, 0, uint16_t(epoch + 1)}
	, hash(hash)
{
	X_SMBD_COUNTER_INC_CREATE(lease, 1);
}

int x_smbd_lease_pool_init(uint32_t count, uint32_t mutex_count)
{
	g_smbd_lease_pool.init(count, mutex_count);
	return 0;
}

struct x_smbd_lease_list_t : x_ctrl_handler_t
{
	bool output(std::string &data) override;
	uint32_t next_bucket_idx = 0;
};

bool x_smbd_lease_list_t::output(std::string &data)
{
	std::ostringstream os;

	size_t count = 0;
	while (next_bucket_idx < g_smbd_lease_pool.hashtable.buckets.size() && count == 0) {
		auto &bucket = g_smbd_lease_pool.hashtable.buckets[next_bucket_idx];
		auto lock = smbd_lease_lock(next_bucket_idx);

		for (x_dqlink_t *link = bucket.get_front();
				link; link = link->get_next()) {
			auto item = smbd_lease_hash_traits::container(link);
			os << next_bucket_idx << ' ' << item->refcnt << ' '
				<< item->data.key << ' '
				<< item->client_guid << ' ' << int(item->data.version) << ' '
				<< int(item->data.state) << ' ' << int(item->data.epoch) << ' '
				<< (item->data.breaking ? 'B' : '-') << ' ' << int(item->data.breaking_to_requested) << ' '
				<< int(item->data.breaking_to_required) << std::endl;
			++count;
		}
		++next_bucket_idx;
	}
	if (count > 0) {
		data = os.str();
		return true;
	} else {
		return false;
	}
}

x_ctrl_handler_t *x_smbd_lease_list_create()
{
	return new x_smbd_lease_list_t;
}
