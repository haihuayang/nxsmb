
#include "smbd_lease.hxx"
#include "smbd_stats.hxx"
#include "smbd_open.hxx"
#include "smbd_ctrl.hxx"
#include "include/hashtable.hxx"
#include <mutex>

struct x_smbd_lease_t
{
	x_smbd_lease_t(const x_smb2_uuid_t &client_guid,
			const x_smb2_lease_key_t &lease_key,
			uint32_t hash, uint8_t version);
	x_dqlink_t hash_link;
	x_timerq_entry_t timer;
	const x_smb2_uuid_t client_guid;
	const x_smb2_lease_key_t lease_key;
	x_smbd_object_t * smbd_object{}; // protected by bucket mutex
	x_smbd_stream_t * smbd_stream{}; // protected by bucket mutex
	const uint32_t hash;
	uint32_t refcnt{1}; // protected by bucket mutex
	uint32_t open_cnt{0};
	const uint8_t version;
	uint8_t lease_state{0};
	uint16_t epoch{0};
	bool breaking{false};
	uint8_t breaking_to_requested{0}, breaking_to_required{0};
};

std::ostream &operator<<(std::ostream &os, const x_smb2_uuid_t &val);

std::ostream &operator<<(std::ostream &os, const x_smb2_uuid_t &val)
{
	char buf[80];
	snprintf(buf, sizeof buf, "%016lx-%016lx", val.data[0], val.data[1]);
	return os << buf;
}

X_DECLARE_MEMBER_TRAITS(smbd_lease_hash_traits, x_smbd_lease_t, hash_link)

static uint32_t lease_hash(const x_smb2_uuid_t &client_guid, const x_smb2_lease_key_t &lease_key)
{
	uint64_t hash = client_guid.data[0];
	hash = hash * 31 + client_guid.data[1];
	hash = hash * 31 + lease_key.data[0];
	hash = hash * 31 + lease_key.data[1];
	return uint32_t((hash >> 32) ^ hash);
}


template <typename HashTraits>
struct smbd_npool_t
{
	void init(uint32_t count, uint32_t mutex_count) {
		uint32_t bucket_size = x_convert_assert<uint32_t>(x_next_2_power(count));
		hashtable.init(bucket_size);
		capacity = count;
		std::vector<std::mutex> tmp(mutex_count);
		std::swap(mutex, tmp);
	}

	x_hashtable_t<HashTraits> hashtable;
	std::atomic<uint32_t> count;
	uint32_t capacity;
	std::vector<std::mutex> mutex;
};

using smbd_lease_pool_t = smbd_npool_t<smbd_lease_hash_traits>;

static smbd_lease_pool_t g_smbd_lease_pool;

uint8_t x_smbd_lease_get_state(const x_smbd_lease_t *smbd_lease)
{
	return smbd_lease->lease_state;
}

bool x_smbd_lease_is_breaking(const x_smbd_lease_t *smbd_lease)
{
	return smbd_lease->breaking;
}
#if 0
/* return true if already in breaking, otherwise set breaking and return false */
bool x_smbd_lease_set_breaking_if(const x_smbd_lease_t *smbd_lease)
{
	if (smbd_lease->breaking) {
		return true;
	} else {
		smbd_lease->breaking = false;
		return false;
	}
}
#endif
static inline auto smbd_lease_lock(uint32_t hash)
{
	return std::lock_guard<std::mutex>(g_smbd_lease_pool.mutex[hash % g_smbd_lease_pool.mutex.size()]);
}

static inline auto smbd_lease_lock(const x_smbd_lease_t *smbd_lease)
{
	return smbd_lease_lock(smbd_lease->hash);
}

bool x_smbd_lease_match(const x_smbd_lease_t *smbd_lease,
		x_smbd_object_t *smbd_object,
		void *smbd_stream)
{
	auto lock = smbd_lease_lock(smbd_lease);
	if (smbd_lease->smbd_object) {
		return smbd_lease->smbd_object == smbd_object &&
			(void *)smbd_lease->smbd_stream == smbd_stream;
	}
	return true;
}

static bool smbd_lease_match(const x_smbd_lease_t *smbd_lease,
		const x_smb2_uuid_t &client_guid,
		const x_smb2_lease_key_t &lkey)
{
	return smbd_lease->client_guid == client_guid && smbd_lease->lease_key == lkey;
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
		X_ASSERT(!smbd_lease->breaking);
		if (smbd_lease->smbd_object) {
			x_smbd_object_release(smbd_lease->smbd_object, smbd_lease->smbd_stream);
		}
		X_SMBD_COUNTER_INC(lease_delete, 1);
		delete smbd_lease;
	}
}

void x_smbd_lease_release(x_smbd_lease_t *smbd_lease)
{
	smbd_lease_decref(smbd_lease);
}

static inline void smbd_lease_cancel_timer(x_smbd_lease_t *smbd_lease)
{
	if (x_smbd_cancel_timer(x_smbd_timer_t::BREAK, &smbd_lease->timer)) {
		X_ASSERT(--smbd_lease->refcnt > 0);
	}
}

void x_smbd_lease_close(x_smbd_lease_t *smbd_lease)
{
	{
		auto lock = smbd_lease_lock(smbd_lease);
		X_ASSERT(smbd_lease->open_cnt > 0);
		if (--smbd_lease->open_cnt == 0) {
			if (smbd_lease->breaking) {
				smbd_lease_cancel_timer(smbd_lease);
				smbd_lease->breaking = false;
				smbd_lease->lease_state = 0;
			}
		}
	}
	smbd_lease_decref(smbd_lease);
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
		const x_smb2_lease_key_t &lease_key,
		uint8_t version,
		bool create_if)
{
	uint32_t hash = lease_hash(client_guid, lease_key);

	auto lock = smbd_lease_lock(hash);
	x_smbd_lease_t *smbd_lease = smbd_lease_find(hash, client_guid, lease_key);
	if (smbd_lease) {
		++smbd_lease->refcnt;
	} else if (create_if) {
		smbd_lease = new x_smbd_lease_t(client_guid, lease_key,
				hash, version);
		g_smbd_lease_pool.hashtable.insert(smbd_lease, hash);
	}
	return smbd_lease;
}

bool x_smbd_lease_grant(x_smbd_lease_t *smbd_lease,
		x_smb2_lease_t &lease,
		uint8_t granted,
		x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream,
		bool &new_lease)
{
	auto lock = smbd_lease_lock(smbd_lease);

	if (!smbd_lease->smbd_object) {
		smbd_lease->smbd_object = smbd_object;
		smbd_lease->smbd_stream = smbd_stream;
		lease.state = smbd_lease->lease_state = granted;
		smbd_lease->epoch = ++lease.epoch;
		new_lease = true;
		++smbd_lease->open_cnt;
		++smbd_lease->refcnt;
		return true;
	}

	if (smbd_object != smbd_lease->smbd_object
			|| smbd_stream != smbd_lease->smbd_stream) {
		return false;
	}

	uint32_t existing = smbd_lease->lease_state;
	uint32_t requested = lease.state;

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
	do_upgrade &= !smbd_lease->breaking;

	if (do_upgrade) {
		smbd_lease->lease_state = granted;
		smbd_lease->epoch++;
	}

	lease.state = smbd_lease->lease_state;
	lease.epoch = smbd_lease->epoch;

	if (smbd_lease->breaking) {
		lease.flags |= SMB2_LEASE_FLAG_BREAK_IN_PROGRESS;
	} else {
		lease.flags &= ~SMB2_LEASE_FLAG_BREAK_IN_PROGRESS;
	}

	++smbd_lease->open_cnt;
	++smbd_lease->refcnt;
	return true;
}

/* samba process_oplock_break_message */
bool x_smbd_lease_require_break(x_smbd_lease_t *smbd_lease,
		x_smb2_lease_key_t &lease_key,
		uint8_t &new_state, /* in out */
		uint8_t &curr_state,
		uint16_t &epoch,
		uint32_t &flags)
{
	auto lock = smbd_lease_lock(smbd_lease);

	uint8_t break_from = smbd_lease->lease_state;
	uint8_t break_to = new_state & break_from;
	if (smbd_lease->breaking) {
		break_to &= smbd_lease->breaking_to_required;
		if (smbd_lease->breaking_to_required != break_to) {
			/*
			 * Note we don't increment the epoch
			 * here, which might be a bug in
			 * Windows too...
			 */
			smbd_lease->breaking_to_required = break_to;
		}
		return false;
	} else if (smbd_lease->lease_state == break_to) {
		return false;
	} else if (smbd_lease->lease_state == X_SMB2_LEASE_READ) {
		smbd_lease->lease_state = X_SMB2_LEASE_NONE;
		/* Need to increment the epoch */
		smbd_lease->epoch++;
	} else {
		smbd_lease->breaking = true;
		smbd_lease->breaking_to_required = break_to;
		smbd_lease->breaking_to_requested = break_to;
		smbd_lease->epoch++;
		/* set timer */
	}
	/* Ensure we're in sync with current lease state. */
	// fsp_lease_update(lck, fsp);

	if (break_from == X_SMB2_LEASE_NONE) {
		X_LOG_NOTICE("Already downgraded oplock to none");
		return false;
	}

	X_LOG_DBG("break_from=%u break_to=%u", break_from, break_to);
	if (break_from == break_to) {
		X_LOG_NOTICE("Already downgraded oplock to %u", break_to);
		return false;
	}

	if (break_from != X_SMB2_LEASE_READ || break_to == X_SMB2_LEASE_NONE) {
		smbd_lease_incref(smbd_lease);
		x_smbd_add_timer(x_smbd_timer_t::BREAK, &smbd_lease->timer);
	}
	lease_key = smbd_lease->lease_key;
	new_state = break_to;
	curr_state = break_from;
	epoch = (smbd_lease->version > 1) ? smbd_lease->epoch : 0;
	flags = (break_from != X_SMB2_LEASE_READ) ? SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED : 0;
	return true;
}

/* downgrade_lease() */
static NTSTATUS smbd_lease_process_break(x_smbd_lease_t *smbd_lease,
		const x_smb2_state_lease_break_t &state,
		bool &modified)
{
	auto lock = smbd_lease_lock(smbd_lease);
	if (!smbd_lease->breaking) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	smbd_lease_cancel_timer(smbd_lease);

	if ((state.in_state & smbd_lease->breaking_to_requested) != state.in_state) {
		X_LOG_DBG("Attempt to upgrade from %d to %d - expected %d\n",
				(int)smbd_lease->lease_state, (int)state.in_state,
				(int)smbd_lease->breaking_to_requested);
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}

	if (smbd_lease->lease_state != state.in_state) {
		/* TODO should not assert with invalid client in_state */
		smbd_lease->lease_state = x_convert_assert<uint8_t>(state.in_state);
		modified = true;
	}

	if ((state.in_state & (~smbd_lease->breaking_to_required)) != 0) {
		X_LOG_DBG("lease state %d not fully broken from %d to %d\n",
				(int)state.in_state,
				(int)smbd_lease->lease_state,
				(int)smbd_lease->breaking_to_required);
		smbd_lease->breaking_to_requested = smbd_lease->breaking_to_required;
		if (smbd_lease->lease_state & (~X_SMB2_LEASE_READ)) {
			/*
			 * Here we break in steps, as windows does
			 * see the breaking3 and v2_breaking3 tests.
			 */
			smbd_lease->breaking_to_requested |= X_SMB2_LEASE_READ;
		}
		modified = true;
		return NT_STATUS_OPLOCK_BREAK_IN_PROGRESS;
	}

	X_LOG_DBG("breaking from %d to %d - expected %d\n",
			(int)smbd_lease->lease_state, (int)state.in_state,
			(int)smbd_lease->breaking_to_requested);

	smbd_lease->breaking_to_requested = 0;
	smbd_lease->breaking_to_required = 0;
	smbd_lease->breaking = false;
	return NT_STATUS_OK;
}

NTSTATUS x_smbd_lease_process_break(const x_smb2_state_lease_break_t &state)
{
	bool modified = false;
	auto &client_guid = x_smbd_conn_curr_client_guid();
	auto &lease_key = state.in_key;

	x_smbd_lease_t *smbd_lease;
	NTSTATUS status;
	uint32_t hash = lease_hash(client_guid, lease_key);

	{
		auto lock = smbd_lease_lock(hash);

		smbd_lease = smbd_lease_find(hash, client_guid, lease_key);
		if (!smbd_lease) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		
		if (!smbd_lease->smbd_object) {
			/* not yet granted */
			return NT_STATUS_INVALID_PARAMETER;
		}

		++smbd_lease->refcnt;
	}

	status = smbd_lease_process_break(smbd_lease, state, modified);
	if (modified) {
		x_smbd_object_op_break_lease(smbd_lease->smbd_object, smbd_lease->smbd_stream);
	}
	if (NT_STATUS_EQUAL(status, NT_STATUS_OPLOCK_BREAK_IN_PROGRESS)) {
		X_TODO;
	}
	smbd_lease_decref(smbd_lease);
	return status;
}

static void smbd_lease_break_timeout(x_timerq_entry_t *timerq_entry)
{
	/* we already have a ref on smbd_chan when adding timer */
	x_smbd_lease_t *smbd_lease = X_CONTAINER_OF(timerq_entry, x_smbd_lease_t, timer);
	bool modified = false;
	{
		auto lock = smbd_lease_lock(smbd_lease);
		/* down grade lease  TODO */
		smbd_lease->breaking_to_requested = 0;
		smbd_lease->breaking_to_required = 0;
		smbd_lease->breaking = false;
		if (smbd_lease->lease_state != X_SMB2_LEASE_NONE) {
			smbd_lease->lease_state = X_SMB2_LEASE_NONE;
			modified = true;
		}
	}
	if (modified) {
		x_smbd_object_op_break_lease(smbd_lease->smbd_object,
				smbd_lease->smbd_stream);
	}
	smbd_lease_decref(smbd_lease);
}

inline x_smbd_lease_t::x_smbd_lease_t(const x_smb2_uuid_t &client_guid,
		const x_smb2_lease_key_t &lease_key,
		uint32_t hash, uint8_t version)
	: client_guid(client_guid), lease_key(lease_key)
	, hash(hash), version(version)
{
	timer.func = smbd_lease_break_timeout;
	X_SMBD_COUNTER_INC(lease_create, 1);
}

int x_smbd_lease_pool_init(uint32_t count, uint32_t mutex_count)
{
	g_smbd_lease_pool.init(count, mutex_count);
	return 0;
}

struct x_smbd_lease_list_t : x_smbd_ctrl_handler_t
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
				<< item->lease_key << ' '
				<< item->client_guid << ' ' << int(item->version) << ' '
				<< int(item->lease_state) << ' ' << int(item->epoch) << ' '
				<< (item->breaking ? 'B' : '-') << ' ' << int(item->breaking_to_requested) << ' '
				<< int(item->breaking_to_required) << std::endl;
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

x_smbd_ctrl_handler_t *x_smbd_lease_list_create()
{
	return new x_smbd_lease_list_t;
}
