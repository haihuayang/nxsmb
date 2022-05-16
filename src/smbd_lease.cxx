
#include "smbd_lease.hxx"
#include "smbd_open.hxx"
#include "include/hashtable.hxx"
#include <mutex>

X_DECLARE_MEMBER_TRAITS(smbd_lease_hash_traits, x_smbd_lease_t, hash_link)

static uint32_t lease_hash(const x_smb2_uuid_t &client_guid, const x_smb2_lease_key_t &lease_key)
{
	/* TODO better hash algorithm */
	uint64_t hash = 0;
	const uint64_t *p = reinterpret_cast<const uint64_t *>(&client_guid);
	hash ^= p[0];
	hash ^= p[1];
	p = lease_key.data.data();
	hash ^= p[0];
	hash ^= p[1];
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

x_smbd_lease_t::x_smbd_lease_t(const x_smb2_uuid_t &client_guid,
		const x_smb2_lease_key_t &lease_key, uint32_t hash)
	: client_guid(client_guid), lease_key(lease_key), hash(hash), refcnt(1)
{
}

uint8_t x_smbd_lease_get_state(const x_smbd_lease_t *smbd_lease)
{
	return smbd_lease->lease_state;
}

bool x_smbd_lease_is_breaking(const x_smbd_lease_t *smbd_lease)
{
	return smbd_lease->breaking;
}

bool x_smbd_lease_match(const x_smbd_lease_t *smbd_lease,
		const x_smb2_uuid_t &client_guid,
		const x_smb2_lease_key_t &lkey)
{
	return smbd_lease->client_guid == client_guid && smbd_lease->lease_key == lkey;
}

void x_smbd_lease_release(x_smbd_lease_t *smbd_lease)
{
	{
		std::lock_guard<std::mutex> lock(g_smbd_lease_pool.mutex[smbd_lease->hash % g_smbd_lease_pool.mutex.size()]);
		if (--smbd_lease->refcnt == 0) {
			g_smbd_lease_pool.hashtable.remove(smbd_lease);
		}
	}

	if (smbd_lease->refcnt == 0) {
		delete smbd_lease;
	}
}

/* TODO lease should ref smbd_object */
x_smbd_lease_t *x_smbd_lease_find(
		const x_smb2_uuid_t &client_guid,
		const x_smb2_lease_key_t &lease_key)
{
	uint32_t hash = lease_hash(client_guid, lease_key);

	std::lock_guard<std::mutex> lock(g_smbd_lease_pool.mutex[hash % g_smbd_lease_pool.mutex.size()]);
	x_smbd_lease_t *smbd_lease = g_smbd_lease_pool.hashtable.find(hash,
			[client_guid, lease_key](const x_smbd_lease_t &smbd_lease) {
				return x_smbd_lease_match(&smbd_lease, client_guid, lease_key);
			});
	if (smbd_lease) {
		++smbd_lease->refcnt;
	}
	return smbd_lease;
}

x_smbd_lease_t *x_smbd_lease_grant(
		const x_smb2_uuid_t &client_guid,
		x_smb2_lease_t *lease,
		uint8_t granted,
		x_smbd_object_t *smbd_object)
{
	uint32_t hash = lease_hash(client_guid, lease->key);

	std::lock_guard<std::mutex> lock(g_smbd_lease_pool.mutex[hash % g_smbd_lease_pool.mutex.size()]);
	x_smbd_lease_t *smbd_lease = g_smbd_lease_pool.hashtable.find(hash,
			[client_guid, lease](const x_smbd_lease_t &smbd_lease) {
				return x_smbd_lease_match(&smbd_lease, client_guid, lease->key);
			});
	if (!smbd_lease) {
		smbd_lease = new x_smbd_lease_t(client_guid, lease->key, hash);
		lease->state = smbd_lease->lease_state = granted;
		smbd_lease->lease_epoch = ++lease->epoch;
		smbd_lease->smbd_object = smbd_object;
		g_smbd_lease_pool.hashtable.insert(smbd_lease, hash);
		return smbd_lease;
	}

	X_ASSERT(smbd_object == smbd_lease->smbd_object);

	uint32_t existing = smbd_lease->lease_state;
	uint32_t requested = lease->state;

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
		smbd_lease->lease_epoch++;
	}

	lease->epoch = smbd_lease->lease_epoch;

	if (smbd_lease->breaking) {
		lease->flags |= SMB2_LEASE_FLAG_BREAK_IN_PROGRESS;
	} else {
		lease->flags &= ~SMB2_LEASE_FLAG_BREAK_IN_PROGRESS;
	}
	++smbd_lease->refcnt;
	return smbd_lease;
}

int x_smbd_lease_pool_init(uint32_t count, uint32_t mutex_count)
{
	g_smbd_lease_pool.init(count, mutex_count);
	return 0;
}


