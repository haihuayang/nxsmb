
#include "smbd.hxx"
#include "smbd_replay.hxx"
#include "smbd_hashtable.hxx"
#include "smbd_open.hxx"
#include "nxfsd_stats.hxx"

struct replay_item_t
{
	replay_item_t(const x_smb2_uuid_t &client_guid,
			const x_smb2_uuid_t &create_guid)
		: client_guid(client_guid), create_guid(create_guid)
	{
		X_SMBD_COUNTER_INC_CREATE(smbd_replay, 1);
	}

	~replay_item_t()
	{
		X_SMBD_COUNTER_INC_DELETE(smbd_replay, 1);
	}

	x_dqlink_t hash_link; // replay cache
	const x_smb2_uuid_t client_guid;
	const x_smb2_uuid_t create_guid;
	x_smbd_open_t *smbd_open = nullptr;
};
X_DECLARE_MEMBER_TRAITS(replay_cache_hash_traits, replay_item_t, hash_link)

using replay_cache_t = x_smbd_hashtable_t<replay_cache_hash_traits>;

static replay_cache_t g_replay_cache;

static uint32_t replay_cache_hash(const x_smb2_uuid_t &client_guid,
		const x_smb2_uuid_t &create_guid)
{
	uint64_t hash = create_guid.data[0];
	hash = hash * 31 + client_guid.data[1];
	hash = hash * 31 + create_guid.data[0];
	hash = hash * 31 + create_guid.data[1];
	return uint32_t((hash >> 32) ^ hash);
}

static inline auto replay_cache_lock(uint32_t hash)
{
	return std::lock_guard<std::mutex>(g_replay_cache.mutex[
			hash % g_replay_cache.mutex.size()]);
}

static replay_item_t *replay_cache_find(uint32_t hash,
		const x_smb2_uuid_t &client_guid,
		const x_smb2_uuid_t &create_guid)
{
	return g_replay_cache.hashtable.find(hash,
			[client_guid, create_guid](const replay_item_t &item) {
				return item.client_guid == client_guid &&
					item.create_guid == create_guid;
			});
}

static NTSTATUS smbd_replay_cache_lookup(
		x_smbd_open_t **psmbd_open,
		const x_smb2_uuid_t &client_guid,
		const x_smb2_uuid_t &create_guid,
		bool replay_operation)
{
	uint32_t hash = replay_cache_hash(client_guid, create_guid);

	auto lock = replay_cache_lock(hash);
	replay_item_t *replay_item = replay_cache_find(hash, client_guid,
			create_guid);
	if (!replay_item) {
		replay_item = new replay_item_t(client_guid, create_guid);
		g_replay_cache.hashtable.insert(replay_item, hash);
		return NT_STATUS_FWP_RESERVED;
	} else if (replay_item->smbd_open) {
		if (!replay_operation) {
			return NT_STATUS_DUPLICATE_OBJECTID;
		} else {
			*psmbd_open = x_ref_inc(replay_item->smbd_open);
			return NT_STATUS_OK;
		}
	} else {
		return NT_STATUS_FILE_NOT_AVAILABLE;
	}
}

NTSTATUS x_smbd_replay_cache_lookup(
		x_smbd_open_t **psmbd_open,
		const x_smb2_uuid_t &client_guid,
		const x_smb2_uuid_t &create_guid,
		bool replay_operation)
{
	NTSTATUS status = smbd_replay_cache_lookup(psmbd_open, client_guid,
			create_guid, replay_operation);
	X_LOG(SMB, DBG, "client=%s create=%s open=%p status=%s",
			x_tostr(client_guid).c_str(),
			x_tostr(create_guid).c_str(),
			*psmbd_open, x_ntstatus_str(status));
	return status;
}

void x_smbd_replay_cache_clear(
		const x_smb2_uuid_t &client_guid,
		const x_smb2_uuid_t &create_guid)
{
	uint32_t hash = replay_cache_hash(client_guid, create_guid);
	replay_item_t *replay_item;
	{
		auto lock = replay_cache_lock(hash);
		replay_item = replay_cache_find(hash, client_guid,
				create_guid);
		X_ASSERT(replay_item);
		g_replay_cache.hashtable.remove(replay_item);
	}

	X_LOG(SMB, DBG, "client=%s create=%s open=%p",
			x_tostr(client_guid).c_str(),
			x_tostr(create_guid).c_str(),
			replay_item->smbd_open);
	if (replay_item->smbd_open) {
		x_ref_dec(replay_item->smbd_open);
	}
	delete replay_item;
}

void x_smbd_replay_cache_set(
		const x_smb2_uuid_t &client_guid,
		const x_smb2_uuid_t &create_guid,
		x_smbd_open_t *smbd_open)
{
	uint32_t hash = replay_cache_hash(client_guid, create_guid);

	{
		auto lock = replay_cache_lock(hash);
		replay_item_t *replay_item = replay_cache_find(hash, client_guid,
				create_guid);
		X_ASSERT(replay_item);
		X_ASSERT(!replay_item->smbd_open);
		replay_item->smbd_open = x_ref_inc(smbd_open);
	}
	X_LOG(SMB, DBG, "client=%s create=%s open=%p",
			x_tostr(client_guid).c_str(),
			x_tostr(create_guid).c_str(),
			smbd_open);
}
#if 0
bool x_smbd_replay_cache_add(
		const x_smb2_uuid_t &client_guid,
		const x_smb2_uuid_t &create_guid,
		x_smbd_open_t *smbd_open)
{
	uint32_t hash = replay_cache_hash(client_guid, create_guid);

	auto lock = replay_cache_lock(hash);
	replay_item_t *replay_item = replay_cache_find(hash, client_guid,
			create_guid);
	if (replay_item) {
		return false;
	}
	replay_item = new replay_item_t(client_guid, create_guid);
	replay_item->smbd_open = x_ref_inc(smbd_open);
	g_replay_cache.hashtable.insert(replay_item, hash);
	return true;
}
#endif

int x_smbd_replay_cache_init(uint32_t count, uint32_t mutex_count)
{
	g_replay_cache.init(count, mutex_count);
	return 0;
}


