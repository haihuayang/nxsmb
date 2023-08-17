
#include "smbd_open.hxx"
#include "smbd_stats.hxx"

x_smbd_object_t::x_smbd_object_t(const std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		long priv_data, uint64_t hash, const std::u16string &path)
	: smbd_volume(smbd_volume), priv_data(priv_data), hash(hash), path(path)
{
	X_SMBD_COUNTER_INC(object_create, 1);
}

x_smbd_object_t::~x_smbd_object_t()
{
	X_SMBD_COUNTER_INC(object_delete, 1);
}

x_smb2_state_create_t::~x_smb2_state_create_t()
{
	if (smbd_object) {
		x_smbd_object_release(smbd_object, smbd_stream);
	}
	if (smbd_lease) {
		x_smbd_lease_release(smbd_lease);
	}
}

struct smbd_object_pool_t
{
	static const uint64_t cache_time = 60ul * 1000000000; // 60 second
	struct bucket_t
	{
		x_sdqueue_t head;
		std::mutex mutex;
	};
	std::vector<bucket_t> buckets;
	std::atomic<uint32_t> count{0}, unused_count{0};
};

static smbd_object_pool_t smbd_object_pool;

std::pair<bool, uint64_t> x_smbd_hash_path(const x_smbd_volume_t &smbd_volume,
		const std::u16string &path)
{
	auto [ ok, hash ] = x_strcase_hash(path);
	if (ok) {
		return { true, hash ^ smbd_volume.volume_id };
	} else {
		return { false, 0 };
	}
}

/* call hold bucket lock */
static x_smbd_object_t *smbd_object_lookup_intl(
		const std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		smbd_object_pool_t::bucket_t &bucket,
		const std::u16string &path,
		uint64_t hash)
{
	for (x_dqlink_t *link = bucket.head.get_front(); link; link = link->get_next()) {
		x_smbd_object_t *elem = X_CONTAINER_OF(link, x_smbd_object_t, hash_link);
		if (elem->hash == hash && elem->smbd_volume == smbd_volume
				&& x_strcase_equal(elem->path, path)) {
			return elem;
		}
	}
	return nullptr;
}

/**
 * open, find object in pool, 
 	if exist and open count == 0 then
		delink freelist
	if notexist
		if create
 * close, reduce object's open count, if zero, link to freelist
 */
/* TODO case insensitive */
x_smbd_object_t *x_smbd_object_lookup(
		const std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		const std::u16string &path,
		uint64_t path_data,
		bool create_if,
		uint64_t hash)
{
	auto &pool = smbd_object_pool;
	auto bucket_idx = hash % pool.buckets.size();
	auto &bucket = pool.buckets[bucket_idx];

	auto lock = std::lock_guard(bucket.mutex);
	x_smbd_object_t *smbd_object = smbd_object_lookup_intl(
			smbd_volume, bucket, path, hash);

	if (!smbd_object) {
		if (!create_if) {
			return nullptr;
		}
		smbd_object = smbd_volume->ops->allocate_object(
				smbd_volume, path_data, hash, path);
		X_ASSERT(smbd_object);
		bucket.head.push_front(&smbd_object->hash_link);
		++pool.count;
	} else {
		smbd_object->incref();
	}
	/* move it to head of the bucket to make latest used elem */
	if (&smbd_object->hash_link != bucket.head.get_front()) {
		smbd_object->hash_link.remove();
		bucket.head.push_front(&smbd_object->hash_link);
	}
	return smbd_object;
}

void x_smbd_object_new_release(x_smbd_object_t *smbd_object)
{
	auto &pool = smbd_object_pool;
	auto bucket_idx = smbd_object->hash % pool.buckets.size();
	auto &bucket = pool.buckets[bucket_idx];
	bool free = false;

	{
		/* TODO optimize when use_count > 1 */
		auto lock = std::lock_guard(bucket.mutex);

		X_ASSERT(smbd_object->use_count > 0);
		if (--smbd_object->use_count == 0) {
			bucket.head.remove(&smbd_object->hash_link);
			free = true;
		}
	}
	if (free) {
		smbd_object->smbd_volume->ops->destroy_object(smbd_object);
	}
}

NTSTATUS x_smbd_open_object_only(x_smbd_object_t **p_smbd_object,
		std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		const std::u16string &path,
		long path_priv_data,
		bool create_if)
{
	auto [ ok, hash ] = x_smbd_hash_path(*smbd_volume, path);
	if (!ok) {
		return NT_STATUS_ILLEGAL_CHARACTER;
	}

	x_smbd_object_t *smbd_object = x_smbd_object_lookup(smbd_volume, path,
			path_priv_data, create_if, hash);
	if (!smbd_object) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	NTSTATUS status = NT_STATUS_OK;
	{
		auto lock = std::lock_guard(smbd_object->mutex);
		if (!(smbd_object->flags & x_smbd_object_t::flag_initialized)) {
			status = smbd_volume->ops->initialize_object(smbd_object);
			smbd_object->flags = x_smbd_object_t::flag_initialized;
		}
	}

	if (!NT_STATUS_IS_OK(status)) {
		x_smbd_object_new_release(smbd_object);
		return status;
	}
	*p_smbd_object = smbd_object;
	return status;
}


struct smbd_defer_rename_evt_t
{
	static void func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user)
	{
		smbd_defer_rename_evt_t *evt = X_CONTAINER_OF(fdevt_user,
				smbd_defer_rename_evt_t, base);
		x_smbd_requ_t *smbd_requ = evt->smbd_requ;
		X_LOG_DBG("evt=%p, requ=%p, smbd_conn=%p", evt, smbd_requ, smbd_conn);

		auto state = smbd_requ->release_state<x_smb2_state_rename_t>();
		if (x_smbd_requ_async_remove(smbd_requ) && smbd_conn) {
			NTSTATUS status = x_smbd_open_rename(smbd_requ,
					state);
			if (!NT_STATUS_EQUAL(status, NT_STATUS_PENDING)) {
				smbd_requ->save_requ_state(state);
				smbd_requ->async_done_fn(smbd_conn, smbd_requ, status);
			}
		}

		delete evt;
	}

	explicit smbd_defer_rename_evt_t(x_smbd_requ_t *smbd_requ)
		: base(func), smbd_requ(smbd_requ)
	{
	}

	~smbd_defer_rename_evt_t()
	{
		x_smbd_ref_dec(smbd_requ);
	}

	x_fdevt_user_t base;
	x_smbd_requ_t * const smbd_requ;
};

/* rename_internals_fsp */
static NTSTATUS rename_object_intl(smbd_object_pool_t::bucket_t &new_bucket,
		smbd_object_pool_t::bucket_t &old_bucket,
		const std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		x_smbd_object_t *old_object,
		const std::u16string &new_path,
		std::u16string &old_path,
		uint64_t new_hash)
{
	x_smbd_object_t *new_object = smbd_object_lookup_intl(smbd_volume,
			new_bucket, new_path, new_hash);
	if (new_object && new_object->exists()) {
		/* TODO replace forced */
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	if (new_object) {
		/* not exists, should none refer it??? */
		new_bucket.head.remove(&new_object->hash_link);
		X_ASSERT(new_object->use_count == 0);
		delete new_object;
	}

	NTSTATUS status = smbd_volume->ops->rename_object(old_object,
			/* TODO replace */
			false, new_path);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	old_path = old_object->path;
	old_bucket.head.remove(&old_object->hash_link);
	old_object->hash = new_hash;
	old_object->path = new_path;
	new_bucket.head.push_front(&old_object->hash_link);
	return NT_STATUS_OK;
}

/* caller locked smbd_object */
static bool delay_rename_for_lease_break(x_smbd_object_t *smbd_object,
		x_smbd_sharemode_t *smbd_sharemode,
		x_smbd_open_t *smbd_open)
{
	/* this function is called when rename a file or
	 * rename/delete a dir. for unknown reason, it skips lease break
	 * for files if the renamer is not granted lease. but for dir,
	 * it cannot skip.
	 */
	if (smbd_open->get_oplock_level() != X_SMB2_OPLOCK_LEVEL_LEASE &&
			x_smbd_open_is_data(smbd_open)) {
		return false;
	}

	uint32_t break_count = 0;
	bool delay = false;
	auto &open_list = smbd_sharemode->open_list;
	x_smbd_open_t *curr_open;
	for (curr_open = open_list.get_front(); curr_open; curr_open = open_list.next(curr_open)) {
		if (curr_open->open_state.oplock_level != X_SMB2_OPLOCK_LEVEL_LEASE) {
			continue;
		}

		if (smbd_open->get_oplock_level() == X_SMB2_OPLOCK_LEVEL_LEASE &&
				smbd_open->smbd_lease == curr_open->smbd_lease) {
			continue;
		}

		uint8_t e_lease_type = x_smbd_lease_get_state(curr_open->smbd_lease);
		if ((e_lease_type & X_SMB2_LEASE_HANDLE) == 0) {
			continue;
		}

		delay = true;
		uint8_t break_to = x_convert<uint8_t>(e_lease_type & ~X_SMB2_LEASE_HANDLE);
		++break_count;
		x_smbd_open_break_lease(curr_open, nullptr, nullptr, break_to);
	}
	return delay;
}

static void smbd_rename_cancel(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	x_smbd_object_t *smbd_object = smbd_requ->smbd_open->smbd_object;
	x_smbd_sharemode_t *sharemode = x_smbd_open_get_sharemode(
			smbd_requ->smbd_open);

	{
		auto lock = std::lock_guard(smbd_object->mutex);
		sharemode->defer_rename_list.remove(smbd_requ);
	}
	x_smbd_conn_post_cancel(smbd_conn, smbd_requ, NT_STATUS_CANCELLED);
}

static std::u16string get_parent_path(
		const std::u16string &path)
{
	X_ASSERT(!path.empty());
	std::u16string parent_path;
	auto sep = path.rfind('\\');
	if (sep != std::u16string::npos) {
		parent_path = path.substr(0, sep);
	}
	return parent_path;
}

static NTSTATUS parent_dirname_compatible_open(
		std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		const std::u16string &path)
{
	if (path.empty()) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	std::u16string parent_path = get_parent_path(path);
	x_smbd_object_t *smbd_object = nullptr;
	NTSTATUS status = x_smbd_open_object_only(&smbd_object,
			smbd_volume, parent_path, 0, false);
	if (!smbd_object) {
		return NT_STATUS_OK;
	}

	status = NT_STATUS_OK;
	const x_smbd_open_t *curr_open;
	auto &open_list = smbd_object->sharemode.open_list;
	auto lock = std::lock_guard(smbd_object->mutex);
	for (curr_open = open_list.get_front(); curr_open; curr_open = open_list.next(curr_open)) {
		if ((curr_open->open_state.access_mask & idl::SEC_STD_DELETE) ||
				((curr_open->open_state.access_mask & idl::SEC_DIR_ADD_FILE) && 
				 !(curr_open->open_state.share_access & X_SMB2_FILE_SHARE_WRITE))) {
			X_LOG_DBG("access_mask=0x%x share_access=%d STATUS_SHARING_VIOLATION",
					curr_open->open_state.access_mask,
					curr_open->open_state.share_access);
			status = NT_STATUS_SHARING_VIOLATION;
			break;
		}
	}
	x_smbd_object_release(smbd_object, nullptr);
	return status;
}

NTSTATUS x_smbd_object_rename(x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		const std::u16string &new_path,
		std::unique_ptr<x_smb2_state_rename_t> &state)
{
	auto &smbd_volume = smbd_object->smbd_volume;
	x_smbd_sharemode_t *sharemode = x_smbd_open_get_sharemode(
			smbd_requ->smbd_open);

	auto [ ok, new_hash ] = x_smbd_hash_path(*smbd_volume, new_path);
	if (!ok) {
		return NT_STATUS_ILLEGAL_CHARACTER;
	}

	NTSTATUS status;
	if (!smbd_open->smbd_stream) {
		status = parent_dirname_compatible_open(smbd_object->smbd_volume, new_path);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	auto lock = std::lock_guard(smbd_object->mutex);

	if (delay_rename_for_lease_break(smbd_object, sharemode, smbd_open)) {
		smbd_requ->save_requ_state(state);
		/* TODO does it need a timer? can break timer always wake up it? */
		x_smbd_ref_inc(smbd_requ);
		sharemode->defer_rename_list.push_back(smbd_requ);
		/* windows server do not send interim response in renaming */
		x_smbd_requ_async_insert(smbd_requ, smbd_rename_cancel, -1);
		return NT_STATUS_PENDING;
	}

	if (smbd_open->smbd_stream) {
		if (x_strcase_equal(smbd_open->smbd_stream->name, state->in_stream_name)) {
			return NT_STATUS_OK;
		}
		return smbd_object->smbd_volume->ops->rename_stream(smbd_object,
				smbd_open->smbd_stream,
				state->in_replace_if_exists,
				state->in_stream_name);
	}

	auto &pool = smbd_object_pool;
	auto new_bucket_idx = new_hash % pool.buckets.size();
	auto &new_bucket = pool.buckets[new_bucket_idx];
	auto old_bucket_idx = smbd_object->hash % pool.buckets.size();

	std::u16string old_path;
	if (new_bucket_idx == old_bucket_idx) {
		auto bucket_lock = std::lock_guard(new_bucket.mutex);
		status = rename_object_intl(new_bucket, new_bucket, smbd_volume,
				smbd_object,
				new_path, old_path, new_hash);
	} else {
		auto &old_bucket = pool.buckets[old_bucket_idx];
		std::scoped_lock bucket_lock(new_bucket.mutex, old_bucket.mutex);
		status = rename_object_intl(new_bucket, old_bucket, smbd_volume,
				smbd_object,
				new_path, old_path, new_hash);
	}

	if (NT_STATUS_IS_OK(status)) {
		state->out_changes.push_back(x_smb2_change_t{NOTIFY_ACTION_OLD_NAME,
				smbd_object->type == x_smbd_object_t::type_dir ?
					FILE_NOTIFY_CHANGE_DIR_NAME :
					FILE_NOTIFY_CHANGE_FILE_NAME,
				smbd_open->open_state.parent_lease_key,
				smbd_open->open_state.client_guid,
				old_path, new_path});
	}

	return status;
}


int x_smbd_object_pool_init(size_t max_open)
{
	size_t bucket_size = x_next_2_power(max_open);
	std::vector<smbd_object_pool_t::bucket_t> buckets(bucket_size);
	smbd_object_pool.buckets.swap(buckets);
	return 0;
}


