
#include "smbd_open.hxx"
#include "smbd_stats.hxx"

x_smbd_object_t::x_smbd_object_t(const std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		x_smbd_object_t *parent_object,
		long priv_data, uint64_t hash, const std::u16string &path_base)
	: smbd_volume(smbd_volume), priv_data(priv_data), hash(hash)
	, parent_object(parent_object), path_base(path_base)
{
	X_SMBD_COUNTER_INC(object_create, 1);
	if (parent_object) {
		parent_object->incref();
	}
}

x_smbd_object_t::~x_smbd_object_t()
{
	X_SMBD_COUNTER_INC(object_delete, 1);
	if (parent_object) {
		x_smbd_release_object(parent_object);
	}
}

x_smbd_stream_t::x_smbd_stream_t(bool exists, const std::u16string &name)
	: exists(exists), name(name)
{
	X_SMBD_COUNTER_INC(stream_create, 1);
}

x_smbd_stream_t::~x_smbd_stream_t()
{
	X_SMBD_COUNTER_INC(stream_delete, 1);
}

x_smb2_state_create_t::~x_smb2_state_create_t()
{
	if (smbd_object) {
		x_smbd_release_object_and_stream(smbd_object, smbd_stream);
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
		x_sdlist_t head;
		std::mutex mutex;
	};
	bucket_t *buckets = nullptr;
	size_t bucket_size = 0;
	std::atomic<uint32_t> count{0}, unused_count{0};
};

static smbd_object_pool_t smbd_object_pool;

std::pair<bool, uint64_t> x_smbd_hash_path(const x_smbd_volume_t &smbd_volume,
		const x_smbd_object_t *dir_object,
		const std::u16string &path_base)
{
	auto [ ok, hash ] = x_strcase_hash(path_base);
	if (ok) {
		return { true, hash ^ smbd_volume.volume_id ^ dir_object->fileid_hash};
	} else {
		return { false, 0 };
	}
}

/* call hold bucket lock */
static x_smbd_object_t *smbd_object_lookup_intl(
		const std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		smbd_object_pool_t::bucket_t &bucket,
		x_smbd_object_t *parent_object,
		const std::u16string &path_base,
		uint64_t hash)
{
	for (auto *link = bucket.head.get_front(); link; link = link->get_next()) {
		x_smbd_object_t *elem = X_CONTAINER_OF(link, x_smbd_object_t, hash_link);
		if (elem->hash == hash && elem->parent_object == parent_object
				&& elem->smbd_volume == smbd_volume
				&& x_strcase_equal(elem->path_base, path_base)) {
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
		x_smbd_object_t *parent_object,
		const std::u16string &path_base,
		uint64_t path_data,
		bool create_if,
		uint64_t hash)
{
	auto &pool = smbd_object_pool;
	auto bucket_idx = hash % pool.bucket_size;
	auto &bucket = pool.buckets[bucket_idx];

	auto lock = std::lock_guard(bucket.mutex);
	x_smbd_object_t *smbd_object = smbd_object_lookup_intl(
			smbd_volume, bucket, parent_object, path_base, hash);

	if (!smbd_object) {
		if (!create_if) {
			return nullptr;
		}
		smbd_object = smbd_volume->ops->allocate_object(
				smbd_volume, path_data, hash,
				parent_object, path_base);
		X_ASSERT(smbd_object);
		bucket.head.push_front(&smbd_object->hash_link);
		++pool.count;
	} else {
		smbd_object->incref();
	}
	/* move it to head of the bucket to make latest used elem */
	if (&smbd_object->hash_link != bucket.head.get_front()) {
		bucket.head.remove(&smbd_object->hash_link);
		bucket.head.push_front(&smbd_object->hash_link);
	}
	return smbd_object;
}

void x_smbd_release_object(x_smbd_object_t *smbd_object)
{
	auto &pool = smbd_object_pool;
	auto bucket_idx = smbd_object->hash % pool.bucket_size;
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

void x_smbd_release_object_and_stream(x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream)
{
	if (smbd_stream) {
		smbd_object->smbd_volume->ops->release_stream(smbd_object, smbd_stream);
	}
	x_smbd_release_object(smbd_object);
}

static NTSTATUS smbd_object_openat(
		x_smbd_object_t **p_smbd_object,
		const std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		x_smbd_object_t *parent_object,
		const std::u16string &path_base)
{
	if (parent_object->type != x_smbd_object_t::type_dir) {
		return NT_STATUS_OBJECT_PATH_NOT_FOUND;
	}

	auto [ ok, hash ] = x_smbd_hash_path(*smbd_volume, parent_object, path_base);
	if (!ok) {
		return NT_STATUS_ILLEGAL_CHARACTER;
	}

	x_smbd_object_t *smbd_object = x_smbd_object_lookup(smbd_volume,
			parent_object, path_base, 0, true, hash);

	NTSTATUS status = NT_STATUS_OK;
	{
		auto lock = std::lock_guard(smbd_object->mutex);
		if (!(smbd_object->flags & x_smbd_object_t::flag_initialized)) {
			/* TODO can it fail? */
			status = smbd_volume->ops->initialize_object(smbd_object);
			smbd_object->flags = x_smbd_object_t::flag_initialized;
		}
	}

	*p_smbd_object = smbd_object;
	return NT_STATUS_OK;
}


static NTSTATUS open_parent_object(x_smbd_object_t **p_smbd_object,
		std::u16string &base_name,
		const std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		const std::u16string &path)
{
	X_ASSERT(!path.empty());

	std::u16string::size_type pos, last_pos = 0;
	x_smbd_object_t *dir_object = smbd_volume->root_object;
	x_smbd_object_t *sub_object = nullptr;
	dir_object->incref();
	NTSTATUS status;

	/* TODO optimize the loop */
	for (;;) {
		pos = path.find(u'\\', last_pos);
		if (pos == std::u16string::npos) {
			break;
		}
		std::u16string comp = path.substr(last_pos, pos - last_pos);
		status = smbd_object_openat(&sub_object,
				smbd_volume, dir_object, comp);
		x_smbd_release_object(dir_object);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		if (sub_object->type != x_smbd_object_t::type_dir) {
			x_smbd_release_object(sub_object);
			return NT_STATUS_OBJECT_PATH_NOT_FOUND;
		}
		dir_object = sub_object;
		last_pos = pos + 1;
	}

	*p_smbd_object = dir_object;
	base_name = path.substr(last_pos);
	return NT_STATUS_OK;
}


NTSTATUS x_smbd_open_object(x_smbd_object_t **p_smbd_object,
		const std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		const std::u16string &path,
		long path_priv_data,
		bool create_if)
{
	if (path.empty()) {
		smbd_volume->root_object->incref();
		*p_smbd_object = smbd_volume->root_object;
		return NT_STATUS_OK;
	}

	x_smbd_object_t *parent_object, *smbd_object;
	std::u16string path_base;
	NTSTATUS status = open_parent_object(&parent_object, path_base,
			smbd_volume, path);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	auto [ ok, hash ] = x_smbd_hash_path(*smbd_volume, parent_object, path_base);
	if (!ok) {
		x_smbd_release_object(parent_object);
		return NT_STATUS_ILLEGAL_CHARACTER;
	}

	smbd_object = x_smbd_object_lookup(smbd_volume,
			parent_object, path_base,
			path_priv_data, create_if, hash);
	x_smbd_release_object(parent_object);
	if (!smbd_object) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	status = NT_STATUS_OK;
	{
		auto lock = std::lock_guard(smbd_object->mutex);
		if (!(smbd_object->flags & x_smbd_object_t::flag_initialized)) {
			status = smbd_volume->ops->initialize_object(smbd_object);
			smbd_object->flags = x_smbd_object_t::flag_initialized;
		}
	}

	if (!NT_STATUS_IS_OK(status)) {
		x_smbd_release_object(smbd_object);
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
static NTSTATUS rename_object_intl(
		const std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		x_smbd_object_t *smbd_object,
		smbd_object_pool_t::bucket_t &new_bucket,
		smbd_object_pool_t::bucket_t &old_bucket,
		x_smbd_object_t *new_parent_object,
		const std::u16string &new_path_base,
		std::u16string &old_path_base,
		uint64_t new_hash)
{
	x_smbd_object_t *new_object = smbd_object_lookup_intl(smbd_volume,
			new_bucket, new_parent_object, new_path_base, new_hash);
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

	NTSTATUS status = smbd_volume->ops->rename_object(smbd_object,
			/* TODO replace */
			false, new_parent_object, new_path_base);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	old_path_base = smbd_object->path_base;
	old_bucket.head.remove(&smbd_object->hash_link);
	smbd_object->hash = new_hash;
	smbd_object->path_base = new_path_base;
	new_bucket.head.push_front(&smbd_object->hash_link);
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

static NTSTATUS parent_compatible_open(x_smbd_object_t *smbd_object)
{
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
			return NT_STATUS_SHARING_VIOLATION;
		}
	}
	return NT_STATUS_OK;
}

NTSTATUS x_smbd_object_rename(x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_rename_t> &state)
{
	x_smbd_sharemode_t *sharemode = x_smbd_open_get_sharemode(smbd_open);

	auto &smbd_volume = smbd_object->smbd_volume;

	x_smbd_object_t *new_parent_object = nullptr;
	std::u16string new_path_base;

	NTSTATUS status;

	if (!smbd_open->smbd_stream) {
		status = open_parent_object(&new_parent_object, new_path_base,
				smbd_volume, state->in_path);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		status = parent_compatible_open(new_parent_object);
		if (!NT_STATUS_IS_OK(status)) {
			x_smbd_release_object(new_parent_object);
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
		if (new_parent_object) {
			x_smbd_release_object(new_parent_object);
		}
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
	auto [ ok, new_path_hash ] = x_smbd_hash_path(*smbd_volume, new_parent_object, new_path_base);
	if (!ok) {
		x_smbd_release_object(new_parent_object);
	}

	auto new_bucket_idx = new_path_hash % pool.bucket_size;
	auto &new_bucket = pool.buckets[new_bucket_idx];
	auto old_bucket_idx = smbd_object->hash % pool.bucket_size;

	x_smbd_object_t *old_parent_object = smbd_object->parent_object;
	std::u16string old_path_base;
	if (new_bucket_idx == old_bucket_idx) {
		auto bucket_lock = std::lock_guard(new_bucket.mutex);
		status = rename_object_intl(smbd_volume, smbd_object,
				new_bucket, new_bucket,
				new_parent_object, new_path_base,
				old_path_base, new_path_hash);
	} else {
		auto &old_bucket = pool.buckets[old_bucket_idx];
		std::scoped_lock bucket_lock(new_bucket.mutex, old_bucket.mutex);
		status = rename_object_intl(smbd_volume, smbd_object,
				new_bucket, old_bucket,
				new_parent_object, new_path_base,
				old_path_base, new_path_hash);
	}

	if (NT_STATUS_IS_OK(status)) {
		smbd_object->parent_object = new_parent_object;
		x_smbd_schedule_notify(
				NOTIFY_ACTION_OLD_NAME,
				smbd_object->type == x_smbd_object_t::type_dir ?
					FILE_NOTIFY_CHANGE_DIR_NAME :
					FILE_NOTIFY_CHANGE_FILE_NAME,
				smbd_open->open_state.parent_lease_key,
				smbd_open->open_state.client_guid,
				old_parent_object, new_parent_object,
				old_path_base, new_path_base);
		x_smbd_release_object(old_parent_object);
	} else {
		x_smbd_release_object(new_parent_object);
	}

	return status;
}

std::u16string x_smbd_object_get_path(const x_smbd_object_t *smbd_object)
{
	std::vector<const x_smbd_object_t *> stack;
	while (smbd_object->parent_object) {
		stack.push_back(smbd_object);
		smbd_object = smbd_object->parent_object;
	}

	std::u16string full_path;
	for (size_t i = stack.size(); i--; ) {
		smbd_object = stack[i];
		if (!full_path.empty()) {
			full_path.push_back(u'\\');
		}
		full_path.append(smbd_object->path_base);
	}
	return full_path;
}

int x_smbd_object_pool_init(size_t max_open)
{
	size_t bucket_size = x_next_2_power(max_open);
	smbd_object_pool.buckets = new smbd_object_pool_t::bucket_t[bucket_size];
	smbd_object_pool.bucket_size = bucket_size;
	return 0;
}


