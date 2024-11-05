
#include "smbd_open.hxx"
#include "smbd_stats.hxx"
#include "smbd_access.hxx"
#include "include/SpookyV2.hxx"

x_smbd_object_t::x_smbd_object_t(const std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		x_smbd_object_t *parent_object,
		long priv_data, uint64_t path_hash, const std::u16string &path_base)
	: smbd_volume(smbd_volume), priv_data(priv_data), path_hash(path_hash)
	, parent_object(parent_object), path_base(path_base)
{
	X_SMBD_COUNTER_INC_CREATE(object, 1);
	if (parent_object) {
		parent_object->incref();
		auto lock = std::lock_guard(parent_object->mutex);
		parent_object->active_child_object_list.push_back(&parent_link);
	}
}

x_smbd_object_t::~x_smbd_object_t()
{
	X_SMBD_COUNTER_INC_DELETE(object, 1);
	if (parent_object) {
		{
			auto lock = std::lock_guard(parent_object->mutex);
			parent_object->active_child_object_list.remove(&parent_link);
		}
		x_smbd_release_object(parent_object);
	}
}

x_smbd_stream_t::x_smbd_stream_t(bool exists, const std::u16string &name)
	: exists(exists), name(name)
{
	X_SMBD_COUNTER_INC_CREATE(stream, 1);
}

x_smbd_stream_t::~x_smbd_stream_t()
{
	X_SMBD_COUNTER_INC_DELETE(stream, 1);
}

struct smbd_object_pool_t
{
	static const uint64_t cache_time = 60ul * 1000000000; // 60 second
	struct bucket_t
	{
		x_sdlist_t head;
		std::mutex mutex;
	};
	bucket_t *path_buckets = nullptr;
	bucket_t *fileid_buckets = nullptr;
	size_t bucket_size = 0;
	std::atomic<uint32_t> count{0}, unused_count{0};
};

static smbd_object_pool_t smbd_object_pool;

std::pair<bool, uint64_t> x_smbd_hash_path(const x_smbd_volume_t &smbd_volume,
		const x_smbd_object_t *dir_object,
		const std::u16string &path_base)
{
	auto [ ok, path_hash ] = x_strcase_hash(path_base);
	if (ok) {
		return { true, path_hash ^ smbd_volume.volume_id ^ dir_object->fileid_hash};
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
		uint64_t path_hash,
		bool ncase)
{
	for (auto *link = bucket.head.get_front(); link; link = link->get_next()) {
		x_smbd_object_t *elem = X_CONTAINER_OF(link, x_smbd_object_t, path_hash_link);
		if (elem->path_hash == path_hash && elem->parent_object == parent_object
				&& elem->smbd_volume == smbd_volume) {
			if (ncase) {
				if (x_strcase_equal(elem->path_base, path_base)) {
					return elem;
				}
			} else {
				if (elem->path_base == path_base) {
					return elem;
				}
			}
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
NTSTATUS x_smbd_object_lookup(x_smbd_object_t **p_smbd_object,
		const std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		x_smbd_object_t *parent_object,
		const std::u16string &path_base,
		uint64_t path_data,
		bool create_if,
		uint64_t path_hash,
		bool ncase)
{
	auto &pool = smbd_object_pool;
	auto bucket_idx = path_hash % pool.bucket_size;
	auto &bucket = pool.path_buckets[bucket_idx];

	auto lock = std::lock_guard(bucket.mutex);
	x_smbd_object_t *smbd_object = smbd_object_lookup_intl(
			smbd_volume, bucket, parent_object, path_base, path_hash, ncase);

	if (!smbd_object) {
		if (!create_if) {
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}
		NTSTATUS status = smbd_volume->ops->allocate_object(
				&smbd_object,
				smbd_volume, path_data, path_hash,
				parent_object, path_base);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		X_ASSERT(smbd_object);
		bucket.head.push_front(&smbd_object->path_hash_link);
		++pool.count;
	} else {
		smbd_object->incref();
	}
	/* move it to head of the bucket to make latest used elem */
	if (&smbd_object->path_hash_link != bucket.head.get_front()) {
		bucket.head.remove(&smbd_object->path_hash_link);
		bucket.head.push_front(&smbd_object->path_hash_link);
	}
	*p_smbd_object = smbd_object;
	return NT_STATUS_OK;
}

void x_smbd_release_object(x_smbd_object_t *smbd_object)
{
	auto &pool = smbd_object_pool;
	auto bucket_idx = smbd_object->path_hash % pool.bucket_size;
	auto &bucket = pool.path_buckets[bucket_idx];
	bool free = false;

	{
		/* TODO optimize when use_count > 1 */
		auto lock = std::lock_guard(bucket.mutex);

		X_ASSERT(smbd_object->use_count > 0);
		if (--smbd_object->use_count == 0) {
			bucket.head.remove(&smbd_object->path_hash_link);
			free = true;
		}
	}
	if (free) {
		X_ASSERT(smbd_object->parent_object);
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
/*
struct x_smbd_file_handle_t
{
	int cmp(const x_smbd_file_handle_t &other) const
	{
		if (base.handle_type != other.base.handle_type) {
			return base.handle_type - other.base.handle_type;
		}
		if (base.handle_bytes != other.base.handle_bytes) {
			return int(base.handle_bytes - other.base.handle_bytes);
		}
		return memcmp(base.f_handle, other.base.f_handle, base.handle_bytes);
	}

	struct file_handle base;
	unsigned char f_handle[MAX_HANDLE_SZ];
};
*/
static inline uint64_t hash_file_handle(const x_smbd_file_handle_t &fh)
{
	return SpookyHash::Hash64(&fh.base, sizeof(struct file_handle) +
			fh.base.handle_bytes, 0);
}

static NTSTATUS smbd_object_initialize_if(x_smbd_volume_t &smbd_volume,
		x_smbd_object_t *smbd_object)
{
	NTSTATUS status = NT_STATUS_OK;
	auto lock = std::lock_guard(smbd_object->mutex);
	if (!(smbd_object->flags & x_smbd_object_t::flag_initialized)) {
		/* TODO can it fail? */
		status = smbd_volume.ops->initialize_object(smbd_object);
		smbd_object->flags = x_smbd_object_t::flag_initialized;
		if (smbd_object->type != x_smbd_object_t::type_not_exist) {
			smbd_object->fileid_hash = hash_file_handle(
					smbd_object->file_handle);
		}
	}
	return status;
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

	auto [ ok, path_hash ] = x_smbd_hash_path(*smbd_volume, parent_object, path_base);
	if (!ok) {
		return NT_STATUS_ILLEGAL_CHARACTER;
	}

	x_smbd_object_t *smbd_object;
	NTSTATUS status = x_smbd_object_lookup(&smbd_object, smbd_volume,
			parent_object, path_base, 0, true, path_hash, true);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = smbd_object_initialize_if(*smbd_volume, smbd_object);
	if (!NT_STATUS_IS_OK(status)) {
		x_smbd_release_object(smbd_object);
		return status;
	}
	*p_smbd_object = smbd_object;
	return NT_STATUS_OK;
}

static NTSTATUS open_parent_object(x_smbd_object_t **p_smbd_object,
		std::u16string &base_name,
		x_smbd_object_t *root_object,
		const std::u16string &path)
{
	X_ASSERT(!path.empty());

	std::u16string::size_type pos, last_pos = 0;
	x_smbd_object_t *dir_object = root_object;
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
				dir_object->smbd_volume, dir_object, comp);
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
		const std::shared_ptr<x_smbd_share_t> &smbd_share,
		const std::u16string &path,
		long path_priv_data,
		bool create_if)
{
	if (path.empty()) {
		smbd_share->root_object->incref();
		*p_smbd_object = smbd_share->root_object;
		return NT_STATUS_OK;
	}

	x_smbd_object_t *parent_object, *smbd_object;
	std::u16string path_base;
	NTSTATUS status = open_parent_object(&parent_object, path_base,
			smbd_share->root_object, path);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	auto [ ok, path_hash ] = x_smbd_hash_path(*parent_object->smbd_volume,
			parent_object, path_base);
	if (!ok) {
		x_smbd_release_object(parent_object);
		return NT_STATUS_ILLEGAL_CHARACTER;
	}

	status = x_smbd_object_lookup(&smbd_object, parent_object->smbd_volume,
			parent_object, path_base,
			path_priv_data, create_if, path_hash, true);
	x_smbd_release_object(parent_object);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = smbd_object_initialize_if(*parent_object->smbd_volume, smbd_object);

	if (!NT_STATUS_IS_OK(status)) {
		x_smbd_release_object(smbd_object);
		return status;
	}
	*p_smbd_object = smbd_object;
	return status;
}

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
			new_bucket, new_parent_object, new_path_base, new_hash, true);
	if (new_object && new_object->exists()) {
		/* TODO replace forced */
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	if (new_object) {
		/* not exists, should none refer it??? */
		new_bucket.head.remove(&new_object->path_hash_link);
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
	old_bucket.head.remove(&smbd_object->path_hash_link);
	smbd_object->path_hash = new_hash;
	smbd_object->path_base = new_path_base;
	new_bucket.head.push_front(&smbd_object->path_hash_link);
	return NT_STATUS_OK;
}

/* caller locked smbd_object */
static NTSTATUS delay_rename_for_lease_break(x_smbd_object_t *smbd_object,
		x_smbd_sharemode_t *smbd_sharemode,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ)
{
	if (!smbd_open || !smbd_open->smbd_stream) {
		for (x_dlink_t *link = smbd_object->active_child_object_list.get_front();
				link; link = link->next) {
			x_smbd_object_t *child_object = X_CONTAINER_OF(link, x_smbd_object_t,
					parent_link);
			NTSTATUS status;
			child_object->incref();
			{
				auto lock = std::lock_guard(child_object->mutex);
				/* pass null lease as it could not be same */
				status = delay_rename_for_lease_break(child_object,
						&child_object->sharemode,
						nullptr, smbd_requ);
			}

			child_object->decref();

			X_LOG(SMB, DBG, "%s", x_ntstatus_str(status));
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
		}
	}

	bool delay = false;
	auto &open_list = smbd_sharemode->open_list;
	size_t count = 0;
	x_smbd_open_t *curr_open;
	for (curr_open = open_list.get_front(); curr_open; curr_open = open_list.next(curr_open)) {
		if (smbd_open == curr_open) {
			continue;
		}

		if (smbd_open && smbd_open->smbd_lease &&
				curr_open->smbd_lease == smbd_open->smbd_lease) {
			continue;
		}

		++count;
		if (curr_open->smbd_lease) {
			if (x_smbd_open_break_lease(curr_open, nullptr, nullptr,
						X_SMB2_LEASE_HANDLE, X_SMB2_LEASE_HANDLE,
						smbd_requ, false)) {
				delay = true;
			}
		} else {
			if (x_smbd_open_break_oplock(smbd_object, curr_open,
						X_SMB2_LEASE_HANDLE, smbd_requ)) {
				delay = true;
			}
		}
	}
	if (delay) {
		return NT_STATUS_PENDING;
	} else if (count > 0 && !smbd_open) { // only deny when open under the dir
		return NT_STATUS_ACCESS_DENIED;
	}
	return NT_STATUS_OK;
}

static void smbd_rename_cancel(x_nxfsd_conn_t *nxfsd_conn, x_smbd_requ_t *smbd_requ)
{
	x_smbd_requ_post_cancel(smbd_requ, NT_STATUS_CANCELLED);
}

static inline NTSTATUS parent_compatible_open(x_smbd_object_t *smbd_object)
{
	const x_smbd_open_t *curr_open;
	auto &open_list = smbd_object->sharemode.open_list;
	auto lock = std::lock_guard(smbd_object->mutex);
	for (curr_open = open_list.get_front(); curr_open; curr_open = open_list.next(curr_open)) {
		if ((curr_open->open_state.access_mask & idl::SEC_STD_DELETE) ||
				((curr_open->open_state.access_mask & idl::SEC_DIR_ADD_FILE) &&
				 !(curr_open->open_state.share_access & X_SMB2_FILE_SHARE_WRITE))) {
			X_LOG(SMB, DBG, "access_mask=0x%x share_access=%d STATUS_SHARING_VIOLATION",
					curr_open->open_state.access_mask,
					curr_open->open_state.share_access);
			return NT_STATUS_SHARING_VIOLATION;
		}
	}
	return NT_STATUS_OK;
}

static inline void smbd_object_set_parent(x_smbd_object_t *smbd_object,
		x_smbd_object_t *new_parent_object)
{
	auto old_parent_object = smbd_object->parent_object;
	if (new_parent_object != old_parent_object) {
		{
			auto lock = std::lock_guard(old_parent_object->mutex);
			old_parent_object->active_child_object_list.remove(&smbd_object->parent_link);
		}
		{
			auto lock = std::lock_guard(new_parent_object->mutex);
			new_parent_object->active_child_object_list.push_back(&smbd_object->parent_link);
		}
		smbd_object->parent_object = new_parent_object;
	}
}

NTSTATUS x_smbd_object_rename(x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smbd_requ_state_rename_t> &state)
{
	x_smbd_sharemode_t *sharemode = x_smbd_open_get_sharemode(smbd_open);

	auto &smbd_volume = smbd_object->smbd_volume;

	x_smbd_object_t *new_parent_object = nullptr;
	std::u16string new_path_base;

	NTSTATUS status;

	if (!smbd_open->smbd_stream) {
		auto smbd_share = x_smbd_tcon_get_share(smbd_open->smbd_tcon);
		status = open_parent_object(&new_parent_object, new_path_base,
				smbd_share->root_object,
				state->in_path);
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

	status = delay_rename_for_lease_break(smbd_object, sharemode, smbd_open, smbd_requ);
	if (NT_STATUS_EQUAL(status, NT_STATUS_PENDING)) {
		smbd_requ->save_requ_state(state);
		/* windows server do not send interim response in renaming */
		x_smbd_requ_async_insert(smbd_requ, smbd_rename_cancel, -1);
		if (new_parent_object) {
			x_smbd_release_object(new_parent_object);
		}
		return NT_STATUS_PENDING;
	}

	if (!NT_STATUS_IS_OK(status)) {
		return status;
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
	auto &new_bucket = pool.path_buckets[new_bucket_idx];
	auto old_bucket_idx = smbd_object->path_hash % pool.bucket_size;

	x_smbd_object_t *old_parent_object = smbd_object->parent_object;
	std::u16string old_path_base;
	if (new_bucket_idx == old_bucket_idx) {
		auto bucket_lock = std::lock_guard(new_bucket.mutex);
		status = rename_object_intl(smbd_volume, smbd_object,
				new_bucket, new_bucket,
				new_parent_object, new_path_base,
				old_path_base, new_path_hash);
		if (NT_STATUS_IS_OK(status)) {
			smbd_object_set_parent(smbd_object, new_parent_object);
		}
	} else {
		auto &old_bucket = pool.path_buckets[old_bucket_idx];
		std::scoped_lock bucket_lock(new_bucket.mutex, old_bucket.mutex);
		status = rename_object_intl(smbd_volume, smbd_object,
				new_bucket, old_bucket,
				new_parent_object, new_path_base,
				old_path_base, new_path_hash);
		if (NT_STATUS_IS_OK(status)) {
			smbd_object_set_parent(smbd_object, new_parent_object);
		}
	}

	if (NT_STATUS_IS_OK(status)) {
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

NTSTATUS x_smbd_object_set_delete_on_close(x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream,
		uint32_t access_mask,
		bool delete_on_close);

NTSTATUS x_smbd_object_set_delete_pending_intl(x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smbd_requ_state_disposition_t> &state)
{
	auto sharemode = x_smbd_open_get_sharemode(smbd_open);

	if (!state->delete_pending) {
		sharemode->meta.delete_on_close = false;
		return NT_STATUS_OK;
	}

	if (smbd_requ) {
		NTSTATUS status = x_smbd_can_set_delete_on_close(smbd_object,
				smbd_open->smbd_stream,
				smbd_object->meta.file_attributes,
				smbd_open->open_state.access_mask);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	auto &open_list = sharemode->open_list;
	x_smbd_open_t *curr_open;
	bool delay = false;
	for (curr_open = open_list.get_front(); curr_open; curr_open = open_list.next(curr_open)) {
		if (curr_open == smbd_open) {
			continue;
		}
		if (curr_open->smbd_lease) {
			if (curr_open->smbd_lease == smbd_open->smbd_lease) {
				continue;
			}
			if (x_smbd_open_break_lease(curr_open, nullptr, nullptr,
						X_SMB2_LEASE_HANDLE, X_SMB2_LEASE_HANDLE,
						smbd_requ, false)) {
				delay = true;
			}
		} else {
			if (x_smbd_open_break_oplock(smbd_object, curr_open,
						X_SMB2_LEASE_HANDLE, smbd_requ)) {
				delay = true;
			}
		}
	}

	if (delay && smbd_requ) {
		smbd_requ->save_requ_state(state);
		/* windows server do not send interim response in renaming */
		x_smbd_requ_async_insert(smbd_requ, smbd_rename_cancel, -1);
		return NT_STATUS_PENDING;
	}

	sharemode->meta.delete_on_close = true;
	if (smbd_object->type == x_smbd_object_t::type_dir &&
			!smbd_open->smbd_stream) {
		for (curr_open = open_list.get_front(); curr_open; curr_open = open_list.next(curr_open)) {
			x_smbd_requ_t *requ_notify, *requ_next;
			for (requ_notify = curr_open->pending_requ_list.get_front();
					requ_notify;
					requ_notify = requ_next) {

				requ_next = curr_open->pending_requ_list.next(requ_notify);
				if (requ_notify->in_smb2_hdr.opcode != X_SMB2_OP_NOTIFY) {
					continue;
				}
				curr_open->pending_requ_list.remove(requ_notify);
				x_smbd_requ_post_cancel(
						requ_notify, NT_STATUS_DELETE_PENDING);
			}
		}
	}
	return NT_STATUS_OK;
}

NTSTATUS x_smbd_object_set_delete_pending(x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smbd_requ_state_disposition_t> &state)
{
	auto lock = std::lock_guard(smbd_object->mutex);
	return x_smbd_object_set_delete_pending_intl(smbd_object, smbd_open,
			smbd_requ, state);
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
	smbd_object_pool.path_buckets = new smbd_object_pool_t::bucket_t[bucket_size];
	smbd_object_pool.fileid_buckets = new smbd_object_pool_t::bucket_t[bucket_size];
	smbd_object_pool.bucket_size = bucket_size;
	return 0;
}


