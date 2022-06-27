
#include "smbd_open.hxx"
#include "smbd_posixfs.hxx"
#include <fcntl.h>
#include <sys/statvfs.h>
#include "smbd_ntacl.hxx"
#include "smbd_lease.hxx"
#include <dirent.h>
#include <sys/syscall.h>
#include "smbd_share.hxx"

struct qdir_t
{
	uint64_t filepos = 0;
	int save_errno = 0;
	uint32_t file_number = 0;
	uint32_t data_length = 0, data_offset = 0;
	uint8_t data[32 * 1024];
};

struct qdir_pos_t
{
	uint32_t file_number;
	uint32_t data_offset;
	uint64_t filepos;
};

static uint8_t *put_find_timespec(uint8_t *p, struct timespec ts)
{
	auto nttime = x_timespec_to_nttime(ts);
	memcpy(p, &nttime, sizeof nttime); // TODO byte order
	return p + sizeof nttime;
}

static bool is_null_ntime(idl::NTTIME nt)
{
	return nt.val == 0 || nt.val == (uint64_t)-1;
}

static int posixfs_set_basic_info(int fd,
		uint32_t &notify_actions,
		const x_smb2_basic_info_t &basic_info,
		posixfs_statex_t *statex)
{
	dos_attr_t dos_attr = { 0 };
	if (basic_info.file_attributes != 0) {
		dos_attr.attr_mask |= DOS_SET_FILE_ATTR;
		dos_attr.file_attrs = basic_info.file_attributes;
		notify_actions |= FILE_NOTIFY_CHANGE_ATTRIBUTES;
	}

	if (!is_null_ntime(basic_info.creation)) {
		dos_attr.attr_mask |= DOS_SET_CREATE_TIME;
		dos_attr.create_time = x_nttime_to_timespec(basic_info.creation);
		notify_actions |= FILE_NOTIFY_CHANGE_CREATION;
	}

	if (dos_attr.attr_mask != 0) {
		posixfs_dos_attr_set(fd, &dos_attr);
	}

	struct timespec uts[2] = {
		{ 0, UTIME_OMIT },
		{ 0, UTIME_OMIT },
	};

	int count = 0;
	if (!is_null_ntime(basic_info.last_access)) {
		uts[0] = x_nttime_to_timespec(basic_info.last_access);
		notify_actions |= FILE_NOTIFY_CHANGE_LAST_ACCESS;
		++count;
	}

	if (!is_null_ntime(basic_info.last_write)) {
		uts[0] = x_nttime_to_timespec(basic_info.last_write);
		notify_actions |= FILE_NOTIFY_CHANGE_LAST_WRITE;
		++count;
	}

	if (count) {
		int err = futimens(fd, uts);
		X_TODO_ASSERT(err == 0);
	}
	
	posixfs_statex_get(fd, statex);
	return 0;
}

static int posixfs_open(int dirfd, const char *path, posixfs_statex_t *statex)
{
	bool is_dir = false;
	int fd;
	if (!*path) {
		fd = dup(dirfd);
		is_dir = true;
	} else {
		fd = openat(dirfd, path, O_RDWR | O_NOFOLLOW);
		if (fd < 0) {
			if (errno != EISDIR) {
				return -errno;
			}
			fd = openat(dirfd, path, O_RDONLY | O_NOFOLLOW);
			X_ASSERT(fd >= 0);
			is_dir = true;
		}
	}
	posixfs_statex_get(fd, statex);
	X_ASSERT(is_dir == S_ISDIR(statex->stat.st_mode));
	return fd;
}

enum class oplock_break_sent_t {
	OPLOCK_BREAK_NOT_SENT,
	OPLOCK_BREAK_TO_NONE_SENT,
	OPLOCK_BREAK_TO_LEVEL_II_SENT,
};

struct posixfs_open_t
{
	posixfs_open_t(x_smbd_object_t *so, x_smbd_tcon_t *st,
			uint32_t am, uint32_t sa)
		: base(so, st, am, sa) { }
	x_smbd_open_t base;
	x_dlink_t object_link;
	qdir_t *qdir = nullptr;
	uint32_t notify_filter = 0;
	uint8_t oplock_level{X_SMB2_OPLOCK_LEVEL_NONE};
	oplock_break_sent_t oplock_break_sent{oplock_break_sent_t::OPLOCK_BREAK_NOT_SENT};
	/* open's on the same file sharing the same lease can have different parent key */
	x_smb2_lease_key_t parent_lease_key;
	x_smbd_lease_t *smbd_lease{};
	/* notify_requ_list and notify_changes protected by posixfs_object->mutex */
	x_tp_ddlist_t<requ_async_traits> notify_requ_list;
	std::vector<std::pair<uint32_t, std::u16string>> notify_changes;
};
X_DECLARE_MEMBER_TRAITS(posixfs_open_object_traits, posixfs_open_t, object_link)
X_DECLARE_MEMBER_TRAITS(posixfs_open_from_base_t, posixfs_open_t, base)

struct posixfs_object_t
{
	posixfs_object_t(const x_smbd_object_ops_t *ops, uint64_t h,
			const std::shared_ptr<x_smbd_topdir_t> &topdir,
			const std::u16string &p);
	~posixfs_object_t() {
		if (fd != -1) {
			close(fd);
		}
	}

	x_smbd_object_t base;

	bool exists() const { return fd != -1; }
	bool is_dir() const {
		X_ASSERT(fd != -1);
		return S_ISDIR(statex.stat.st_mode);
	}
	x_dqlink_t hash_link;
	uint64_t hash;
	uint64_t unused_timestamp{0};
	std::atomic<uint32_t> use_count{1}; // protected by bucket mutex
	std::mutex mutex;
	// std::atomic<uint32_t> children_count{};
	int fd = -1;
	std::atomic<uint32_t> lease_cnt{0};
	// std::atomic<uint32_t> notify_cnt{0};

	enum {
		flag_initialized = 1,
		flag_not_exist = 2,
		flag_topdir = 4,
		flag_delete_on_close = 0x1000,
	};

	uint32_t flags = 0;
	bool statex_modified{false}; // TODO use flags
	posixfs_statex_t statex;
	const std::shared_ptr<x_smbd_topdir_t> topdir;
	/* protected by bucket mutex */
	std::u16string req_path;
	std::string unix_path;
	/* protected by object mutex */
	x_tp_ddlist_t<posixfs_open_object_traits> open_list;
	x_tp_ddlist_t<requ_async_traits> defer_open_list;
};
X_DECLARE_MEMBER_TRAITS(posixfs_object_from_base_t, posixfs_object_t, base)

struct posixfs_object_pool_t
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

static posixfs_object_pool_t posixfs_object_pool;

static std::string convert_to_unix(const std::u16string &req_path)
{
	/* TODO case insenctive */
	/* TODO does smb allow leading '/'? if so need to remove it */
	std::string ret = x_convert_utf16_to_utf8(req_path);
	for (auto &c: ret) {
		if (c == '\\') {
			c = '/';
		}
	}
	return ret;
}

/* TODO dfs need one more fact refer the topdir */
static uint64_t hash_object(const std::shared_ptr<x_smbd_topdir_t> &topdir,
		const std::u16string &path)
{
	uint64_t hash = std::hash<std::u16string>()(path);
	hash ^= topdir->uuid;
	return hash;
	//return (hash >> 32) ^ hash;
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
static posixfs_object_t *posixfs_object_lookup(
		const x_smbd_object_ops_t *ops,
		const std::shared_ptr<x_smbd_topdir_t> &topdir,
		const std::u16string &path,
		bool create)
{
	auto hash = hash_object(topdir, path);
	auto &pool = posixfs_object_pool;
	auto bucket_idx = hash % pool.buckets.size();
	auto &bucket = pool.buckets[bucket_idx];
	posixfs_object_t *matched_object = nullptr;
	posixfs_object_t *elem = nullptr;

	std::unique_lock<std::mutex> lock(bucket.mutex);

	for (x_dqlink_t *link = bucket.head.get_front(); link; link = link->get_next()) {
		elem = X_CONTAINER_OF(link, posixfs_object_t, hash_link);
		if (elem->hash == hash && elem->topdir->uuid == topdir->uuid
				&& elem->req_path == path) {
			matched_object = elem;
			break;
		}
	}

	if (!matched_object) {
		if (!create) {
			return nullptr;
		}
		if (elem && elem->use_count == 0 &&
				elem->unused_timestamp + posixfs_object_pool_t::cache_time < tick_now) {
			elem->~posixfs_object_t();
			new (elem)posixfs_object_t(ops, hash, topdir, path);
			matched_object = elem;
		} else {
			matched_object = new posixfs_object_t(ops, hash, topdir, path);
			bucket.head.push_front(&matched_object->hash_link);
			++pool.count;
		}
		assert(matched_object->use_count == 1);
	} else {
		++matched_object->use_count;
	}
	/* move it to head of the bucket to make latest used elem */
	if (&matched_object->hash_link != bucket.head.get_front()) {
		matched_object->hash_link.remove();
		bucket.head.push_front(&matched_object->hash_link);
	}
	return matched_object;
}

static void posixfs_object_release(posixfs_object_t *posixfs_object)
{
	auto &pool = posixfs_object_pool;
	auto bucket_idx = posixfs_object->hash % pool.buckets.size();
	auto &bucket = pool.buckets[bucket_idx];

	/* TODO optimize when use_count > 1 */
	std::unique_lock<std::mutex> lock(bucket.mutex);

	X_ASSERT(posixfs_object->use_count > 0);
	if (--posixfs_object->use_count == 0) {
		posixfs_object->unused_timestamp = tick_now;
	}
}

struct posixfs_defer_open_evt_t
{
	x_fdevt_user_t base;
	posixfs_object_t *posixfs_object;
	x_smbd_requ_t *smbd_requ;
};

static void posixfs_defer_open_func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user, bool cancelled)
{
	posixfs_defer_open_evt_t *evt = X_CONTAINER_OF(fdevt_user, posixfs_defer_open_evt_t, base);
	X_LOG_DBG("evt=%p", evt);

	posixfs_object_t *posixfs_object = evt->posixfs_object;
	x_smbd_requ_t *smbd_requ = evt->smbd_requ;
	delete evt;

	if (cancelled) {
		posixfs_object_release(evt->posixfs_object);
		x_smbd_ref_dec(smbd_requ);
		return;
	}

	std::unique_lock<std::mutex> lock(posixfs_object->mutex);

	X_TODO; // re-process the create request
}

static void posixfs_create_cancel(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_requ->smbd_object);
	{
		std::unique_lock<std::mutex> lock(posixfs_object->mutex);
		posixfs_object->defer_open_list.remove(smbd_requ);
	}
	x_smbd_conn_post_cancel(smbd_conn, smbd_requ);
}

static void share_mode_modified(posixfs_object_t *posixfs_object)
{
	/* posixfs_object is locked */
	x_smbd_requ_t *smbd_requ = posixfs_object->defer_open_list.get_front();
	if (!smbd_requ) {
		return;
	}

	posixfs_object->defer_open_list.remove(smbd_requ);
	posixfs_defer_open_evt_t *evt = new posixfs_defer_open_evt_t;
	evt->base.func = posixfs_defer_open_func;
	evt->smbd_requ = smbd_requ;
	x_smbd_chan_post_user(smbd_requ->smbd_chan, &evt->base);
}

struct posixfs_notify_evt_t
{
	posixfs_notify_evt_t(x_smbd_requ_t *requ,
			std::vector<std::pair<uint32_t, std::u16string>> &&changes)
		: smbd_requ(requ), notify_changes(changes)
	{ }
	~posixfs_notify_evt_t() {
		x_smbd_ref_dec(smbd_requ);
	}
	x_fdevt_user_t base;
	x_smbd_requ_t *smbd_requ;
	std::vector<std::pair<uint32_t, std::u16string>> notify_changes;
};

static void posixfs_notify_func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user, bool terminated)
{
	posixfs_notify_evt_t *evt = X_CONTAINER_OF(fdevt_user, posixfs_notify_evt_t, base);
	X_LOG_DBG("evt=%p", evt);

	if (!terminated) {
		x_smbd_requ_t *smbd_requ = evt->smbd_requ;
		x_smb2_state_notify_t *state{(x_smb2_state_notify_t *)smbd_requ->requ_state};
		NTSTATUS status = x_smb2_notify_marshall(evt->notify_changes,
				state->in_output_buffer_length, state->out_data);
		smbd_requ->async_done_fn(smbd_conn, smbd_requ, status);
	}

	delete evt;
}

static void notify_fname_one(const std::shared_ptr<x_smbd_topdir_t> &topdir,
		const std::u16string &path,
		const std::u16string &fullpath,
		const std::u16string *new_name_path,
		uint32_t action,
		uint32_t notify_filter,
		bool last_level)
{
	posixfs_object_t *posixfs_object = posixfs_object_lookup(nullptr, topdir, path, false);
	if (!posixfs_object) {
		return;
	}

	std::u16string subpath;
	std::u16string new_subpath;
	/* TODO change to read lock */
	std::unique_lock<std::mutex> lock(posixfs_object->mutex);
	auto &open_list = posixfs_object->open_list;
	posixfs_open_t *curr_open;
	for (curr_open = open_list.get_front(); curr_open; curr_open = open_list.next(curr_open)) {
		if (!(curr_open->notify_filter & notify_filter)) {
			continue;
		}
		if (!last_level && !(curr_open->notify_filter & X_FILE_NOTIFY_CHANGE_WATCH_TREE)) {
			continue;
		}
		if (subpath.empty()) {
			if (path.empty()) {
				subpath = fullpath;
				if (new_name_path) {
					new_subpath = *new_name_path;
				}
			} else {
				subpath = fullpath.substr(path.size() + 1);
				if (new_name_path) {
					new_subpath = new_name_path->substr(path.size() + 1);
				}
			}
		}
		curr_open->notify_changes.push_back(std::make_pair(action, subpath));
		if (new_name_path) {
			curr_open->notify_changes.push_back(std::make_pair(NOTIFY_ACTION_NEW_NAME,
						new_subpath));
		}
		x_smbd_requ_t *smbd_requ = curr_open->notify_requ_list.get_front();
		if (smbd_requ) {
			auto notify_changes = std::move(curr_open->notify_changes);
			curr_open->notify_requ_list.remove(smbd_requ);
			lock.unlock();
			x_smbd_requ_remove(smbd_requ); // remove from async
			posixfs_notify_evt_t *evt = new posixfs_notify_evt_t(smbd_requ,
					std::move(notify_changes));
			evt->base.func = posixfs_notify_func;
			if (!x_smbd_chan_post_user(smbd_requ->smbd_chan, &evt->base)) {
				delete evt;
			}
			lock.lock();
		}
	}
	posixfs_object_release(posixfs_object);
}

static void notify_fname_intl(
		std::shared_ptr<x_smbd_topdir_t> topdir,
		const std::u16string req_path,
		uint32_t action,
		uint32_t notify_filter,
		const std::u16string *new_name_path)
{
	std::size_t curr_pos = 0, last_sep_pos = 0;
	for (;;) {
		auto found = req_path.find('\\', curr_pos);
		if (found == std::string::npos) {
			break;
		}
		
		if (topdir->watch_tree_cnt > 0) {
			notify_fname_one(topdir,
					req_path.substr(0, last_sep_pos),
					req_path, new_name_path,
					action, notify_filter, false);
		}
		last_sep_pos = found;
		curr_pos = found + 1;
	}

	notify_fname_one(topdir,
			req_path.substr(0, last_sep_pos),
			req_path, new_name_path,
			action, notify_filter, true);
}

static void notify_fname(
		posixfs_object_t *posixfs_object,
		uint32_t action,
		uint32_t notify_filter)
{
	X_LOG_DBG("path=%s action=%d filter=0x%x", posixfs_object->unix_path.c_str(),
			action, notify_filter);
	notify_fname_intl(posixfs_object->topdir, posixfs_object->req_path,
			action, notify_filter, nullptr);
}

static void notify_rename(const std::shared_ptr<x_smbd_topdir_t> topdir,
		const std::u16string dst_path,
		const std::u16string src_path,
		bool is_dir)
{
	auto dst_sep = dst_path.rfind(u'\\');
	auto src_sep = src_path.rfind(u'\\');
	uint32_t notify_filter = is_dir ? FILE_NOTIFY_CHANGE_DIR_NAME
		: FILE_NOTIFY_CHANGE_FILE_NAME;
	if (dst_sep == src_sep && (dst_sep == std::u16string::npos || memcmp(dst_path.data(), src_path.data(), dst_sep * 2)) == 0) {
		notify_fname_intl(topdir, src_path, NOTIFY_ACTION_OLD_NAME, notify_filter, &dst_path);

	} else {
		notify_fname_intl(topdir, src_path, NOTIFY_ACTION_REMOVED, notify_filter, nullptr);
		notify_fname_intl(topdir, dst_path, NOTIFY_ACTION_ADDED, notify_filter, nullptr);
	}
}

/* rename_internals_fsp */
static NTSTATUS rename_object_intl(posixfs_object_pool_t::bucket_t &dst_bucket,
		posixfs_object_pool_t::bucket_t &src_bucket,
		const std::shared_ptr<x_smbd_topdir_t> &topdir,
		posixfs_object_t *src_object,
		const std::u16string &dst_path,
		std::u16string &src_path,
		uint64_t dst_hash)
{
	posixfs_object_t *dst_object = nullptr;
	for (x_dqlink_t *link = dst_bucket.head.get_front(); link; link = link->get_next()) {
		posixfs_object_t *elem = X_CONTAINER_OF(link, posixfs_object_t, hash_link);
		if (elem->hash == dst_hash && elem->topdir->uuid == topdir->uuid
				&& elem->req_path == dst_path) {
			dst_object = elem;
			break;
		}
	}
	if (dst_object && dst_object->exists()) {
		/* TODO replace forced */
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	/* check if exists on file system */
	std::string dst_unix_path = convert_to_unix(dst_path);
	int fd = openat(topdir->fd, dst_unix_path.c_str(), O_RDONLY);
	if (fd != -1) {
		if (dst_object) {
			dst_object->fd = fd;
			/* so it needs to reload statex when using it */
			dst_object->statex_modified = true;
		} else {
			close(fd);
		}
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	int err = renameat(topdir->fd, src_object->unix_path.c_str(),
			topdir->fd, dst_unix_path.c_str());
	if (err != 0) {
		return x_map_nt_error_from_unix(-err);
	}	

	if (dst_object) {
		/* not exists, should none refer it??? */
		dst_bucket.head.remove(&dst_object->hash_link);
		X_ASSERT(dst_object->use_count == 0);
		delete dst_object;
	}

	src_path = src_object->req_path;
	src_bucket.head.remove(&src_object->hash_link);
	src_object->hash = dst_hash;
	src_object->req_path = dst_path;
	src_object->unix_path = dst_unix_path;
	dst_bucket.head.push_front(&src_object->hash_link);
	return NT_STATUS_OK;
}

NTSTATUS posixfs_object_rename(x_smbd_object_t *smbd_object,
		x_smbd_requ_t *smbd_requ,
		std::shared_ptr<x_smbd_topdir_t> dst_topdir,
		const std::u16string &dst_path,
		bool replace_if_exists)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	if (!dst_topdir) {
		dst_topdir = posixfs_object->topdir;
	}

	auto &pool = posixfs_object_pool;
	auto dst_hash = hash_object(dst_topdir, dst_path);
	auto dst_bucket_idx = dst_hash % pool.buckets.size();
	auto &dst_bucket = pool.buckets[dst_bucket_idx];
	auto src_bucket_idx = posixfs_object->hash % pool.buckets.size();

	NTSTATUS status;
	std::u16string src_path;
	if (dst_bucket_idx == src_bucket_idx) {
		std::lock_guard<std::mutex> lock(dst_bucket.mutex);
		status = rename_object_intl(dst_bucket, dst_bucket, dst_topdir,
				posixfs_object,
				dst_path, src_path, dst_hash);
	} else {
		auto &src_bucket = pool.buckets[src_bucket_idx];
		std::scoped_lock lock(dst_bucket.mutex, src_bucket.mutex);
		status = rename_object_intl(dst_bucket, dst_bucket, dst_topdir,
				posixfs_object,
				dst_path, src_path, dst_hash);
	}

	if (NT_STATUS_IS_OK(status)) {
		notify_rename(dst_topdir, dst_path, src_path, posixfs_object->is_dir());
	}
	return status;
}

NTSTATUS posixfs_object_op_rename(x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		bool replace_if_exists,
		const std::u16string &new_path)
{
	/* does it happen renaming cross topdir? if not we do not need dst_topdir */
	std::shared_ptr<x_smbd_topdir_t> dst_topdir;
	return posixfs_object_rename(smbd_object, smbd_requ, 
			dst_topdir, new_path, replace_if_exists);
}

#if 0
static NTSTATUS posixfs_object_rename(posixfs_object_t *posixfs_object,
		const std::shared_ptr<x_smbd_share_t> &smbd_share,
		bool dfs,
		bool replace_if_exists,
		const std::u16string &in_dst_path)
{
	std::u16string dst_path;
	std::shared_ptr<x_smbd_topdir_t> topdir;
	NTSTATUS status = smbd_share->resolve_path(
			in_dst_path, dfs,
			topdir, dst_path);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	
	if (topdir->uuid != posixfs_object->topdir->uuid) {
		/* we cannot move between filesystem */
		return NT_STATUS_UNSUCCESSFUL; // TODO
	}

	auto &pool = posixfs_object_pool;
	auto dst_hash = hash_object(topdir, dst_path);
	auto dst_bucket_idx = dst_hash % pool.buckets.size();
	auto &dst_bucket = pool.buckets[dst_bucket_idx];
	auto src_bucket_idx = posixfs_object->hash % pool.buckets.size();

	std::u16string src_path;
	if (dst_bucket_idx == src_bucket_idx) {
		std::lock_guard<std::mutex> lock(dst_bucket.mutex);
		status = rename_object_intl(dst_bucket, dst_bucket, topdir,
				posixfs_object,
				dst_path, src_path, dst_hash);
	} else {
		auto &src_bucket = pool.buckets[src_bucket_idx];
		std::scoped_lock lock(dst_bucket.mutex, src_bucket.mutex);
		status = rename_object_intl(dst_bucket, dst_bucket, topdir,
				posixfs_object,
				dst_path, src_path, dst_hash);
	}

	if (NT_STATUS_IS_OK(status)) {
		notify_rename(topdir, dst_path, src_path, posixfs_object->is_dir());
	}
	return status;
}
#endif
static posixfs_object_t *posixfs_object_open(
		const x_smbd_object_ops_t *ops,
		const std::shared_ptr<x_smbd_topdir_t> &topdir,
		const std::u16string &path)
{
	posixfs_object_t *posixfs_object = posixfs_object_lookup(ops, topdir, path, true);

	std::unique_lock<std::mutex> lock(posixfs_object->mutex);
	if (!(posixfs_object->flags & posixfs_object_t::flag_initialized)) {
		std::string unix_path = convert_to_unix(path);
		int fd = posixfs_open(topdir->fd, unix_path.c_str(),
				&posixfs_object->statex);
		if (fd < 0) {
			assert(errno == ENOENT);
			posixfs_object->flags = posixfs_object_t::flag_not_exist | posixfs_object_t::flag_initialized;
		} else {
			posixfs_object->fd = fd;
			posixfs_object->flags = posixfs_object_t::flag_initialized;
			if (unix_path.size() == 0) {
				posixfs_object->flags |= posixfs_object_t::flag_topdir;
			}
		}
		posixfs_object->unix_path = unix_path;
	}
	return posixfs_object;
}

static NTSTATUS posixfs_object_get_sd__(posixfs_object_t *posixfs_object,
		std::shared_ptr<idl::security_descriptor> &psd)
{
	std::vector<uint8_t> blob;
	if (!posixfs_object->exists()) {
		return NT_STATUS_OBJECT_PATH_NOT_FOUND;
	}

	int err = posixfs_get_ntacl_blob(posixfs_object->fd, blob);
	if (err < 0) {
		return x_map_nt_error_from_unix(-err);
	}

	uint16_t hash_type;
	uint16_t version;
	std::array<uint8_t, idl::XATTR_SD_HASH_SIZE> hash;
	return parse_acl_blob(blob, psd, &hash_type, &version, hash);
}

static NTSTATUS posixfs_object_get_sd(posixfs_object_t *posixfs_object,
		std::shared_ptr<idl::security_descriptor> &psd)
{
	std::unique_lock<std::mutex> lock(posixfs_object->mutex);
	return posixfs_object_get_sd__(posixfs_object, psd);
}

static posixfs_object_t *posixfs_object_open_parent(
		const x_smbd_object_ops_t *ops,
		const posixfs_object_t *child_object)
{
	if (child_object->req_path.empty()) {
		return nullptr;
	}

	std::u16string parent_path;
	auto sep = child_object->req_path.rfind('\\');
	if (sep != std::u16string::npos) {
		parent_path = child_object->req_path.substr(0, sep);
	}

	posixfs_object_t *parent_object = posixfs_object_open(ops,
			child_object->topdir, parent_path);
	if (!parent_object->exists() || !parent_object->is_dir()) {
		/* it should not happend */
		posixfs_object_release(parent_object);
		return nullptr;
	}
	return parent_object;
}

static bool is_stat_open(uint32_t access_mask)
{
	const uint32_t stat_open_bits =
		(idl::SEC_STD_SYNCHRONIZE|
		 idl::SEC_FILE_READ_ATTRIBUTE|
		 idl::SEC_FILE_WRITE_ATTRIBUTE);

	return (((access_mask &  stat_open_bits) != 0) &&
			((access_mask & ~stat_open_bits) == 0));
}

static bool share_conflict(const x_smbd_open_t *smbd_open,
		uint32_t access_mask, uint32_t share_access)
{
	if ((smbd_open->access_mask & (idl::SEC_FILE_WRITE_DATA|
				idl::SEC_FILE_APPEND_DATA|
				idl::SEC_FILE_READ_DATA|
				idl::SEC_FILE_EXECUTE|
				idl::SEC_STD_DELETE)) == 0) {
		return false;
	}

#define CHECK_MASK(num, am, right, sa, share) \
	if (((am) & (right)) && !((sa) & (share))) { \
		X_DBG("share_conflict: check %d conflict am = 0x%x, right = 0x%x, \
				sa = 0x%x, share = 0x%x\n", (num), (unsigned int)(am), (unsigned int)(right), (unsigned int)(sa), \
				(unsigned int)(share) ); \
		return true; \
	}

	CHECK_MASK(1, smbd_open->access_mask, idl::SEC_FILE_WRITE_DATA | idl::SEC_FILE_APPEND_DATA,
			share_access, FILE_SHARE_WRITE);
	CHECK_MASK(2, access_mask, idl::SEC_FILE_WRITE_DATA | idl::SEC_FILE_APPEND_DATA,
			smbd_open->share_access, FILE_SHARE_WRITE);

	CHECK_MASK(3, smbd_open->access_mask, idl::SEC_FILE_READ_DATA | idl::SEC_FILE_EXECUTE,
			share_access, FILE_SHARE_READ);
	CHECK_MASK(4, access_mask, idl::SEC_FILE_READ_DATA | idl::SEC_FILE_EXECUTE,
			smbd_open->share_access, FILE_SHARE_READ);

	CHECK_MASK(5, smbd_open->access_mask, idl::SEC_STD_DELETE,
			share_access, FILE_SHARE_DELETE);
	CHECK_MASK(6, access_mask, idl::SEC_STD_DELETE,
			smbd_open->share_access, FILE_SHARE_DELETE);

	return false;
}

/* caller locked posixfs_object */
static bool open_mode_check(posixfs_object_t *posixfs_object,
		uint32_t access_mask, uint32_t share_access)
{
	if (is_stat_open(access_mask)) {
		/* Stat open that doesn't trigger oplock breaks or share mode
		 * checks... ! JRA. */
		return false;
	}

	if ((access_mask & (idl::SEC_FILE_WRITE_DATA|
					idl::SEC_FILE_APPEND_DATA|
					idl::SEC_FILE_READ_DATA|
					idl::SEC_FILE_EXECUTE|
					idl::SEC_STD_DELETE)) == 0) {
#if 0
		DEBUG(10,("share_conflict: No conflict due to "
					"access_mask = 0x%x\n",
					(unsigned int)access_mask ));
#endif
		return false;
	}

	auto &open_list = posixfs_object->open_list;
	posixfs_open_t *posixfs_open;
	for (posixfs_open = open_list.get_front(); posixfs_open; posixfs_open = open_list.next(posixfs_open)) {
		if (share_conflict(&posixfs_open->base, access_mask, share_access)) {
			return true;
		}
	}
	return false;
}

static inline uint8_t get_lease_type(const posixfs_open_t *posixfs_open)
{
	if (posixfs_open->oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE) {
		return x_smbd_lease_get_state(posixfs_open->smbd_lease);
	} else if (posixfs_open->oplock_level == X_SMB2_OPLOCK_LEVEL_II) {
		return X_SMB2_LEASE_READ;
	} else if (posixfs_open->oplock_level == X_SMB2_OPLOCK_LEVEL_EXCLUSIVE) {
		return X_SMB2_LEASE_READ | X_SMB2_LEASE_WRITE;
	} else if (posixfs_open->oplock_level == X_SMB2_OPLOCK_LEVEL_BATCH) {
		return X_SMB2_LEASE_READ | X_SMB2_LEASE_WRITE | X_SMB2_LEASE_HANDLE;
	} else {
		return 0;
	}
}

struct posixfs_break_evt_t
{
	~posixfs_break_evt_t() {
		if (smbd_sess) {
			x_smbd_ref_dec(smbd_sess);
		}
		x_smbd_ref_dec(&posixfs_open->base);
	}
	x_fdevt_user_t base;
	posixfs_open_t *posixfs_open;
	x_smbd_sess_t *smbd_sess = nullptr;
	uint8_t breakto;
};

static void posixfs_break_func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user, bool terminated)
{
	posixfs_break_evt_t *evt = X_CONTAINER_OF(fdevt_user, posixfs_break_evt_t, base);
	X_LOG_DBG("evt=%p", evt);

	if (terminated) {
		delete evt;
		return;
	}

	posixfs_open_t *posixfs_open = evt->posixfs_open;
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(posixfs_open->base.smbd_object);

	std::lock_guard<std::mutex> lock(posixfs_object->mutex);
	if (posixfs_open->smbd_lease) {
		/* TODO check breaking */
		x_smb2_send_lease_break(smbd_conn,
				evt->smbd_sess,
				&posixfs_open->smbd_lease->lease_key,
				0, // TODO epoch
				SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED, // TODO
				posixfs_open->smbd_lease->lease_state,
				evt->breakto);
	} else {
		if (posixfs_open->oplock_break_sent != oplock_break_sent_t::OPLOCK_BREAK_NOT_SENT) {
			posixfs_open->oplock_break_sent = evt->breakto == X_SMB2_OPLOCK_LEVEL_II ?
				oplock_break_sent_t::OPLOCK_BREAK_TO_LEVEL_II_SENT : oplock_break_sent_t::OPLOCK_BREAK_TO_NONE_SENT;
			x_smb2_send_oplock_break(smbd_conn,
					evt->smbd_sess,
					&posixfs_open->base,
					evt->breakto);
		}
	}
	delete evt;
}

static void send_break(posixfs_open_t *posixfs_open,
		uint8_t breakto)
{
	/* already hold posixfs_object mutex */
	posixfs_break_evt_t *evt = new posixfs_break_evt_t;
	evt->base.func = posixfs_break_func;
	x_smbd_ref_inc(&posixfs_open->base);
	evt->posixfs_open = posixfs_open;
	evt->breakto = breakto;
	evt->smbd_sess = x_smbd_tcon_get_sess(posixfs_open->base.smbd_tcon);
	x_smbd_chan_t *smbd_chan = x_smbd_sess_get_active_chan(evt->smbd_sess);
	if (smbd_chan) {
		if (x_smbd_chan_post_user(smbd_chan, &evt->base)) {
			return;
		}
		x_smbd_ref_dec(smbd_chan);
	}
	X_LOG_ERR("failed to post send_break %p", smbd_chan);
	delete evt;
}

/* caller locked posixfs_object */
static bool delay_for_oplock(posixfs_object_t *posixfs_object,
		const x_smb2_uuid_t &client_guid,
		const x_smb2_lease_t *lease,
		uint32_t create_disposition,
		bool have_sharing_violation,
		bool first_open_attempt)
{
	bool will_overwrite;

	switch (create_disposition) {
	case FILE_SUPERSEDE:
	case FILE_OVERWRITE:
	case FILE_OVERWRITE_IF:
		will_overwrite = true;
		break;
	default:
		will_overwrite = false;
		break;
	}

	uint32_t break_count = 0;
	bool delay = false;
	auto &open_list = posixfs_object->open_list;
	posixfs_open_t *curr_open;
	for (curr_open = open_list.get_front(); curr_open; curr_open = open_list.next(curr_open)) {
		/* TODO mutex curr_open ? */
		uint8_t e_lease_type = get_lease_type(curr_open);
		uint8_t break_to;
		uint8_t delay_mask = 0;
		if (curr_open->oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE) {
			if (lease && x_smbd_lease_match(curr_open->smbd_lease,
						client_guid, lease->key)) {
				continue;
			}
		}

		if (have_sharing_violation) {
			delay_mask = X_SMB2_LEASE_HANDLE;
		} else {
			delay_mask = X_SMB2_LEASE_WRITE;
		}

		break_to = x_convert<uint8_t>(e_lease_type & ~delay_mask);

		if (will_overwrite) {
			break_to = x_convert<uint8_t>(break_to & ~X_SMB2_LEASE_HANDLE);
		}

		if ((e_lease_type & ~break_to) == 0) {
			if (curr_open->oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE && x_smbd_lease_is_breaking(curr_open->smbd_lease)) {
				delay = true;
			}
			continue;
		}
		if (will_overwrite) {
			/*
			 * If we break anyway break to NONE directly.
			 * Otherwise vfs_set_filelen() will trigger the
			 * break.
			 */
			break_to = x_convert<uint8_t>(break_to & ~(X_SMB2_LEASE_READ|X_SMB2_LEASE_WRITE));
		}

		if (curr_open->oplock_level != X_SMB2_OPLOCK_LEVEL_LEASE) {
			/*
			 * Oplocks only support breaking to R or NONE.
			 */
			break_to = x_convert<uint8_t>(break_to & ~(X_SMB2_LEASE_HANDLE|X_SMB2_LEASE_WRITE));
		}
		++break_count;
		send_break(curr_open, break_to);
		if (e_lease_type & delay_mask) {
			delay = true;
		}
		if (curr_open->oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE && x_smbd_lease_is_breaking(curr_open->smbd_lease) && !first_open_attempt) {
			delay = true;
		}
	}
	return delay;
}

/* caller locked posixfs_object */
static NTSTATUS grant_oplock(posixfs_object_t *posixfs_object,
		const x_smb2_uuid_t &client_guid,
		x_smb2_state_create_t &state,
		x_smbd_lease_t **psmbd_lease)
{
	x_smbd_lease_t *smbd_lease = nullptr;
	uint8_t granted = X_SMB2_LEASE_NONE;
	uint8_t oplock_level = state.oplock_level;
	x_smb2_lease_t *lease = nullptr;
	if (oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE) {
		lease = &state.lease;
	}

	if (posixfs_object->is_dir()) {
		if (lease) {
			granted = lease->state & (X_SMB2_LEASE_READ|X_SMB2_LEASE_HANDLE);
			if (!(granted & X_SMB2_LEASE_READ)) {
				granted = X_SMB2_LEASE_NONE;
			}
		} else {
			oplock_level = X_SMB2_OPLOCK_LEVEL_NONE;
			granted = X_SMB2_LEASE_NONE;
		}
	} else {
		if (lease) {
			granted = lease->state & (X_SMB2_LEASE_READ|X_SMB2_LEASE_HANDLE|X_SMB2_LEASE_WRITE);
			if (!(granted & X_SMB2_LEASE_READ)) {
				granted = X_SMB2_LEASE_NONE;
			}
		} else if (oplock_level == X_SMB2_OPLOCK_LEVEL_II) {
			granted = X_SMB2_LEASE_READ;
		} else if (oplock_level == X_SMB2_OPLOCK_LEVEL_EXCLUSIVE) {
			granted = X_SMB2_LEASE_READ|X_SMB2_LEASE_WRITE;
		} else if (oplock_level == X_SMB2_OPLOCK_LEVEL_BATCH) {
			granted = X_SMB2_LEASE_READ|X_SMB2_LEASE_HANDLE|X_SMB2_LEASE_WRITE;
		} else {
			oplock_level = X_SMB2_OPLOCK_LEVEL_NONE;
			granted = X_SMB2_LEASE_NONE;
		}
	}

	bool self_is_stat_open = is_stat_open(state.in_desired_access);
	bool got_handle_lease = false;
	bool got_oplock = false;

	auto &open_list = posixfs_object->open_list;
	posixfs_open_t *curr_open;
	for (curr_open = open_list.get_front(); curr_open; curr_open = open_list.next(curr_open)) {
		/* TODO mutex curr_open? */
		uint32_t e_lease_type = get_lease_type(curr_open);
		/* Stat opens should be ignored when granting leases
		 * especially the ones without any leases.
		 */
		if (is_stat_open(curr_open->base.access_mask) && e_lease_type == 0) {
			continue;
		}
		if (curr_open->oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE &&
				lease && x_smbd_lease_match(curr_open->smbd_lease,
					client_guid,
					lease->key)) {
			if (e_lease_type & X_SMB2_LEASE_WRITE) {
				granted = X_SMB2_LEASE_NONE;
				break;
			} else if (!self_is_stat_open || e_lease_type != 0) {
				/* Windows server allow WRITE_LEASE if new open
				 * is stat open and no current one has no lease.
				 */
				granted &= uint8_t(~X_SMB2_LEASE_WRITE);
			}
		}

		if (e_lease_type & X_SMB2_LEASE_HANDLE) {
			got_handle_lease = true;
		}

		if (curr_open->oplock_level != X_SMB2_OPLOCK_LEVEL_LEASE && curr_open->oplock_level != X_SMB2_OPLOCK_LEVEL_NONE) {
			got_oplock = true;
		}
	}

	if ((granted & (X_SMB2_LEASE_READ|X_SMB2_LEASE_WRITE)) == X_SMB2_LEASE_READ) {
#if 0
		bool allow_level2 =
			lp_level2_oplocks(SNUM(fsp->conn));

		if (!allow_level2) {
			granted = SMB2_LEASE_NONE;
		}
#endif
	}

	if (oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE) {
		if (got_oplock) {
			granted &= uint8_t(~X_SMB2_LEASE_HANDLE);
		}
		state.oplock_level = X_SMB2_OPLOCK_LEVEL_LEASE;
		smbd_lease = x_smbd_lease_grant(
				client_guid,
				lease,
				granted,
				&posixfs_object->base);
		*psmbd_lease = smbd_lease;
	} else {
		if (got_handle_lease) {
			granted = X_SMB2_LEASE_NONE;
		}
		switch (granted) {
		case X_SMB2_LEASE_READ|X_SMB2_LEASE_WRITE|X_SMB2_LEASE_HANDLE:
			state.oplock_level = X_SMB2_OPLOCK_LEVEL_BATCH;
			break;
		case X_SMB2_LEASE_READ|X_SMB2_LEASE_WRITE:
			state.oplock_level = X_SMB2_OPLOCK_LEVEL_EXCLUSIVE;
			break;
		case X_SMB2_LEASE_READ|X_SMB2_LEASE_HANDLE:
		case X_SMB2_LEASE_READ:
			state.oplock_level = X_SMB2_OPLOCK_LEVEL_II;
			break;
		default:
			state.oplock_level = X_SMB2_OPLOCK_LEVEL_NONE;
			break;
		}
	}
	return NT_STATUS_OK;
}

/* posixfs_object mutex is locked */
static NTSTATUS posixfs_object_set_delete_on_close(posixfs_object_t *posixfs_object,
		bool delete_on_close)
{
	if (delete_on_close) {
		if (posixfs_object->statex.file_attributes & FILE_ATTRIBUTE_READONLY) {
			return NT_STATUS_CANNOT_DELETE;
		}
		if (true /*!is_stream_open(posixfs_open) */) {
			posixfs_object->flags |= posixfs_object_t::flag_delete_on_close;
		} else {
			X_TODO;
		}
	} else {
		/* TODO handle streams */
		posixfs_object->flags &= ~posixfs_object_t::flag_delete_on_close;
	}
	return NT_STATUS_OK;
}

static posixfs_open_t *posixfs_open_create(
		NTSTATUS *pstatus,
		x_smbd_tcon_t *smbd_tcon,
		posixfs_object_t *posixfs_object,
		const x_smb2_state_create_t &state,
		x_smbd_lease_t *smbd_lease)
{
	NTSTATUS status;
	if (state.in_create_options & FILE_DELETE_ON_CLOSE) {
		status = posixfs_object_set_delete_on_close(posixfs_object, true);
		if (!NT_STATUS_IS_OK(status)) {
			*pstatus = status;
			return nullptr;
		}
	}

	posixfs_open_t *posixfs_open = new posixfs_open_t(&posixfs_object->base,
			smbd_tcon, state.granted_access, state.in_share_access);
	posixfs_open->oplock_level = state.oplock_level;
	posixfs_open->smbd_lease = smbd_lease;
	++posixfs_object->use_count;
	posixfs_object->open_list.push_back(posixfs_open);
	*pstatus = NT_STATUS_OK;
	return posixfs_open;
}

static void fill_out_info(x_smb2_create_close_info_t &info, const posixfs_statex_t &statex)
{
	info.out_create_ts = x_timespec_to_nttime(statex.birth_time);
	info.out_last_access_ts = x_timespec_to_nttime(statex.stat.st_atim);
	info.out_last_write_ts = x_timespec_to_nttime(statex.stat.st_mtim);
	info.out_change_ts = x_timespec_to_nttime(statex.stat.st_ctim);
	info.out_file_attributes = statex.file_attributes;
	info.out_allocation_size = statex.get_allocation();
	info.out_end_of_file = statex.get_end_of_file();
}

static void reply_requ_create(x_smb2_state_create_t &state,
		const posixfs_object_t *posixfs_object,
		uint32_t create_action)
{
	state.out_create_flags = 0;
	state.out_create_action = create_action;
	fill_out_info(state.out_info, posixfs_object->statex);
}

static NTSTATUS get_parent_sd(const posixfs_object_t *posixfs_object,
		std::shared_ptr<idl::security_descriptor> &psd)
{
	// posixfs_object mutex is locked here, and it is going to lock the parent
	// TODO release parent_object
	posixfs_object_t *parent_object = posixfs_object_open_parent(
			posixfs_object->base.ops,
			posixfs_object);
	if (!parent_object) {
		return NT_STATUS_OBJECT_PATH_NOT_FOUND;
	}

	NTSTATUS status = posixfs_object_get_sd(parent_object, psd);
	posixfs_object_release(parent_object);

	return status;
}

/* TODO pass sec_desc context
#define SMB2_CREATE_TAG_SECD "SecD"
 */
static posixfs_open_t *open_object_new(
		posixfs_object_t *posixfs_object,
		x_smbd_sess_t *smbd_sess,
		x_smbd_tcon_t *smbd_tcon,
		x_smb2_state_create_t &state,
		NTSTATUS &status)
{
	std::shared_ptr<idl::security_descriptor> parent_psd;
	status = get_parent_sd(posixfs_object, parent_psd);
	if (!NT_STATUS_IS_OK(status)) {
		return nullptr;
	}

	auto smbd_user = x_smbd_sess_get_user(smbd_sess);
	uint32_t rejected_mask = 0;
	status = se_file_access_check(*parent_psd, *smbd_user,
			false, idl::SEC_DIR_ADD_FILE, &rejected_mask);
	if (!NT_STATUS_IS_OK(status)) {
		return nullptr;
	}

	std::shared_ptr<idl::security_descriptor> psd;
	status = make_child_sec_desc(psd, parent_psd,
			*smbd_user,
			state.in_create_options & FILE_DIRECTORY_FILE);
	if (!NT_STATUS_IS_OK(status)) {
		return nullptr;
	}

	std::vector<uint8_t> ntacl_blob;
	create_acl_blob(ntacl_blob, psd, idl::XATTR_SD_HASH_TYPE_NONE, std::array<uint8_t, idl::XATTR_SD_HASH_SIZE>());

	/* if parent is not enable inherit, make_sec_desc */
	int fd = posixfs_create(posixfs_object->topdir->fd,
			state.in_create_options & FILE_DIRECTORY_FILE,
			posixfs_object->unix_path.c_str(),
			&posixfs_object->statex,
			ntacl_blob);

	if (fd < 0) {
		X_ASSERT(-fd == EEXIST);
		status = NT_STATUS_OBJECT_NAME_COLLISION;
		return nullptr;
	}

	state.out_maximal_access = se_calculate_maximal_access(*psd, *smbd_user);
	/* Windows server seem not do access check for create new object */
	if (state.in_desired_access & idl::SEC_FLAG_MAXIMUM_ALLOWED) {
		state.granted_access = state.out_maximal_access;
	} else {
		state.granted_access = state.out_maximal_access & state.in_desired_access;
	}

	X_ASSERT(posixfs_object->fd == -1);
	X_ASSERT(posixfs_object->flags & posixfs_object_t::flag_not_exist);
	posixfs_object->fd = fd;
	posixfs_object->flags &= ~(posixfs_object_t::flag_not_exist);

	x_smbd_lease_t *smbd_lease = nullptr;
       	status = grant_oplock(posixfs_object,
			x_smbd_conn_curr_client_guid(), state, &smbd_lease);
	X_ASSERT(NT_STATUS_IS_OK(status));
	reply_requ_create(state, posixfs_object, FILE_WAS_CREATED);
	return posixfs_open_create(&status, smbd_tcon, posixfs_object, state, smbd_lease);
}

static bool can_delete_file_in_directory(
		posixfs_object_t *posixfs_object,
		x_smbd_tcon_t *smbd_tcon,
		const x_smbd_user_t &smbd_user)
{
#if 0
	char *dname = NULL;
	struct smb_filename *smb_fname_parent;
	bool ret;

	if (!CAN_WRITE(conn)) {
		return False;
	}

	if (!lp_acl_check_permissions(SNUM(conn))) {
		/* This option means don't check. */
		return true;
	}

	/* Get the parent directory permission mask and owners. */
	if (!parent_dirname(ctx, smb_fname->base_name, &dname, NULL)) {
		return False;
	}

	smb_fname_parent = synthetic_smb_fname(ctx,
				dname,
				NULL,
				NULL,
				smb_fname->flags);
	if (smb_fname_parent == NULL) {
		ret = false;
		goto out;
	}

	if(SMB_VFS_STAT(conn, smb_fname_parent) != 0) {
		ret = false;
		goto out;
	}

	/* fast paths first */

	if (!S_ISDIR(smb_fname_parent->st.st_ex_mode)) {
		ret = false;
		goto out;
	}
	if (get_current_uid(conn) == (uid_t)0) {
		/* I'm sorry sir, I didn't know you were root... */
		ret = true;
		goto out;
	}

#ifdef S_ISVTX
	/* sticky bit means delete only by owner of file or by root or
	 * by owner of directory. */
	if (smb_fname_parent->st.st_ex_mode & S_ISVTX) {
		if (!VALID_STAT(smb_fname->st)) {
			/* If the file doesn't already exist then
			 * yes we'll be able to delete it. */
			ret = true;
			goto out;
		}

		/*
		 * Patch from SATOH Fumiyasu <fumiyas@miraclelinux.com>
		 * for bug #3348. Don't assume owning sticky bit
		 * directory means write access allowed.
		 * Fail to delete if we're not the owner of the file,
		 * or the owner of the directory as we have no possible
		 * chance of deleting. Otherwise, go on and check the ACL.
		 */
		if ((get_current_uid(conn) !=
			smb_fname_parent->st.st_ex_uid) &&
		    (get_current_uid(conn) != smb_fname->st.st_ex_uid)) {
			DEBUG(10,("can_delete_file_in_directory: not "
				  "owner of file %s or directory %s",
				  smb_fname_str_dbg(smb_fname),
				  smb_fname_str_dbg(smb_fname_parent)));
			ret = false;
			goto out;
		}
	}
#endif
#endif
	/* now for ACL checks */
	std::shared_ptr<idl::security_descriptor> psd;
	NTSTATUS status = get_parent_sd(posixfs_object, psd);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	uint32_t rejected_mask = 0;
	status = se_file_access_check(*psd, smbd_user, false, idl::SEC_DIR_DELETE_CHILD, &rejected_mask);
	return NT_STATUS_IS_OK(status);
	/*
	 * There's two ways to get the permission to delete a file: First by
	 * having the DELETE bit on the file itself and second if that does
	 * not help, by the DELETE_CHILD bit on the containing directory.
	 *
	 * Here we only check the directory permissions, we will
	 * check the file DELETE permission separately.
	 */
}

static inline NTSTATUS check_object_access(
		posixfs_object_t *posixfs_object,
		x_smbd_tcon_t *smbd_tcon,
		const x_smbd_user_t &smbd_user,
		uint32_t access)
{
	// No access check needed for attribute opens.
	if ((access & ~(idl::SEC_FILE_READ_ATTRIBUTE | idl::SEC_STD_SYNCHRONIZE)) == 0) {
		return NT_STATUS_OK;
	}

	// TODO smbd_check_access_rights
	// if (!use_privs && can_skip_access_check(conn)) {
	// if ((access_mask & DELETE_ACCESS) && !lp_acl_check_permissions(SNUM(conn))) {

	std::shared_ptr<idl::security_descriptor> psd;
	NTSTATUS status = posixfs_object_get_sd__(posixfs_object, psd);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	uint32_t rejected_mask = 0;
	status = se_file_access_check(*psd, smbd_user, false, access, &rejected_mask);
	X_LOG_DBG("check_object_access 0x%x 0x%x 0x%x, sd=%s", status.v,
			access, rejected_mask,
			idl_tostring(*psd).c_str());

	if (!NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
		return status;
	}
	
	if (rejected_mask == idl::SEC_STD_DELETE && can_delete_file_in_directory(posixfs_object,
				smbd_tcon, smbd_user)) {
		return NT_STATUS_OK;
	} else {
		return NT_STATUS_ACCESS_DENIED;
	}
}

static posixfs_open_t *open_object_exist(
		posixfs_object_t *posixfs_object,
		x_smbd_sess_t *smbd_sess,
		x_smbd_tcon_t *smbd_tcon,
		std::unique_ptr<x_smb2_state_create_t> &state,
		NTSTATUS &status,
		x_smbd_requ_t *smbd_requ)
{
	if (posixfs_object->flags & posixfs_object_t::flag_delete_on_close) {
		status = NT_STATUS_DELETE_PENDING;
		return nullptr;
	}

	if (!x_smbd_tcon_access_check(smbd_tcon, state->in_desired_access)) {
		status = NT_STATUS_ACCESS_DENIED;
		return nullptr;
	}

	if (posixfs_object->statex.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
		X_LOG_DBG("object %s is reparse_point", posixfs_object->unix_path.c_str());
		status = NT_STATUS_PATH_NOT_COVERED;
		return nullptr;
	}

	std::shared_ptr<idl::security_descriptor> psd;
	status = posixfs_object_get_sd__(posixfs_object, psd);
	if (!NT_STATUS_IS_OK(status)) {
		return nullptr;
	}

	auto smbd_user = x_smbd_sess_get_user(smbd_sess);
	state->out_maximal_access = se_calculate_maximal_access(*psd, *smbd_user);
	uint32_t desired_access = state->in_desired_access & ~idl::SEC_FLAG_MAXIMUM_ALLOWED;

	uint32_t granted = state->out_maximal_access;
	if (state->in_desired_access & idl::SEC_FLAG_MAXIMUM_ALLOWED) {
		if (posixfs_object->statex.file_attributes & FILE_ATTRIBUTE_READONLY) {
			granted &= ~(idl::SEC_FILE_WRITE_DATA | idl::SEC_FILE_APPEND_DATA);
		}
	} else {
		granted = (desired_access & state->out_maximal_access);
	}

	uint32_t rejected_mask = desired_access & ~granted;
	if (rejected_mask == idl::SEC_STD_DELETE) {
	       	if (!can_delete_file_in_directory(posixfs_object,
					smbd_tcon, *smbd_user)) {
			status = NT_STATUS_ACCESS_DENIED;
			return nullptr;
		}
	} else if (rejected_mask != 0) {
		status = NT_STATUS_ACCESS_DENIED;
		return nullptr;
	}

	state->granted_access = granted;

	auto &curr_client_guid = x_smbd_conn_curr_client_guid();
	bool conflict = open_mode_check(posixfs_object, state->in_desired_access, state->in_share_access);
	if (delay_for_oplock(posixfs_object, curr_client_guid,
				state->oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE ?
					&state->lease : nullptr,
				state->in_create_disposition,
				conflict, true)) {
		smbd_requ->requ_state = state.release();
		/* TODO add timer */
		x_smbd_ref_inc(smbd_requ);
		posixfs_object->defer_open_list.push_back(smbd_requ);
		++posixfs_object->use_count;
		smbd_requ->smbd_object = &posixfs_object->base;
		x_smbd_conn_set_async(g_smbd_conn_curr, smbd_requ, posixfs_create_cancel);
		status = NT_STATUS_PENDING;
		return nullptr;
	}

	if (conflict) {
		status = NT_STATUS_SHARING_VIOLATION;
		return nullptr;
	}

	x_smbd_lease_t *smbd_lease = nullptr;
       	status = grant_oplock(posixfs_object,
			curr_client_guid, *state, &smbd_lease);
	X_ASSERT(NT_STATUS_IS_OK(status));
	reply_requ_create(*state, posixfs_object, FILE_WAS_OPENED);
	return posixfs_open_create(&status, smbd_tcon, posixfs_object, *state, smbd_lease);
}

static posixfs_open_t *create_posixfs_open(
		posixfs_object_t *posixfs_object,
		NTSTATUS &status,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state)
{
	posixfs_open_t *posixfs_open = nullptr;
	x_smbd_tcon_t *smbd_tcon = smbd_requ->smbd_tcon;
	// x_smbd_conn_t *smbd_conn = smbd_requ->smbd_sess->smbd_conn;
	std::unique_lock<std::mutex> lock(posixfs_object->mutex);

	if (state->in_create_disposition == FILE_CREATE) {
		if (posixfs_object->exists()) {
			status = NT_STATUS_OBJECT_NAME_COLLISION;
		} else {
			posixfs_open = open_object_new(posixfs_object, smbd_requ->smbd_sess, smbd_tcon, *state, status);
		}

	} else if (state->in_create_disposition == FILE_OPEN) {
		if (posixfs_object->exists()) {
			posixfs_open = open_object_exist(posixfs_object, smbd_requ->smbd_sess, smbd_tcon, state, status, smbd_requ);
		} else {
			status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}

	} else if (state->in_create_disposition == FILE_OPEN_IF) {
		if (posixfs_object->exists()) {
			posixfs_open = open_object_exist(posixfs_object, smbd_requ->smbd_sess, smbd_tcon, state, status, smbd_requ);
		} else {
			posixfs_open = open_object_new(posixfs_object, smbd_requ->smbd_sess, smbd_tcon, *state, status);
		}

	} else if (state->in_create_disposition == FILE_OVERWRITE_IF ||
			state->in_create_disposition == FILE_SUPERSEDE) {
		/* TODO
		 * Currently we're using FILE_SUPERSEDE as the same as
		 * FILE_OVERWRITE_IF but they really are
		 * different. FILE_SUPERSEDE deletes an existing file
		 * (requiring delete access) then recreates it.
		 */
		if (posixfs_object->exists()) {
			int err = ftruncate(posixfs_object->fd, 0);
			X_ASSERT(err == 0); // TODO
			posixfs_open = open_object_exist(posixfs_object, smbd_requ->smbd_sess, smbd_tcon, state, status, smbd_requ);
		} else {
			posixfs_open = open_object_new(posixfs_object, smbd_requ->smbd_sess, smbd_tcon, *state, status);
		}

	} else {
		X_TODO;
	}

	if (!posixfs_open) {
		return nullptr;
	}

	return posixfs_open;
}

/* TODO should not hold the posixfs_object's mutex */
NTSTATUS posixfs_object_op_unlink(x_smbd_object_t *smbd_object, int fd)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	int err = unlinkat(posixfs_object->topdir->fd, posixfs_object->unix_path.c_str(),
			posixfs_object->is_dir() ? AT_REMOVEDIR : 0);
	X_ASSERT(err == 0);
	err = close(posixfs_object->fd);
	X_ASSERT(err == 0);
	posixfs_object->fd = -1;
	posixfs_object->flags = posixfs_object_t::flag_not_exist;
	return NT_STATUS_OK;
}

static void posixfs_object_remove(posixfs_object_t *posixfs_object,
		posixfs_open_t *posixfs_open)
{
	if (!posixfs_open->object_link.is_valid()) {
		return;
	}
	posixfs_object->open_list.remove(posixfs_open);
	if (posixfs_object->open_list.empty()) {
		if (posixfs_object->flags & posixfs_object_t::flag_delete_on_close) {
			uint32_t notify_filter;
			if (posixfs_object->is_dir()) {
				notify_filter = FILE_NOTIFY_CHANGE_DIR_NAME;
			} else {
				notify_filter = FILE_NOTIFY_CHANGE_FILE_NAME;
			}

			NTSTATUS status = x_smbd_object_unlink(&posixfs_object->base, posixfs_object->fd);
			if (NT_STATUS_IS_OK(status)) {
				notify_fname(posixfs_object, NOTIFY_ACTION_REMOVED,
						notify_filter);
			}
		}
	}
}

NTSTATUS posixfs_object_op_close(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_close_t> &state)
{
	posixfs_open_t *posixfs_open = posixfs_open_from_base_t::container(smbd_open);
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);

	std::unique_lock<std::mutex> lock(posixfs_object->mutex);

	if (posixfs_open->smbd_lease) {
		x_smbd_lease_release(posixfs_open->smbd_lease);
		posixfs_open->smbd_lease = nullptr;
	}

	/* Windows server send NT_STATUS_NOTIFY_CLEANUP
	   when tree disconect.
	   while samba not send.
	   for simplicity we do not either for now
	 */
	x_smbd_requ_t *requ_notify;
	while ((requ_notify = posixfs_open->notify_requ_list.get_front()) != nullptr) {
		posixfs_open->notify_requ_list.remove(requ_notify);
		lock.unlock();

		// TODO multi-thread safe
		std::unique_ptr<x_smb2_state_notify_t> notify_state{(x_smb2_state_notify_t *)requ_notify->requ_state};
		requ_notify->requ_state = nullptr;
		x_smbd_requ_remove(requ_notify);
		// TODO notify_state->done(smbd_conn, requ_notify, NT_STATUS_NOTIFY_CLEANUP);
		x_smbd_ref_dec(requ_notify);

		lock.lock();
	}

	posixfs_object_remove(posixfs_object, posixfs_open);

	share_mode_modified(posixfs_object);

	// TODO if last_write_time updated
	if (smbd_requ) {
		if (state->in_flags & SMB2_CLOSE_FLAGS_FULL_INFORMATION) {
			state->out_flags = SMB2_CLOSE_FLAGS_FULL_INFORMATION;
			fill_out_info(state->out_info, posixfs_object->statex);
		}
	}
	return NT_STATUS_OK;
}

struct posixfs_read_evt_t
{
	posixfs_read_evt_t(x_smbd_requ_t *r, NTSTATUS s)
		: smbd_requ(r), status(s) { }
	x_fdevt_user_t base;
	x_smbd_requ_t *smbd_requ;
	NTSTATUS const status;
};

static void posixfs_read_evt_func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user, bool cancelled)
{
	posixfs_read_evt_t *evt = X_CONTAINER_OF(fdevt_user, posixfs_read_evt_t, base);
	X_LOG_DBG("evt=%p", evt);

	if (!cancelled) {
		x_smbd_requ_t *smbd_requ = evt->smbd_requ;
		x_smbd_requ_remove(smbd_requ);
		smbd_requ->async_done_fn(smbd_conn, smbd_requ, evt->status);
	}

	delete evt;
}

struct posixfs_read_job_t
{
	posixfs_read_job_t(posixfs_object_t *po, x_smbd_requ_t *r);
	x_job_t base;
	posixfs_object_t *posixfs_object;
	x_smbd_requ_t *smbd_requ;
};

static x_job_t::retval_t posixfs_read_job_run(x_job_t *job)
{
	posixfs_read_job_t *posixfs_read_job = X_CONTAINER_OF(job, posixfs_read_job_t, base);

	x_smbd_requ_t *smbd_requ = posixfs_read_job->smbd_requ;
	posixfs_object_t *posixfs_object = posixfs_read_job->posixfs_object;
	posixfs_read_job->smbd_requ = nullptr;
	posixfs_read_job->posixfs_object = nullptr;

	x_smb2_state_read_t *state = (x_smb2_state_read_t *)smbd_requ->requ_state;

	uint32_t length = std::min(state->in_length, 1024u * 1024);
	state->out_buf = x_buf_alloc(length);
	ssize_t ret = pread(posixfs_object->fd, state->out_buf->data,
			length, state->in_offset);
	X_LOG_DBG("pread %lu at %lu ret %ld", length, state->in_offset, ret);
	NTSTATUS status;
	if (ret < 0) {
		status = NT_STATUS_INTERNAL_ERROR;
	} else if (ret == 0) {
		state->out_buf_length = 0;
		status = NT_STATUS_END_OF_FILE;
	} else {
		state->out_buf_length = x_convert_assert<uint32_t>(ret);
		status = NT_STATUS_OK;
	}

	posixfs_object_release(posixfs_object);
	posixfs_read_evt_t *evt = new posixfs_read_evt_t(smbd_requ, status);
	evt->base.func = posixfs_read_evt_func;
	x_smbd_chan_post_user(smbd_requ->smbd_chan, &evt->base);
	return x_job_t::JOB_DONE;
}

static void posixfs_read_job_done(x_job_t *job)
{
	posixfs_read_job_t *posixfs_read_job = X_CONTAINER_OF(job, posixfs_read_job_t, base);
	X_ASSERT(!posixfs_read_job->posixfs_object);
	X_ASSERT(!posixfs_read_job->smbd_requ);
	delete posixfs_read_job;
}

static const x_job_ops_t posixfs_read_job_ops = {
	posixfs_read_job_run,
	posixfs_read_job_done,
};

inline posixfs_read_job_t::posixfs_read_job_t(posixfs_object_t *po, x_smbd_requ_t *r)
	: posixfs_object(po), smbd_requ(r)
{
	base.ops = &posixfs_read_job_ops;
}

static void posixfs_read_cancel(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	x_smbd_conn_post_cancel(smbd_conn, smbd_requ);
}

NTSTATUS posixfs_object_op_read(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_read_t> &state)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	++posixfs_object->use_count;
	x_smbd_ref_inc(smbd_requ);
	posixfs_read_job_t *read_job = new posixfs_read_job_t(posixfs_object, smbd_requ);
	smbd_requ->requ_state = state.release();
	x_smbd_conn_set_async(smbd_conn, smbd_requ, posixfs_read_cancel);
	x_smbd_schedule_async(&read_job->base);
	return NT_STATUS_PENDING;
#if 0
	uint32_t length = std::min(state->in_length, 1024u * 1024);
	state->out_data.resize(length);
	ssize_t ret = pread(posixfs_object->fd, state->out_data.data(),
			length, state->in_offset);
	if (ret < 0) {
		X_TODO;
	} else if (ret == 0) {
		state->out_data.resize(0);
		return NT_STATUS_END_OF_FILE;
	} else {
		state->out_data.resize(ret);
	}
	return NT_STATUS_OK;
#endif
}


struct posixfs_write_evt_t
{
	posixfs_write_evt_t(x_smbd_requ_t *r, NTSTATUS s)
		: smbd_requ(r), status(s) { }
	x_fdevt_user_t base;
	x_smbd_requ_t *smbd_requ;
	NTSTATUS const status;
};

static void posixfs_write_evt_func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user, bool cancelled)
{
	posixfs_write_evt_t *evt = X_CONTAINER_OF(fdevt_user, posixfs_write_evt_t, base);
	X_LOG_DBG("evt=%p", evt);

	if (!cancelled) {
		x_smbd_requ_t *smbd_requ = evt->smbd_requ;
		x_smbd_requ_remove(smbd_requ);
		smbd_requ->async_done_fn(smbd_conn, smbd_requ, evt->status);
	}

	delete evt;
}

struct posixfs_write_job_t
{
	posixfs_write_job_t(posixfs_object_t *po, x_smbd_requ_t *r);
	x_job_t base;
	posixfs_object_t *posixfs_object;
	x_smbd_requ_t *smbd_requ;
};

static x_job_t::retval_t posixfs_write_job_run(x_job_t *job)
{
	posixfs_write_job_t *posixfs_write_job = X_CONTAINER_OF(job, posixfs_write_job_t, base);

	x_smbd_requ_t *smbd_requ = posixfs_write_job->smbd_requ;
	posixfs_object_t *posixfs_object = posixfs_write_job->posixfs_object;
	posixfs_write_job->smbd_requ = nullptr;
	posixfs_write_job->posixfs_object = nullptr;

	x_smb2_state_write_t *state = (x_smb2_state_write_t *)smbd_requ->requ_state;
	ssize_t ret = pwrite(posixfs_object->fd,
			state->in_buf->data + state->in_buf_offset,
			state->in_buf_length, state->in_offset);
	X_LOG_DBG("pwrite %lu at %lu ret %ld", state->in_buf_length, state->in_offset, ret);
	NTSTATUS status;
	if (ret <= 0) {
		status = NT_STATUS_INTERNAL_ERROR;
	} else {
		posixfs_object->statex_modified = true; // TODO atomic
		state->out_count = x_convert_assert<uint32_t>(ret);
		state->out_remaining = 0;
		status = NT_STATUS_OK;
	}

	posixfs_object_release(posixfs_object);
	posixfs_write_evt_t *evt = new posixfs_write_evt_t(smbd_requ, status);
	evt->base.func = posixfs_write_evt_func;
	x_smbd_chan_post_user(smbd_requ->smbd_chan, &evt->base);
	return x_job_t::JOB_DONE;
}

static void posixfs_write_job_done(x_job_t *job)
{
	posixfs_write_job_t *posixfs_write_job = X_CONTAINER_OF(job, posixfs_write_job_t, base);
	X_ASSERT(!posixfs_write_job->posixfs_object);
	X_ASSERT(!posixfs_write_job->smbd_requ);
	delete posixfs_write_job;
}

static const x_job_ops_t posixfs_write_job_ops = {
	posixfs_write_job_run,
	posixfs_write_job_done,
};

inline posixfs_write_job_t::posixfs_write_job_t(posixfs_object_t *po, x_smbd_requ_t *r)
	: posixfs_object(po), smbd_requ(r)
{
	base.ops = &posixfs_write_job_ops;
}

static void posixfs_write_cancel(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	x_smbd_conn_post_cancel(smbd_conn, smbd_requ);
}

NTSTATUS posixfs_object_op_write(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_write_t> &state)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	++posixfs_object->use_count;
	x_smbd_ref_inc(smbd_requ);
	posixfs_write_job_t *write_job = new posixfs_write_job_t(posixfs_object, smbd_requ);
	smbd_requ->requ_state = state.release();
	x_smbd_conn_set_async(smbd_conn, smbd_requ, posixfs_write_cancel);
	x_smbd_schedule_async(&write_job->base);
	return NT_STATUS_PENDING;
#if 0
	ssize_t ret = pwrite(posixfs_object->fd, state->in_data.data(),
			state->in_data.size(), state->in_offset);
	if (ret < 0) {
		X_TODO;
	} else {
		state->out_count = ret;
		state->out_remaining = 0;
	}
	return NT_STATUS_OK;
#endif
}

static NTSTATUS getinfo_file(posixfs_object_t *posixfs_object,
		x_smb2_state_getinfo_t &state)
{
	if (state.in_info_level == SMB2_FILE_INFO_FILE_NETWORK_OPEN_INFORMATION) {
		if (state.in_output_buffer_length < 56) {
			return STATUS_BUFFER_OVERFLOW;
		}
		state.out_data.resize(56);
		uint8_t *p = state.out_data.data();
		
		const auto statex = &posixfs_object->statex;
		p = put_find_timespec(p, statex->birth_time);
		p = put_find_timespec(p, statex->stat.st_atim);
		p = put_find_timespec(p, statex->stat.st_mtim);
		p = put_find_timespec(p, statex->stat.st_ctim);
		x_put_le64(p, statex->get_allocation()); p += 8;
		x_put_le64(p, statex->get_end_of_file()); p += 8;
		x_put_le32(p, statex->file_attributes); p += 4;
		x_put_le32(p, 0); p += 4;

		return NT_STATUS_OK;
	} else {
		return NT_STATUS_INVALID_LEVEL;
	}
}

static NTSTATUS setinfo_file(posixfs_object_t *posixfs_object,
		x_smbd_requ_t *smbd_requ,
		x_smb2_state_setinfo_t &state)
{
	if (state.in_info_level == SMB2_FILE_INFO_FILE_BASIC_INFORMATION) {
		if (state.in_data.size() < 0x24) {
			return NT_STATUS_INFO_LENGTH_MISMATCH;
		}
		if (!smbd_requ->smbd_open->check_access(idl::SEC_FILE_WRITE_ATTRIBUTE)) {
			return NT_STATUS_ACCESS_DENIED;
		}

		x_smb2_basic_info_t basic_info;
		if (!x_smb2_basic_info_decode(basic_info, state.in_data)) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		uint32_t notify_actions = 0;
		int err = posixfs_set_basic_info(posixfs_object->fd,
				notify_actions, basic_info,
				&posixfs_object->statex);
		if (err == 0) {
			if (notify_actions) {
				notify_fname(posixfs_object, NOTIFY_ACTION_MODIFIED, notify_actions);
			}
			return NT_STATUS_OK;
		} else {
			X_TODO;
			return NT_STATUS_INTERNAL_ERROR;
		}
#if 0
	} else if (state.in_info_level == SMB2_FILE_INFO_FILE_RENAME_INFORMATION) {
		/* MS-FSA 2.1.5.14.11 */
		if (!smbd_requ->smbd_open->check_access(idl::SEC_STD_DELETE)) {
			return NT_STATUS_ACCESS_DENIED;
		}
		bool replace_if_exists;
		std::u16string file_name;
		if (!x_smb2_rename_info_decode(replace_if_exists, file_name, state.in_data)) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		return posixfs_object_rename(posixfs_object,
				x_smbd_tcon_get_share(smbd_requ->smbd_tcon),
				smbd_requ->in_hdr_flags & SMB2_HDR_FLAG_DFS,
				replace_if_exists, file_name);
	} else if (state.in_info_level == SMB2_FILE_INFO_FILE_DISPOSITION_INFORMATION) {
		/* MS-FSA 2.1.5.14.3 */
		if (state.in_data.size() < 1) {
			return NT_STATUS_INFO_LENGTH_MISMATCH;
		}
		if (!smbd_requ->smbd_open->check_access(idl::SEC_STD_DELETE)) {
			return NT_STATUS_ACCESS_DENIED;
		}
		bool delete_on_close = (state.in_data[0] != 0);
		if (delete_on_close) {
			if (posixfs_object->statex.file_attributes & FILE_ATTRIBUTE_READONLY) {
				return NT_STATUS_CANNOT_DELETE;
			}
			if (true /*!is_stream_open(posixfs_open) */) {
				posixfs_object->flags |= posixfs_object_t::flag_delete_on_close;
			} else {
				X_TODO;
			}
		} else {
			/* TODO handle streams */
			posixfs_object->flags &= ~posixfs_object_t::flag_delete_on_close;
		}
		return NT_STATUS_OK;
#endif
	} else {
		return NT_STATUS_INVALID_LEVEL;
	}
}

static NTSTATUS getinfo_fs(posixfs_object_t *posixfs_object,
		x_smb2_state_getinfo_t &state)
{
	if (state.in_info_level == SMB2_FILE_INFO_FS_SIZE_INFORMATION) {
		if (state.in_output_buffer_length < 24) {
			return STATUS_BUFFER_OVERFLOW;
		}
		struct statvfs fsstat;
		int err = fstatvfs(posixfs_object->fd, &fsstat);
		assert(err == 0);
		state.out_data.resize(24);
		uint8_t *p = state.out_data.data();
		x_put_le64(p, fsstat.f_blocks); p += 8;
		x_put_le64(p, fsstat.f_bfree); p += 8;
		x_put_le32(p, x_convert_assert<uint32_t>(fsstat.f_bsize / 512)); p += 4;
		x_put_le32(p, 512); p += 4;

		return NT_STATUS_OK;
	} else if (state.in_info_level == SMB2_FILE_INFO_FS_ATTRIBUTE_INFORMATION) {
		/* 20 = 4 + 4 + 4 + 'NTFS' */
		if (state.in_output_buffer_length < 20) {
			return STATUS_BUFFER_OVERFLOW;
		}
		struct statvfs fsstat;
		int err = fstatvfs(posixfs_object->fd, &fsstat);
		assert(err == 0);

		uint32_t fs_cap = FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES;
		if (fsstat.f_flag & ST_RDONLY) {
			fs_cap |= FILE_READ_ONLY_VOLUME;
		}

		fs_cap |= FILE_VOLUME_QUOTAS;
		fs_cap |= FILE_SUPPORTS_SPARSE_FILES;
		fs_cap |= (FILE_SUPPORTS_REPARSE_POINTS | FILE_SUPPORTS_SPARSE_FILES);
		fs_cap |= FILE_NAMED_STREAMS;
		fs_cap |= FILE_PERSISTENT_ACLS;;
		fs_cap |= FILE_SUPPORTS_OBJECT_IDS | FILE_UNICODE_ON_DISK;
		// fs_cap |= smbshare->fake_fs_caps;

		state.out_data.resize(20);
		uint8_t *p = state.out_data.data();
		x_put_le32(p, fs_cap);
		x_put_le32(p, 255); /* Max filename component length */
		x_put_le32(p, 8); /* length of NTFS */
		x_put_le64(p, 0x5300460054004e); /* NTFS char16 le order */

		return NT_STATUS_OK;
	}

	return NT_STATUS_INVALID_LEVEL;
}

static NTSTATUS getinfo_security(posixfs_object_t *posixfs_object,
		x_smb2_state_getinfo_t &state)
{
	std::shared_ptr<idl::security_descriptor> psd;
	NTSTATUS status = posixfs_object_get_sd(posixfs_object, psd);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	auto ndr_ret = idl::x_ndr_push(*psd, state.out_data, state.in_output_buffer_length);
	if (ndr_ret < 0) {
		return x_map_nt_error_from_ndr_err(idl::x_ndr_err_code_t(-ndr_ret));
	}
	return NT_STATUS_OK;
}

static NTSTATUS setinfo_security(posixfs_object_t *posixfs_object,
		x_smbd_requ_t *smbd_requ,
		const x_smb2_state_setinfo_t &state)
{
	uint32_t security_info_sent = state.in_additional & idl::SMB_SUPPORTED_SECINFO_FLAGS;
	idl::security_descriptor sd;

	NTSTATUS status = parse_setinfo_sd_blob(sd, security_info_sent,
			smbd_requ->smbd_open->access_mask,
			state.in_data);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if ((security_info_sent & (idl::SECINFO_OWNER|idl::SECINFO_GROUP|idl::SECINFO_DACL|idl::SECINFO_SACL)) == 0) {
		/* Just like W2K3 */
		return NT_STATUS_OK;
	}

	std::vector<uint8_t> old_blob;
	int err = posixfs_get_ntacl_blob(posixfs_object->fd, old_blob);
	if (err < 0) {
		return x_map_nt_error_from_unix(-err);
	}

	std::vector<uint8_t> new_blob;
	status = create_acl_blob_from_old(new_blob, old_blob, sd, security_info_sent);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	err = posixfs_set_ntacl_blob(posixfs_object->fd, new_blob);
	if (err < 0) {
		return x_map_nt_error_from_unix(-err);
	}

	notify_fname(posixfs_object, NOTIFY_ACTION_MODIFIED,
			FILE_NOTIFY_CHANGE_SECURITY);
	return NT_STATUS_OK;
}

static NTSTATUS getinfo_quota(posixfs_object_t *posixfs_object,
		x_smb2_state_getinfo_t &state)
{
	return NT_STATUS_INVALID_LEVEL;
}

NTSTATUS posixfs_object_op_getinfo(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_getinfo_t> &state)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);

	if (state->in_info_class == SMB2_GETINFO_FILE) {
		return getinfo_file(posixfs_object, *state);
	} else if (state->in_info_class == SMB2_GETINFO_FS) {
		return getinfo_fs(posixfs_object, *state);
	} else if (state->in_info_class == SMB2_GETINFO_SECURITY) {
		return getinfo_security(posixfs_object, *state);
	} else if (state->in_info_class == SMB2_GETINFO_QUOTA) {
		return getinfo_quota(posixfs_object, *state);
	} else {
		return NT_STATUS_INVALID_PARAMETER;
	}
	/* TODO should access check ? */
	/* SMB2_GETINFO_FILE, SMB2_FILE_STANDARD_INFO */
}

NTSTATUS posixfs_object_op_setinfo(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_setinfo_t> &state)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);

	if (state->in_info_class == SMB2_GETINFO_FILE) {
		return setinfo_file(posixfs_object, smbd_requ, *state);
#if 0
	} else if (state->in_info_class == SMB2_GETINFO_FS) {
		return setinfo_fs(posixfs_object, smbd_requ, *state);
#endif
	} else if (state->in_info_class == SMB2_GETINFO_SECURITY) {
		return setinfo_security(posixfs_object, smbd_requ, *state);
	} else {
		return NT_STATUS_INVALID_PARAMETER;
	}
}


NTSTATUS posixfs_object_op_ioctl(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_ioctl_t> &state)
{
	// TODO;
	return NT_STATUS_NOT_SUPPORTED;
}

static long qdir_filldents(qdir_t &qdir, posixfs_object_t *posixfs_object)
{
	std::unique_lock<std::mutex> lock(posixfs_object->mutex);
	lseek(posixfs_object->fd, qdir.filepos, SEEK_SET);
	return syscall(SYS_getdents64, posixfs_object->fd, qdir.data, sizeof(qdir.data));
}

static inline bool is_dot_or_dotdot(const char *name)
{
	return name[0] == '.' && (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'));
}

static const char *qdir_get(qdir_t &qdir, qdir_pos_t &pos,
		posixfs_object_t *posixfs_object,
		const char *pseudo_entries[],
		uint32_t pseudo_entry_count)
{
	const char *ent_name;
	if ((qdir.save_errno != 0)) {
		return nullptr;
	} else if (qdir.file_number >= pseudo_entry_count) {
		for (;;) {
			if (qdir.data_offset >= qdir.data_length) {
				long retval = qdir_filldents(qdir, posixfs_object);
				if (retval > 0) {
					qdir.data_length = x_convert_assert<uint32_t>(retval);
					qdir.data_offset = 0;
				} else if (retval == 0) {
					qdir.save_errno = ENOENT;
					return nullptr;
				} else {
					qdir.save_errno = errno;
					return nullptr;
				}
			}
			struct dirent *dp = (struct dirent *)&qdir.data[qdir.data_offset];
			pos.data_offset = qdir.data_offset;
			pos.file_number = qdir.file_number;
			pos.filepos = qdir.filepos;

			qdir.data_offset += dp->d_reclen;
			++qdir.file_number;
			qdir.filepos = dp->d_off;
			ent_name = dp->d_name;

			if (is_dot_or_dotdot(ent_name) || strcmp(ent_name, ":streams") == 0) {
				continue;
			}
			return ent_name;
		}
	} else {
		ent_name = pseudo_entries[qdir.file_number];
		pos.data_offset = qdir.data_offset;
		pos.file_number = qdir.file_number;
		pos.filepos = qdir.filepos;
		++qdir.file_number;
		return ent_name;
	}
}
	
static void qdir_unget(qdir_t &qdir, qdir_pos_t &pos)
{
	X_ASSERT(qdir.file_number == pos.file_number + 1);
	qdir.file_number = pos.file_number;
	qdir.data_offset = pos.data_offset;
	qdir.filepos = pos.filepos;
}


static uint8_t *marshall_entry(posixfs_statex_t *statex, const char *fname,
		uint8_t *pbegin, uint8_t *pend, uint32_t align,
		int info_level)
{
	uint8_t *p = pbegin;
	std::u16string name = x_convert_utf8_to_utf16(fname);
	switch (info_level) {
	case SMB2_FIND_ID_BOTH_DIRECTORY_INFO:
		// TODO check size if (p + name.size() * 2 + 
		if (p + 300 > pend) {
			return nullptr;
		}
		SIVAL(p, 0, 0); p += 4;
		SIVAL(p, 0, 0); p += 4;
		p = put_find_timespec(p, statex->birth_time);
		p = put_find_timespec(p, statex->stat.st_atim);
		p = put_find_timespec(p, statex->stat.st_mtim);
		p = put_find_timespec(p, statex->stat.st_ctim);
		x_put_le64(p, statex->get_end_of_file()); p += 8;
		x_put_le64(p, statex->get_allocation()); p += 8;
		x_put_le32(p, statex->file_attributes); p += 4;
		x_put_le32(p, x_convert_assert<uint32_t>(name.size() * 2)); p += 4;
		if (statex->file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
			x_put_le32(p, IO_REPARSE_TAG_DFS);
		} else {
			/*
			 * OS X specific SMB2 extension negotiated via
			 * AAPL create context: return max_access in
			 * ea_size field.
			 */
			x_put_le32(p, 0);
		}
		p += 4;
		
		memset(p, 0, 26); p += 26; // shortname
		x_put_le16(p, 0); p += 2; // aapl mode

		{
			uint64_t file_index = statex->stat.st_ino; // TODO
			x_put_le64(p, file_index); p += 8;
			memcpy(p, name.data(), name.size() * 2);
			p += name.size() * 2;
			size_t len = p - pbegin;
			uint8_t *ptmp = pbegin + ((len + (align - 1)) & ~(align - 1));
			memset(p, 0, ptmp - p);
			p = ptmp;
		}
		break;

	case SMB2_FIND_BOTH_DIRECTORY_INFO:
		// TODO check size if (p + name.size() * 2 + 
		if (p + 300 > pend) {
			return nullptr;
		}
		SIVAL(p, 0, 0); p += 4;
		SIVAL(p, 0, 0); p += 4;
		p = put_find_timespec(p, statex->birth_time);
		p = put_find_timespec(p, statex->stat.st_atim);
		p = put_find_timespec(p, statex->stat.st_mtim);
		p = put_find_timespec(p, statex->stat.st_ctim);
		x_put_le64(p, statex->get_end_of_file()); p += 8;
		x_put_le64(p, statex->get_allocation()); p += 8;
		x_put_le32(p, statex->file_attributes); p += 4;
		x_put_le32(p, x_convert_assert<uint32_t>(name.size() * 2)); p += 4;
		if (statex->file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
			x_put_le32(p, IO_REPARSE_TAG_DFS);
		} else {
			/*
			 * OS X specific SMB2 extension negotiated via
			 * AAPL create context: return max_access in
			 * ea_size field.
			 */
			x_put_le32(p, 0);
		}
		p += 4;
		
		memset(p, 0, 26); p += 26; // shortname
		{
			memcpy(p, name.data(), name.size() * 2);
			p += name.size() * 2;
			size_t len = p - pbegin;
			uint8_t *ptmp = pbegin + ((len + (align - 1)) & ~(align - 1));
			memset(p, 0, ptmp - p);
			p = ptmp;
		}
		break;

	case SMB2_FIND_FULL_DIRECTORY_INFO:
		if (p + 300 > pend) {
			return nullptr;
		}
		SIVAL(p, 0, 0); p += 4;
		SIVAL(p, 0, 0); p += 4;
		p = put_find_timespec(p, statex->birth_time);
		p = put_find_timespec(p, statex->stat.st_atim);
		p = put_find_timespec(p, statex->stat.st_mtim);
		p = put_find_timespec(p, statex->stat.st_ctim);
		x_put_le64(p, statex->get_end_of_file()); p += 8;
		x_put_le64(p, statex->get_allocation()); p += 8;
		x_put_le32(p, statex->file_attributes); p += 4;
		x_put_le32(p, x_convert_assert<uint32_t>(name.size() * 2)); p += 4;
		if (statex->file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
			x_put_le32(p, IO_REPARSE_TAG_DFS);
		} else {
			/*
			 * OS X specific SMB2 extension negotiated via
			 * AAPL create context: return max_access in
			 * ea_size field.
			 */
			x_put_le32(p, 0);
		}
		p += 4;
		
		{
			memcpy(p, name.data(), name.size() * 2);
			p += name.size() * 2;
			size_t len = p - pbegin;
			uint8_t *ptmp = pbegin + ((len + (align - 1)) & ~(align - 1));
			memset(p, 0, ptmp - p);
			p = ptmp;
		}
		break;

	default:
		X_ASSERT(0);
	}
	return p;
}

NTSTATUS posixfs_object_qdir(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_qdir_t> &state,
		const char *pseudo_entries[],
		uint32_t pseudo_entry_count,
		bool (*process_entry_func)(posixfs_statex_t *statex,
			posixfs_object_t *dir_obj,
			const char *ent_name,
			uint32_t file_number))
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	if (!posixfs_object->is_dir()) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	posixfs_open_t *posixfs_open = posixfs_open_from_base_t::container(smbd_requ->smbd_open);
	if (state->in_flags & (SMB2_CONTINUE_FLAG_REOPEN | SMB2_CONTINUE_FLAG_RESTART)) {
		if (posixfs_open->qdir) {
			delete posixfs_open->qdir;
			posixfs_open->qdir = nullptr;
		}
	}

	if (!posixfs_open->qdir) {
		posixfs_open->qdir = new qdir_t;
	}

	uint32_t max_count = 0x7fffffffu;
	if (state->in_flags & SMB2_CONTINUE_FLAG_SINGLE) {
		max_count = 1;
	}

	qdir_t *qdir = posixfs_open->qdir;
	state->out_data.resize(state->in_output_buffer_length);
	uint8_t *pbegin = state->out_data.data();
	uint8_t *pend = state->out_data.data() + state->out_data.size();
	uint8_t *pcurr =  pbegin, *plast = nullptr;
	uint32_t num = 0, matched_count = 0;

	x_fnmatch_t *fnmatch = x_fnmatch_create(state->in_name, true);
	while (num < max_count) {
		qdir_pos_t qdir_pos;
		const char *ent_name = qdir_get(*qdir, qdir_pos, posixfs_object,
				pseudo_entries, pseudo_entry_count);
		if (!ent_name) {
			break;
		}

		if (fnmatch && !x_fnmatch_match(fnmatch, ent_name)) {
			continue;
		}

		posixfs_statex_t statex;
		if (!process_entry_func(&statex, posixfs_object, ent_name, qdir_pos.file_number)) {
			X_LOG_WARN("qdir_process_entry %s %d,0x%x %d errno=%d",
					ent_name, qdir_pos.file_number, qdir_pos.filepos,
					qdir_pos.data_offset, errno);
			continue;
		}

		++matched_count;
		uint8_t *p = marshall_entry(&statex, ent_name, pcurr, pend, 8, state->in_info_level);
		if (p) {
			++num;
			if (plast) {
				x_put_le32(plast, x_convert_assert<uint32_t>(pcurr - plast));
			}
			plast = pcurr;
			pcurr = p;
		} else {
			qdir_unget(*qdir, qdir_pos);
			max_count = num;
		}
	}

	if (num > 0) {
		state->out_data.resize(pcurr - pbegin);
		// x_put_le32(plast, 0);
		return NT_STATUS_OK;
	}
	
	state->out_data.resize(0);
	if (matched_count > 0) {
		return NT_STATUS_INFO_LENGTH_MISMATCH;
	} else {
		return STATUS_NO_MORE_FILES;
	}
}



/* SMB2_NOTIFY */
static void posixfs_notify_cancel(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	posixfs_open_t *posixfs_open = posixfs_open_from_base_t::container(smbd_requ->smbd_open);
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(posixfs_open->base.smbd_object);

	{
		std::lock_guard<std::mutex> lock(posixfs_object->mutex);
		posixfs_open->notify_requ_list.remove(smbd_requ);
	}
	x_smbd_conn_post_cancel(smbd_conn, smbd_requ);
}

NTSTATUS posixfs_object_op_notify(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_notify_t> &state)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	if (!posixfs_object->is_dir()) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	posixfs_open_t *posixfs_open = posixfs_open_from_base_t::container(smbd_requ->smbd_open);
	std::lock_guard<std::mutex> lock(posixfs_object->mutex);

	/* notify filter cannot be overwritten */
	if (posixfs_open->notify_filter == 0) {
		posixfs_open->notify_filter = state->in_filter | X_FILE_NOTIFY_CHANGE_VALID;
		if (state->in_flags & SMB2_WATCH_TREE) {
			posixfs_open->notify_filter |= X_FILE_NOTIFY_CHANGE_WATCH_TREE;
		}
	}

	auto notify_changes = std::move(posixfs_open->notify_changes);
	X_LOG_DBG("changes count %d", notify_changes.size());
	if (notify_changes.empty()) {
		// TODO smbd_conn add Cancels
		smbd_requ->requ_state = state.release();
		x_smbd_ref_inc(smbd_requ);
		posixfs_open->notify_requ_list.push_back(smbd_requ);
		x_smbd_conn_set_async(smbd_conn, smbd_requ, posixfs_notify_cancel);
		return NT_STATUS_PENDING;
	} else {
		return x_smb2_notify_marshall(notify_changes, state->in_output_buffer_length, state->out_data);
	}
}

static NTSTATUS posixfs_lease_break(
		x_smbd_lease_t *smbd_lease,
		const x_smb2_state_lease_break_t &state,
		bool &modified)
{
	/* TODO atomic */
	if ((state.in_state & smbd_lease->breaking_to_requested) != state.in_state) {
		X_LOG_DBG("Attempt to upgrade from %d to %d - expected %d\n",
				(int)smbd_lease->lease_state, (int)state.in_state,
				(int)smbd_lease->breaking_to_requested);
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}

	modified = false;
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

NTSTATUS posixfs_object_op_lease_break(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		x_smbd_lease_t *smbd_lease,
		std::unique_ptr<x_smb2_state_lease_break_t> &state)
{
	/* downgrade_lease() */
	bool modified = false;
	NTSTATUS status = posixfs_lease_break(smbd_lease, *state, modified);
	if (modified) {
		posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);

		std::unique_lock<std::mutex> lock(posixfs_object->mutex);
		share_mode_modified(posixfs_object);
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_OPLOCK_BREAK_IN_PROGRESS)) {
		X_TODO;
	}
	// state->out_state = state->in_state;
	return status;
}

NTSTATUS posixfs_object_op_oplock_break(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_oplock_break_t> &state)
{
	posixfs_open_t *posixfs_open = posixfs_open_from_base_t::container(smbd_requ->smbd_open);
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_requ->smbd_object);
	uint8_t out_oplock_level;
	if (posixfs_open->oplock_break_sent == oplock_break_sent_t::OPLOCK_BREAK_TO_NONE_SENT || state->in_oplock_level == X_SMB2_OPLOCK_LEVEL_NONE) {
		out_oplock_level = X_SMB2_OPLOCK_LEVEL_NONE;
	} else {
		out_oplock_level = X_SMB2_OPLOCK_LEVEL_II;
	}
	bool modified = false;
	if (posixfs_open->oplock_level != out_oplock_level) {
		modified = true;
		posixfs_open->oplock_level = out_oplock_level;
	}

	state->out_oplock_level = out_oplock_level;
	if (modified) {
		// TODO downgrade_file_oplock
		std::unique_lock<std::mutex> lock(posixfs_object->mutex);
		share_mode_modified(posixfs_object);
	}

	return NT_STATUS_OK;
}

NTSTATUS posixfs_object_op_set_delete_on_close(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		bool delete_on_close)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	std::lock_guard<std::mutex> lock(posixfs_object->mutex);
	return posixfs_object_set_delete_on_close(posixfs_object, delete_on_close);
}

std::string posixfs_object_op_get_path(
		const x_smbd_object_t *smbd_object)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	return posixfs_object->unix_path;
}

void posixfs_object_op_destroy(x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	posixfs_open_t *posixfs_open = posixfs_open_from_base_t::container(smbd_open);
	{
		std::unique_lock<std::mutex> lock(posixfs_object->mutex);
		posixfs_object_remove(posixfs_object, posixfs_open);
	}
	delete posixfs_open;
}

NTSTATUS posixfs_create_open(const x_smbd_object_ops_t *ops,
		x_smbd_open_t **psmbd_open,
		std::shared_ptr<x_smbd_topdir_t> &topdir,
		const std::u16string &path,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state)
{
	/* TODO only local filesystem for now, support dfs later */
	posixfs_object_t *posixfs_object = posixfs_object_open(ops, 
			topdir, path);

	NTSTATUS status;
	posixfs_open_t *posixfs_open = create_posixfs_open(posixfs_object,
			status, smbd_requ, state);
	if (!posixfs_open) {
		// TODO if (NT_STATUS_EQUAL(status, 
		/* if succeed, it do not release it because the open hold it */
		posixfs_object_release(posixfs_object);
		return status;
	}

	if (state->out_create_action == FILE_WAS_CREATED) {
		notify_fname(posixfs_object, NOTIFY_ACTION_ADDED,
				(state->in_create_options & FILE_DIRECTORY_FILE) ? FILE_NOTIFY_CHANGE_DIR_NAME : FILE_NOTIFY_CHANGE_FILE_NAME);
	}

	uint32_t contexts = state->contexts;
	state->contexts = 0;
	/* TODO we support MXAC and QFID for now,
	   without QFID Windows 10 client query
	   couple getinfo SMB2_FILE_INFO_FILE_NETWORK_OPEN_INFORMATION */
	if (contexts & X_SMB2_CONTEXT_FLAG_MXAC) {
		state->contexts |= X_SMB2_CONTEXT_FLAG_MXAC;
	}
	if (contexts & X_SMB2_CONTEXT_FLAG_QFID) {
		state->contexts |= X_SMB2_CONTEXT_FLAG_QFID;
		x_put_le64(state->out_qfid_info, posixfs_object->statex.stat.st_ino);
		x_put_le64(state->out_qfid_info + 8, posixfs_object->statex.stat.st_dev);
		memset(state->out_qfid_info + 16, 0, 16);
	}

	*psmbd_open = &posixfs_open->base;
	return NT_STATUS_OK;
}

posixfs_object_t::posixfs_object_t(const x_smbd_object_ops_t *ops,
		uint64_t h,
		const std::shared_ptr<x_smbd_topdir_t> &topdir,
		const std::u16string &p)
	: base(ops), hash(h), topdir(topdir), req_path(p)
{
}

#if 0
static const x_smbd_object_ops_t posixfs_object_ops = {
	posixfs_object_op_close,
	posixfs_object_op_read,
	posixfs_object_op_write,
	posixfs_object_op_getinfo,
	posixfs_object_op_setinfo,
	posixfs_object_op_ioctl,
	posixfs_object_op_qdir,
	posixfs_object_op_notify,
	posixfs_object_op_lease_break,
	posixfs_object_op_oplock_break,
	posixfs_object_op_get_path,
	posixfs_object_op_destroy,
};

struct posixfs_share_t : x_smbd_share_t
{
	posixfs_share_t(const std::string &name,
			const std::string &path)
		: x_smbd_share_t(name)
	{
		root_dir = x_smbd_topdir_create(path);
	}
					
	uint8_t get_type() const override {
		return SMB2_SHARE_TYPE_DISK;
	}
	bool is_dfs() const override { return false; }
	/* TODO not support ABE for now */
	bool abe_enabled() const override { return false; }

	NTSTATUS create(x_smbd_open_t **psmbd_open,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_create_t> &state) override;
	NTSTATUS get_dfs_referral(x_dfs_referral_resp_t &dfs_referral,
			const char16_t *in_full_path_begin,
			const char16_t *in_full_path_end,
			const char16_t *in_server_begin,
			const char16_t *in_server_end,
			const char16_t *in_share_begin,
			const char16_t *in_share_end) const override
	{
		return NT_STATUS_FS_DRIVER_REQUIRED;
	}
	NTSTATUS resolve_path(const std::u16string &in_path,
		bool dfs,
		std::shared_ptr<x_smbd_topdir_t> &topdir,
		std::u16string &path) override;
	std::shared_ptr<x_smbd_topdir_t> root_dir;
};

static NTSTATUS posixfs_op_create(posixfs_share_t &posixfs_share,
		x_smbd_open_t **psmbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state)
{
	std::u16string path;
	std::shared_ptr<x_smbd_topdir_t> topdir;
	NTSTATUS status = posixfs_share.resolve_path(
			state->in_name,
			smbd_requ->in_hdr_flags & SMB2_HDR_FLAG_DFS,
			topdir, path);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* TODO only local filesystem for now, support dfs later */
	posixfs_object_t *posixfs_object = posixfs_object_open(
			topdir, path);

	posixfs_open_t *posixfs_open = create_posixfs_open(posixfs_object,
			status, smbd_requ, state);
	if (!posixfs_open) {
		// TODO if (NT_STATUS_EQUAL(status, 
		/* if succeed, it do not release it because the open hold it */
		posixfs_object_release(posixfs_object);
		return status;
	}

	if (state->out_create_action == FILE_WAS_CREATED) {
		notify_fname(posixfs_object, NOTIFY_ACTION_ADDED,
				(state->in_create_options & FILE_DIRECTORY_FILE) ? FILE_NOTIFY_CHANGE_DIR_NAME : FILE_NOTIFY_CHANGE_FILE_NAME);
	}

	uint32_t contexts = state->contexts;
	state->contexts = 0;
	/* TODO we support MXAC and QFID for now,
	   without QFID Windows 10 client query
	   couple getinfo SMB2_FILE_INFO_FILE_NETWORK_OPEN_INFORMATION */
	if (contexts & X_SMB2_CONTEXT_FLAG_MXAC) {
		state->contexts |= X_SMB2_CONTEXT_FLAG_MXAC;
	}
	if (contexts & X_SMB2_CONTEXT_FLAG_QFID) {
		state->contexts |= X_SMB2_CONTEXT_FLAG_QFID;
		x_put_le64(state->out_qfid_info, posixfs_object->statex.stat.st_ino);
		x_put_le64(state->out_qfid_info + 8, posixfs_object->statex.stat.st_dev);
		memset(state->out_qfid_info + 16, 0, 16);
	}

	*psmbd_open = &posixfs_open->base;
	return NT_STATUS_OK;
}

NTSTATUS posixfs_share_t::create(x_smbd_open_t **psmbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state)
{
	return posixfs_op_create(*this, psmbd_open, smbd_requ, state);
}

NTSTATUS posixfs_share_t::resolve_path(
		const std::u16string &in_path,
		bool dfs,
		std::shared_ptr<x_smbd_topdir_t> &topdir,
		std::u16string &path)
{
	if (dfs) {
		/* TODO we just skip the first 2 components for now */
		auto pos = in_path.find(u'\\');
		X_ASSERT(pos != std::u16string::npos);
		pos = in_path.find(u'\\', pos + 1);
		if (pos == std::u16string::npos) {
			path = u"";
		} else {
			path = in_path.substr(pos + 1);
		}
	} else {
		path = in_path;
	}
	topdir = root_dir;
	return NT_STATUS_OK;
}


std::shared_ptr<x_smbd_share_t> x_smbd_posixfs_share_create(
		const std::string &name,
		const std::string &path)
{
	return std::make_shared<posixfs_share_t>(name, path);
}
#endif
int x_smbd_posixfs_init(size_t max_open)
{
	size_t bucket_size = x_next_2_power(max_open);
	std::vector<posixfs_object_pool_t::bucket_t> buckets(bucket_size);
	posixfs_object_pool.buckets.swap(buckets);
	return 0;
}

x_smbd_object_t *x_smbd_posixfs_object_open_parent(const x_smbd_object_ops_t *ops,
		const x_smbd_object_t *child_object)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(child_object);
	posixfs_object_t *parent_object = posixfs_object_open_parent(ops, posixfs_object);
	if (parent_object) {
		return &parent_object->base;
	}
	return nullptr;
}

int posixfs_object_get_statex(const posixfs_object_t *posixfs_object,
		posixfs_statex_t *statex)
{
	*statex = posixfs_object->statex;
	return 0;
}

/* posixfs_object must be directory */
int posixfs_object_get_parent_statex(const posixfs_object_t *dir_obj,
		posixfs_statex_t *statex)
{
	if (dir_obj->flags & posixfs_object_t::flag_topdir) {
		/* TODO should lock dir_obj */
		/* not go beyond share root */
		*statex = dir_obj->statex;
		return 0;
	}
	return posixfs_statex_getat(dir_obj->fd, "..", statex);
}

int posixfs_object_statex_getat(posixfs_object_t *dir_obj, const char *name,
		posixfs_statex_t *statex)
{
	return posixfs_statex_getat(dir_obj->fd, name, statex);
}

int posixfs_mktld(const std::shared_ptr<x_smbd_user_t> &smbd_user,
		const x_smbd_topdir_t &topdir,
		const std::string &name,
		std::vector<uint8_t> &ntacl_blob)
{
	std::shared_ptr<idl::security_descriptor> top_psd, psd;
	NTSTATUS status = posixfs_get_sd(topdir.fd, top_psd);
	X_ASSERT(NT_STATUS_IS_OK(status));

	status = make_child_sec_desc(psd, top_psd,
			*smbd_user, true);
	X_ASSERT(NT_STATUS_IS_OK(status));

	create_acl_blob(ntacl_blob, psd, idl::XATTR_SD_HASH_TYPE_NONE, std::array<uint8_t, idl::XATTR_SD_HASH_SIZE>());

	posixfs_statex_t statex;
	/* if parent is not enable inherit, make_sec_desc */
	int fd = posixfs_create(topdir.fd,
			true,
			name.c_str(),
			&statex,
			ntacl_blob);

	X_ASSERT(fd != -1);
	close(fd);
	return 0;
}


