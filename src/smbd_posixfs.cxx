
#include "smbd_open.hxx"
#include "smbd_posixfs.hxx"
#include <fcntl.h>
#include <sys/statvfs.h>
#include "smbd_ntacl.hxx"
#include "smbd_lease.hxx"
#include <dirent.h>
#include <sys/syscall.h>
#include "smbd_share.hxx"
#include <sys/xattr.h>

#define POSIXFS_ADS_PREFIX      "user.ads:"
struct posixfs_ads_header_t
{
	uint32_t version;
	uint32_t allocation_size;
};
// TODO ext4 xattr max size is 4k
static const uint64_t posixfs_ads_max_length = 0x1000 - sizeof(posixfs_ads_header_t);


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

static bool is_null_ntime(idl::NTTIME nt)
{
	return nt.val == 0 || nt.val == (uint64_t)-1;
}

static int posixfs_set_basic_info(int fd,
		uint32_t &notify_actions,
		const x_smb2_file_basic_info_t &basic_info,
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
		uts[1] = x_nttime_to_timespec(basic_info.last_write);
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

struct posixfs_stream_t;
struct posixfs_open_t
{
	posixfs_open_t(x_smbd_object_t *so, x_smbd_tcon_t *st,
			uint32_t am, uint32_t sa, long priv_data,
			posixfs_stream_t *stream)
		: base(so, st, am, sa, priv_data), stream(stream) { }
	x_smbd_open_t base;
	x_dlink_t object_link;
	posixfs_stream_t * const stream;
	qdir_t *qdir = nullptr;
	uint8_t oplock_level{X_SMB2_OPLOCK_LEVEL_NONE};
	oplock_break_sent_t oplock_break_sent{oplock_break_sent_t::OPLOCK_BREAK_NOT_SENT};
	/* open's on the same file sharing the same lease can have different parent key */
	x_smb2_lease_key_t parent_lease_key;
	x_smbd_lease_t *smbd_lease{};
	uint8_t lock_sequency_array[64];
	/* notify_requ_list and notify_changes protected by posixfs_object->mutex */
	x_tp_ddlist_t<requ_async_traits> notify_requ_list;
	x_tp_ddlist_t<requ_async_traits> lock_requ_list;
	std::vector<std::pair<uint32_t, std::u16string>> notify_changes;
	std::vector<x_smb2_lock_element_t> locks;
};
X_DECLARE_MEMBER_TRAITS(posixfs_open_object_traits, posixfs_open_t, object_link)
X_DECLARE_MEMBER_TRAITS(posixfs_open_from_base_t, posixfs_open_t, base)

struct posixfs_stream_t
{
	x_tp_ddlist_t<posixfs_open_object_traits> open_list;
	x_tp_ddlist_t<requ_async_traits> defer_open_list;
	bool delete_on_close = false;
	std::atomic<int> ref_count{1};
};

struct posixfs_ads_t
{
	posixfs_ads_t(const std::u16string &name) : name(name) { }
	posixfs_stream_t base;
	x_dlink_t object_link; // link into object
	uint32_t allocation_size, eof;
	bool exists = false;
	bool initialized = false;
	const std::u16string name;
	std::string xattr_name;
};
X_DECLARE_MEMBER_TRAITS(posixfs_ads_object_traits, posixfs_ads_t, object_link)

struct posixfs_object_t
{
	posixfs_object_t(uint64_t h,
			const std::shared_ptr<x_smbd_topdir_t> &topdir,
			const std::u16string &p, uint64_t data_data);
	~posixfs_object_t() {
		if (fd != -1) {
			close(fd);
		}
	}

	x_smbd_object_t base;

	bool exists() const { return base.type != x_smbd_object_t::type_not_exist; }
	x_dqlink_t hash_link;
	uint64_t hash;
	uint64_t unused_timestamp{0};
	std::atomic<uint32_t> use_count{1}; // protected by bucket mutex
	// std::atomic<uint32_t> children_count{};
	int fd = -1;
	std::atomic<uint32_t> lease_cnt{0};
	// std::atomic<uint32_t> notify_cnt{0};
#if 0
	std::mutex mutex;
	enum {
		flag_initialized = 1,
		flag_not_exist = 2,
		flag_topdir = 4,
		flag_delete_on_close = 0x1000,
	};

	uint32_t flags = 0;
#endif
	bool statex_modified{false}; // TODO use flags
	posixfs_statex_t statex;
	/* protected by bucket mutex */
	// std::u16string req_path;
	std::string unix_path;
	/* protected by object mutex */
	posixfs_stream_t default_stream;
	x_tp_ddlist_t<posixfs_ads_object_traits> ads_list;
};
X_DECLARE_MEMBER_TRAITS(posixfs_object_from_base_t, posixfs_object_t, base)

static inline bool is_default_stream(const posixfs_object_t *object,
		const posixfs_stream_t *stream)
{
	return stream == &object->default_stream;
}

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

static inline void posixfs_object_update_type(posixfs_object_t *posixfs_object)
{
	if (S_ISDIR(posixfs_object->statex.stat.st_mode)) {
		posixfs_object->base.type = x_smbd_object_t::type_dir;
	} else {
		/* TODO we only support dir and file for now */
		posixfs_object->base.type = x_smbd_object_t::type_file;
	}
}

static inline bool posixfs_object_is_dir(const posixfs_object_t *posixfs_object)
{
	return posixfs_object->base.type == x_smbd_object_t::type_dir;
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
		const std::shared_ptr<x_smbd_topdir_t> &topdir,
		const std::u16string &path,
		uint64_t path_data,
		bool create_if)
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
		if (elem->hash == hash && elem->base.topdir->uuid == topdir->uuid
				&& elem->base.path == path) {
			matched_object = elem;
			break;
		}
	}

	if (!matched_object) {
		if (!create_if) {
			return nullptr;
		}
		if (elem && elem->use_count == 0 &&
				elem->unused_timestamp + posixfs_object_pool_t::cache_time < tick_now) {
			elem->~posixfs_object_t();
			new (elem)posixfs_object_t(hash, topdir, path, path_data);
			matched_object = elem;
		} else {
			matched_object = new posixfs_object_t(hash, topdir, path, path_data);
			X_ASSERT(matched_object);
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

static void posixfs_re_lock(posixfs_stream_t *posixfs_stream);

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

static bool brl_conflict(const posixfs_stream_t *posixfs_stream,
		const posixfs_open_t *posixfs_open,
		const x_smb2_lock_element_t &le)
{
	auto &open_list = posixfs_stream->open_list;
	const posixfs_open_t *curr_open;
	for (curr_open = open_list.get_front(); curr_open; curr_open = open_list.next(curr_open)) {
		for (auto &l: curr_open->locks) {
			if (!(le.flags & SMB2_LOCK_FLAG_EXCLUSIVE) &&
					!(l.flags & SMB2_LOCK_FLAG_EXCLUSIVE)) {
				continue;
			}

			/* A READ lock can stack on top of a WRITE lock if they are
			 * the same open */
			if ((l.flags & SMB2_LOCK_FLAG_EXCLUSIVE) &&
					!(le.flags & SMB2_LOCK_FLAG_EXCLUSIVE) &&
					curr_open == posixfs_open) {
				continue;
			}

			if (brl_overlap(le, l)) {
				return true;
			}
		}
	}
	return false;
}

static bool brl_conflict(const posixfs_stream_t *posixfs_stream,
		const posixfs_open_t *posixfs_open,
		const std::vector<x_smb2_lock_element_t> &locks)
{
	for (auto &le: locks) {
		if (brl_conflict(posixfs_stream, posixfs_open, le)) {
			return true;
		}
	}
	return false;
}

static bool brl_conflict_other(const posixfs_stream_t *posixfs_stream,
		const posixfs_open_t *posixfs_open,
		const x_smb2_lock_element_t &le)
{
	auto &open_list = posixfs_stream->open_list;
	const posixfs_open_t *curr_open;
	for (curr_open = open_list.get_front(); curr_open; curr_open = open_list.next(curr_open)) {
		for (auto &l: curr_open->locks) {
			if (!(le.flags & SMB2_LOCK_FLAG_EXCLUSIVE) &&
					!(l.flags & SMB2_LOCK_FLAG_EXCLUSIVE)) {
				continue;
			}

			if (!brl_overlap(le, l)) {
				continue;
			}

			if (curr_open != posixfs_open) {
				return true;
			}

			/*
			 * Incoming WRITE locks conflict with existing READ locks even
			 * if the context is the same. JRA. See LOCKTEST7 in
			 * smbtorture.
			 */
			if (!(l.flags & SMB2_LOCK_FLAG_EXCLUSIVE) &&
					(le.flags & SMB2_LOCK_FLAG_EXCLUSIVE)) {
				return true;
			}
		}
	}
	return false;
}

static bool check_io_brl_conflict(posixfs_object_t *posixfs_object,
		const posixfs_open_t *posixfs_open,
		uint64_t offset, uint64_t length, bool is_write)
{
	struct x_smb2_lock_element_t le;
	le.offset = offset;
	le.length = length;
	le.flags = is_write ? SMB2_LOCK_FLAG_EXCLUSIVE : SMB2_LOCK_FLAG_SHARED;
	std::lock_guard<std::mutex> lock(posixfs_object->base.mutex);
	return brl_conflict_other(posixfs_open->stream, posixfs_open, le);
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

	std::unique_lock<std::mutex> lock(posixfs_object->base.mutex);

	X_TODO; // re-process the create request
}

static void posixfs_create_cancel(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_requ->smbd_object);
	{
		std::unique_lock<std::mutex> lock(posixfs_object->base.mutex);
		X_TODO;
	//	posixfs_object->defer_open_list.remove(smbd_requ);
	}
	x_smbd_conn_post_cancel(smbd_conn, smbd_requ);
}

static void share_mode_modified(posixfs_object_t *posixfs_object,
		posixfs_stream_t *posixfs_stream)
{
	/* posixfs_object is locked */
	x_smbd_requ_t *smbd_requ = posixfs_stream->defer_open_list.get_front();
	if (!smbd_requ) {
		return;
	}

	posixfs_stream->defer_open_list.remove(smbd_requ);
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

void posixfs_object_notify_change(x_smbd_object_t *smbd_object,
		uint32_t notify_action,
		uint32_t notify_filter,
		const std::u16string &fullpath,
		const std::u16string *new_name_path,
		bool last_level)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);

	std::u16string subpath;
	std::u16string new_subpath;
	/* TODO change to read lock */
	std::unique_lock<std::mutex> lock(posixfs_object->base.mutex);
	auto &open_list = posixfs_object->default_stream.open_list;
	posixfs_open_t *curr_open;
	for (curr_open = open_list.get_front(); curr_open; curr_open = open_list.next(curr_open)) {
		if (!(curr_open->base.notify_filter & notify_filter)) {
			continue;
		}
		if (!last_level && !(curr_open->base.notify_filter & X_FILE_NOTIFY_CHANGE_WATCH_TREE)) {
			continue;
		}
		if (subpath.empty()) {
			if (smbd_object->path.empty()) {
				subpath = fullpath;
				if (new_name_path) {
					new_subpath = *new_name_path;
				}
			} else {
				subpath = fullpath.substr(smbd_object->path.size() + 1);
				if (new_name_path) {
					new_subpath = new_name_path->substr(smbd_object->path.size() + 1);
				}
			}
		}
		bool orig_empty = curr_open->notify_changes.empty();
		curr_open->notify_changes.push_back(std::make_pair(notify_action, subpath));
		if (new_name_path) {
			curr_open->notify_changes.push_back(std::make_pair(NOTIFY_ACTION_NEW_NAME,
						new_subpath));
		}

		if (!orig_empty) {
		       continue;
		}

		x_smbd_requ_t *smbd_requ = curr_open->notify_requ_list.get_front();
		if (!smbd_requ) {
			continue;
		}

		auto notify_changes = std::move(curr_open->notify_changes);
		curr_open->notify_requ_list.remove(smbd_requ);
		lock.unlock();

		/* TODO should be in context of conn */
		x_smbd_requ_async_remove(smbd_requ); // remove from async
		posixfs_notify_evt_t *evt = new posixfs_notify_evt_t(smbd_requ,
				std::move(notify_changes));
		evt->base.func = posixfs_notify_func;
		if (!x_smbd_chan_post_user(smbd_requ->smbd_chan, &evt->base)) {
			delete evt;
		}
		lock.lock();
	}
}

/* rename_internals_fsp */
static NTSTATUS rename_object_intl(posixfs_object_pool_t::bucket_t &new_bucket,
		posixfs_object_pool_t::bucket_t &old_bucket,
		const std::shared_ptr<x_smbd_topdir_t> &topdir,
		posixfs_object_t *old_object,
		const std::u16string &new_path,
		std::u16string &old_path,
		uint64_t new_hash)
{
	posixfs_object_t *new_object = nullptr;
	for (x_dqlink_t *link = new_bucket.head.get_front(); link; link = link->get_next()) {
		posixfs_object_t *elem = X_CONTAINER_OF(link, posixfs_object_t, hash_link);
		if (elem->hash == new_hash && elem->base.topdir->uuid == topdir->uuid
				&& elem->base.path == new_path) {
			new_object = elem;
			break;
		}
	}
	if (new_object && new_object->exists()) {
		/* TODO replace forced */
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	/* check if exists on file system */
	std::string new_unix_path = convert_to_unix(new_path);
	int fd = openat(topdir->fd, new_unix_path.c_str(), O_RDONLY);
	if (fd != -1) {
		if (new_object) {
			new_object->fd = fd;
			/* so it needs to reload statex when using it */
			new_object->statex_modified = true;
		} else {
			close(fd);
		}
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	int err = renameat(topdir->fd, old_object->unix_path.c_str(),
			topdir->fd, new_unix_path.c_str());
	if (err != 0) {
		return x_map_nt_error_from_unix(-err);
	}	

	if (new_object) {
		/* not exists, should none refer it??? */
		new_bucket.head.remove(&new_object->hash_link);
		X_ASSERT(new_object->use_count == 0);
		delete new_object;
	}

	old_path = old_object->base.path;
	old_bucket.head.remove(&old_object->hash_link);
	old_object->hash = new_hash;
	old_object->base.path = new_path;
	old_object->unix_path = new_unix_path;
	new_bucket.head.push_front(&old_object->hash_link);
	return NT_STATUS_OK;
}

NTSTATUS posixfs_object_rename(x_smbd_object_t *smbd_object,
		x_smbd_requ_t *smbd_requ,
		const std::u16string &new_path,
		const std::u16string &new_stream_name,
		bool replace_if_exists,
		std::vector<x_smb2_change_t> &changes)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	auto &topdir = posixfs_object->base.topdir;

	auto &pool = posixfs_object_pool;
	auto new_hash = hash_object(topdir, new_path);
	auto new_bucket_idx = new_hash % pool.buckets.size();
	auto &new_bucket = pool.buckets[new_bucket_idx];
	auto old_bucket_idx = posixfs_object->hash % pool.buckets.size();

	NTSTATUS status;
	std::u16string old_path;
	if (new_bucket_idx == old_bucket_idx) {
		std::lock_guard<std::mutex> lock(new_bucket.mutex);
		status = rename_object_intl(new_bucket, new_bucket, topdir,
				posixfs_object,
				new_path, old_path, new_hash);
	} else {
		auto &old_bucket = pool.buckets[old_bucket_idx];
		std::scoped_lock lock(new_bucket.mutex, old_bucket.mutex);
		status = rename_object_intl(new_bucket, old_bucket, topdir,
				posixfs_object,
				new_path, old_path, new_hash);
	}

	if (NT_STATUS_IS_OK(status)) {
		changes.push_back(x_smb2_change_t{NOTIFY_ACTION_OLD_NAME,
				posixfs_object->base.type == x_smbd_object_t::type_dir ?
					FILE_NOTIFY_CHANGE_DIR_NAME :
					FILE_NOTIFY_CHANGE_FILE_NAME,
				old_path, new_path});
	}

	return status;
}

NTSTATUS posixfs_object_op_rename(x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		bool replace_if_exists,
		const std::u16string &new_path,
		const std::u16string &new_stream_name,
		std::vector<x_smb2_change_t> &changes)
{
	return posixfs_object_rename(smbd_object, smbd_requ, 
			new_path, new_stream_name, replace_if_exists, changes);
}

static posixfs_object_t *posixfs_object_open(
		const std::shared_ptr<x_smbd_topdir_t> &topdir,
		const std::u16string &path,
		uint64_t path_data,
		bool create_if)
{
	posixfs_object_t *posixfs_object = posixfs_object_lookup(topdir, path,
			path_data, create_if);
	if (!posixfs_object) {
		return nullptr;
	}

	std::unique_lock<std::mutex> lock(posixfs_object->base.mutex);
	if (!(posixfs_object->base.flags & x_smbd_object_t::flag_initialized)) {
		std::string unix_path = convert_to_unix(path);
		int fd = posixfs_open(topdir->fd, unix_path.c_str(),
				&posixfs_object->statex);
		if (fd < 0) {
			assert(errno == ENOENT);
			posixfs_object->base.type = x_smbd_object_t::type_not_exist;
		} else {
			posixfs_object->fd = fd;
			posixfs_object_update_type(posixfs_object);
		}
		posixfs_object->base.flags = x_smbd_object_t::flag_initialized;
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
	std::unique_lock<std::mutex> lock(posixfs_object->base.mutex);
	return posixfs_object_get_sd__(posixfs_object, psd);
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
		posixfs_stream_t *posixfs_stream,
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

	auto &open_list = posixfs_stream->open_list;
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

	std::lock_guard<std::mutex> lock(posixfs_object->base.mutex);
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
		posixfs_stream_t *posixfs_stream,
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
	auto &open_list = posixfs_stream->open_list;
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
		posixfs_stream_t *posixfs_stream,
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

	if (posixfs_object->base.type == x_smbd_object_t::type_dir &&
			posixfs_stream != &posixfs_object->default_stream) {
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

	auto &open_list = posixfs_stream->open_list;
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
		posixfs_stream_t *posixfs_stream,
		bool delete_on_close)
{
	if (delete_on_close) {
		if (posixfs_object->statex.file_attributes & FILE_ATTRIBUTE_READONLY) {
			return NT_STATUS_CANNOT_DELETE;
		}
		posixfs_stream->delete_on_close = true;
	} else {
		posixfs_stream->delete_on_close = false;
	}
	return NT_STATUS_OK;
}

static posixfs_open_t *posixfs_open_create(
		NTSTATUS *pstatus,
		x_smbd_tcon_t *smbd_tcon,
		posixfs_object_t *posixfs_object,
		posixfs_stream_t *posixfs_stream,
		const x_smb2_state_create_t &state,
		x_smbd_lease_t *smbd_lease,
		long priv_data)
{
	NTSTATUS status;
	if (state.in_create_options & FILE_DELETE_ON_CLOSE) {
		status = posixfs_object_set_delete_on_close(posixfs_object, posixfs_stream, true);
		if (!NT_STATUS_IS_OK(status)) {
			*pstatus = status;
			return nullptr;
		}
	}

	posixfs_open_t *posixfs_open = new posixfs_open_t(&posixfs_object->base,
			smbd_tcon, state.granted_access, state.in_share_access, priv_data,
			posixfs_stream);
	posixfs_open->oplock_level = state.oplock_level;
	posixfs_open->smbd_lease = smbd_lease;
	if (!x_smbd_open_store(&posixfs_open->base)) {
		delete posixfs_open;
		*pstatus = NT_STATUS_INSUFFICIENT_RESOURCES;
		return nullptr;
	}

	++posixfs_stream->ref_count;
	posixfs_stream->open_list.push_back(posixfs_open);
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

static int open_parent(const std::shared_ptr<x_smbd_topdir_t> &topdir,
		const std::u16string &path)
{
	if (path.empty()) {
		return -1;
	}

	std::u16string parent_path;
	auto sep = path.rfind('\\');
	if (sep == std::u16string::npos) {
		return dup(topdir->fd);
	}
	parent_path = path.substr(0, sep);
	std::string unix_path = convert_to_unix(parent_path);
	int fd = openat(topdir->fd, unix_path.c_str(), O_RDONLY | O_NOFOLLOW);
	return fd;
}

static NTSTATUS get_parent_sd(const posixfs_object_t *posixfs_object,
		std::shared_ptr<idl::security_descriptor> &psd)
{
	int fd = open_parent(posixfs_object->base.topdir, posixfs_object->base.path);
	if (fd == -1) {
		return x_map_nt_error_from_unix(-errno);
	}

	std::vector<uint8_t> blob;
	NTSTATUS status;
	int err = posixfs_get_ntacl_blob(fd, blob);
	if (err < 0) {
		status = x_map_nt_error_from_unix(-err);
	} else {
		uint16_t hash_type;
		uint16_t version;
		std::array<uint8_t, idl::XATTR_SD_HASH_SIZE> hash;
		status = parse_acl_blob(blob, psd, &hash_type, &version, hash);
	}
	close(fd);

	return status;
}

static inline bool is_sd_empty(const idl::security_descriptor &sd)
{
	return !sd.owner_sid && !sd.group_sid && !sd.dacl && !sd.sacl;
}

static NTSTATUS posixfs_new_object(
		posixfs_object_t *posixfs_object,
		x_smbd_requ_t *smbd_requ,
		x_smb2_state_create_t &state,
		uint64_t allocation_size,
		std::shared_ptr<idl::security_descriptor> &psd)
{
	std::shared_ptr<idl::security_descriptor> parent_psd;
	NTSTATUS status = get_parent_sd(posixfs_object, parent_psd);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	auto smbd_user = x_smbd_sess_get_user(smbd_requ->smbd_sess);
	uint32_t rejected_mask = 0;
	status = se_file_access_check(*parent_psd, *smbd_user,
			false, idl::SEC_DIR_ADD_FILE, &rejected_mask);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (state.in_security_descriptor) {
		if (!is_sd_empty(*state.in_security_descriptor)) {
			psd = state.in_security_descriptor;
		}
	} else {
		status = make_child_sec_desc(psd, parent_psd,
				*smbd_user,
				state.in_create_options & FILE_DIRECTORY_FILE);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	std::vector<uint8_t> ntacl_blob;
	if (psd) {
		create_acl_blob(ntacl_blob, psd, idl::XATTR_SD_HASH_TYPE_NONE, std::array<uint8_t, idl::XATTR_SD_HASH_SIZE>());
	}

	/* if parent is not enable inherit, make_sec_desc */
	int fd = posixfs_create(posixfs_object->base.topdir->fd,
			state.in_create_options & FILE_DIRECTORY_FILE,
			posixfs_object->unix_path.c_str(),
			&posixfs_object->statex,
			state.in_file_attributes,
			state.in_allocation_size,
			ntacl_blob);

	if (fd < 0) {
		X_ASSERT(-fd == EEXIST);
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	X_ASSERT(posixfs_object->fd == -1);
	X_ASSERT(posixfs_object->base.type == x_smbd_object_t::type_not_exist);
	posixfs_object_update_type(posixfs_object);
	posixfs_object->fd = fd;

	return NT_STATUS_OK;
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

static posixfs_open_t *posixfs_create_open_exist_object(
		posixfs_object_t *posixfs_object,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state,
		long priv_data,
		NTSTATUS &status)
{
	if (posixfs_object->default_stream.delete_on_close) {
		status = NT_STATUS_DELETE_PENDING;
		return nullptr;
	}

	if (posixfs_object->base.type == x_smbd_object_t::type_dir) {
		if (state->in_create_options & FILE_NON_DIRECTORY_FILE) {
			status = NT_STATUS_FILE_IS_A_DIRECTORY;
			return nullptr;
		}
	} else {
		if (state->in_create_options & FILE_DIRECTORY_FILE) {
			status = NT_STATUS_NOT_A_DIRECTORY;
			return nullptr;
		}
	}

	if ((posixfs_object->statex.file_attributes & FILE_ATTRIBUTE_READONLY) &&
			(state->in_desired_access & (idl::SEC_FILE_WRITE_DATA | idl::SEC_FILE_APPEND_DATA))) {
		X_LOG_NOTICE("deny access 0x%x to %s due to readonly 0x%x",
				state->in_desired_access, posixfs_object->unix_path.c_str(),
				posixfs_object->statex.file_attributes);
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

	auto smbd_user = x_smbd_sess_get_user(smbd_requ->smbd_sess);
	uint32_t share_access = x_smbd_tcon_get_share_access(smbd_requ->smbd_tcon);
	state->out_maximal_access = se_calculate_maximal_access(*psd, *smbd_user);
	state->out_maximal_access &= share_access;
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
					smbd_requ->smbd_tcon, *smbd_user)) {
			status = NT_STATUS_ACCESS_DENIED;
			return nullptr;
		}
	} else if (rejected_mask != 0) {
		status = NT_STATUS_ACCESS_DENIED;
		return nullptr;
	}

	state->granted_access = granted;

	auto &curr_client_guid = x_smbd_conn_curr_client_guid();
	bool conflict = open_mode_check(posixfs_object,
			&posixfs_object->default_stream,
			state->in_desired_access, state->in_share_access);
	if (delay_for_oplock(posixfs_object,
				&posixfs_object->default_stream,
				curr_client_guid,
				state->oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE ?
					&state->lease : nullptr,
				state->in_create_disposition,
				conflict, true)) {
		smbd_requ->requ_state = state.release();
		/* TODO add timer */
		x_smbd_ref_inc(smbd_requ);
		posixfs_object->default_stream.defer_open_list.push_back(smbd_requ);
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
			&posixfs_object->default_stream,
			curr_client_guid, *state, &smbd_lease);
	X_ASSERT(NT_STATUS_IS_OK(status));
	reply_requ_create(*state, posixfs_object, FILE_WAS_OPENED);
	return posixfs_open_create(&status, smbd_requ->smbd_tcon, posixfs_object,
			&posixfs_object->default_stream,
			*state, smbd_lease, priv_data);
}

static posixfs_open_t *posixfs_create_open_new_object(
		posixfs_object_t *posixfs_object,
		x_smbd_requ_t *smbd_requ,
		x_smb2_state_create_t &state,
		long priv_data,
		NTSTATUS &status)
{
	std::shared_ptr<idl::security_descriptor> psd;
	status = posixfs_new_object(posixfs_object, smbd_requ,
			state, state.in_allocation_size, psd);
	if (!NT_STATUS_IS_OK(status)) {
		return nullptr;
	}

	auto smbd_user = x_smbd_sess_get_user(smbd_requ->smbd_sess);
	state.out_maximal_access = se_calculate_maximal_access(*psd, *smbd_user);
	/* Windows server seem not do access check for create new object */
	if (state.in_desired_access & idl::SEC_FLAG_MAXIMUM_ALLOWED) {
		state.granted_access = state.out_maximal_access;
	} else {
		state.granted_access = state.out_maximal_access & state.in_desired_access;
	}

	x_smbd_lease_t *smbd_lease = nullptr;
       	status = grant_oplock(posixfs_object, &posixfs_object->default_stream,
			x_smbd_conn_curr_client_guid(), state, &smbd_lease);
	X_ASSERT(NT_STATUS_IS_OK(status));
	reply_requ_create(state, posixfs_object, FILE_WAS_CREATED);
	return posixfs_open_create(&status, smbd_requ->smbd_tcon, posixfs_object,
			&posixfs_object->default_stream, state, smbd_lease, priv_data);
}

/* caller should hold posixfs_object's mutex */
template <class T>
static int posixfs_ads_foreach_1(const posixfs_object_t *posixfs_object, T &&visitor)
{
	std::vector<char> buf(0x10000);
	ssize_t ret = flistxattr(posixfs_object->fd, buf.data(), buf.size());
	X_TODO_ASSERT(ret >= 0);
	if (ret == 0) {
		return 0;
	}
	size_t listxattr_len = ret;
	X_TODO_ASSERT(buf[listxattr_len - 1] == '\0');
	const char *data = buf.data();
	const char *end = data + listxattr_len;
	for ( ; data < end; data = data + strlen(data) + 1) {
		if (strncmp(data, POSIXFS_ADS_PREFIX, strlen(POSIXFS_ADS_PREFIX)) != 0) {
			continue;
		}
		const char *stream_name = data + strlen(POSIXFS_ADS_PREFIX);
		if (!visitor(data, stream_name)) {
			break;
		}
	}
	return 0;
}

template <class T>
static int posixfs_ads_foreach_2(const posixfs_object_t *posixfs_object, T &&visitor)
{
	return posixfs_ads_foreach_1(posixfs_object, [=] (const char *xattr_name,
				const char *stream_name) {
			std::vector<uint8_t> content(0x10000);
			ssize_t ret = fgetxattr(posixfs_object->fd, xattr_name, content.data(), content.size());
			X_TODO_ASSERT(ret >= x_convert<ssize_t>(sizeof(posixfs_ads_header_t)));
			const posixfs_ads_header_t *ads_hdr = (posixfs_ads_header_t *)content.data();
			uint32_t version = X_LE2H32(ads_hdr->version);
			uint32_t allocation_size = X_LE2H32(ads_hdr->allocation_size);
			X_TODO_ASSERT(version == 0);

			return visitor(stream_name, ret - sizeof(posixfs_ads_header_t),
					allocation_size);
		});
}

static posixfs_ads_t *posixfs_ads_add(
		posixfs_object_t *posixfs_object,
		const std::u16string &name)
{
	posixfs_ads_t *posixfs_ads = new posixfs_ads_t(name);
	posixfs_object->ads_list.push_front(posixfs_ads);
	return posixfs_ads;
}

static posixfs_ads_t *posixfs_ads_open(
		posixfs_object_t *posixfs_object,
		const std::u16string &name,
		bool exist_only)
{
	posixfs_ads_t *ads{};
	for (ads = posixfs_object->ads_list.get_front(); ads;
			ads = posixfs_object->ads_list.next(ads)) {
		/* TODO case insensitive */
		if (ads->name == name) {
			if (ads->exists || !exist_only) {
				++ads->base.ref_count;
				return ads;
			} else {
				return nullptr;
			}
		}
	}
	
	std::string utf8_name = x_convert_utf16_to_utf8(name);
	
	posixfs_ads_foreach_1(posixfs_object, [&utf8_name, &ads] (const char *xattr_name,
				const char *stream_name) {
			if (strcasecmp(stream_name, utf8_name.c_str()) == 0) {
				ads = new posixfs_ads_t(x_convert_utf8_to_utf16(stream_name));
				ads->xattr_name = xattr_name;
				ads->exists = true;
				return false;
			}
			return true;
		});
	return ads;
}

static void posixfs_ads_release(posixfs_object_t *posixfs_object,
		posixfs_ads_t *ads)
{
	if (--ads->base.ref_count == 0) {
		posixfs_object->ads_list.remove(ads);
		delete ads;
	}
}

static std::string posixfs_get_ads_xattr_name(const std::string &stream_name)
{
	return POSIXFS_ADS_PREFIX + stream_name;
}

static void posixfs_ads_reset(posixfs_object_t *posixfs_object,
		posixfs_ads_t *posixfs_ads,
		uint32_t allocation_size)
{
	posixfs_ads_header_t ads_header = { 0, allocation_size };
	int ret = fsetxattr(posixfs_object->fd, posixfs_ads->xattr_name.c_str(),
		&ads_header, sizeof(ads_header), 0);
	posixfs_ads->exists = true;
	posixfs_ads->initialized = true;
	posixfs_ads->allocation_size = allocation_size;
	posixfs_ads->eof = 0;
	X_TODO_ASSERT(ret >= 0);
}

static posixfs_open_t *open_object_new_ads(
		posixfs_object_t *posixfs_object,
		posixfs_ads_t *posixfs_ads,
		x_smbd_requ_t *smbd_requ,
		x_smb2_state_create_t &state,
		long priv_data,
		NTSTATUS &status)
{
	X_ASSERT(!posixfs_ads->exists);

	if (posixfs_object->default_stream.delete_on_close) {
		status = NT_STATUS_DELETE_PENDING;
		return nullptr;
	}

	// TODO should it fail for large in_allocation_size?
	uint32_t allocation_size = x_convert_assert<uint32_t>(
			std::min(state.in_allocation_size, posixfs_ads_max_length));
	posixfs_ads->xattr_name = posixfs_get_ads_xattr_name(x_convert_utf16_to_utf8(
				posixfs_ads->name));
	posixfs_ads_reset(posixfs_object, posixfs_ads, allocation_size);

	std::shared_ptr<idl::security_descriptor> psd;
	status = posixfs_object_get_sd__(posixfs_object, psd);
	if (!NT_STATUS_IS_OK(status)) {
		return nullptr;
	}

	auto smbd_user = x_smbd_sess_get_user(smbd_requ->smbd_sess);
	state.out_maximal_access = se_calculate_maximal_access(*psd, *smbd_user);
	/* Windows server seem not do access check for create new object */
	if (state.in_desired_access & idl::SEC_FLAG_MAXIMUM_ALLOWED) {
		state.granted_access = state.out_maximal_access;
	} else {
		state.granted_access = state.out_maximal_access & state.in_desired_access;
	}

	x_smbd_lease_t *smbd_lease = nullptr;
       	status = grant_oplock(posixfs_object, &posixfs_ads->base,
			x_smbd_conn_curr_client_guid(), state, &smbd_lease);
	X_ASSERT(NT_STATUS_IS_OK(status));
	reply_requ_create(state, posixfs_object, FILE_WAS_CREATED);
	return posixfs_open_create(&status, smbd_requ->smbd_tcon,
			posixfs_object, &posixfs_ads->base,
			state, smbd_lease, priv_data);
}

static posixfs_open_t *open_object_exist_ads(
		posixfs_object_t *posixfs_object,
		posixfs_ads_t *posixfs_ads,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state,
		long priv_data,
		NTSTATUS &status)
{
	X_ASSERT(posixfs_ads->exists);

	if (posixfs_object->default_stream.delete_on_close ||
			posixfs_ads->base.delete_on_close) {
		status = NT_STATUS_DELETE_PENDING;
		return nullptr;
	}

	if (!posixfs_ads->initialized) {
		std::vector<uint8_t> data(64 * 1024);
		ssize_t err = fgetxattr(posixfs_object->fd, posixfs_ads->xattr_name.c_str(),
				data.data(), data.size());
		X_TODO_ASSERT(err >= ssize_t(sizeof(posixfs_ads_header_t)));
		const posixfs_ads_header_t *header = (const posixfs_ads_header_t *)data.data();
		posixfs_ads->eof = x_convert_assert<uint32_t>(err - (sizeof(posixfs_ads_header_t)));
		posixfs_ads->allocation_size = X_LE2H32(header->allocation_size);
		posixfs_ads->initialized = true;
	}

	if ((posixfs_object->statex.file_attributes & FILE_ATTRIBUTE_READONLY) &&
			(state->in_desired_access & (idl::SEC_FILE_WRITE_DATA | idl::SEC_FILE_APPEND_DATA))) {
		X_LOG_NOTICE("deny access 0x%x to %s due to readonly 0x%x",
				state->in_desired_access, posixfs_object->unix_path.c_str(),
				posixfs_object->statex.file_attributes);
		status = NT_STATUS_ACCESS_DENIED;
		return nullptr;
	}

	/* is this check needed? */
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

	auto smbd_user = x_smbd_sess_get_user(smbd_requ->smbd_sess);
	uint32_t share_access = x_smbd_tcon_get_share_access(smbd_requ->smbd_tcon);
	state->out_maximal_access = se_calculate_maximal_access(*psd, *smbd_user);
	state->out_maximal_access &= share_access;
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
	if (rejected_mask != 0) {
		status = NT_STATUS_ACCESS_DENIED;
		return nullptr;
	}

	state->granted_access = granted;

	auto &curr_client_guid = x_smbd_conn_curr_client_guid();
	bool conflict = open_mode_check(posixfs_object,
			&posixfs_ads->base,
			state->in_desired_access, state->in_share_access);
	if (delay_for_oplock(posixfs_object,
				&posixfs_object->default_stream,
				curr_client_guid,
				state->oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE ?
					&state->lease : nullptr,
				state->in_create_disposition,
				conflict, true)) {
		smbd_requ->requ_state = state.release();
		/* TODO add timer */
		x_smbd_ref_inc(smbd_requ);
		posixfs_object->default_stream.defer_open_list.push_back(smbd_requ);
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
			&posixfs_object->default_stream,
			curr_client_guid, *state, &smbd_lease);
	X_ASSERT(NT_STATUS_IS_OK(status));
	reply_requ_create(*state, posixfs_object, FILE_WAS_OPENED);
	return posixfs_open_create(&status, smbd_requ->smbd_tcon,
			posixfs_object, &posixfs_ads->base,
			*state, smbd_lease, priv_data);
}

static posixfs_open_t *posixfs_create_open_overwrite_ads(
		posixfs_object_t *posixfs_object,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state,
		long priv_data,
		NTSTATUS &status)
{
	posixfs_ads_t *posixfs_ads = posixfs_ads_open(
			posixfs_object,
			state->in_ads_name,
			true);
	if (!posixfs_ads) {
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		return nullptr;
	} else {
		posixfs_ads_reset(posixfs_object, posixfs_ads, 0);
		posixfs_open_t *posixfs_open = open_object_exist_ads(posixfs_object,
				posixfs_ads,
				smbd_requ,
				state, priv_data, status);
		posixfs_ads_release(posixfs_object, posixfs_ads);
		return posixfs_open;
	}
}

static posixfs_open_t *posixfs_create_open_overwrite_ads_if(
		posixfs_object_t *posixfs_object,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state,
		long priv_data,
		NTSTATUS &status)
{
	posixfs_open_t *posixfs_open{};
	posixfs_ads_t *posixfs_ads = posixfs_ads_open(
			posixfs_object,
			state->in_ads_name,
			false);
	if (posixfs_ads && posixfs_ads->exists) {
		posixfs_ads_reset(posixfs_object, posixfs_ads, 0);
	} else {
		if (!posixfs_ads) {
			posixfs_ads = posixfs_ads_add(posixfs_object, state->in_ads_name);
		}
		posixfs_open = open_object_new_ads(
				posixfs_object,
				posixfs_ads,
				smbd_requ,
				*state,
				priv_data, status);
	}
	posixfs_ads_release(posixfs_object, posixfs_ads);
	return posixfs_open;
}


static posixfs_open_t *posix_create_open_exist_ads(posixfs_object_t *posixfs_object,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state,
		long priv_data,
		NTSTATUS &status)
{
	posixfs_open_t *posixfs_open{};
	posixfs_ads_t *posixfs_ads = posixfs_ads_open(
			posixfs_object,
			state->in_ads_name,
			true);
	if (!posixfs_ads) {
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
	} else {
		posixfs_open = open_object_exist_ads(
				posixfs_object,
				posixfs_ads,
				smbd_requ,
				state, priv_data, status);
		posixfs_ads_release(posixfs_object, posixfs_ads);
	}
	return posixfs_open;
}

static posixfs_open_t *posixfs_create_open_new_ads(posixfs_object_t *posixfs_object,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state,
		long priv_data,
		NTSTATUS &status)
{
	posixfs_open_t *posixfs_open{};
	posixfs_ads_t *posixfs_ads = posixfs_ads_open(
			posixfs_object,
			state->in_ads_name,
			false);
	if (!posixfs_ads) {
		posixfs_ads = posixfs_ads_add(posixfs_object,
				state->in_ads_name);
	}
	if (posixfs_ads->exists) {
		status = NT_STATUS_OBJECT_NAME_COLLISION;
	} else {
		posixfs_open = open_object_new_ads(
				posixfs_object,
				posixfs_ads,
				smbd_requ,
				*state, priv_data, status);
	}
	posixfs_ads_release(posixfs_object, posixfs_ads);
	return posixfs_open;
}

static posixfs_open_t *posixfs_create_open_new_ads_if(posixfs_object_t *posixfs_object,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state,
		long priv_data,
		NTSTATUS &status)
{
	posixfs_open_t *posixfs_open{};
	posixfs_ads_t *posixfs_ads = posixfs_ads_open(
			posixfs_object,
			state->in_ads_name,
			false);
	if (posixfs_ads && posixfs_ads->exists) {
		posixfs_open = open_object_exist_ads(
				posixfs_object,
				posixfs_ads,
				smbd_requ,
				state,
				priv_data, status);
	} else {
		if (!posixfs_ads) {
			posixfs_ads = posixfs_ads_add(posixfs_object, state->in_ads_name);
		}
		posixfs_open = open_object_new_ads(
				posixfs_object,
				posixfs_ads,
				smbd_requ,
				*state,
				priv_data, status);
	}
	posixfs_ads_release(posixfs_object, posixfs_ads);
	return posixfs_open;
}

static posixfs_open_t *posixfs_create_open_new_object_ads(posixfs_object_t *posixfs_object,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state,
		long priv_data,
		NTSTATUS &status)
{
	std::shared_ptr<idl::security_descriptor> psd;
	status = posixfs_new_object(posixfs_object, smbd_requ,
			*state, 0, psd);
	if (!NT_STATUS_IS_OK(status)) {
		return nullptr;
	}

	posixfs_ads_t *posixfs_ads = posixfs_ads_add(
			posixfs_object,
			state->in_ads_name);
	posixfs_open_t *posixfs_open = open_object_new_ads(
			posixfs_object,
			posixfs_ads,
			smbd_requ,
			*state, priv_data, status);
	posixfs_ads_release(posixfs_object, posixfs_ads);
	return posixfs_open;
}

static posixfs_open_t *posixfs_create_open(
		posixfs_object_t *posixfs_object,
		NTSTATUS &status,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state,
		long priv_data)
{
	posixfs_open_t *posixfs_open = nullptr;

	if (state->in_create_disposition == FILE_CREATE) {
		if (!posixfs_object->exists()) {
			if (state->end_with_sep) {
				status = NT_STATUS_OBJECT_NAME_INVALID;
			} else if (state->in_ads_name.size() == 0) {
				posixfs_open = posixfs_create_open_new_object(
						posixfs_object,
						smbd_requ,
						*state, priv_data, status);
			} else {
				posixfs_open = posixfs_create_open_new_object_ads(
						posixfs_object,
						smbd_requ,
						state, priv_data, status);
			}
		} else {
			if (state->in_ads_name.size() == 0) {
				status = NT_STATUS_OBJECT_NAME_COLLISION;
			} else {
				posixfs_open = posixfs_create_open_new_ads(
						posixfs_object,
						smbd_requ,
						state, priv_data, status);
			}
		}

	} else if (state->in_create_disposition == FILE_OPEN) {
		if (state->in_timestamp != 0) {
			X_TODO; /* TODO snapshot */
			status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		} else if (!posixfs_object->exists()) {
			status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		} else if (posixfs_object_is_dir(posixfs_object)) {
			if (state->is_dollar_data) {
				status = NT_STATUS_FILE_IS_A_DIRECTORY;
			} else if (state->in_ads_name.size() == 0) {
				posixfs_open = posixfs_create_open_exist_object(
						posixfs_object,
						smbd_requ,
						state, priv_data, status);
			} else {
				posixfs_open = posix_create_open_exist_ads(
						posixfs_object,
						smbd_requ,
						state, priv_data, status);
			}
		} else {
			if (state->end_with_sep) {
				status = NT_STATUS_OBJECT_NAME_INVALID;
			} else if (state->in_ads_name.size() == 0) {
				posixfs_open = posixfs_create_open_exist_object(
						posixfs_object,
						smbd_requ,
						state, priv_data, status);
			} else {
				posixfs_open = posix_create_open_exist_ads(
						posixfs_object,
						smbd_requ,
						state, priv_data, status);
			}
		}

	} else if (state->in_create_disposition == FILE_OPEN_IF) {
		if (state->in_timestamp != 0) {
			/* TODO snapshot */
			status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		} else if (!posixfs_object->exists()) {
			if (state->end_with_sep) {
				status = NT_STATUS_OBJECT_NAME_INVALID;
			} else if (state->in_ads_name.size() == 0) {
				posixfs_open = posixfs_create_open_new_object(
						posixfs_object,
						smbd_requ,
						*state, priv_data, status);
			} else {
				posixfs_open = posixfs_create_open_new_object_ads(
						posixfs_object,
						smbd_requ,
						state, priv_data, status);
			}
		} else if (posixfs_object_is_dir(posixfs_object)) {
			if (state->is_dollar_data) {
				status = NT_STATUS_FILE_IS_A_DIRECTORY;
			} else if (state->in_ads_name.size() == 0) {
				posixfs_open = posixfs_create_open_exist_object(
						posixfs_object,
						smbd_requ,
						state, priv_data, status);
			} else {
				posixfs_open = posixfs_create_open_new_ads_if(
						posixfs_object,
						smbd_requ,
						state, priv_data, status);
			}
		} else {
			if (state->in_ads_name.size() == 0) {
				posixfs_open = posixfs_create_open_exist_object(
						posixfs_object,
						smbd_requ,
						state, priv_data, status);
			} else {
				posixfs_open = posixfs_create_open_new_ads_if(
						posixfs_object,
						smbd_requ,
						state, priv_data, status);
			}
		}

	} else if (state->in_create_disposition == FILE_OVERWRITE) {
		if (!posixfs_object->exists()) {
			status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		} else if (posixfs_object_is_dir(posixfs_object)) {
			if (state->in_ads_name.size() == 0) {
				if (state->is_dollar_data) {
					status = NT_STATUS_FILE_IS_A_DIRECTORY;
				} else {
					status = NT_STATUS_INVALID_PARAMETER;
				}
			} else {
				posixfs_open = posixfs_create_open_overwrite_ads(
						posixfs_object,
						smbd_requ,
						state, priv_data, status);
			}
		} else {
			if (state->in_ads_name.size() == 0) {
				// TODO DELETE_ALL_STREAM;
				int err = ftruncate(posixfs_object->fd, 0);
				X_TODO_ASSERT(err == 0);
				posixfs_open = posixfs_create_open_exist_object(
						posixfs_object,
						smbd_requ,
						state, priv_data, status);
			} else {
				posixfs_open = posixfs_create_open_overwrite_ads(
						posixfs_object,
						smbd_requ,
						state, priv_data, status);
			}
		}
	
	} else if (state->in_create_disposition == FILE_OVERWRITE_IF ||
			state->in_create_disposition == FILE_SUPERSEDE) {
		/* TODO
		 * Currently we're using FILE_SUPERSEDE as the same as
		 * FILE_OVERWRITE_IF but they really are
		 * different. FILE_SUPERSEDE deletes an existing file
		 * (requiring delete access) then recreates it.
		 */
		if (state->in_timestamp != 0) {
			/* TODO */
			status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		} else if (!posixfs_object->exists()) {
			if (state->end_with_sep) {
				status = NT_STATUS_OBJECT_NAME_INVALID;
			} else if (state->in_ads_name.size() == 0) {
				posixfs_open = posixfs_create_open_new_object(
						posixfs_object,
						smbd_requ,
						*state, priv_data, status);
			} else {
				posixfs_open = posixfs_create_open_new_object_ads(
						posixfs_object,
						smbd_requ,
						state, priv_data, status);
			}
		} else if (posixfs_object_is_dir(posixfs_object)) {
			if (state->in_ads_name.size() == 0) {
				if (state->is_dollar_data) {
					status = NT_STATUS_FILE_IS_A_DIRECTORY;
				} else {
					status = NT_STATUS_INVALID_PARAMETER;
				}
			} else {
				posixfs_open = posixfs_create_open_overwrite_ads_if(
						posixfs_object,
						smbd_requ,
						state, priv_data, status);
			}
		} else {
			if (state->in_ads_name.size() == 0) {
				// TODO DELETE_ALL_STREAM;
				int err = ftruncate(posixfs_object->fd, 0);
				X_TODO_ASSERT(err == 0);
				posixfs_open = posixfs_create_open_exist_object(
						posixfs_object,
						smbd_requ,
						state, priv_data, status);
			} else {
				posixfs_open = posixfs_create_open_overwrite_ads_if(
						posixfs_object,
						smbd_requ,
						state, priv_data, status);
			}
		}

	} else {
		status = NT_STATUS_INVALID_PARAMETER;
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
	int err = unlinkat(posixfs_object->base.topdir->fd, posixfs_object->unix_path.c_str(),
			posixfs_object_is_dir(posixfs_object) ? AT_REMOVEDIR : 0);
	X_ASSERT(err == 0);
	err = close(posixfs_object->fd);
	X_ASSERT(err == 0);
	posixfs_object->fd = -1;
	posixfs_object->base.type = x_smbd_object_t::type_not_exist;
	return NT_STATUS_OK;
}

static void posixfs_object_remove(posixfs_object_t *posixfs_object,
		posixfs_open_t *posixfs_open,
		std::vector<x_smb2_change_t> &changes)
{
	if (!posixfs_open->object_link.is_valid()) {
		return;
	}
	posixfs_stream_t *posixfs_stream = posixfs_open->stream;
	posixfs_stream->open_list.remove(posixfs_open);
	if (posixfs_open->locks.size()) {
		posixfs_re_lock(posixfs_stream);
	}

	if (posixfs_stream->open_list.empty() &&
			posixfs_stream->delete_on_close) {
		if (!is_default_stream(posixfs_object, posixfs_stream)) {
			posixfs_ads_t *ads = X_CONTAINER_OF(posixfs_stream,
					posixfs_ads_t, base);
			int ret = fremovexattr(posixfs_object->fd, ads->xattr_name.c_str());
			X_TODO_ASSERT(ret == 0);
			// TODO should it also notify object MODIFIED
			changes.push_back(x_smb2_change_t{NOTIFY_ACTION_REMOVED_STREAM,
					FILE_NOTIFY_CHANGE_STREAM_NAME,
					posixfs_object->base.path + u':' + ads->name,
					{}});

		} else if (!posixfs_object->ads_list.get_front()) {
			uint32_t notify_filter;
			if (posixfs_object_is_dir(posixfs_object)) {
				notify_filter = FILE_NOTIFY_CHANGE_DIR_NAME;
			} else {
				notify_filter = FILE_NOTIFY_CHANGE_FILE_NAME;
			}

			NTSTATUS status = x_smbd_object_unlink(&posixfs_object->base, posixfs_object->fd);
			if (NT_STATUS_IS_OK(status)) {
				changes.push_back(x_smb2_change_t{NOTIFY_ACTION_REMOVED, notify_filter,
						posixfs_object->base.path, {}});
			}
		}
	}
}

NTSTATUS posixfs_object_op_close(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_close_t> &state,
		std::vector<x_smb2_change_t> &changes)
{
	posixfs_open_t *posixfs_open = posixfs_open_from_base_t::container(smbd_open);
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);

	std::unique_lock<std::mutex> lock(posixfs_object->base.mutex);

	if (posixfs_open->smbd_lease) {
		x_smbd_lease_release(posixfs_open->smbd_lease);
		posixfs_open->smbd_lease = nullptr;
	}

	/* Windows server send NT_STATUS_NOTIFY_CLEANUP
	   when tree disconect.
	   while samba not send.
	   for simplicity we do not either for now
	 */
	if (posixfs_open->base.notify_filter & X_FILE_NOTIFY_CHANGE_WATCH_TREE) {
		/* TODO make it atomic */
		X_ASSERT(smbd_object->topdir->watch_tree_cnt > 0);
		--smbd_object->topdir->watch_tree_cnt;
	}
	x_smbd_requ_t *requ_notify;
	while ((requ_notify = posixfs_open->notify_requ_list.get_front()) != nullptr) {
		posixfs_open->notify_requ_list.remove(requ_notify);
		lock.unlock();

		// TODO multi-thread safe
		std::unique_ptr<x_smb2_state_notify_t> notify_state{(x_smb2_state_notify_t *)requ_notify->requ_state};
		requ_notify->requ_state = nullptr;
		x_smbd_requ_async_remove(requ_notify);
		// TODO notify_state->done(smbd_conn, requ_notify, NT_STATUS_NOTIFY_CLEANUP);
		x_smbd_ref_dec(requ_notify);

		lock.lock();
	}

	posixfs_object_remove(posixfs_object, posixfs_open, changes);

	share_mode_modified(posixfs_object, posixfs_open->stream);

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
	~posixfs_read_evt_t() {
		x_smbd_ref_dec(smbd_requ);
	}
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
		x_smbd_requ_async_remove(smbd_requ);
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

static NTSTATUS posixfs_ads_read(posixfs_object_t *posixfs_object,
		posixfs_ads_t *ads,
		x_smb2_state_read_t &state)
{
	if (state.in_length == 0) {
		state.out_buf_length = 0;
		return NT_STATUS_OK;
	}
	if (state.in_offset >= ads->eof) {
		state.out_buf_length = 0;
		return NT_STATUS_END_OF_FILE;
	}
	uint64_t max_read = ads->eof - state.in_offset;
	if (max_read > state.in_length) {
		max_read = state.in_length;
	}
	std::vector<uint8_t> content(0x10000);
	ssize_t ret = fgetxattr(posixfs_object->fd, ads->xattr_name.c_str(), content.data(), content.size());
	X_TODO_ASSERT(ret >= ssize_t(sizeof(posixfs_ads_header_t)));
	const posixfs_ads_header_t *ads_hdr = (const posixfs_ads_header_t *)content.data();
	uint32_t version = X_LE2H32(ads_hdr->version);
	X_TODO_ASSERT(version == 0);
	X_TODO_ASSERT(ret == ssize_t(ads->eof + sizeof(posixfs_ads_header_t)));
	state.out_buf = x_buf_alloc(max_read);
	memcpy(state.out_buf->data, (uint8_t *)(ads_hdr + 1) + state.in_offset,
			max_read);
	state.out_buf_length = x_convert<uint32_t>(max_read);
	return NT_STATUS_OK;
}

static NTSTATUS posixfs_ads_write(posixfs_object_t *posixfs_object,
		posixfs_ads_t *posixfs_ads,
		x_smb2_state_write_t &state)
{
	uint64_t last_offset = state.in_offset + state.in_buf_length;
	if (last_offset > posixfs_ads_max_length) {
		return NT_STATUS_DISK_FULL; // windows server return this
	}
	std::vector<uint8_t> content(0x10000);
	ssize_t ret = fgetxattr(posixfs_object->fd, posixfs_ads->xattr_name.c_str(), content.data(), content.size());
	X_TODO_ASSERT(ret >= ssize_t(sizeof(posixfs_ads_header_t)));
	posixfs_ads_header_t *ads_hdr = (posixfs_ads_header_t *)content.data();
	uint32_t version = X_LE2H32(ads_hdr->version);
	uint32_t allocation_size = X_LE2H32(ads_hdr->allocation_size);
	X_TODO_ASSERT(version == 0);
	memcpy((uint8_t *)(ads_hdr + 1) + state.in_offset,
			state.in_buf->data + state.in_buf_offset,
			state.in_buf_length);
	uint64_t orig_eof = ret - sizeof(posixfs_ads_header_t);
	if (last_offset > orig_eof) {
		content.resize(sizeof(posixfs_ads_header_t) + last_offset);
		if (allocation_size < last_offset) {
			ads_hdr->allocation_size = X_H2LE32(x_convert<uint32_t>(last_offset));
			posixfs_ads->allocation_size = x_convert<uint32_t>(last_offset);
		}
		posixfs_ads->eof = x_convert<uint32_t>(last_offset);
	} else {
		content.resize(sizeof(posixfs_ads_header_t) + orig_eof);
	}
	ret = fsetxattr(posixfs_object->fd, posixfs_ads->xattr_name.c_str(), content.data(), content.size(), 0);
	X_TODO_ASSERT(ret == 0);
	return NT_STATUS_OK;
}

NTSTATUS posixfs_object_op_read(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_read_t> &state)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	posixfs_open_t *posixfs_open = posixfs_open_from_base_t::container(smbd_requ->smbd_open);
	if (check_io_brl_conflict(posixfs_object, posixfs_open, state->in_offset, state->in_length, false)) {
		return NT_STATUS_FILE_LOCK_CONFLICT;
	}

	if (!is_default_stream(posixfs_object, posixfs_open->stream)) {
		posixfs_ads_t *ads = X_CONTAINER_OF(posixfs_open->stream, posixfs_ads_t, base);
		return posixfs_ads_read(posixfs_object, ads, *state);
	}

	if (posixfs_object_is_dir(posixfs_object)) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}

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
	~posixfs_write_evt_t() {
		x_smbd_ref_dec(smbd_requ);
	}
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
		x_smbd_requ_async_remove(smbd_requ);
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
		x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_write_t> &state)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	posixfs_open_t *posixfs_open = posixfs_open_from_base_t::container(smbd_requ->smbd_open);

	if (check_io_brl_conflict(posixfs_object, posixfs_open, state->in_offset, state->in_buf_length, true)) {
		return NT_STATUS_FILE_LOCK_CONFLICT;
	}

	if (!is_default_stream(posixfs_object, posixfs_open->stream)) {
		posixfs_ads_t *ads = X_CONTAINER_OF(posixfs_open->stream, posixfs_ads_t, base);
		return posixfs_ads_write(posixfs_object, ads, *state);
	}

	if (posixfs_object_is_dir(posixfs_object)) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}

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

static void posixfs_lock_cancel(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	posixfs_open_t *posixfs_open = posixfs_open_from_base_t::container(smbd_requ->smbd_open);
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(posixfs_open->base.smbd_object);

	{
		std::lock_guard<std::mutex> lock(posixfs_object->base.mutex);
		posixfs_open->lock_requ_list.remove(smbd_requ);
	}
	x_smbd_conn_post_cancel(smbd_conn, smbd_requ);
}

struct posixfs_lock_evt_t
{
	explicit posixfs_lock_evt_t(x_smbd_requ_t *requ)
		: smbd_requ(requ)
	{ }
	~posixfs_lock_evt_t() {
		x_smbd_ref_dec(smbd_requ);
	}
	x_fdevt_user_t base;
	x_smbd_requ_t *smbd_requ;
};

static void posixfs_lock_func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user, bool terminated)
{
	posixfs_lock_evt_t *evt = X_CONTAINER_OF(fdevt_user, posixfs_lock_evt_t, base);
	X_LOG_DBG("evt=%p", evt);

	if (!terminated) {
		x_smbd_requ_t *smbd_requ = evt->smbd_requ;
		smbd_requ->async_done_fn(smbd_conn, smbd_requ, NT_STATUS_OK);
	}

	delete evt;
}

static void posixfs_re_lock(posixfs_stream_t *posixfs_stream)
{
	/* TODO it is not fair, it always scan the lock from open_list */
	posixfs_open_t *posixfs_open;
	auto &open_list = posixfs_stream->open_list;
	for (posixfs_open = open_list.get_front(); posixfs_open; posixfs_open = open_list.next(posixfs_open)) {
		x_smbd_requ_t *smbd_requ = posixfs_open->lock_requ_list.get_front();
		while (smbd_requ) {
			x_smbd_requ_t *next_requ = posixfs_open->lock_requ_list.next(smbd_requ);
			x_smb2_state_lock_t *state{(x_smb2_state_lock_t *)smbd_requ->requ_state};
			if (!brl_conflict(posixfs_stream, posixfs_open, state->in_lock_elements)) {
				posixfs_open->lock_requ_list.remove(smbd_requ);
				// TODO should be in context of conn
				x_smbd_requ_async_remove(smbd_requ); // remove from async
				posixfs_lock_evt_t *evt = new posixfs_lock_evt_t(smbd_requ);
				evt->base.func = posixfs_lock_func;
				if (!x_smbd_chan_post_user(smbd_requ->smbd_chan, &evt->base)) {
					delete evt;
				}
			}
			smbd_requ = next_requ;
		}
	}
}

NTSTATUS posixfs_object_op_lock(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_lock_t> &state)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	if (posixfs_object_is_dir(posixfs_object)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	posixfs_open_t *posixfs_open = posixfs_open_from_base_t::container(smbd_requ->smbd_open);
	std::lock_guard<std::mutex> lock(posixfs_object->base.mutex);

	if (state->in_lock_elements[0].flags & SMB2_LOCK_FLAG_UNLOCK) {
		for (auto &l1: state->in_lock_elements) {
			auto it = posixfs_open->locks.begin();
			for (; it != posixfs_open->locks.end(); ++it) {
				if (it->offset == l1.offset && it->length == l1.length) {
					break;
				}
			}
			if (it == posixfs_open->locks.end()) {
				X_LOG_NOTICE("failed to unlock");
				return NT_STATUS_RANGE_NOT_LOCKED;
			}
			posixfs_open->locks.erase(it);
		}
		posixfs_re_lock(posixfs_open->stream);
		return NT_STATUS_OK;
	} else {
		bool conflict = brl_conflict(posixfs_open->stream, posixfs_open,
				state->in_lock_elements);
		if (!conflict) {
			posixfs_open->locks.insert(posixfs_open->locks.end(),
					state->in_lock_elements.begin(),
					state->in_lock_elements.end());
			return NT_STATUS_OK;
		} else if (state->in_lock_elements[0].flags & SMB2_LOCK_FLAG_FAIL_IMMEDIATELY) {
			return NT_STATUS_LOCK_NOT_GRANTED;
		} else {
			X_ASSERT(state->in_lock_elements.size() == 1);
			X_LOG_DBG("lock conflict");
			smbd_requ->requ_state = state.release();
			x_smbd_ref_inc(smbd_requ);
			posixfs_open->lock_requ_list.push_back(smbd_requ);
			x_smbd_conn_set_async(smbd_conn, smbd_requ, posixfs_lock_cancel);
			return NT_STATUS_PENDING;
		}
	}
}

static bool marshall_stream_info(x_smb2_chain_marshall_t &marshall,
		const char *stream_name,
		uint64_t size, uint64_t allocation_size)
{
	std::u16string name = x_convert_utf8_to_utf16(stream_name);
	name += u":$DATA";

	uint32_t rec_size = x_convert_assert<uint32_t>(sizeof(x_smb2_file_stream_name_info_t) + name.size() * 2);
	uint8_t *pbegin = marshall.get_begin(rec_size);
	if (!pbegin) {
		return false;
	}
	x_smb2_file_stream_name_info_t *info = (x_smb2_file_stream_name_info_t *)pbegin;
	info->next_offset = 0;
	info->name_length = X_H2LE32(x_convert_assert<uint32_t>(name.size() * 2));
	info->size = X_H2LE64(size);
	info->allocation_size = X_H2LE64(allocation_size);
	// TODO byte order
	memcpy(info->name, name.data(), name.size() * 2);
	return true;
}

static NTSTATUS getinfo_stream_info(const posixfs_object_t *posixfs_object,
		x_smb2_state_getinfo_t &state)
{
	state.out_data.resize(state.in_output_buffer_length);
	x_smb2_chain_marshall_t marshall{state.out_data.data(), state.out_data.data() + state.out_data.size(), 8};

	if (!posixfs_object_is_dir(posixfs_object)) {
		if (!marshall_stream_info(marshall, "", posixfs_object->statex.get_end_of_file(),
					posixfs_object->statex.get_allocation())) {
			return STATUS_BUFFER_OVERFLOW;
		}
	}

	bool marshall_ret = true;
	posixfs_ads_foreach_2(posixfs_object,
			[&marshall, &marshall_ret] (const char *stream_name, uint64_t eof, uint64_t alloc) {
			marshall_ret = marshall_stream_info(marshall, stream_name, eof, alloc);
			return marshall_ret;
		});
	if (!marshall_ret) {
		return STATUS_BUFFER_OVERFLOW;
	}
	state.out_data.resize(marshall.get_size());
	return NT_STATUS_OK;
}

static NTSTATUS getinfo_file(posixfs_object_t *posixfs_object,
		x_smbd_open_t *smbd_open,
		x_smb2_state_getinfo_t &state)
{
	if (state.in_info_level == SMB2_FILE_INFO_FILE_ALL_INFORMATION) {
		if (state.in_output_buffer_length < sizeof(x_smb2_file_all_info_t)) {
			return STATUS_BUFFER_OVERFLOW;
		}
		state.out_data.resize(sizeof(x_smb2_file_all_info_t));
		x_smb2_file_all_info_t *info =
			(x_smb2_file_all_info_t *)state.out_data.data();

		const auto &statex = posixfs_object->statex;
		info->basic_info.creation = X_H2LE64(x_timespec_to_nttime(statex.birth_time));
		info->basic_info.last_access = X_H2LE64(x_timespec_to_nttime(statex.stat.st_atim));
		info->basic_info.last_write = X_H2LE64(x_timespec_to_nttime(statex.stat.st_mtim));
		info->basic_info.change = X_H2LE64(x_timespec_to_nttime(statex.stat.st_ctim));
		info->basic_info.file_attributes = X_H2LE32(statex.file_attributes);
		info->basic_info.unused = 0;

		info->standard_info.allocation_size = X_H2LE64(statex.get_allocation());
		info->standard_info.end_of_file = X_H2LE64(statex.get_end_of_file());
		uint8_t delete_pending = posixfs_object->default_stream.delete_on_close ? 1 : 0;
		/* not sure why samba for nlink to 1 for directory, just follow it */
		uint32_t nlink = x_convert<uint32_t>(statex.stat.st_nlink);
		if (nlink && S_ISDIR(statex.stat.st_mode)) {
			nlink = 1;
		}
		if (nlink > 0) {
			nlink -= delete_pending;
		}

		info->standard_info.nlinks = X_H2LE32(nlink);
		info->standard_info.delete_pending = delete_pending;
		info->standard_info.directory = S_ISDIR(statex.stat.st_mode) ? 1 : 0;
		info->standard_info.unused = 0;

		info->file_id = X_H2LE64(statex.stat.st_ino);
		info->ea_size = 0; // not supported
		info->access_flags = X_H2LE32(smbd_open->access_mask);
		info->current_offset = 0; // TODO
		info->mode = 0;
		info->alignment_requirement = 0;
		info->file_name_length = 0;
		info->unused = 0;
	} else if (state.in_info_level == SMB2_FILE_INFO_FILE_NETWORK_OPEN_INFORMATION) {
		if (state.in_output_buffer_length < sizeof(x_smb2_file_network_open_info_t)) {
			return STATUS_BUFFER_OVERFLOW;
		}
		state.out_data.resize(sizeof(x_smb2_file_network_open_info_t));
		x_smb2_file_network_open_info_t *info =
			(x_smb2_file_network_open_info_t *)state.out_data.data();
		
		const auto &statex = posixfs_object->statex;
		info->creation = X_H2LE64(x_timespec_to_nttime(statex.birth_time));
		info->last_access = X_H2LE64(x_timespec_to_nttime(statex.stat.st_atim));
		info->last_write = X_H2LE64(x_timespec_to_nttime(statex.stat.st_mtim));
		info->change = X_H2LE64(x_timespec_to_nttime(statex.stat.st_ctim));
		info->allocation_size = X_H2LE64(statex.get_allocation());
		info->end_of_file = X_H2LE64(statex.get_end_of_file());
		info->file_attributes = X_H2LE32(statex.file_attributes);
		info->unused = 0;
	} else if (state.in_info_level == SMB2_FILE_INFO_FILE_STREAM_INFORMATION) {
		return getinfo_stream_info(posixfs_object, state);
	} else {
		return NT_STATUS_INVALID_LEVEL;
	}
	return NT_STATUS_OK;
}

static NTSTATUS setinfo_file(posixfs_object_t *posixfs_object,
		x_smbd_requ_t *smbd_requ,
		x_smb2_state_setinfo_t &state,
		std::vector<x_smb2_change_t> &changes)
{
	if (state.in_info_level == SMB2_FILE_INFO_FILE_BASIC_INFORMATION) {
		if (!smbd_requ->smbd_open->check_access(idl::SEC_FILE_WRITE_ATTRIBUTE)) {
			return NT_STATUS_ACCESS_DENIED;
		}

		x_smb2_file_basic_info_t basic_info;
		if (!x_smb2_file_basic_info_decode(basic_info, state.in_data)) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		uint32_t notify_actions = 0;
		int err = posixfs_set_basic_info(posixfs_object->fd,
				notify_actions, basic_info,
				&posixfs_object->statex);
		if (err == 0) {
			if (notify_actions) {
				changes.push_back(x_smb2_change_t{NOTIFY_ACTION_MODIFIED,
						notify_actions, posixfs_object->base.path, {}});
			}
			return NT_STATUS_OK;
		} else {
			X_TODO;
			return NT_STATUS_INTERNAL_ERROR;
		}
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
		const x_smb2_state_setinfo_t &state,
		std::vector<x_smb2_change_t> &changes)
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

	changes.push_back(x_smb2_change_t{NOTIFY_ACTION_MODIFIED, FILE_NOTIFY_CHANGE_SECURITY,
			posixfs_object->base.path, {}});
	return NT_STATUS_OK;
}

static NTSTATUS getinfo_quota(posixfs_object_t *posixfs_object,
		x_smb2_state_getinfo_t &state)
{
	return NT_STATUS_INVALID_LEVEL;
}

NTSTATUS posixfs_object_op_getinfo(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_getinfo_t> &state)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);

	if (state->in_info_class == SMB2_GETINFO_FILE) {
		return getinfo_file(posixfs_object, smbd_open, *state);
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
		std::unique_ptr<x_smb2_state_setinfo_t> &state,
		std::vector<x_smb2_change_t> &changes)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);

	if (state->in_info_class == SMB2_GETINFO_FILE) {
		return setinfo_file(posixfs_object, smbd_requ, *state, changes);
#if 0
	} else if (state->in_info_class == SMB2_GETINFO_FS) {
		return setinfo_fs(posixfs_object, smbd_requ, *state);
#endif
	} else if (state->in_info_class == SMB2_GETINFO_SECURITY) {
		return setinfo_security(posixfs_object, smbd_requ, *state, changes);
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
	std::unique_lock<std::mutex> lock(posixfs_object->base.mutex);
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

static bool marshall_entry(x_smb2_chain_marshall_t &marshall,
		const posixfs_statex_t &statex, const char *fname,
		int info_level)
{
	std::u16string name = x_convert_utf8_to_utf16(fname);
	uint8_t *pbegin;
	uint32_t rec_size;

	switch (info_level) {
	case SMB2_FIND_ID_BOTH_DIRECTORY_INFO:
		rec_size = x_convert_assert<uint32_t>(sizeof(x_smb2_file_id_both_dir_info_t) + name.size() * 2);
		pbegin = marshall.get_begin(rec_size);
		if (!pbegin) {
			return false;
		}
		{
			x_smb2_file_id_both_dir_info_t *info = (x_smb2_file_id_both_dir_info_t *)pbegin;
			info->next_offset = 0;
			info->file_index = 0;
			info->creation = X_H2LE64(x_timespec_to_nttime(statex.birth_time));
			info->last_access = X_H2LE64(x_timespec_to_nttime(statex.stat.st_atim));
			info->last_write = X_H2LE64(x_timespec_to_nttime(statex.stat.st_mtim));
			info->change = X_H2LE64(x_timespec_to_nttime(statex.stat.st_ctim));
			info->end_of_file = X_H2LE64(statex.get_end_of_file());
			info->allocation_size = X_H2LE64(statex.get_allocation());
			info->file_attributes = X_H2LE32(statex.file_attributes);
			info->file_name_length = X_H2LE32(x_convert_assert<uint32_t>(name.size() * 2));
			if (statex.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
				info->ea_size = X_H2LE32(IO_REPARSE_TAG_DFS);
			} else {
				/*
				 * OS X specific SMB2 extension negotiated via
				 * AAPL create context: return max_access in
				 * ea_size field.
				 */
				info->ea_size = 0;
			}
		
			// TODO get short name
			info->short_name_length = 0;
			memset(info->short_name, 0, sizeof info->short_name);
			info->unused0 = 0; // aapl mode

			uint64_t file_index = statex.stat.st_ino; // TODO
			info->file_id_low = X_H2LE32(file_index & 0xffffffff);
			info->file_id_high = X_H2LE32(x_convert<uint32_t>(file_index >> 32));
			// TODO byte order
			memcpy(info->file_name, name.data(), name.size() * 2);
		}
		break;

	case SMB2_FIND_ID_FULL_DIRECTORY_INFO:
		rec_size = x_convert_assert<uint32_t>(sizeof(x_smb2_file_id_full_dir_info_t) + name.size() * 2);
		pbegin = marshall.get_begin(rec_size);
		if (!pbegin) {
			return false;
		}
		{
			x_smb2_file_id_full_dir_info_t *info = (x_smb2_file_id_full_dir_info_t *)pbegin;
			info->next_offset = 0;
			info->file_index = 0;
			info->creation = X_H2LE64(x_timespec_to_nttime(statex.birth_time));
			info->last_access = X_H2LE64(x_timespec_to_nttime(statex.stat.st_atim));
			info->last_write = X_H2LE64(x_timespec_to_nttime(statex.stat.st_mtim));
			info->change = X_H2LE64(x_timespec_to_nttime(statex.stat.st_ctim));
			info->end_of_file = X_H2LE64(statex.get_end_of_file());
			info->allocation_size = X_H2LE64(statex.get_allocation());
			info->file_attributes = X_H2LE32(statex.file_attributes);
			info->file_name_length = X_H2LE32(x_convert_assert<uint32_t>(name.size() * 2));
			if (statex.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
				info->ea_size = X_H2LE32(IO_REPARSE_TAG_DFS);
			} else {
				/*
				 * OS X specific SMB2 extension negotiated via
				 * AAPL create context: return max_access in
				 * ea_size field.
				 */
				info->ea_size = 0;
			}
		
			info->unused0 = 0; // aapl mode

			info->file_id = X_H2LE64(statex.stat.st_ino);
			// TODO byte order
			memcpy(info->file_name, name.data(), name.size() * 2);
		}
		break;

	case SMB2_FIND_DIRECTORY_INFO:
		rec_size = x_convert_assert<uint32_t>(sizeof(x_smb2_file_dir_info_t) + name.size() * 2);
		pbegin = marshall.get_begin(rec_size);
		if (!pbegin) {
			return false;
		}
		{
			x_smb2_file_dir_info_t *info = (x_smb2_file_dir_info_t *)pbegin;
			info->next_offset = 0;
			info->file_index = 0;
			info->creation = X_H2LE64(x_timespec_to_nttime(statex.birth_time));
			info->last_access = X_H2LE64(x_timespec_to_nttime(statex.stat.st_atim));
			info->last_write = X_H2LE64(x_timespec_to_nttime(statex.stat.st_mtim));
			info->change = X_H2LE64(x_timespec_to_nttime(statex.stat.st_ctim));
			info->end_of_file = X_H2LE64(statex.get_end_of_file());
			info->allocation_size = X_H2LE64(statex.get_allocation());
			info->file_attributes = X_H2LE32(statex.file_attributes);
			info->file_name_length = X_H2LE32(x_convert_assert<uint32_t>(name.size() * 2));
			// TODO byte order
			memcpy(info->file_name, name.data(), name.size() * 2);
		}
		break;

	case SMB2_FIND_BOTH_DIRECTORY_INFO:
		rec_size = x_convert_assert<uint32_t>(sizeof(x_smb2_file_both_dir_info_t) + name.size() * 2);
		pbegin = marshall.get_begin(rec_size);
		if (!pbegin) {
			return false;
		}
		{
			x_smb2_file_both_dir_info_t *info = (x_smb2_file_both_dir_info_t *)pbegin;
			info->next_offset = 0;
			info->file_index = 0;
			info->creation = X_H2LE64(x_timespec_to_nttime(statex.birth_time));
			info->last_access = X_H2LE64(x_timespec_to_nttime(statex.stat.st_atim));
			info->last_write = X_H2LE64(x_timespec_to_nttime(statex.stat.st_mtim));
			info->change = X_H2LE64(x_timespec_to_nttime(statex.stat.st_ctim));
			info->end_of_file = X_H2LE64(statex.get_end_of_file());
			info->allocation_size = X_H2LE64(statex.get_allocation());
			info->file_attributes = X_H2LE32(statex.file_attributes);
			info->file_name_length = X_H2LE32(x_convert_assert<uint32_t>(name.size() * 2));
			if (statex.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
				info->ea_size = X_H2LE32(IO_REPARSE_TAG_DFS);
			} else {
				/*
				 * OS X specific SMB2 extension negotiated via
				 * AAPL create context: return max_access in
				 * ea_size field.
				 */
				info->ea_size = 0;
			}
		
			// TODO get short name
			info->short_name_length = 0;
			memset(info->short_name, 0, sizeof info->short_name);
			// TODO byte order
			memcpy(info->file_name, name.data(), name.size() * 2);
		}
		break;

	case SMB2_FIND_FULL_DIRECTORY_INFO:
		rec_size = x_convert_assert<uint32_t>(sizeof(x_smb2_file_full_dir_info_t) + name.size() * 2);
		pbegin = marshall.get_begin(rec_size);
		if (!pbegin) {
			return false;
		}
		{
			x_smb2_file_full_dir_info_t *info = (x_smb2_file_full_dir_info_t *)pbegin;
			info->next_offset = 0;
			info->file_index = 0;
			info->creation = X_H2LE64(x_timespec_to_nttime(statex.birth_time));
			info->last_access = X_H2LE64(x_timespec_to_nttime(statex.stat.st_atim));
			info->last_write = X_H2LE64(x_timespec_to_nttime(statex.stat.st_mtim));
			info->change = X_H2LE64(x_timespec_to_nttime(statex.stat.st_ctim));
			info->end_of_file = X_H2LE64(statex.get_end_of_file());
			info->allocation_size = X_H2LE64(statex.get_allocation());
			info->file_attributes = X_H2LE32(statex.file_attributes);
			info->file_name_length = X_H2LE32(x_convert_assert<uint32_t>(name.size() * 2));
			if (statex.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
				info->ea_size = X_H2LE32(IO_REPARSE_TAG_DFS);
			} else {
				/*
				 * OS X specific SMB2 extension negotiated via
				 * AAPL create context: return max_access in
				 * ea_size field.
				 */
				info->ea_size = 0;
			}
		
			// TODO byte order
			memcpy(info->file_name, name.data(), name.size() * 2);
		}
		break;

	case SMB2_FIND_NAME_INFO:
		rec_size = x_convert_assert<uint32_t>(sizeof(x_smb2_file_names_info_t) + name.size() * 2);
		pbegin = marshall.get_begin(rec_size);
		if (!pbegin) {
			return false;
		}
		{
			x_smb2_file_names_info_t *info = (x_smb2_file_names_info_t *)pbegin;
			info->next_offset = 0;
			info->file_index = 0;
			info->file_name_length = X_H2LE32(x_convert_assert<uint32_t>(name.size() * 2));
			memcpy(info->file_name, name.data(), name.size() * 2);
		}
		break;

	default:
		X_ASSERT(0);
	}
	return true;
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
	if (!posixfs_object_is_dir(posixfs_object)) {
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
	uint32_t num = 0, matched_count = 0;

	x_smb2_chain_marshall_t marshall{state->out_data.data(), state->out_data.data() + state->out_data.size(), 8};

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
		if (marshall_entry(marshall, statex, ent_name, state->in_info_level)) {
			++num;
		} else {
			qdir_unget(*qdir, qdir_pos);
			max_count = num;
		}
	}

	if (num > 0) {
		state->out_data.resize(marshall.get_size());
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
		std::lock_guard<std::mutex> lock(posixfs_object->base.mutex);
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
	if (!posixfs_object_is_dir(posixfs_object)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	posixfs_open_t *posixfs_open = posixfs_open_from_base_t::container(smbd_requ->smbd_open);
	std::lock_guard<std::mutex> lock(posixfs_object->base.mutex);

	/* notify filter cannot be overwritten */
	if (posixfs_open->base.notify_filter == 0) {
		posixfs_open->base.notify_filter = state->in_filter | X_FILE_NOTIFY_CHANGE_VALID;
		if (state->in_flags & SMB2_WATCH_TREE) {
			posixfs_open->base.notify_filter |= X_FILE_NOTIFY_CHANGE_WATCH_TREE;
			++smbd_object->topdir->watch_tree_cnt;
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
	posixfs_open_t *posixfs_open = posixfs_open_from_base_t::container(smbd_requ->smbd_open);
	bool modified = false;
	NTSTATUS status = posixfs_lease_break(smbd_lease, *state, modified);
	if (modified) {
		posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);

		std::unique_lock<std::mutex> lock(posixfs_object->base.mutex);
		share_mode_modified(posixfs_object, posixfs_open->stream);
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
		std::unique_lock<std::mutex> lock(posixfs_object->base.mutex);
		share_mode_modified(posixfs_object, posixfs_open->stream);
	}

	return NT_STATUS_OK;
}

NTSTATUS posixfs_object_op_set_delete_on_close(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		bool delete_on_close)
{
	posixfs_open_t *posixfs_open = posixfs_open_from_base_t::container(smbd_open);
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	std::lock_guard<std::mutex> lock(posixfs_object->base.mutex);
	return posixfs_object_set_delete_on_close(posixfs_object,
			posixfs_open->stream, delete_on_close);
}

void posixfs_object_op_destroy(x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open)
{
	posixfs_open_t *posixfs_open = posixfs_open_from_base_t::container(smbd_open);
#if 0
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	{
		std::unique_lock<std::mutex> lock(posixfs_object->base.mutex);
		posixfs_object_remove(posixfs_object, posixfs_open);
	}
#endif
	delete posixfs_open;
}

x_smbd_object_t *posixfs_open_object(NTSTATUS *pstatus,
		std::shared_ptr<x_smbd_topdir_t> &topdir,
		const std::u16string &path, uint64_t path_data,
		bool create_if)
{
	posixfs_object_t *posixfs_object = posixfs_object_open(
			topdir, path, path_data, create_if);
	if (posixfs_object) {
		return &posixfs_object->base;
	} else {
		return nullptr;
	}
}

void posixfs_op_release_object(x_smbd_object_t *smbd_object)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	posixfs_object_release(posixfs_object);
}

uint32_t posixfs_op_get_attributes(const x_smbd_object_t *smbd_object)
{
	const posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	return posixfs_object->statex.file_attributes;
}


posixfs_object_t::posixfs_object_t(
		uint64_t h,
		const std::shared_ptr<x_smbd_topdir_t> &topdir,
		const std::u16string &p, uint64_t path_data)
	: base(topdir, path_data, p), hash(h)
{
}

int x_smbd_posixfs_init(size_t max_open)
{
	size_t bucket_size = x_next_2_power(max_open);
	std::vector<posixfs_object_pool_t::bucket_t> buckets(bucket_size);
	posixfs_object_pool.buckets.swap(buckets);
	return 0;
}
#if 0
x_smbd_object_t *x_smbd_posixfs_object_open_parent(const x_smbd_object_t *child_object)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(child_object);
	posixfs_object_t *parent_object = posixfs_object_open_parent(posixfs_object);
	if (parent_object) {
		return &parent_object->base;
	}
	return nullptr;
}
#endif
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
	if (dir_obj->base.path.empty()) {
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
			0, 0,
			ntacl_blob);

	X_ASSERT(fd != -1);
	close(fd);
	return 0;
}

/* smbd_object's mutex is locked */
NTSTATUS x_smbd_posixfs_create_open(x_smbd_open_t **psmbd_open,
		x_smbd_object_t *smbd_object,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state,
		long priv_data,
		std::vector<x_smb2_change_t> &changes)
{
	NTSTATUS status;
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);

	posixfs_open_t *posixfs_open = posixfs_create_open(posixfs_object,
			status, smbd_requ, state, priv_data);
	if (!posixfs_open) {
		return status;
	}

	if (state->out_create_action == FILE_WAS_CREATED) {
		changes.push_back(x_smb2_change_t{NOTIFY_ACTION_ADDED, 
				uint16_t((state->in_create_options & FILE_DIRECTORY_FILE) ? FILE_NOTIFY_CHANGE_DIR_NAME : FILE_NOTIFY_CHANGE_FILE_NAME),
				posixfs_object->base.path,
				{}});
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

