
#include "smbd_open.hxx"
#include "smbd_stats.hxx"
#include "smbd_posixfs.hxx"
#include <fcntl.h>
#include <sys/statvfs.h>
#include "smbd_ntacl.hxx"
#include "smbd_lease.hxx"
#include "smbd_share.hxx"
#include "smbd_conf.hxx"
#include "util_io.hxx"
#include <dirent.h>
#include <sys/syscall.h>
#include <sys/xattr.h>

#define POSIXFS_ADS_PREFIX      "user.ads:"
#define POSIXFS_EA_PREFIX      "user.ea:"
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

/*
 * TODO, Disable automatic timestamp updates, as described in MS-FSA.
 * we do not support it for now
 */
#define NTTIME_FREEZE UINT64_MAX
#define NTTIME_THAW (UINT64_MAX - 1)
static bool is_null_ntime(idl::NTTIME nt)
{
	return nt.val == 0 || nt.val == NTTIME_FREEZE || nt.val == NTTIME_THAW;
}

static NTSTATUS posixfs_set_basic_info(int fd,
		uint32_t &notify_actions,
		const x_smb2_file_basic_info_t &basic_info,
		x_smbd_object_meta_t *object_meta)
{
	dos_attr_t dos_attr = { 0 };
	if (basic_info.file_attributes != 0) {
		if ((object_meta->file_attributes & FILE_ATTRIBUTE_DIRECTORY) !=
				(basic_info.file_attributes & FILE_ATTRIBUTE_DIRECTORY)) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		dos_attr.attr_mask |= DOS_SET_FILE_ATTR;
		dos_attr.file_attrs = basic_info.file_attributes;
		notify_actions |= FILE_NOTIFY_CHANGE_ATTRIBUTES;
	} else {
		dos_attr.file_attrs = object_meta->file_attributes;
	}

	if (!is_null_ntime(basic_info.creation)) {
		dos_attr.attr_mask |= DOS_SET_CREATE_TIME;
		dos_attr.create_time = x_nttime_to_timespec(basic_info.creation);
		notify_actions |= FILE_NOTIFY_CHANGE_CREATION;
	} else {
		dos_attr.create_time = x_nttime_to_timespec(object_meta->creation);
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
	
	x_smbd_stream_meta_t stream_meta;
	posixfs_statex_get(fd, object_meta, &stream_meta);
	return NT_STATUS_OK;
}

static int posixfs_open(int dirfd, const char *path,
		x_smbd_object_meta_t *object_meta,
		x_smbd_stream_meta_t *stream_meta)
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
	posixfs_statex_get(fd, object_meta, stream_meta);
	X_ASSERT(is_dir == object_meta->isdir());
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
			x_smbd_stream_t *stream)
		: base(so, stream, st, am, sa, priv_data)
	{
	}

	x_smbd_open_t base;
	x_dlink_t object_link;
	// posixfs_stream_t * const stream;
	qdir_t *qdir = nullptr;
	uint8_t oplock_level{X_SMB2_OPLOCK_LEVEL_NONE};
	oplock_break_sent_t oplock_break_sent{oplock_break_sent_t::OPLOCK_BREAK_NOT_SENT};
	/* open's on the same file sharing the same lease can have different parent key */
	x_smbd_lease_t *smbd_lease{};
	uint8_t lock_sequency_array[64];
	uint64_t current_offset = 0;
	uint32_t mode = 0; // [MS-FSCC] 2.4.26
	bool update_write_time = false;
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
	x_smbd_stream_t base;
	x_tp_ddlist_t<posixfs_open_object_traits> open_list;
	x_tp_ddlist_t<requ_async_traits> defer_open_list;
	std::atomic<int> ref_count{1};
	x_smbd_stream_meta_t meta;
};

struct posixfs_ads_t
{
	posixfs_ads_t(const std::u16string &name) : name(name) {
		X_SMBD_COUNTER_INC(ads_create, 1);
	}
	~posixfs_ads_t() {
		X_SMBD_COUNTER_INC(ads_delete, 1);
	}

	posixfs_stream_t base;
	x_dlink_t object_link; // link into object
	bool exists = false;
	bool initialized = false;
	std::u16string name;
	std::string xattr_name;
};
X_DECLARE_MEMBER_TRAITS(posixfs_ads_object_traits, posixfs_ads_t, object_link)

static inline posixfs_ads_t *posixfs_ads_from_smbd_stream(x_smbd_stream_t *smbd_stream)
{
	return X_CONTAINER_OF(smbd_stream, posixfs_ads_t, base.base);
}


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
#if 0
	std::atomic<uint32_t> lease_cnt{0};
	// std::atomic<uint32_t> notify_cnt{0};
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
	x_smbd_object_meta_t meta;
	/* protected by bucket mutex */
	// std::u16string req_path;
	std::string unix_path;
	/* protected by object mutex */
	posixfs_stream_t default_stream;
	x_tp_ddlist_t<posixfs_ads_object_traits> ads_list;
};
X_DECLARE_MEMBER_TRAITS(posixfs_object_from_base_t, posixfs_object_t, base)

static void do_break_lease(posixfs_open_t *posixfs_open,
		const x_smb2_lease_key_t *ignore_lease_key,
		uint8_t break_to);

static inline posixfs_stream_t *posixfs_get_stream(posixfs_object_t *posixfs_object,
		x_smbd_stream_t *smbd_stream)
{
	if (!smbd_stream) {
		return &posixfs_object->default_stream;
	} else {
		return X_CONTAINER_OF(smbd_stream, posixfs_stream_t, base);
	}
}

static inline const posixfs_stream_t *posixfs_get_stream(
		const posixfs_object_t *posixfs_object,
		const x_smbd_stream_t *smbd_stream)
{
	if (!smbd_stream) {
		return &posixfs_object->default_stream;
	} else {
		return X_CONTAINER_OF(smbd_stream, posixfs_stream_t, base);
	}
}

static inline posixfs_stream_t *posixfs_get_stream(posixfs_object_t *posixfs_object,
		posixfs_open_t *posixfs_open)
{
	return posixfs_get_stream(posixfs_object, posixfs_open->base.smbd_stream);
}

static inline const posixfs_stream_t *posixfs_get_stream(
		const posixfs_object_t *posixfs_object,
		const posixfs_open_t *posixfs_open)
{
	return posixfs_get_stream(posixfs_object, posixfs_open->base.smbd_stream);
}

static inline bool posixfs_is_default_stream(
		const x_smbd_stream_t *smbd_stream)
{
	return !smbd_stream;
}

static inline bool posixfs_is_default_stream(
		const posixfs_open_t *posixfs_open)
{
	return !posixfs_open->base.smbd_stream;
}
#if 0
static inline bool is_default_stream(const posixfs_object_t *object,
		const posixfs_stream_t *stream)
{
	return stream == &object->default_stream;
}
#endif

static const char *skip_prefix(const char *str, const char *prefix)
{
	for ( ; ; ++str, ++prefix) {
		if (!*prefix) {
			return str;
		}
		if (!*str || *str != *prefix) {
			return nullptr;
		}
	}
}

/* caller should hold posixfs_object's mutex */
template <class T>
static int posixfs_foreach_xattr(const posixfs_object_t *posixfs_object,
		const char *prefix, T &&visitor)
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
		const char *name = skip_prefix(data, prefix);
		if (name) {
			if (!visitor(data, name)) {
				break;
			}
		}
	}
	return 0;
}

template <class T>
static int posixfs_ads_foreach_1(const posixfs_object_t *posixfs_object, T &&visitor)
{
	return posixfs_foreach_xattr(posixfs_object, POSIXFS_ADS_PREFIX,
			std::forward<T>(visitor));
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

#define CHECK_LEASE(l, obj, strm) do { \
	if ((l) && !x_smbd_lease_match((l), (obj), (strm))) { \
		return NT_STATUS_INVALID_PARAMETER; \
	} \
} while (0)

#define CHECK_OBJECT_LEASE(l, pobj) \
	CHECK_LEASE((l), &(pobj)->base, &(pobj)->default_stream.base)

#define CHECK_STREAM_LEASE(l, pobj, pads) \
	CHECK_LEASE((l), &(pobj)->base, \
			(pads) ? &(pads)->base.base : &(pobj)->default_stream.base)


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
	if (posixfs_object->meta.isdir()) {
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

static inline void posixfs_object_incref(posixfs_object_t *posixfs_object)
{
	X_ASSERT(++posixfs_object->use_count > 1);
}

static inline void posixfs_object_decref(posixfs_object_t *posixfs_object)
{
	X_ASSERT(--posixfs_object->use_count > 0);
}

static inline void posixfs_stream_incref(posixfs_stream_t *posixfs_stream)
{
	X_ASSERT(++posixfs_stream->ref_count > 1);
}

static inline void posixfs_stream_decref(posixfs_stream_t *posixfs_stream)
{
	X_ASSERT(--posixfs_stream->ref_count > 0);
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
		posixfs_object_incref(matched_object);
	}
	/* move it to head of the bucket to make latest used elem */
	if (&matched_object->hash_link != bucket.head.get_front()) {
		matched_object->hash_link.remove();
		bucket.head.push_front(&matched_object->hash_link);
	}
	return matched_object;
}

static inline void posixfs_object_add_ads(posixfs_object_t *posixfs_object,
		posixfs_ads_t *posixfs_ads)
{
	posixfs_object->ads_list.push_front(posixfs_ads);
}

static inline void posixfs_object_remove_ads(posixfs_object_t *posixfs_object,
		posixfs_ads_t *posixfs_ads)
{
	posixfs_object->ads_list.remove(posixfs_ads);
}

static NTSTATUS posixfs_ads_set_eof(posixfs_object_t *posixfs_object,
		posixfs_ads_t *posixfs_ads, uint64_t new_size)
{
	std::vector<uint8_t> content(0x10000);
	ssize_t ret = fgetxattr(posixfs_object->fd, posixfs_ads->xattr_name.c_str(), content.data(), content.size());
	X_TODO_ASSERT(ret >= ssize_t(sizeof(posixfs_ads_header_t)));
	posixfs_ads_header_t *ads_hdr = (posixfs_ads_header_t *)content.data();
	uint32_t version = X_LE2H32(ads_hdr->version);
	uint32_t orig_alloc = X_LE2H32(ads_hdr->allocation_size);
	X_TODO_ASSERT(version == 0);

	content.resize(sizeof(posixfs_ads_header_t) + new_size);
	posixfs_ads->base.meta.end_of_file = new_size;
	if (new_size > orig_alloc) {
		ads_hdr->allocation_size = X_LE2H32(x_convert<uint32_t>(new_size));
		posixfs_ads->base.meta.allocation_size = new_size;
	}

	ret = fsetxattr(posixfs_object->fd, posixfs_ads->xattr_name.c_str(), content.data(), content.size(), 0);
	X_TODO_ASSERT(ret == 0);
	return NT_STATUS_OK;
}

static NTSTATUS posixfs_ads_set_alloc(posixfs_object_t *posixfs_object,
		posixfs_ads_t *posixfs_ads, uint64_t new_size)
{
	std::vector<uint8_t> content(0x10000);
	ssize_t ret = fgetxattr(posixfs_object->fd, posixfs_ads->xattr_name.c_str(), content.data(), content.size());
	X_TODO_ASSERT(ret >= ssize_t(sizeof(posixfs_ads_header_t)));
	posixfs_ads_header_t *ads_hdr = (posixfs_ads_header_t *)content.data();
	uint32_t version = X_LE2H32(ads_hdr->version);
	X_TODO_ASSERT(version == 0);
	uint64_t orig_size = ret - sizeof(posixfs_ads_header_t);

	ads_hdr->allocation_size = X_H2LE32(uint32_t(new_size));
	if (new_size < orig_size) {
		content.resize(sizeof(posixfs_ads_header_t) + new_size);
		posixfs_ads->base.meta.end_of_file = x_convert<uint32_t>(new_size);
	}

	posixfs_ads->base.meta.allocation_size = x_convert<uint32_t>(new_size);

	ret = fsetxattr(posixfs_object->fd, posixfs_ads->xattr_name.c_str(), content.data(), content.size(), 0);
	X_TODO_ASSERT(ret == 0);
	return NT_STATUS_OK;
}


/* samba vfs_set_filelen */
static NTSTATUS posixfs_set_end_of_file(
		posixfs_object_t *posixfs_object,
		posixfs_ads_t *posixfs_ads,
		uint64_t new_size)
{
	posixfs_stream_t *posixfs_stream = posixfs_ads ?
		&posixfs_ads->base : &posixfs_object->default_stream;

	if (posixfs_stream->meta.end_of_file == new_size) {
		return NT_STATUS_OK;
	}

	NTSTATUS status = NT_STATUS_OK;

	// TODO contend_level2_oplocks_begin(fsp, LEVEL2_CONTEND_SET_FILE_LEN);
	if (posixfs_ads) {
		status = posixfs_ads_set_eof(posixfs_object, posixfs_ads,
				new_size);
	} else {
		int err = ftruncate(posixfs_object->fd, new_size);
		X_TODO_ASSERT(err == 0);
	}
	// TODO contend_level2_oplocks_end(fsp, LEVEL2_CONTEND_SET_FILE_LEN);

	int err = posixfs_statex_get(posixfs_object->fd,
			&posixfs_object->meta,
			&posixfs_object->default_stream.meta);
	X_TODO_ASSERT(err == 0);
	if (!posixfs_ads) {
		posixfs_object->default_stream.meta.allocation_size =
			std::max(new_size, posixfs_object->default_stream.meta.allocation_size);
	}
	posixfs_object->statex_modified = false;

	return status;
}


/* samba vfs_allocate_file_space */
static NTSTATUS posixfs_set_allocation_size(
		posixfs_object_t *posixfs_object,
		posixfs_ads_t *posixfs_ads,
		uint64_t allocation_size)
{
	posixfs_stream_t *posixfs_stream = posixfs_ads ?
		&posixfs_ads->base : &posixfs_object->default_stream;

	if (!posixfs_ads) {
		/* only round up for base file */
		allocation_size = (allocation_size + 4095ul) & ~4095ul;
	}

	bool modified = false;
	NTSTATUS status = NT_STATUS_OK;
	if (posixfs_stream->meta.end_of_file == allocation_size) {
		return NT_STATUS_OK;

	} else if (posixfs_stream->meta.end_of_file <= allocation_size) {
		// TODO contend_level2_oplocks_begin(fsp, LEVEL2_CONTEND_ALLOC_GROW);
		/* we do not support set allocation size for base file */
		if (posixfs_ads) {
			 status = posixfs_ads_set_alloc(posixfs_object, posixfs_ads,
					 allocation_size);
		}
		posixfs_stream->meta.allocation_size = allocation_size;
		// TODO contend_level2_oplocks_end(fsp, LEVEL2_CONTEND_ALLOC_GROW);

	 } else {
		 // TODO contend_level2_oplocks_begin(fsp, LEVEL2_CONTEND_ALLOC_SHRINK);
		 if (posixfs_ads) {
			 status = posixfs_ads_set_alloc(posixfs_object, posixfs_ads,
					 allocation_size);
		 } else {
			 int err = ftruncate(posixfs_object->fd, allocation_size);
			 X_TODO_ASSERT(err == 0);
		 }
		 // TODO contend_level2_oplocks_end(fsp, LEVEL2_CONTEND_ALLOC_SHRINK);
		 modified = true;
	 }

	if (modified) {
		int err = posixfs_statex_get(posixfs_object->fd,
				&posixfs_object->meta,
				&posixfs_object->default_stream.meta);
		X_TODO_ASSERT(err == 0);
		if (!posixfs_ads) {
			posixfs_object->default_stream.meta.allocation_size =
				allocation_size;
		}
		posixfs_object->statex_modified = false;
	}

	return status;
}


static void posixfs_object_release(posixfs_object_t *posixfs_object)
{
	auto &pool = posixfs_object_pool;
	auto bucket_idx = posixfs_object->hash % pool.buckets.size();
	auto &bucket = pool.buckets[bucket_idx];
	bool free = false;

	{
		/* TODO optimize when use_count > 1 */
		std::unique_lock<std::mutex> lock(bucket.mutex);

		X_ASSERT(posixfs_object->use_count > 0);
		if (--posixfs_object->use_count == 0) {
			posixfs_object->unused_timestamp = tick_now;
			bucket.head.remove(&posixfs_object->hash_link);
			free = true;
		}
	}
	if (free) {
		delete posixfs_object;
	}
}

static void posixfs_lock_retry(posixfs_stream_t *posixfs_stream);

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
	return brl_conflict_other(posixfs_get_stream(posixfs_object, posixfs_open),
			posixfs_open, le);
}

static void posixfs_create_cancel(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	auto state = smbd_requ->get_state<x_smb2_state_create_t>();
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(state->smbd_object);
	posixfs_stream_t *posixfs_stream = posixfs_get_stream(posixfs_object,
			state->smbd_stream);

	{
		auto lock = std::lock_guard(posixfs_object->base.mutex);
		posixfs_stream->defer_open_list.remove(smbd_requ);
	}
	x_smbd_conn_post_cancel(smbd_conn, smbd_requ);
}

struct posixfs_defer_open_evt_t
{
	static void func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user, bool terminated)
	{
		posixfs_defer_open_evt_t *evt = X_CONTAINER_OF(fdevt_user,
				posixfs_defer_open_evt_t, base);
		x_smbd_requ_t *smbd_requ = evt->smbd_requ;
		X_LOG_DBG("evt=%p, requ=%p, terminated=%d", evt, smbd_requ, terminated);

		auto state = smbd_requ->release_state<x_smb2_state_create_t>();
		if (x_smbd_requ_async_remove(smbd_requ) && !terminated) {
			NTSTATUS status = x_smbd_tcon_op_create(smbd_requ, state);
			if (!NT_STATUS_EQUAL(status, NT_STATUS_PENDING)) {
				smbd_requ->save_state(state);
				smbd_requ->async_done_fn(smbd_conn, smbd_requ, status, false);
			}
		}

		delete evt;
	}

	explicit posixfs_defer_open_evt_t(x_smbd_requ_t *smbd_requ)
		: base(func), smbd_requ(smbd_requ)
	{
	}

	~posixfs_defer_open_evt_t()
	{
		x_smbd_ref_dec(smbd_requ);
	}

	x_fdevt_user_t base;
	x_smbd_requ_t * const smbd_requ;
};

static void share_mode_modified(posixfs_object_t *posixfs_object,
		x_smbd_stream_t *smbd_stream)
{
	posixfs_stream_t *posixfs_stream = posixfs_get_stream(posixfs_object, smbd_stream);
	/* posixfs_object is locked */
	while (x_smbd_requ_t *smbd_requ = posixfs_stream->defer_open_list.get_front()) {
		posixfs_stream->defer_open_list.remove(smbd_requ);
		posixfs_defer_open_evt_t *evt = new posixfs_defer_open_evt_t(smbd_requ);
		X_SMBD_CHAN_POST_USER(smbd_requ->smbd_chan, evt);
	}
}

struct posixfs_notify_evt_t
{
	static void func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user, bool terminated)
	{
		posixfs_notify_evt_t *evt = X_CONTAINER_OF(fdevt_user, posixfs_notify_evt_t, base);
		x_smbd_requ_t *smbd_requ = evt->smbd_requ;
		X_LOG_DBG("evt=%p, requ=%p, terminated=%d", evt, smbd_requ, terminated);

		auto state = smbd_requ->get_state<x_smb2_state_notify_t>();
		state->out_notify_changes = std::move(evt->notify_changes);
		x_smbd_requ_async_done(smbd_conn, smbd_requ, NT_STATUS_OK, terminated);
		delete evt;
	}

	posixfs_notify_evt_t(x_smbd_requ_t *requ,
			std::vector<std::pair<uint32_t, std::u16string>> &&changes)
		: base(func), smbd_requ(requ), notify_changes(changes)
	{
	}

	~posixfs_notify_evt_t()
	{
		x_smbd_ref_dec(smbd_requ);
	}

	x_fdevt_user_t base;
	x_smbd_requ_t * const smbd_requ;
	std::vector<std::pair<uint32_t, std::u16string>> notify_changes;
};

void posixfs_object_notify_change(x_smbd_object_t *smbd_object,
		uint32_t notify_action,
		uint32_t notify_filter,
		const std::u16string &fullpath,
		const std::u16string *new_name_path,
		const x_smb2_lease_key_t &ignore_lease_key,
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
		if (last_level && curr_open->smbd_lease) {
			do_break_lease(curr_open, &ignore_lease_key, 0);
		}

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

		X_SMBD_CHAN_POST_USER(smbd_requ->smbd_chan, 
				new posixfs_notify_evt_t(smbd_requ,
					std::move(notify_changes)));
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

static NTSTATUS rename_ads_intl(posixfs_object_t *posixfs_object,
		posixfs_ads_t *posixfs_ads,
                bool replace_if_exists,
                const std::u16string &new_stream_name)
{
	std::lock_guard<std::mutex> lock(posixfs_object->base.mutex);
	posixfs_ads_t *other_ads;
	for (other_ads = posixfs_object->ads_list.get_front(); other_ads;
			other_ads = posixfs_object->ads_list.next(other_ads)) {
		if (other_ads == posixfs_ads) {
			continue;
		}
		if (other_ads->name == new_stream_name) { // TODO case insensitive
			/* windows server behavior */
			return replace_if_exists ? NT_STATUS_INVALID_PARAMETER :
				NT_STATUS_OBJECT_NAME_COLLISION;
		}
	}

	bool collision = false;
	std::string new_name_utf8 = x_convert_utf16_to_utf8(new_stream_name);
	posixfs_ads_foreach_1(posixfs_object, [=, &collision] (const char *xattr_name,
				const char *stream_name) {
			if (strcasecmp(stream_name, new_name_utf8.c_str()) == 0) {
				if (replace_if_exists) {
					fremovexattr(posixfs_object->fd, xattr_name);
				} else {
					collision = true;
				}
				return false;
			}
			return true;
		});

	if (collision) {
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	std::vector<uint8_t> data(64 * 1024);
	ssize_t ret = fgetxattr(posixfs_object->fd, posixfs_ads->xattr_name.c_str(),
			data.data(), data.size());
	X_TODO_ASSERT(ret >= 0);

	std::string new_xattr_name = POSIXFS_ADS_PREFIX + new_name_utf8;
	fsetxattr(posixfs_object->fd, new_xattr_name.c_str(), data.data(), ret, 0);
	posixfs_ads->name = new_stream_name;
	posixfs_ads->xattr_name = new_xattr_name;

	/* notify_fname */
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
	posixfs_open_t *posixfs_open = posixfs_open_from_base_t::container(smbd_requ->smbd_open);
	if (!posixfs_is_default_stream(posixfs_open)) {
		if (new_path.size()) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		posixfs_ads_t *posixfs_ads = posixfs_ads_from_smbd_stream(posixfs_open->base.smbd_stream);

		if (posixfs_ads->name == new_stream_name) { // TODO case insensitive
			return NT_STATUS_OK;
		}
		return rename_ads_intl(posixfs_object, posixfs_ads,
				replace_if_exists, new_stream_name);
	}

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
				posixfs_open->base.parent_lease_key,
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
				&posixfs_object->meta,
				&posixfs_object->default_stream.meta);
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

struct posixfs_send_lease_break_evt_t
{
	static void func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user, bool terminated)
	{
		posixfs_send_lease_break_evt_t *evt = X_CONTAINER_OF(fdevt_user,
				posixfs_send_lease_break_evt_t, base);
		X_LOG_DBG("evt=%p", evt);

		if (!terminated) {
			x_smb2_send_lease_break(smbd_conn,
					evt->smbd_sess,
					&evt->lease_key,
					evt->curr_state,
					evt->new_state,
					evt->new_epoch,
					evt->flags);
		}
		delete evt;
	}

	posixfs_send_lease_break_evt_t(x_smbd_sess_t *smbd_sess,
			const x_smb2_lease_key_t &lease_key,
			uint8_t curr_state,
			uint8_t new_state,
			uint16_t new_epoch,
			uint32_t flags)
		: base(func), smbd_sess(smbd_sess)
		, lease_key(lease_key)
		, curr_state(curr_state)
		, new_state(new_state)
		, new_epoch(new_epoch)
		, flags(flags)
	{
	}

	~posixfs_send_lease_break_evt_t()
	{
		x_smbd_ref_dec(smbd_sess);
	}

	x_fdevt_user_t base;
	x_smbd_sess_t * const smbd_sess;
	const x_smb2_lease_key_t lease_key;
	const uint8_t curr_state, new_state;
	const uint16_t new_epoch;
	const uint32_t flags;
};

static void do_break_lease(posixfs_open_t *posixfs_open,
		const x_smb2_lease_key_t *ignore_lease_key,
		uint8_t break_to)
{
	x_smb2_lease_key_t lease_key;
	uint8_t curr_state;
	uint16_t new_epoch;
	uint32_t flags;

	bool send_break = x_smbd_lease_require_break(posixfs_open->smbd_lease,
			ignore_lease_key,
			lease_key, break_to, curr_state,
			new_epoch, flags);
	if (!send_break) {
		return;
	}

	x_smbd_sess_t *smbd_sess = x_smbd_tcon_get_sess(posixfs_open->base.smbd_tcon);
	X_SMBD_SESS_POST_USER(smbd_sess, new posixfs_send_lease_break_evt_t(
				smbd_sess, lease_key, curr_state, break_to,
				new_epoch, flags));
	/* if posted fails, the connection is in shutdown,
	 * and it eventually close the open and wakeup the
	 * defer opens
	 */
}

struct posixfs_send_oplock_break_evt_t
{
	static void func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user, bool terminated)
	{
		posixfs_send_oplock_break_evt_t *evt = X_CONTAINER_OF(fdevt_user,
				posixfs_send_oplock_break_evt_t, base);
		X_LOG_DBG("evt=%p", evt);

		if (!terminated) {
			x_smb2_send_oplock_break(smbd_conn,
					evt->smbd_sess,
					evt->open_persistent_id,
					evt->open_volatile_id,
					evt->oplock_level);
		}
		delete evt;
	}

	posixfs_send_oplock_break_evt_t(x_smbd_sess_t *smbd_sess,
			uint64_t open_persistent_id,
			uint64_t open_volatile_id,
			uint8_t oplock_level)
		: base(func), smbd_sess(smbd_sess)
		, open_persistent_id(open_persistent_id)
		, open_volatile_id(open_volatile_id)
		, oplock_level(oplock_level)
	{
	}

	~posixfs_send_oplock_break_evt_t()
	{
		x_smbd_ref_dec(smbd_sess);
	}

	x_fdevt_user_t base;
	x_smbd_sess_t * const smbd_sess;
	uint64_t const open_persistent_id, open_volatile_id;
	uint8_t const oplock_level;
};

static void do_break_oplock(posixfs_open_t *posixfs_open,
		uint8_t break_to)
{
	/* TODO timer */
	/* already hold posixfs_object mutex */
	auto [ persistent_id, volatile_id ] = x_smbd_open_get_id(&posixfs_open->base); 
	x_smbd_sess_t *smbd_sess = x_smbd_tcon_get_sess(posixfs_open->base.smbd_tcon);
	X_SMBD_SESS_POST_USER(smbd_sess, new posixfs_send_oplock_break_evt_t(
				smbd_sess, persistent_id, volatile_id,
				break_to == X_SMB2_LEASE_READ ? X_SMB2_OPLOCK_LEVEL_II :
					X_SMB2_OPLOCK_LEVEL_NONE));
	/* if posted fails, the connection is in shutdown,
	 * and it eventually close the open and wakeup the
	 * defer opens
	 */
}

/* caller locked posixfs_object */
static bool delay_for_oplock(posixfs_object_t *posixfs_object,
		posixfs_stream_t *posixfs_stream,
		x_smbd_lease_t *smbd_lease,
		uint32_t create_disposition,
		uint32_t desired_access,
		bool have_sharing_violation,
		bool first_open_attempt)
{
	if (is_stat_open(desired_access)) {
		return false;
	}

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
			if (smbd_lease && curr_open->smbd_lease == smbd_lease) {
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
			if (curr_open->smbd_lease && x_smbd_lease_is_breaking(curr_open->smbd_lease)) {
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
		if (curr_open->smbd_lease) {
			do_break_lease(curr_open, nullptr, break_to);
		} else {
			do_break_oplock(curr_open, break_to);
		}
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
		x_smb2_state_create_t &state)
{
	uint8_t granted = X_SMB2_LEASE_NONE;
	uint8_t oplock_level = state.in_oplock_level;
	x_smb2_lease_t *lease = nullptr;
	if (oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE) {
		lease = &state.lease;
	}

	if (posixfs_object->base.type == x_smbd_object_t::type_dir &&
			posixfs_stream == &posixfs_object->default_stream) {
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
		if (!(state.smbd_lease && curr_open->smbd_lease == state.smbd_lease)) {
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
		state.out_oplock_level = X_SMB2_OPLOCK_LEVEL_LEASE;
		bool new_lease = false;
		if (!x_smbd_lease_grant(state.smbd_lease,
					state.lease,
					granted,
					&posixfs_object->base,
					(x_smbd_stream_t *)posixfs_stream,
					new_lease)) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		if (new_lease) {
			/* it hold the ref of object, so it is ok the incref after lease
			 * TODO eventually it should incref inside x_smbd_lease_grant
			 */
			posixfs_object_incref(posixfs_object);
			posixfs_stream_incref(posixfs_stream);
		}
	} else {
		if (got_handle_lease) {
			granted = X_SMB2_LEASE_NONE;
		}
		switch (granted) {
		case X_SMB2_LEASE_READ|X_SMB2_LEASE_WRITE|X_SMB2_LEASE_HANDLE:
			state.out_oplock_level = X_SMB2_OPLOCK_LEVEL_BATCH;
			break;
		case X_SMB2_LEASE_READ|X_SMB2_LEASE_WRITE:
			state.out_oplock_level = X_SMB2_OPLOCK_LEVEL_EXCLUSIVE;
			break;
		case X_SMB2_LEASE_READ|X_SMB2_LEASE_HANDLE:
		case X_SMB2_LEASE_READ:
			state.out_oplock_level = X_SMB2_OPLOCK_LEVEL_II;
			break;
		default:
			state.out_oplock_level = X_SMB2_OPLOCK_LEVEL_NONE;
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
		if (posixfs_object->meta.file_attributes & FILE_ATTRIBUTE_READONLY) {
			return NT_STATUS_CANNOT_DELETE;
		}
		posixfs_stream->meta.delete_on_close = true;
	} else {
		posixfs_stream->meta.delete_on_close = false;
	}
	return NT_STATUS_OK;
}

static posixfs_open_t *posixfs_open_create(
		NTSTATUS *pstatus,
		x_smbd_tcon_t *smbd_tcon,
		posixfs_object_t *posixfs_object,
		posixfs_stream_t *posixfs_stream,
		const x_smb2_state_create_t &state)
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
			smbd_tcon, state.granted_access, state.in_share_access,
			state.open_priv_data,
			posixfs_stream == &posixfs_object->default_stream ? nullptr :
				&posixfs_stream->base);
	posixfs_open->oplock_level = state.out_oplock_level;
	/* not need incref because it already do in lease_grant */
	posixfs_open->smbd_lease = state.smbd_lease;
	posixfs_open->base.parent_lease_key = state.lease.parent_key;

	if (!x_smbd_open_store(&posixfs_open->base)) {
		if (posixfs_open->smbd_lease) {
			x_smbd_lease_close(posixfs_open->smbd_lease);
			posixfs_open->smbd_lease = nullptr;
		}
		delete posixfs_open;
		*pstatus = NT_STATUS_INSUFFICIENT_RESOURCES;
		return nullptr;
	}

	posixfs_stream_incref(posixfs_stream);
	posixfs_object_incref(posixfs_object);
	posixfs_stream->open_list.push_back(posixfs_open);
	*pstatus = NT_STATUS_OK;
	return posixfs_open;
}

static void fill_out_info(x_smb2_create_close_info_t &info,
		const x_smbd_object_meta_t &object_meta,
		const x_smbd_stream_meta_t &stream_meta)
{
	info.out_create_ts = object_meta.creation;
	info.out_last_access_ts = object_meta.last_access;
	info.out_last_write_ts = object_meta.last_write;
	info.out_change_ts = object_meta.change;
	info.out_file_attributes = object_meta.file_attributes;
	info.out_allocation_size = stream_meta.allocation_size;
	info.out_end_of_file = stream_meta.end_of_file;
}

static void reply_requ_create(x_smb2_state_create_t &state,
		const posixfs_object_t *posixfs_object,
		const posixfs_stream_t *posixfs_stream,
		uint32_t create_action)
{
	state.out_create_flags = 0;
	state.out_create_action = create_action;
	fill_out_info(state.out_info, posixfs_object->meta,
			posixfs_stream->meta);
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
		uint32_t file_attributes,
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
		/* From samba create_file_unixpath
		 * According to the MS documentation, the only time the security
		 * descriptor is applied to the opened file is iff we *created* the
		 * file; an existing file stays the same.
		 *
		 * Also, it seems (from observation) that you can open the file with
		 * any access mask but you can still write the sd. We need to override
		 * the granted access before we call set_sd
		 * Patch for bug #2242 from Tom Lackemann <cessnatomny@yahoo.com>.
		 */
		status = normalize_sec_desc(*state.in_security_descriptor,
				*smbd_user,
				FILE_GENERIC_ALL,
				state.in_create_options & FILE_DIRECTORY_FILE);
		psd = state.in_security_descriptor;
	} else {
		status = make_child_sec_desc(psd, parent_psd,
				*smbd_user,
				state.in_create_options & FILE_DIRECTORY_FILE);
	}
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	std::vector<uint8_t> ntacl_blob;
	if (psd) {
		create_acl_blob(ntacl_blob, psd, idl::XATTR_SD_HASH_TYPE_NONE, std::array<uint8_t, idl::XATTR_SD_HASH_SIZE>());
	}

	/* if parent is not enable inherit, make_sec_desc */
	int fd = posixfs_create(posixfs_object->base.topdir->fd,
			state.in_create_options & FILE_DIRECTORY_FILE,
			posixfs_object->unix_path.c_str(),
			&posixfs_object->meta,
			&posixfs_object->default_stream.meta,
			file_attributes,
			allocation_size,
			ntacl_blob);

	if (fd < 0) {
		X_ASSERT(-fd == EEXIST);
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	posixfs_object->default_stream.meta.delete_on_close = false;
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

static bool check_ads_share_access(posixfs_object_t *posixfs_object,
		uint32_t granted)
{
	posixfs_ads_t *posixfs_ads;
	for (posixfs_ads = posixfs_object->ads_list.get_front();
			posixfs_ads;
			posixfs_ads = posixfs_object->ads_list.next(posixfs_ads)) {
		posixfs_open_t *other_open;
		for (other_open = posixfs_ads->base.open_list.get_front();
				other_open;
				other_open = posixfs_ads->base.open_list.next(other_open)) {
			if (!(other_open->base.share_access & FILE_SHARE_DELETE)) {
				X_LOG_NOTICE("ads %s share-access %d violate access 0x%x",
						posixfs_ads->xattr_name.c_str(),
						other_open->base.share_access,
						posixfs_object->unix_path.c_str(),
						granted);

				return false;
			}
		}
	}
	return true;
}

static void defer_open(
		posixfs_object_t *posixfs_object,
		posixfs_stream_t *posixfs_stream,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state)
{
	if (!state->smbd_stream) {
		posixfs_stream_incref(posixfs_stream);
		state->smbd_stream = &posixfs_stream->base;
	} else {
		X_ASSERT(state->smbd_stream == &posixfs_stream->base);
	}

	smbd_requ->save_state(state);
	/* TODO does it need a timer? can break timer always wake up it? */
	x_smbd_ref_inc(smbd_requ);
	posixfs_stream->defer_open_list.push_back(smbd_requ);
	x_smbd_requ_async_insert(smbd_requ, posixfs_create_cancel);
}

static NTSTATUS posixfs_create_open_exist_object(
		posixfs_open_t *&posixfs_open,
		posixfs_object_t *posixfs_object,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state,
		bool overwrite)
{
	CHECK_OBJECT_LEASE(state->smbd_lease, posixfs_object);

	if (posixfs_object->default_stream.meta.delete_on_close) {
		return NT_STATUS_DELETE_PENDING;
	}

	if (posixfs_object->base.type == x_smbd_object_t::type_dir) {
		if (state->in_create_options & FILE_NON_DIRECTORY_FILE) {
			return NT_STATUS_FILE_IS_A_DIRECTORY;
		}
	} else {
		if (state->in_create_options & FILE_DIRECTORY_FILE) {
			return NT_STATUS_NOT_A_DIRECTORY;
		}
	}

	if ((posixfs_object->meta.file_attributes & FILE_ATTRIBUTE_READONLY) &&
			(state->in_desired_access & (idl::SEC_FILE_WRITE_DATA | idl::SEC_FILE_APPEND_DATA))) {
		X_LOG_NOTICE("deny access 0x%x to %s due to readonly 0x%x",
				state->in_desired_access, posixfs_object->unix_path.c_str(),
				posixfs_object->meta.file_attributes);
		return NT_STATUS_ACCESS_DENIED;
	}

	if (posixfs_object->meta.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
		X_LOG_DBG("object %s is reparse_point", posixfs_object->unix_path.c_str());
		return NT_STATUS_PATH_NOT_COVERED;
	}

	std::shared_ptr<idl::security_descriptor> psd;
	NTSTATUS status = posixfs_object_get_sd__(posixfs_object, psd);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	auto smbd_user = x_smbd_sess_get_user(smbd_requ->smbd_sess);
	uint32_t share_access = x_smbd_tcon_get_share_access(smbd_requ->smbd_tcon);
	state->out_maximal_access = se_calculate_maximal_access(*psd, *smbd_user);
	state->out_maximal_access &= share_access;
	uint32_t desired_access = state->in_desired_access & ~idl::SEC_FLAG_MAXIMUM_ALLOWED;

	uint32_t granted = state->out_maximal_access;
	if (state->in_desired_access & idl::SEC_FLAG_MAXIMUM_ALLOWED) {
		if (posixfs_object->meta.file_attributes & FILE_ATTRIBUTE_READONLY) {
			granted &= ~(idl::SEC_FILE_WRITE_DATA | idl::SEC_FILE_APPEND_DATA);
		}
	} else {
		granted = (desired_access & state->out_maximal_access);
	}

	uint32_t rejected_mask = desired_access & ~granted;
	if (rejected_mask == idl::SEC_STD_DELETE) {
	       	if (!can_delete_file_in_directory(posixfs_object,
					smbd_requ->smbd_tcon, *smbd_user)) {
			return NT_STATUS_ACCESS_DENIED;
		}
	} else if (rejected_mask != 0) {
		return NT_STATUS_ACCESS_DENIED;
	}

	if (granted & idl::SEC_STD_DELETE) {
		if (!check_ads_share_access(posixfs_object, granted)) {
			return NT_STATUS_SHARING_VIOLATION;
		}
	}

	state->granted_access = granted;

	bool conflict = open_mode_check(posixfs_object,
			&posixfs_object->default_stream,
			state->in_desired_access, state->in_share_access);
	if (delay_for_oplock(posixfs_object,
				&posixfs_object->default_stream,
				state->smbd_lease,
				state->in_create_disposition,
				state->in_desired_access,
				conflict, true)) {
		defer_open(posixfs_object, &posixfs_object->default_stream,
				smbd_requ, state);
		return NT_STATUS_PENDING;
	}

	if (conflict) {
		return NT_STATUS_SHARING_VIOLATION;
	}

       	status = grant_oplock(posixfs_object,
			&posixfs_object->default_stream,
			*state);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	bool reload_meta = false;
	if (overwrite) {
		// TODO DELETE_ALL_STREAM;
		/* TODO set AlSi */
		int err = ftruncate(posixfs_object->fd, 0);
		X_TODO_ASSERT(err == 0);
		reload_meta = true;
	} else if ((state->contexts & X_SMB2_CONTEXT_FLAG_ALSI)) {
		status = posixfs_set_allocation_size(posixfs_object, nullptr,
			state->in_allocation_size);
		X_TODO_ASSERT(NT_STATUS_IS_OK(status));
	}

	if (reload_meta) {
		int err = posixfs_statex_get(posixfs_object->fd,
				&posixfs_object->meta,
				&posixfs_object->default_stream.meta);
		X_TODO_ASSERT(err == 0);
		posixfs_object->statex_modified = false;
	}

	reply_requ_create(*state, posixfs_object, &posixfs_object->default_stream,
			FILE_WAS_OPENED);
	posixfs_open = posixfs_open_create(&status, smbd_requ->smbd_tcon, posixfs_object,
			&posixfs_object->default_stream,
			*state);
	return status;
}

static NTSTATUS posixfs_create_open_new_object(
		posixfs_open_t *&posixfs_open,
		posixfs_object_t *posixfs_object,
		x_smbd_requ_t *smbd_requ,
		x_smb2_state_create_t &state)
{
	std::shared_ptr<idl::security_descriptor> psd;
	NTSTATUS status = posixfs_new_object(posixfs_object, smbd_requ,
			state, state.in_file_attributes, state.in_allocation_size, psd);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	auto smbd_user = x_smbd_sess_get_user(smbd_requ->smbd_sess);
	state.out_maximal_access = se_calculate_maximal_access(*psd, *smbd_user);
	/* Windows server seem not do access check for create new object */
	if (state.in_desired_access & idl::SEC_FLAG_MAXIMUM_ALLOWED) {
		state.granted_access = state.out_maximal_access;
	} else {
		state.granted_access = state.out_maximal_access & state.in_desired_access;
	}

       	status = grant_oplock(posixfs_object, &posixfs_object->default_stream,
			state);
	X_ASSERT(NT_STATUS_IS_OK(status));
	reply_requ_create(state, posixfs_object, &posixfs_object->default_stream,
			FILE_WAS_CREATED);
	posixfs_open = posixfs_open_create(&status, smbd_requ->smbd_tcon, posixfs_object,
			&posixfs_object->default_stream, state);
	return status;
}

static posixfs_ads_t *posixfs_ads_add(
		posixfs_object_t *posixfs_object,
		const std::u16string &name)
{
	posixfs_ads_t *posixfs_ads = new posixfs_ads_t(name);
	posixfs_object_add_ads(posixfs_object, posixfs_ads);
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
	if (ads) {
		posixfs_object_add_ads(posixfs_object, ads);
	}
	return ads;
}

static void posixfs_ads_release(posixfs_object_t *posixfs_object,
		posixfs_ads_t *ads)
{
	if (--ads->base.ref_count == 0) {
		posixfs_object_remove_ads(posixfs_object, ads);
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
	posixfs_ads->base.meta.allocation_size = allocation_size;
	posixfs_ads->base.meta.end_of_file = 0;
	X_TODO_ASSERT(ret >= 0);
}

static NTSTATUS open_object_new_ads(
		posixfs_open_t *&posixfs_open,
		posixfs_object_t *posixfs_object,
		posixfs_ads_t *posixfs_ads,
		x_smbd_requ_t *smbd_requ,
		x_smb2_state_create_t &state)
{
	X_ASSERT(!posixfs_ads->exists);

	if (posixfs_object->default_stream.meta.delete_on_close) {
		return NT_STATUS_DELETE_PENDING;
	}

	// TODO should it fail for large in_allocation_size?
	uint32_t allocation_size = x_convert_assert<uint32_t>(
			std::min(state.in_allocation_size, posixfs_ads_max_length));
	posixfs_ads->xattr_name = posixfs_get_ads_xattr_name(x_convert_utf16_to_utf8(
				posixfs_ads->name));
	posixfs_ads_reset(posixfs_object, posixfs_ads, allocation_size);

	std::shared_ptr<idl::security_descriptor> psd;
	NTSTATUS status = posixfs_object_get_sd__(posixfs_object, psd);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	auto smbd_user = x_smbd_sess_get_user(smbd_requ->smbd_sess);
	state.out_maximal_access = se_calculate_maximal_access(*psd, *smbd_user);
	/* Windows server seem not do access check for create new object */
	if (state.in_desired_access & idl::SEC_FLAG_MAXIMUM_ALLOWED) {
		state.granted_access = state.out_maximal_access;
	} else {
		state.granted_access = state.out_maximal_access & state.in_desired_access;
	}

       	status = grant_oplock(posixfs_object, &posixfs_ads->base,
			state);
	X_ASSERT(NT_STATUS_IS_OK(status));
	reply_requ_create(state, posixfs_object, &posixfs_ads->base, FILE_WAS_CREATED);
	posixfs_open = posixfs_open_create(&status, smbd_requ->smbd_tcon,
			posixfs_object, &posixfs_ads->base,
			state);
	return status;
}

static NTSTATUS open_object_exist_ads(
		posixfs_open_t *&posixfs_open,
		posixfs_object_t *posixfs_object,
		posixfs_ads_t *posixfs_ads,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state,
		bool overwrite)
{
	X_ASSERT(posixfs_ads->exists);

	if (posixfs_object->default_stream.meta.delete_on_close ||
			posixfs_ads->base.meta.delete_on_close) {
		return NT_STATUS_DELETE_PENDING;
	}

	if (!posixfs_ads->initialized) {
		std::vector<uint8_t> data(64 * 1024);
		ssize_t err = fgetxattr(posixfs_object->fd, posixfs_ads->xattr_name.c_str(),
				data.data(), data.size());
		X_TODO_ASSERT(err >= ssize_t(sizeof(posixfs_ads_header_t)));
		const posixfs_ads_header_t *header = (const posixfs_ads_header_t *)data.data();
		posixfs_ads->base.meta.end_of_file = x_convert_assert<uint32_t>(err - (sizeof(posixfs_ads_header_t)));
		posixfs_ads->base.meta.allocation_size = X_LE2H32(header->allocation_size);
		posixfs_ads->initialized = true;
	}

	if ((posixfs_object->meta.file_attributes & FILE_ATTRIBUTE_READONLY) &&
			(state->in_desired_access & (idl::SEC_FILE_WRITE_DATA | idl::SEC_FILE_APPEND_DATA))) {
		X_LOG_NOTICE("deny access 0x%x to %s due to readonly 0x%x",
				state->in_desired_access, posixfs_object->unix_path.c_str(),
				posixfs_object->meta.file_attributes);
		return NT_STATUS_ACCESS_DENIED;
	}

	/* is this check needed? */
	if (posixfs_object->meta.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
		X_LOG_DBG("object %s is reparse_point", posixfs_object->unix_path.c_str());
		return NT_STATUS_PATH_NOT_COVERED;
	}

	std::shared_ptr<idl::security_descriptor> psd;
	NTSTATUS status = posixfs_object_get_sd__(posixfs_object, psd);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	auto smbd_user = x_smbd_sess_get_user(smbd_requ->smbd_sess);
	uint32_t share_access = x_smbd_tcon_get_share_access(smbd_requ->smbd_tcon);
	state->out_maximal_access = se_calculate_maximal_access(*psd, *smbd_user);
	state->out_maximal_access &= share_access;
	uint32_t desired_access = state->in_desired_access & ~idl::SEC_FLAG_MAXIMUM_ALLOWED;

	uint32_t granted = state->out_maximal_access;
	if (state->in_desired_access & idl::SEC_FLAG_MAXIMUM_ALLOWED) {
		if (posixfs_object->meta.file_attributes & FILE_ATTRIBUTE_READONLY) {
			granted &= ~(idl::SEC_FILE_WRITE_DATA | idl::SEC_FILE_APPEND_DATA);
		}
	} else {
		granted = (desired_access & state->out_maximal_access);
	}

	uint32_t rejected_mask = desired_access & ~granted;
	if (rejected_mask != 0) {
		return NT_STATUS_ACCESS_DENIED;
	}

	state->granted_access = granted;

	bool conflict = open_mode_check(posixfs_object,
			&posixfs_ads->base,
			state->in_desired_access, state->in_share_access);
	if (delay_for_oplock(posixfs_object,
				&posixfs_ads->base,
				state->smbd_lease,
				state->in_create_disposition,
				state->in_desired_access,
				conflict, true)) {
		defer_open(posixfs_object, &posixfs_ads->base,
				smbd_requ, state);
		return NT_STATUS_PENDING;
	}

	if (conflict) {
		return NT_STATUS_SHARING_VIOLATION;
	}

       	status = grant_oplock(posixfs_object,
			&posixfs_ads->base, *state);
	X_ASSERT(NT_STATUS_IS_OK(status));

	bool reload_meta = false;
	if (overwrite) {
		uint32_t allocation_size = x_convert_assert<uint32_t>(
				std::min(state->in_allocation_size, posixfs_ads_max_length));
		posixfs_ads_reset(posixfs_object, posixfs_ads,
				allocation_size);
	} else if ((state->contexts & X_SMB2_CONTEXT_FLAG_ALSI)) {
		posixfs_set_allocation_size(posixfs_object,
				posixfs_ads,
				state->in_allocation_size);
	}

	if (reload_meta) {
		int err = posixfs_statex_get(posixfs_object->fd,
				&posixfs_object->meta,
				&posixfs_object->default_stream.meta);
		X_TODO_ASSERT(err == 0);
		posixfs_object->statex_modified = false;
	}

	reply_requ_create(*state, posixfs_object, &posixfs_ads->base,
			FILE_WAS_OPENED);
	posixfs_open = posixfs_open_create(&status, smbd_requ->smbd_tcon,
			posixfs_object, &posixfs_ads->base,
			*state);
	return status;
}

static NTSTATUS posixfs_create_open_overwrite_ads(
		posixfs_open_t *&posixfs_open,
		posixfs_object_t *posixfs_object,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state)
{
	posixfs_ads_t *posixfs_ads = posixfs_ads_open(
			posixfs_object,
			state->in_ads_name,
			true);
	CHECK_STREAM_LEASE(state->smbd_lease, posixfs_object, posixfs_ads);

	if (!posixfs_ads) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	NTSTATUS status = open_object_exist_ads(
			posixfs_open,
			posixfs_object,
			posixfs_ads,
			smbd_requ,
			state,
			true);
	posixfs_ads_release(posixfs_object, posixfs_ads);
	return status;
}

static NTSTATUS posixfs_create_open_overwrite_ads_if(
		posixfs_open_t *&posixfs_open,
		posixfs_object_t *posixfs_object,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state)
{
	posixfs_ads_t *posixfs_ads = posixfs_ads_open(
			posixfs_object,
			state->in_ads_name,
			false);
	CHECK_STREAM_LEASE(state->smbd_lease, posixfs_object, posixfs_ads);

	NTSTATUS status = NT_STATUS_OK;
	if (posixfs_ads && posixfs_ads->exists) {
		/* TODO it is not right reset before open it */
		status = open_object_exist_ads(
				posixfs_open,
				posixfs_object,
				posixfs_ads,
				smbd_requ,
				state,
				true);
	} else {
		if (!posixfs_ads) {
			posixfs_ads = posixfs_ads_add(posixfs_object, state->in_ads_name);
		}
		status = open_object_new_ads(
				posixfs_open,
				posixfs_object,
				posixfs_ads,
				smbd_requ,
				*state);
	}
	posixfs_ads_release(posixfs_object, posixfs_ads);
	return status;
}


static NTSTATUS posix_create_open_exist_ads(
		posixfs_open_t *&posixfs_open,
		posixfs_object_t *posixfs_object,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state)
{
	posixfs_ads_t *posixfs_ads = posixfs_ads_open(
			posixfs_object,
			state->in_ads_name,
			true);

	CHECK_STREAM_LEASE(state->smbd_lease, posixfs_object, posixfs_ads);

	if (!posixfs_ads) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	NTSTATUS status = open_object_exist_ads(
			posixfs_open,
			posixfs_object,
			posixfs_ads,
			smbd_requ,
			state,
			false);
	posixfs_ads_release(posixfs_object, posixfs_ads);
	return status;
}

static NTSTATUS posixfs_create_open_new_ads(
		posixfs_open_t *&posixfs_open,
		posixfs_object_t *posixfs_object,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state)
{
	posixfs_ads_t *posixfs_ads = posixfs_ads_open(
			posixfs_object,
			state->in_ads_name,
			false);

	if (!posixfs_ads) {
		posixfs_ads = posixfs_ads_add(posixfs_object,
				state->in_ads_name);
	}
	NTSTATUS status = NT_STATUS_OK;
	if (posixfs_ads->exists) {
		status = NT_STATUS_OBJECT_NAME_COLLISION;
	} else {
		status = open_object_new_ads(
				posixfs_open,
				posixfs_object,
				posixfs_ads,
				smbd_requ,
				*state);
	}
	posixfs_ads_release(posixfs_object, posixfs_ads);
	return status;
}

static NTSTATUS posixfs_create_open_new_ads_if(
		posixfs_open_t *&posixfs_open,
		posixfs_object_t *posixfs_object,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state)
{
	posixfs_ads_t *posixfs_ads = posixfs_ads_open(
			posixfs_object,
			state->in_ads_name,
			false);

	CHECK_STREAM_LEASE(state->smbd_lease, posixfs_object, posixfs_ads);

	NTSTATUS status = NT_STATUS_OK;
	if (posixfs_ads && posixfs_ads->exists) {
		status = open_object_exist_ads(
				posixfs_open,
				posixfs_object,
				posixfs_ads,
				smbd_requ,
				state,
				false);
	} else {
		if (!posixfs_ads) {
			posixfs_ads = posixfs_ads_add(posixfs_object, state->in_ads_name);
		}
		status = open_object_new_ads(
				posixfs_open,
				posixfs_object,
				posixfs_ads,
				smbd_requ,
				*state);
	}
	posixfs_ads_release(posixfs_object, posixfs_ads);
	return status;
}

static NTSTATUS posixfs_create_open_new_object_ads(
		posixfs_open_t *&posixfs_open,
		posixfs_object_t *posixfs_object,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state)
{
	std::shared_ptr<idl::security_descriptor> psd;
	NTSTATUS status = posixfs_new_object(posixfs_object, smbd_requ,
			*state, 0, 0, psd);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	posixfs_ads_t *posixfs_ads = posixfs_ads_add(
			posixfs_object,
			state->in_ads_name);
	status = open_object_new_ads(
			posixfs_open,
			posixfs_object,
			posixfs_ads,
			smbd_requ,
			*state);
	posixfs_ads_release(posixfs_object, posixfs_ads);
	return status;
}

static NTSTATUS posixfs_create_open(
		posixfs_open_t *&posixfs_open,
		posixfs_object_t *posixfs_object,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state)
{
	if (state->in_create_disposition == FILE_CREATE) {
		CHECK_OBJECT_LEASE(state->smbd_lease, posixfs_object);

		if (!posixfs_object->exists()) {
			if (state->end_with_sep) {
				return NT_STATUS_OBJECT_NAME_INVALID;
			}
			if (state->in_ads_name.size() == 0) {
				return posixfs_create_open_new_object(
						posixfs_open,
						posixfs_object,
						smbd_requ,
						*state);
			} else {
				return posixfs_create_open_new_object_ads(
						posixfs_open,
						posixfs_object,
						smbd_requ,
						state);
			}
		} else {
			if (state->in_ads_name.size() == 0) {
				return NT_STATUS_OBJECT_NAME_COLLISION;
			} else {
				return posixfs_create_open_new_ads(
						posixfs_open,
						posixfs_object,
						smbd_requ,
						state);
			}
		}

	} else if (state->in_create_disposition == FILE_OPEN) {
		if (state->in_timestamp != 0) {
			X_TODO; /* TODO snapshot */
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}
		if (!posixfs_object->exists()) {
			/* check lease first */
			CHECK_OBJECT_LEASE(state->smbd_lease, posixfs_object);

			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		} else if (posixfs_object_is_dir(posixfs_object)) {
			if (state->is_dollar_data) {
				CHECK_OBJECT_LEASE(state->smbd_lease, posixfs_object);

				return NT_STATUS_FILE_IS_A_DIRECTORY;
			} else if (state->in_ads_name.size() == 0) {
				return posixfs_create_open_exist_object(
						posixfs_open,
						posixfs_object,
						smbd_requ,
						state,
						false);
			} else {
				/* lease check inside posix_create_open_exist_ads */
				return posix_create_open_exist_ads(
						posixfs_open,
						posixfs_object,
						smbd_requ,
						state);
			}
		} else {
			if (state->end_with_sep) {
				CHECK_OBJECT_LEASE(state->smbd_lease, posixfs_object);

				return NT_STATUS_OBJECT_NAME_INVALID;
			} else if (state->in_ads_name.size() == 0) {
				return posixfs_create_open_exist_object(
						posixfs_open,
						posixfs_object,
						smbd_requ,
						state,
						false);
			} else {
				/* lease check inside posix_create_open_exist_ads */
				return posix_create_open_exist_ads(
						posixfs_open,
						posixfs_object,
						smbd_requ,
						state);
			}
		}

	} else if (state->in_create_disposition == FILE_OPEN_IF) {
		if (state->in_timestamp != 0) {
			/* TODO snapshot */
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		} else if (!posixfs_object->exists()) {
			CHECK_OBJECT_LEASE(state->smbd_lease, posixfs_object);

			if (state->end_with_sep) {
				return NT_STATUS_OBJECT_NAME_INVALID;
			} else if (state->in_ads_name.size() == 0) {
				return posixfs_create_open_new_object(
						posixfs_open,
						posixfs_object,
						smbd_requ,
						*state);
			} else {
				return posixfs_create_open_new_object_ads(
						posixfs_open,
						posixfs_object,
						smbd_requ,
						state);
			}
		} else if (posixfs_object_is_dir(posixfs_object)) {
			if (state->is_dollar_data) {
				CHECK_OBJECT_LEASE(state->smbd_lease, posixfs_object);

				return NT_STATUS_FILE_IS_A_DIRECTORY;
			} else if (state->in_ads_name.size() == 0) {
				return posixfs_create_open_exist_object(
						posixfs_open,
						posixfs_object,
						smbd_requ,
						state,
						false);
			} else {
				return posixfs_create_open_new_ads_if(
						posixfs_open,
						posixfs_object,
						smbd_requ,
						state);
			}
		} else {
			if (state->in_ads_name.size() == 0) {
				return posixfs_create_open_exist_object(
						posixfs_open,
						posixfs_object,
						smbd_requ,
						state,
						false);
			} else {
				return posixfs_create_open_new_ads_if(
						posixfs_open,
						posixfs_object,
						smbd_requ,
						state);
			}
		}

	} else if (state->in_create_disposition == FILE_OVERWRITE) {
		if (!posixfs_object->exists()) {
			CHECK_OBJECT_LEASE(state->smbd_lease, posixfs_object);

			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		} else if (posixfs_object_is_dir(posixfs_object)) {
			if (state->in_ads_name.size() == 0) {
				CHECK_OBJECT_LEASE(state->smbd_lease, posixfs_object);

				if (state->is_dollar_data) {
					return NT_STATUS_FILE_IS_A_DIRECTORY;
				} else {
					return NT_STATUS_INVALID_PARAMETER;
				}
			} else {
				return posixfs_create_open_overwrite_ads(
						posixfs_open,
						posixfs_object,
						smbd_requ,
						state);
			}
		} else {
			if (state->in_ads_name.size() == 0) {
				return posixfs_create_open_exist_object(
						posixfs_open,
						posixfs_object,
						smbd_requ,
						state,
						true);
			} else {
				return posixfs_create_open_overwrite_ads(
						posixfs_open,
						posixfs_object,
						smbd_requ,
						state);
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
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		} else if (!posixfs_object->exists()) {
			CHECK_OBJECT_LEASE(state->smbd_lease, posixfs_object);

			if (state->end_with_sep) {
				return NT_STATUS_OBJECT_NAME_INVALID;
			} else if (state->in_ads_name.size() == 0) {
				return posixfs_create_open_new_object(
						posixfs_open,
						posixfs_object,
						smbd_requ,
						*state);
			} else {
				return posixfs_create_open_new_object_ads(
						posixfs_open,
						posixfs_object,
						smbd_requ,
						state);
			}
		} else if (posixfs_object_is_dir(posixfs_object)) {
			if (state->in_ads_name.size() == 0) {
				CHECK_OBJECT_LEASE(state->smbd_lease, posixfs_object);

				if (state->is_dollar_data) {
					return NT_STATUS_FILE_IS_A_DIRECTORY;
				} else {
					return NT_STATUS_INVALID_PARAMETER;
				}
			} else {
				return posixfs_create_open_overwrite_ads_if(
						posixfs_open,
						posixfs_object,
						smbd_requ,
						state);
			}
		} else {
			if (state->in_ads_name.size() == 0) {
				return posixfs_create_open_exist_object(
						posixfs_open,
						posixfs_object,
						smbd_requ,
						state,
						true);
			} else {
				return posixfs_create_open_overwrite_ads_if(
						posixfs_open,
						posixfs_object,
						smbd_requ,
						state);
			}
		}

	} else {
		return NT_STATUS_INVALID_PARAMETER;
	}
}

/* TODO should not hold the posixfs_object's mutex */
NTSTATUS posixfs_object_op_unlink(x_smbd_object_t *smbd_object, int fd)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	int err = unlinkat(posixfs_object->base.topdir->fd, posixfs_object->unix_path.c_str(),
			posixfs_object_is_dir(posixfs_object) ? AT_REMOVEDIR : 0);
	if (err != 0) {
		X_TODO_ASSERT(errno == ENOTEMPTY);
		return NT_STATUS_DIRECTORY_NOT_EMPTY;
	}

	err = close(posixfs_object->fd);
	X_ASSERT(err == 0);
	posixfs_object->fd = -1;
	posixfs_object->base.type = x_smbd_object_t::type_not_exist;
	return NT_STATUS_OK;
}

static bool have_active_open(posixfs_object_t *posixfs_object)
{
	if (!posixfs_object->default_stream.open_list.empty()) {
		return true;
	}
	
	for (posixfs_ads_t *posixfs_ads = posixfs_object->ads_list.get_front();
			posixfs_ads;
			posixfs_ads = posixfs_object->ads_list.next(posixfs_ads)) {
		if (!posixfs_ads->base.open_list.empty()) {
			return true;
		}
	}
	return false;
}

static NTSTATUS posixfs_object_remove(posixfs_object_t *posixfs_object,
		posixfs_open_t *posixfs_open,
		std::vector<x_smb2_change_t> &changes)
{
	if (!posixfs_open->object_link.is_valid()) {
		X_ASSERT(false);
		return NT_STATUS_OK;
	}
	posixfs_stream_t *posixfs_stream = posixfs_get_stream(posixfs_object, posixfs_open);
	posixfs_stream->open_list.remove(posixfs_open);

	if (posixfs_open->locks.size()) {
		posixfs_lock_retry(posixfs_stream);
	}

	if (!posixfs_stream->open_list.empty()) {
		return NT_STATUS_OK;
	}

	auto orig_changes_size = changes.size();
	if (posixfs_object->default_stream.meta.delete_on_close &&
			!have_active_open(posixfs_object)) {
		posixfs_ads_foreach_1(posixfs_object, [posixfs_object, posixfs_open, &changes] (
					const char *xattr_name,
					const char *stream_name) {
				changes.push_back(x_smb2_change_t{
						NOTIFY_ACTION_REMOVED_STREAM,
						FILE_NOTIFY_CHANGE_STREAM_NAME,
						posixfs_open->base.parent_lease_key,
						posixfs_object->base.path + u':' + x_convert_utf8_to_utf16(stream_name),
						{}});
				return true;
			});

		uint32_t notify_filter = posixfs_object_is_dir(posixfs_object) ?
			FILE_NOTIFY_CHANGE_DIR_NAME : FILE_NOTIFY_CHANGE_FILE_NAME;

		// NTSTATUS status = x_smbd_object_unlink(&posixfs_object->base, posixfs_object->fd);
		NTSTATUS status = x_smbd_tcon_delete_object(
				posixfs_open->base.smbd_tcon,
				&posixfs_object->base,
				&posixfs_open->base,
				posixfs_object->fd,
				changes);
		if (!NT_STATUS_IS_OK(status)) {
			changes.resize(orig_changes_size);
			X_LOG_WARN("fail to unlink %s status=%x",
					posixfs_object->unix_path.c_str(), status.v);
			return status;
		}
		for (posixfs_ads_t *posixfs_ads = posixfs_object->ads_list.get_front();
				posixfs_ads;
				posixfs_ads = posixfs_object->ads_list.next(posixfs_ads)) {
			posixfs_ads->exists = false;
		}
		changes.push_back(x_smb2_change_t{NOTIFY_ACTION_REMOVED, notify_filter,
				posixfs_open->base.parent_lease_key,
				posixfs_object->base.path, {}});
	} else if (!posixfs_is_default_stream(posixfs_open) &&
			posixfs_stream->meta.delete_on_close) {
		posixfs_ads_t *ads = X_CONTAINER_OF(posixfs_stream,
				posixfs_ads_t, base);
		int ret = fremovexattr(posixfs_object->fd, ads->xattr_name.c_str());
		X_TODO_ASSERT(ret == 0);
		ads->exists = false;
		// TODO should it also notify object MODIFIED
		changes.push_back(x_smb2_change_t{NOTIFY_ACTION_REMOVED_STREAM,
				FILE_NOTIFY_CHANGE_STREAM_NAME,
				posixfs_open->base.parent_lease_key,
				posixfs_object->base.path + u':' + ads->name,
				{}});
	}

	return NT_STATUS_OK;
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
	x_smbd_lease_t *smbd_lease;

	std::unique_lock<std::mutex> lock(posixfs_object->base.mutex);
       	smbd_lease = posixfs_open->smbd_lease;
	posixfs_open->smbd_lease = nullptr;

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
		x_smbd_conn_post_cancel(x_smbd_chan_get_conn(requ_notify->smbd_chan),
				requ_notify);
		lock.lock();
	}

	if (posixfs_open->update_write_time) {
		changes.push_back(x_smb2_change_t{NOTIFY_ACTION_MODIFIED,
				FILE_NOTIFY_CHANGE_LAST_WRITE,
				posixfs_open->base.parent_lease_key,
				posixfs_object->base.path, {}});
		posixfs_open->update_write_time = false;
	}

	posixfs_object_remove(posixfs_object, posixfs_open, changes);

	posixfs_stream_t *posixfs_stream = posixfs_get_stream(posixfs_object,
			posixfs_open);
	share_mode_modified(posixfs_object, posixfs_open->base.smbd_stream);

	// TODO if last_write_time updated
	if (smbd_requ) {
		if (state->in_flags & SMB2_CLOSE_FLAGS_FULL_INFORMATION) {
			state->out_flags = SMB2_CLOSE_FLAGS_FULL_INFORMATION;
			/* TODO stream may be freed */
			fill_out_info(state->out_info, posixfs_object->meta,
					posixfs_stream->meta);
		}
	}
	lock.unlock();

	if (smbd_lease) {
		x_smbd_lease_close(smbd_lease);
	}

	return NT_STATUS_OK;
}

struct posixfs_read_evt_t
{
	static void func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user, bool terminated)
	{
		posixfs_read_evt_t *evt = X_CONTAINER_OF(fdevt_user, posixfs_read_evt_t, base);
		x_smbd_requ_t *smbd_requ = evt->smbd_requ;
		X_LOG_DBG("evt=%p, requ=%p, terminated=%d", evt, smbd_requ, terminated);
		x_smbd_requ_async_done(smbd_conn, smbd_requ, evt->status, terminated);
		delete evt;
	}

	posixfs_read_evt_t(x_smbd_requ_t *r, NTSTATUS s)
		: base(func), smbd_requ(r), status(s)
	{
	}
	~posixfs_read_evt_t()
	{
		x_smbd_ref_dec(smbd_requ);
	}
	x_fdevt_user_t base;
	x_smbd_requ_t * const smbd_requ;
	NTSTATUS const status;
};

static NTSTATUS posixfs_do_read(posixfs_object_t *posixfs_object,
		x_smb2_state_read_t &state)
{
	uint32_t length = std::min(state.in_length, 1024u * 1024);
	state.out_buf = x_buf_alloc(length);
	ssize_t ret = pread(posixfs_object->fd, state.out_buf->data,
			length, state.in_offset);
	X_LOG_DBG("pread %lu at %lu ret %ld", length, state.in_offset, ret);
	if (ret < 0) {
		return NT_STATUS_INTERNAL_ERROR;
	} else if (ret == 0) {
		state.out_buf_length = 0;
		return NT_STATUS_END_OF_FILE;
	} else {
		state.out_buf_length = x_convert_assert<uint32_t>(ret);
		return NT_STATUS_OK;
	}
}

/* TODO posixfs_read_job_t or posixfs_write_job_t should not access requ_state fields,
   which is not threadsafe
 */
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

	auto state = smbd_requ->get_state<x_smb2_state_read_t>();

	NTSTATUS status = posixfs_do_read(posixfs_object, *state);

	posixfs_object_release(posixfs_object);
	X_SMBD_CHAN_POST_USER(smbd_requ->smbd_chan,
			new posixfs_read_evt_t(smbd_requ, status));
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
	if (state.in_offset >= ads->base.meta.end_of_file) {
		state.out_buf_length = 0;
		return NT_STATUS_END_OF_FILE;
	}
	uint64_t max_read = ads->base.meta.end_of_file - state.in_offset;
	if (max_read > state.in_length) {
		max_read = state.in_length;
	}
	std::vector<uint8_t> content(0x10000);
	ssize_t ret = fgetxattr(posixfs_object->fd, ads->xattr_name.c_str(), content.data(), content.size());
	X_TODO_ASSERT(ret >= ssize_t(sizeof(posixfs_ads_header_t)));
	const posixfs_ads_header_t *ads_hdr = (const posixfs_ads_header_t *)content.data();
	uint32_t version = X_LE2H32(ads_hdr->version);
	X_TODO_ASSERT(version == 0);
	X_TODO_ASSERT(ret == ssize_t(ads->base.meta.end_of_file + sizeof(posixfs_ads_header_t)));
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
			posixfs_ads->base.meta.allocation_size = x_convert<uint32_t>(last_offset);
		}
		posixfs_ads->base.meta.end_of_file = x_convert<uint32_t>(last_offset);
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
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_read_t> &state)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	posixfs_open_t *posixfs_open = posixfs_open_from_base_t::container(smbd_open);

	/* TODO move this check into smb2_read */
	if (posixfs_object_is_dir(posixfs_object) &&
			posixfs_is_default_stream(posixfs_open)) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}

	{
		std::lock_guard<std::mutex> lock(posixfs_object->base.mutex);
		if (check_io_brl_conflict(posixfs_object, posixfs_open, state->in_offset, state->in_length, false)) {
			return NT_STATUS_FILE_LOCK_CONFLICT;
		}

		if (!posixfs_is_default_stream(posixfs_open)) {
			posixfs_ads_t *posixfs_ads = posixfs_ads_from_smbd_stream(posixfs_open->base.smbd_stream);
			return posixfs_ads_read(posixfs_object, posixfs_ads, *state);
		}
	}

	if (state->in_offset > posixfs_object->default_stream.meta.end_of_file) {
		return NT_STATUS_END_OF_FILE;
	}

	if (state->in_length == 0) {
		return NT_STATUS_OK;
	}

	if (state->in_offset == posixfs_object->default_stream.meta.end_of_file) {
		return NT_STATUS_END_OF_FILE;
	}

	if (!smbd_requ) {
		return posixfs_do_read(posixfs_object, *state);
	}
	posixfs_object_incref(posixfs_object);
	x_smbd_ref_inc(smbd_requ);
	posixfs_read_job_t *read_job = new posixfs_read_job_t(posixfs_object, smbd_requ);
	smbd_requ->save_state(state);
	x_smbd_requ_async_insert(smbd_requ, posixfs_read_cancel);
	x_smbd_schedule_async(&read_job->base);
	return NT_STATUS_PENDING;
}

static NTSTATUS posixfs_do_write(posixfs_object_t *posixfs_object,
		posixfs_open_t *posixfs_open,
		x_smb2_state_write_t &state)
{
	ssize_t ret = pwrite(posixfs_object->fd,
			state.in_buf->data + state.in_buf_offset,
			state.in_buf_length, state.in_offset);
	X_LOG_DBG("pwrite %lu at %lu ret %ld", state.in_buf_length, state.in_offset, ret);
	if (ret <= 0) {
		return NT_STATUS_INTERNAL_ERROR;
	} else {
		/* TODO atomic */
		posixfs_object->statex_modified = true;
		posixfs_open->update_write_time = true;
		uint64_t end_of_write = state.in_offset + ret;
		if (posixfs_object->default_stream.meta.end_of_file < end_of_write) {
			posixfs_object->default_stream.meta.end_of_file = end_of_write;
		}

		state.out_count = x_convert_assert<uint32_t>(ret);
		state.out_remaining = 0;
		return NT_STATUS_OK;
	}
}

struct posixfs_write_evt_t
{
	static void func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user, bool terminated)
	{
		posixfs_write_evt_t *evt = X_CONTAINER_OF(fdevt_user, posixfs_write_evt_t, base);
		x_smbd_requ_t *smbd_requ = evt->smbd_requ;
		X_LOG_DBG("evt=%p, requ=%p, terminated=%d", evt, smbd_requ, terminated);
		x_smbd_requ_async_done(smbd_conn, smbd_requ, evt->status, terminated);
		delete evt;
	}

	posixfs_write_evt_t(x_smbd_requ_t *r, NTSTATUS s)
		: base(func), smbd_requ(r), status(s)
	{
	}
	~posixfs_write_evt_t()
	{
		x_smbd_ref_dec(smbd_requ);
	}
	x_fdevt_user_t base;
	x_smbd_requ_t * const smbd_requ;
	NTSTATUS const status;
};

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
	posixfs_open_t *posixfs_open = posixfs_open_from_base_t::container(smbd_requ->smbd_open);
	posixfs_write_job->smbd_requ = nullptr;
	posixfs_write_job->posixfs_object = nullptr;

	auto state = smbd_requ->get_state<x_smb2_state_write_t>();
	NTSTATUS status = posixfs_do_write(posixfs_object, posixfs_open, *state);

	posixfs_object_release(posixfs_object);
	X_SMBD_CHAN_POST_USER(smbd_requ->smbd_chan,
			new posixfs_write_evt_t(smbd_requ, status));
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

static bool lease_type_is_exclusive(posixfs_open_t *posixfs_open)
{
	if (posixfs_open->smbd_lease) {
		uint8_t state = x_smbd_lease_get_state(posixfs_open->smbd_lease);
		return (state & (X_SMB2_LEASE_READ | X_SMB2_LEASE_WRITE)) == 
			(X_SMB2_LEASE_READ | X_SMB2_LEASE_WRITE);
	} else {
		return posixfs_open->oplock_level == X_SMB2_OPLOCK_LEVEL_EXCLUSIVE ||
			posixfs_open->oplock_level == X_SMB2_OPLOCK_LEVEL_BATCH;
	}
}

static void break_others_to_none(posixfs_object_t *posixfs_object,
		posixfs_open_t *posixfs_open)
{
	if (lease_type_is_exclusive(posixfs_open)) {
		return;
	}

	x_smbd_lease_t *smbd_lease = posixfs_open->smbd_lease;
	/* break other to none */
	posixfs_stream_t *posixfs_stream = posixfs_get_stream(posixfs_object, posixfs_open);
	auto &open_list = posixfs_stream->open_list;
	for (posixfs_open_t *other_open = open_list.get_front(); other_open;
			other_open = open_list.next(other_open)) {
		if (smbd_lease && other_open->smbd_lease == smbd_lease) {
			continue;
		}
		if (other_open->smbd_lease) {
			do_break_lease(other_open, nullptr, X_SMB2_LEASE_NONE);
		} else {
			/* This can break the open's self oplock II, but 
			 * Windows behave same
			 */
			X_ASSERT(other_open->oplock_level != X_SMB2_OPLOCK_LEVEL_BATCH);
			X_ASSERT(other_open->oplock_level != X_SMB2_OPLOCK_LEVEL_EXCLUSIVE);
			if (other_open->oplock_level == X_SMB2_OPLOCK_LEVEL_II) {
				do_break_oplock(other_open, X_SMB2_LEASE_NONE);
			}
		}
	}
}


NTSTATUS posixfs_object_op_write(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_write_t> &state)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	posixfs_open_t *posixfs_open = posixfs_open_from_base_t::container(smbd_open);

	{
		std::lock_guard<std::mutex> lock(posixfs_object->base.mutex);
		if (check_io_brl_conflict(posixfs_object, posixfs_open, state->in_offset, state->in_buf_length, true)) {
			return NT_STATUS_FILE_LOCK_CONFLICT;
		}

		break_others_to_none(posixfs_object, posixfs_open);

		if (!posixfs_is_default_stream(posixfs_open)) {
			posixfs_ads_t *ads = posixfs_ads_from_smbd_stream(posixfs_open->base.smbd_stream);
			return posixfs_ads_write(posixfs_object, ads, *state);
		}
	}

	if (posixfs_object_is_dir(posixfs_object)) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}

	if (!smbd_requ) {
		return posixfs_do_write(posixfs_object, posixfs_open, *state);
	}
	posixfs_object_incref(posixfs_object);
	x_smbd_ref_inc(smbd_requ);
	posixfs_write_job_t *write_job = new posixfs_write_job_t(posixfs_object, smbd_requ);
	smbd_requ->save_state(state);
	x_smbd_requ_async_insert(smbd_requ, posixfs_write_cancel);
	x_smbd_schedule_async(&write_job->base);
	return NT_STATUS_PENDING;
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
	static void func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user, bool terminated)
	{
		posixfs_lock_evt_t *evt = X_CONTAINER_OF(fdevt_user, posixfs_lock_evt_t, base);
		x_smbd_requ_t *smbd_requ = evt->smbd_requ;
		X_LOG_DBG("evt=%p, requ=%p, terminated=%d", evt, smbd_requ, terminated);
		x_smbd_requ_async_done(smbd_conn, smbd_requ, NT_STATUS_OK, terminated);
		delete evt;
	}

	explicit posixfs_lock_evt_t(x_smbd_requ_t *requ)
		: base(func), smbd_requ(requ)
	{
	}
	~posixfs_lock_evt_t()
	{
		x_smbd_ref_dec(smbd_requ);
	}
	x_fdevt_user_t base;
	x_smbd_requ_t * const smbd_requ;
};

static void posixfs_lock_retry(posixfs_stream_t *posixfs_stream)
{
	/* TODO it is not fair, it always scan the lock from open_list */
	posixfs_open_t *posixfs_open;
	auto &open_list = posixfs_stream->open_list;
	for (posixfs_open = open_list.get_front(); posixfs_open; posixfs_open = open_list.next(posixfs_open)) {
		x_smbd_requ_t *smbd_requ = posixfs_open->lock_requ_list.get_front();
		/* TODO show it post retry to smbd_conn */
		while (smbd_requ) {
			x_smbd_requ_t *next_requ = posixfs_open->lock_requ_list.next(smbd_requ);
			auto state = smbd_requ->get_state<x_smb2_state_lock_t>();
			if (!brl_conflict(posixfs_stream, posixfs_open, state->in_lock_elements)) {
				posixfs_open->lock_requ_list.remove(smbd_requ);
				posixfs_open->locks.insert(posixfs_open->locks.end(),
						state->in_lock_elements.begin(),
						state->in_lock_elements.end());
				X_SMBD_CHAN_POST_USER(smbd_requ->smbd_chan, 
						new posixfs_lock_evt_t(smbd_requ));
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

	posixfs_open_t *posixfs_open = posixfs_open_from_base_t::container(smbd_open);
	posixfs_stream_t *posixfs_stream = posixfs_get_stream(posixfs_object,
			smbd_open->smbd_stream);
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
		posixfs_lock_retry(posixfs_stream);
		return NT_STATUS_OK;
	} else {
		bool conflict = brl_conflict(posixfs_stream, posixfs_open,
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
			smbd_requ->save_state(state);
			x_smbd_ref_inc(smbd_requ);
			posixfs_open->lock_requ_list.push_back(smbd_requ);
			x_smbd_requ_async_insert(smbd_requ, posixfs_lock_cancel);
			return NT_STATUS_PENDING;
		}
	}
}

template<typename T>
static bool decode_le(T &val,
		const std::vector<uint8_t> &in_data)
{
	if (in_data.size() < sizeof(val)) {
		return false;
	}

	const T *p = (const T *)in_data.data();
	val = x_le2h(*p);
	return true;
}

template<typename T>
static NTSTATUS getinfo_encode_le(T val,
		x_smb2_state_getinfo_t &state)
{
	if (state.in_output_buffer_length < sizeof(T)) {
		return NT_STATUS_INFO_LENGTH_MISMATCH;
	}

	state.out_data.resize(sizeof(T));
	T *info = (T *)state.out_data.data();
	*info = x_h2le(val);
	return NT_STATUS_OK;
}

static bool marshall_stream_info(x_smb2_chain_marshall_t &marshall,
		const char *stream_name,
		uint64_t size, uint64_t allocation_size)
{
	std::u16string name = u":" + x_convert_utf8_to_utf16(stream_name);
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
	x_utf16le_encode(name, info->name);
	return true;
}

static NTSTATUS getinfo_stream_info(const posixfs_object_t *posixfs_object,
		x_smb2_state_getinfo_t &state)
{
	state.out_data.resize(state.in_output_buffer_length);
	x_smb2_chain_marshall_t marshall{state.out_data.data(), state.out_data.data() + state.out_data.size(), 8};

	if (!posixfs_object_is_dir(posixfs_object)) {
		if (!marshall_stream_info(marshall, "",
					posixfs_object->default_stream.meta.end_of_file,
					posixfs_object->default_stream.meta.allocation_size)) {
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
	/* TODO should move it into smb2_getinfo??  does other class request
	   the same access??
	if (!smbd_open->check_access(idl::SEC_FILE_READ_ATTRIBUTE)) {
		return NT_STATUS_ACCESS_DENIED;
	}
	 */

	posixfs_open_t *posixfs_open = posixfs_open_from_base_t::container(smbd_open);
	posixfs_stream_t *posixfs_stream = posixfs_get_stream(posixfs_object, smbd_open->smbd_stream);
	if (state.in_info_level == SMB2_FILE_INFO_FILE_BASIC_INFORMATION) {
		if (state.in_output_buffer_length < sizeof(x_smb2_file_basic_info_t)) {
			return NT_STATUS_INFO_LENGTH_MISMATCH;
		}
		state.out_data.resize(sizeof(x_smb2_file_basic_info_t));
		x_smb2_file_basic_info_t *info =
			(x_smb2_file_basic_info_t *)state.out_data.data();

		x_smbd_get_file_info(*info, posixfs_object->meta);

	} else if (state.in_info_level == SMB2_FILE_INFO_FILE_EA_INFORMATION) {
		/* TODO we do not support EA for now */
		return getinfo_encode_le(uint32_t(0), state);

	} else if (state.in_info_level == SMB2_FILE_INFO_FILE_ACCESS_INFORMATION) {
		return getinfo_encode_le(smbd_open->access_mask, state);

	} else if (state.in_info_level == SMB2_FILE_INFO_FILE_POSITION_INFORMATION) {
		return getinfo_encode_le(posixfs_open->current_offset, state);

	} else if (state.in_info_level == SMB2_FILE_INFO_FILE_MODE_INFORMATION) {
		return getinfo_encode_le(posixfs_open->mode, state);

	} else if (state.in_info_level == SMB2_FILE_INFO_FILE_FULL_EA_INFORMATION) {
		/* TODO we do not support EA for now */
		return NT_STATUS_NO_EAS_ON_FILE;

	} else if (state.in_info_level == SMB2_FILE_INFO_FILE_ALL_INFORMATION) {
		if (state.in_output_buffer_length < sizeof(x_smb2_file_all_info_t)) {
			return NT_STATUS_INFO_LENGTH_MISMATCH;
		}
		state.out_data.resize(sizeof(x_smb2_file_all_info_t));
		x_smb2_file_all_info_t *info =
			(x_smb2_file_all_info_t *)state.out_data.data();

		x_smbd_get_file_info(*info, posixfs_object->meta,
				posixfs_stream->meta,
				smbd_open->access_mask,
				posixfs_open->mode,
				posixfs_open->current_offset);

	} else if (state.in_info_level == SMB2_FILE_INFO_FILE_NETWORK_OPEN_INFORMATION) {
		if (state.in_output_buffer_length < sizeof(x_smb2_file_network_open_info_t)) {
			return NT_STATUS_INFO_LENGTH_MISMATCH;
		}
		state.out_data.resize(sizeof(x_smb2_file_network_open_info_t));
		x_smb2_file_network_open_info_t *info =
			(x_smb2_file_network_open_info_t *)state.out_data.data();
		
		x_smbd_get_file_info(*info, posixfs_object->meta,
				posixfs_stream->meta);

	} else if (state.in_info_level == SMB2_FILE_INFO_FILE_ALTERNATE_NAME_INFORMATION) {
		if (state.in_output_buffer_length < sizeof(x_smb2_file_alternate_name_info_t)) {
			return NT_STATUS_INFO_LENGTH_MISMATCH;
		}
		/* TODO not support 8.3 name for now */
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	} else if (state.in_info_level == SMB2_FILE_INFO_FILE_STREAM_INFORMATION) {
		if (state.in_output_buffer_length < sizeof(x_smb2_file_stream_name_info_t) + 8) {
			return NT_STATUS_INFO_LENGTH_MISMATCH;
		}
		return getinfo_stream_info(posixfs_object, state);

	} else if (state.in_info_level == SMB2_FILE_INFO_FILE_NORMALIZED_NAME_INFORMATION) {
		if (x_smbd_conn_curr_dialect() < 0x311) {
			return NT_STATUS_NOT_SUPPORTED;
		}
		if (state.in_output_buffer_length < sizeof(x_smb2_file_normalized_name_info_t)) {
			return NT_STATUS_INFO_LENGTH_MISMATCH;
		}
		
		posixfs_ads_t *posixfs_ads = nullptr;
		size_t name_length = posixfs_object->base.path.length();
		if (!posixfs_is_default_stream(smbd_open->smbd_stream)) {
			posixfs_ads = X_CONTAINER_OF(posixfs_stream,
					posixfs_ads_t, base);
			name_length += 1 + posixfs_ads->name.length();
		}
		name_length <<= 1;

		uint32_t output_buffer_length = state.in_output_buffer_length & ~1;
		size_t buf_size = std::min(size_t(output_buffer_length),
				offsetof(x_smb2_file_normalized_name_info_t, name) +
				name_length);
		state.out_data.resize(buf_size);
		x_smb2_file_normalized_name_info_t *info =
			(x_smb2_file_normalized_name_info_t *)state.out_data.data();
		info->name_length = X_H2LE32(x_convert_assert<uint32_t>(name_length));

		char16_t *buf = info->name;
		char16_t *buf_end = (char16_t *)((char *)info + buf_size);
		buf = x_utf16le_encode(posixfs_object->base.path, buf, buf_end);
		if (!buf) {
			return STATUS_BUFFER_OVERFLOW;
		}

		if (posixfs_ads) {
			if (buf == buf_end) {
				return STATUS_BUFFER_OVERFLOW;
			}
			*buf++ = X_H2LE16(u':');
			buf = x_utf16le_encode(posixfs_ads->name, buf, buf_end);
			if (!buf) {
				return STATUS_BUFFER_OVERFLOW;
			}
		}

	} else {
		X_TODO;
		return NT_STATUS_INVALID_LEVEL;
	}
	return NT_STATUS_OK;
}

static const char bad_ea_name_chars[] = "\"*+,/:;<=>?[\\]|";

static bool is_invalid_windows_ea_name(const char *name)
{
	for (; *name; ++name) {
		int val = *name;
		if (val < ' ' || strchr(bad_ea_name_chars, val)) {
			return true;
		}
	}
	return false;
}

static std::vector<std::string> collect_ea_names(const posixfs_object_t *posixfs_object)
{
	std::vector<std::string> names;
	posixfs_foreach_xattr(posixfs_object, POSIXFS_EA_PREFIX,
			[&names](const char *xattr_name, const char *name) {
				names.push_back(name);
				return true;
			});
	return names;
}

static NTSTATUS posixfs_set_ea(posixfs_object_t *posixfs_object,
		x_smbd_open_t *smbd_open,
		x_smb2_state_setinfo_t &state)
{
	struct ea_info_t
	{
		uint8_t flags;
		uint8_t name_length;
		uint16_t value_length;
		const char *name;
		const uint8_t *value;
	};
	std::vector<ea_info_t> eas;

	const uint8_t *in_data = state.in_data.data();
	size_t in_length = state.in_data.size();
	uint32_t next_offset;
	size_t length;
	for ( ; ; in_data += next_offset, in_length -= next_offset) {
		if (in_length < sizeof(x_smb2_file_full_ea_info_t)) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		const x_smb2_file_full_ea_info_t *info = (const x_smb2_file_full_ea_info_t *)in_data;
		next_offset = X_LE2H32(info->next_offset);
		if (next_offset == 0) {
			length = in_length;
		} else if ((next_offset % 8) != 0) {
			return NT_STATUS_INVALID_PARAMETER;
		} else {
			length = next_offset;
		}
		uint8_t flags = X_LE2H8(info->flags);
		uint8_t name_length = X_LE2H8(info->name_length);
		uint16_t value_length = X_LE2H16(info->value_length);
		if (length < sizeof(x_smb2_file_full_ea_info_t) + 1 + name_length + value_length) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		if (name_length == 0) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		const char *name = (const char *)in_data + 8;
		if (name[name_length] != 0) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		if (is_invalid_windows_ea_name(name)) {
			return STATUS_INVALID_EA_NAME;
		}
		eas.push_back({flags, name_length, value_length, name,
				in_data + 8 + name_length + 1});
		if (next_offset == 0) {
			break;
		}
	}

	if (!smbd_open->check_access(idl::SEC_FILE_WRITE_EA)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	if (smbd_open->smbd_stream) {
		return NT_STATUS_INVALID_PARAMETER;
	}


	const auto exist_ea_names = collect_ea_names(posixfs_object);
	int ret;
	for (const auto &ea: eas) {
		const char *name = ea.name;
		for (auto &exist: exist_ea_names) {
			if (strcasecmp(exist.c_str(), ea.name) == 0) {
				name = exist.c_str();
				break;
			}
		}
		std::string xattr_name = POSIXFS_EA_PREFIX;
		xattr_name += name;
		if (ea.value_length == 0) {
			if (name != ea.name) {
				X_LOG_DBG("remove existed ea '%s'", name);
				ret = fremovexattr(posixfs_object->fd, xattr_name.c_str());
			} else {
				X_LOG_DBG("skip zero ea '%s'", name);
				ret = 0;
			}
		} else {
			ret = fsetxattr(posixfs_object->fd, xattr_name.c_str(),
					ea.value, ea.value_length, 0);
		}
		X_TODO_ASSERT(ret == 0);
	}

	return NT_STATUS_OK;
}

static NTSTATUS setinfo_file(posixfs_object_t *posixfs_object,
		x_smbd_open_t *smbd_open,
		x_smb2_state_setinfo_t &state,
		std::vector<x_smb2_change_t> &changes)
{
	posixfs_open_t *posixfs_open = posixfs_open_from_base_t::container(smbd_open);
	posixfs_stream_t *posixfs_stream = posixfs_get_stream(posixfs_object, smbd_open->smbd_stream);
	if (state.in_info_level == SMB2_FILE_INFO_FILE_BASIC_INFORMATION) {
		if (!smbd_open->check_access(idl::SEC_FILE_WRITE_ATTRIBUTE)) {
			return NT_STATUS_ACCESS_DENIED;
		}

		x_smb2_file_basic_info_t basic_info;
		if (!x_smb2_file_basic_info_decode(basic_info, state.in_data)) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		uint32_t notify_actions = 0;
		NTSTATUS status = posixfs_set_basic_info(posixfs_object->fd,
				notify_actions, basic_info,
				&posixfs_object->meta);
		if (NT_STATUS_IS_OK(status)) {
			if (notify_actions) {
				changes.push_back(x_smb2_change_t{NOTIFY_ACTION_MODIFIED,
						notify_actions,
						posixfs_open->base.parent_lease_key,
						posixfs_object->base.path, {}});
			}
			return NT_STATUS_OK;
		} else {
			return status;
		}
	} else if (state.in_info_level == SMB2_FILE_INFO_FILE_ALLOCATION_INFORMATION) {
		if (!smbd_open->check_access(idl::SEC_FILE_WRITE_DATA)) {
			return NT_STATUS_ACCESS_DENIED;
		}

		uint64_t new_size;
		if (!decode_le(new_size, state.in_data)) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		if (!valid_write_range(new_size, 0)) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		posixfs_ads_t *posixfs_ads;
		if (posixfs_is_default_stream(smbd_open->smbd_stream)) {
			posixfs_ads = nullptr;
		} else {
			posixfs_ads = X_CONTAINER_OF(posixfs_stream,
					posixfs_ads_t, base);
		}
		return posixfs_set_allocation_size(posixfs_object,
				posixfs_ads, new_size);

	} else if (state.in_info_level == SMB2_FILE_INFO_FILE_END_OF_FILE_INFORMATION) {
		if (!smbd_open->check_access(idl::SEC_FILE_WRITE_DATA)) {
			return NT_STATUS_ACCESS_DENIED;
		}

		uint64_t new_size;
		if (!decode_le(new_size, state.in_data)) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		if (!valid_write_range(new_size, 0)) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		posixfs_ads_t *posixfs_ads;
		if (posixfs_is_default_stream(smbd_open->smbd_stream)) {
			posixfs_ads = nullptr;
		} else {
			posixfs_ads = X_CONTAINER_OF(posixfs_stream,
					posixfs_ads_t, base);
		}
		return posixfs_set_end_of_file(posixfs_object,
				posixfs_ads, new_size);

	} else if (state.in_info_level == SMB2_FILE_INFO_FILE_POSITION_INFORMATION) {
		uint64_t new_size;
		if (!decode_le(new_size, state.in_data)) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		posixfs_open->current_offset = new_size;
		return NT_STATUS_OK;

	} else if (state.in_info_level == SMB2_FILE_INFO_FILE_FULL_EA_INFORMATION) {
		return NT_STATUS_EAS_NOT_SUPPORTED;
		return posixfs_set_ea(posixfs_object, smbd_open, state);

	} else if (state.in_info_level == SMB2_FILE_INFO_FILE_MODE_INFORMATION) {
		uint32_t mode;
		if (!decode_le(mode, state.in_data)) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		/* TODO [MS-FSCC] 2.4.26 */
		if (mode != 0 && mode != 2 && mode != 4 && mode != 6) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		posixfs_open->mode = mode;
		return NT_STATUS_OK;

	} else {
		X_TODO;
		return NT_STATUS_INVALID_LEVEL;
	}
}

static NTSTATUS getinfo_fs(x_smbd_requ_t *smbd_requ,
		posixfs_object_t *posixfs_object,
		x_smb2_state_getinfo_t &state)
{
	if (state.in_info_level == SMB2_FILE_INFO_FS_VOLUME_INFORMATION) {
		if (state.in_output_buffer_length < sizeof(x_smb2_fs_volume_info_t)) {
			return NT_STATUS_INFO_LENGTH_MISMATCH;
		}

		std::string netbios_name = x_smbd_conf_get()->netbios_name;
		std::string volume = x_smbd_tcon_get_volume_label(smbd_requ->smbd_tcon);
		size_t hash = std::hash<std::string>{}(netbios_name + ":" + volume);
		std::u16string u16_volume = x_convert_utf8_to_utf16(volume);

		uint32_t output_buffer_length = state.in_output_buffer_length & ~1;
		size_t buf_size = std::min(size_t(output_buffer_length),
				offsetof(x_smb2_fs_volume_info_t, label) +
				u16_volume.length() * 2);

		state.out_data.resize(buf_size);
		x_smb2_fs_volume_info_t *info =
			(x_smb2_fs_volume_info_t *)state.out_data.data();
		info->creation_time = 0;
		info->serial_number = X_H2LE32(x_convert<uint32_t>(hash));
		info->unused = 0;
		info->label_length = X_H2LE32(8);
		char16_t *buf = info->label;
		char16_t *buf_end = (char16_t *)((char *)info + buf_size);
		buf = x_utf16le_encode(u16_volume, buf, buf_end);
		if (!buf) {
			return STATUS_BUFFER_OVERFLOW;
		}

		return NT_STATUS_OK;

	} else if (state.in_info_level == SMB2_FILE_INFO_FS_SIZE_INFORMATION) {
		if (state.in_output_buffer_length < sizeof(x_smb2_fs_size_info_t)) {
			return NT_STATUS_INFO_LENGTH_MISMATCH;
		}
		struct statvfs fsstat;
		int err = fstatvfs(posixfs_object->fd, &fsstat);
		assert(err == 0);
		state.out_data.resize(sizeof(x_smb2_fs_size_info_t));
		x_smb2_fs_size_info_t *info = (x_smb2_fs_size_info_t *)state.out_data.data();
		info->allocation_size = X_H2LE64(fsstat.f_blocks);
		info->free_units = X_H2LE64(fsstat.f_bfree);
		info->sectors_per_unit = X_H2LE32(x_convert_assert<uint32_t>(fsstat.f_bsize / 512));
		info->bytes_per_sector = X_H2LE32(512);
		return NT_STATUS_OK;

	} else if (state.in_info_level == SMB2_FILE_INFO_FS_ATTRIBUTE_INFORMATION) {
		if (state.in_output_buffer_length < sizeof(x_smb2_fs_attr_info_t)) {
			return NT_STATUS_INFO_LENGTH_MISMATCH;
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

		uint32_t output_buffer_length = state.in_output_buffer_length & ~1;
		size_t buf_size = std::min(size_t(output_buffer_length),
				offsetof(x_smb2_fs_attr_info_t, label) + 8);

		state.out_data.resize(buf_size);
		x_smb2_fs_attr_info_t *info =
			(x_smb2_fs_attr_info_t *)state.out_data.data();
		info->attributes = X_H2LE32(fs_cap);
		info->max_name_length = X_H2LE32(255);
		info->label_length = X_H2LE32(8);
		char16_t *buf = info->label;
		char16_t *buf_end = (char16_t *)((char *)info + buf_size);
		buf = x_utf16le_encode(u"NTFS", buf, buf_end);
		if (!buf) {
			return STATUS_BUFFER_OVERFLOW;
		}

		return NT_STATUS_OK;

	} else {
		X_TODO;
		return NT_STATUS_INVALID_LEVEL;
	}
}

static NTSTATUS getinfo_security(posixfs_object_t *posixfs_object,
		x_smbd_open_t *smbd_open,
		x_smb2_state_getinfo_t &state)
{
	if ((state.in_additional & idl::SECINFO_SACL) &&
			!smbd_open->check_access(idl::SEC_FLAG_SYSTEM_SECURITY)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	if ((state.in_additional & (idl::SECINFO_DACL|idl::SECINFO_OWNER|idl::SECINFO_GROUP)) &&
			!smbd_open->check_access(idl::SEC_STD_READ_CONTROL)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	std::shared_ptr<idl::security_descriptor> psd;
	if (state.in_additional & (idl::SECINFO_DACL|idl::SECINFO_SACL|idl::SECINFO_OWNER|idl::SECINFO_GROUP)) {
		NTSTATUS status = posixfs_object_get_sd(posixfs_object, psd);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		if (!(state.in_additional & idl::SECINFO_OWNER)) {
			psd->owner_sid = nullptr;
		}

		if (!(state.in_additional & idl::SECINFO_GROUP)) {
			psd->group_sid = nullptr;
		}

		if (!(state.in_additional & idl::SECINFO_DACL)) {
			psd->dacl = nullptr;
			psd->type &= ~idl::SEC_DESC_DACL_PRESENT;
		}

		if (!(state.in_additional & idl::SECINFO_SACL)) {
			psd->sacl = nullptr;
			psd->type &= ~idl::SEC_DESC_SACL_PRESENT;
		}
	} else {
		psd = create_empty_sec_desc();
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

	posixfs_open_t *posixfs_open = posixfs_open_from_base_t::container(smbd_requ->smbd_open);
	changes.push_back(x_smb2_change_t{NOTIFY_ACTION_MODIFIED, FILE_NOTIFY_CHANGE_SECURITY,
			posixfs_open->base.parent_lease_key,
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
		return getinfo_fs(smbd_requ, posixfs_object, *state);
	} else if (state->in_info_class == SMB2_GETINFO_SECURITY) {
		return getinfo_security(posixfs_object, smbd_open, *state);
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
		return setinfo_file(posixfs_object, smbd_requ->smbd_open, *state, changes);
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
	return NT_STATUS_INVALID_DEVICE_REQUEST;
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

NTSTATUS posixfs_object_qdir(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_qdir_t> &state,
		const char *pseudo_entries[],
		uint32_t pseudo_entry_count,
		bool (*process_entry_func)(x_smbd_object_meta_t *object_meta,
			x_smbd_stream_meta_t *stream_meta,
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

		x_smbd_object_meta_t object_meta;
		x_smbd_stream_meta_t stream_meta;
		if (!process_entry_func(&object_meta, &stream_meta, posixfs_object, ent_name, qdir_pos.file_number)) {
			X_LOG_WARN("qdir_process_entry %s %d,0x%x %d errno=%d",
					ent_name, qdir_pos.file_number, qdir_pos.filepos,
					qdir_pos.data_offset, errno);
			continue;
		}

		++matched_count;
		if (x_smbd_marshall_dir_entry(marshall, object_meta, stream_meta,
					ent_name, state->in_info_level)) {
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

	X_LOG_DBG("changes count %d", posixfs_open->notify_changes.size());
	state->out_notify_changes = std::move(posixfs_open->notify_changes);
	if (state->out_notify_changes.empty()) {
		smbd_requ->save_state(state);
		x_smbd_ref_inc(smbd_requ);
		posixfs_open->notify_requ_list.push_back(smbd_requ);
		x_smbd_requ_async_insert(smbd_requ, posixfs_notify_cancel);
		return NT_STATUS_PENDING;
	} else {
		return NT_STATUS_OK;
	}
}

void posixfs_object_op_lease_break(
		x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	std::unique_lock<std::mutex> lock(posixfs_object->base.mutex);
	share_mode_modified(posixfs_object, smbd_stream);
}

NTSTATUS posixfs_object_op_oplock_break(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_oplock_break_t> &state)
{
	posixfs_open_t *posixfs_open = posixfs_open_from_base_t::container(smbd_requ->smbd_open);
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
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
		std::lock_guard<std::mutex> lock(posixfs_object->base.mutex);
		share_mode_modified(posixfs_object, posixfs_open->base.smbd_stream);
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
	posixfs_stream_t *posixfs_stream = posixfs_get_stream(posixfs_object, smbd_open->smbd_stream);
	std::lock_guard<std::mutex> lock(posixfs_object->base.mutex);
	return posixfs_object_set_delete_on_close(posixfs_object,
			posixfs_stream, delete_on_close);
}

static void posixfs_object_release_stream(posixfs_object_t *posixfs_object,
		x_smbd_stream_t *smbd_stream)
{
	if (!posixfs_is_default_stream(smbd_stream)) {
		posixfs_ads_t *posixfs_ads = posixfs_ads_from_smbd_stream(smbd_stream);
		std::unique_lock<std::mutex> lock(posixfs_object->base.mutex);
		posixfs_ads_release(posixfs_object, posixfs_ads);
	} else {
		posixfs_stream_decref(&posixfs_object->default_stream);
	}
}

void posixfs_object_op_destroy(x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open)
{
	posixfs_open_t *posixfs_open = posixfs_open_from_base_t::container(smbd_open);
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	posixfs_object_release_stream(posixfs_object, smbd_open->smbd_stream);
	delete posixfs_open;
}

x_smbd_object_t *posixfs_open_object(NTSTATUS *pstatus,
		std::shared_ptr<x_smbd_topdir_t> &topdir,
		const std::u16string &path, long path_data,
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

void posixfs_op_release_object(x_smbd_object_t *smbd_object, x_smbd_stream_t *smbd_stream)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	if (smbd_stream) {
		posixfs_object_release_stream(posixfs_object, smbd_stream);
	}
	posixfs_object_release(posixfs_object);
}

uint32_t posixfs_op_get_attributes(const x_smbd_object_t *smbd_object)
{
	const posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	return posixfs_object->meta.file_attributes;
}

std::u16string posixfs_op_get_path(const x_smbd_object_t *smbd_object,
		const x_smbd_open_t *smbd_open)
{
	if (posixfs_is_default_stream(smbd_open->smbd_stream)) {
		return smbd_object->path;
	} else {
		posixfs_ads_t *posixfs_ads = posixfs_ads_from_smbd_stream(smbd_open->smbd_stream);
		return smbd_object->path + u":" + posixfs_ads->name;
	}
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

int posixfs_object_get_statex(const posixfs_object_t *posixfs_object,
		x_smbd_object_meta_t *object_meta,
		x_smbd_stream_meta_t *stream_meta)
{
	*object_meta = posixfs_object->meta;
	*stream_meta = posixfs_object->default_stream.meta;
	return 0;
}

/* posixfs_object must be directory */
int posixfs_object_get_parent_statex(const posixfs_object_t *dir_obj,
		x_smbd_object_meta_t *object_meta,
		x_smbd_stream_meta_t *stream_meta)
{
	if (dir_obj->base.path.empty()) {
		/* TODO should lock dir_obj */
		return posixfs_object_get_statex(dir_obj, object_meta, stream_meta);
	}
	return posixfs_statex_getat(dir_obj->fd, "..", object_meta, stream_meta);
}

int posixfs_object_statex_getat(posixfs_object_t *dir_obj, const char *name,
		x_smbd_object_meta_t *object_meta,
		x_smbd_stream_meta_t *stream_meta)
{
	return posixfs_statex_getat(dir_obj->fd, name, object_meta, stream_meta);
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

	x_smbd_object_meta_t object_meta;
	x_smbd_stream_meta_t stream_meta;
	/* if parent is not enable inherit, make_sec_desc */
	int fd = posixfs_create(topdir.fd,
			true,
			name.c_str(),
			&object_meta, &stream_meta,
			0, 0,
			ntacl_blob);

	X_ASSERT(fd != -1);
	close(fd);
	return 0;
}

/* smbd_object's mutex is locked */
NTSTATUS x_smbd_posixfs_create_open(x_smbd_open_t **psmbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state,
		std::vector<x_smb2_change_t> &changes)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(state->smbd_object);

	posixfs_open_t *posixfs_open = nullptr;
	NTSTATUS status = posixfs_create_open(posixfs_open, posixfs_object,
			smbd_requ, state);
	if (!posixfs_open) {
		return status;
	}

	if (state->out_create_action == FILE_WAS_CREATED) {
		changes.push_back(x_smb2_change_t{NOTIFY_ACTION_ADDED, 
				uint16_t((state->in_create_options & FILE_DIRECTORY_FILE) ? FILE_NOTIFY_CHANGE_DIR_NAME : FILE_NOTIFY_CHANGE_FILE_NAME),
				posixfs_open->base.parent_lease_key,
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
		x_put_le64(state->out_qfid_info, posixfs_object->meta.inode);
		x_put_le64(state->out_qfid_info + 8, posixfs_object->meta.fsid);
		memset(state->out_qfid_info + 16, 0, 16);
	}

	*psmbd_open = &posixfs_open->base;
	return NT_STATUS_OK;
}

/* caller lock smbd_object->mutex */
NTSTATUS x_smbd_posixfs_object_init(x_smbd_object_t *smbd_object,
		int fd, uint32_t file_attributes,
		const std::string &unix_path,
		const std::vector<uint8_t> &ntacl_blob)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);

	posixfs_post_create(fd, file_attributes,
			&posixfs_object->meta,
			&posixfs_object->default_stream.meta,
			ntacl_blob);
	
	posixfs_object->fd = fd;
	posixfs_object_update_type(posixfs_object);
	posixfs_object->base.flags = x_smbd_object_t::flag_initialized;
	posixfs_object->unix_path = unix_path;
	return NT_STATUS_OK;
}

