
#include "smbd_open.hxx"
#include "smbd_stats.hxx"
#include "smbd_posixfs.hxx"
#include "smbd_volume.hxx"
#include <fcntl.h>
#include <sys/statvfs.h>
#include "smbd_ntacl.hxx"
#include "smbd_access.hxx"
#include "smbd_lease.hxx"
#include "smbd_share.hxx"
#include "smbd_conf.hxx"
#include "util_io.hxx"
#include "include/nttime.hxx"
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

// TODO ext4 xattr max size is 4k while linux fattr is 64k
static const uint64_t posixfs_ads_max_length = 0x10000 - sizeof(posixfs_ads_header_t);

struct posixfs_qdir_t
{
	posixfs_qdir_t(x_smbd_open_t *smbd_open, const x_smbd_qdir_ops_t *ops)
		: base(smbd_open, ops) { }
	x_smbd_qdir_t base;
	int save_errno = 0;
	uint32_t data_length = 0;
	uint8_t data[32 * 1024];
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

static uint64_t roundup_allocation_size(uint64_t allocation_size)
{
	return (allocation_size + 4095ul) & ~4095ul;
}

static NTSTATUS posixfs_set_basic_info(int fd,
		uint32_t &notify_actions,
		const x_smb2_file_basic_info_t &basic_info,
		x_smbd_object_meta_t *object_meta)
{
	dos_attr_t dos_attr = { 0 };
	if (basic_info.file_attributes != 0) {
		dos_attr.attr_mask |= DOS_SET_FILE_ATTR;
		dos_attr.file_attrs = basic_info.file_attributes & X_NXSMB_FILE_ATTRIBUTE_MASK;
		if ((object_meta->file_attributes & X_SMB2_FILE_ATTRIBUTE_DIRECTORY)) {
			if (basic_info.file_attributes & X_SMB2_FILE_ATTRIBUTE_TEMPORARY) {
				RETURN_STATUS(NT_STATUS_INVALID_PARAMETER);
			}
			dos_attr.file_attrs |= X_SMB2_FILE_ATTRIBUTE_DIRECTORY;
		} else {
			if (basic_info.file_attributes & X_SMB2_FILE_ATTRIBUTE_DIRECTORY) {
				RETURN_STATUS(NT_STATUS_INVALID_PARAMETER);
			}
		}
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

static int posixfs_openat(int dirfd, const char *path,
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

struct posixfs_open_t
{
	posixfs_open_t(x_smbd_object_t *so, x_smbd_tcon_t *st,
			x_smbd_stream_t *stream,
			const x_smbd_open_state_t &open_state)
		: base(so, stream, st, open_state)
	{
	}

	uint8_t get_oplock_level() const
	{
		return base.open_state.oplock_level;
	}

	void set_oplock_level(uint8_t oplock_level)
	{
		base.open_state.oplock_level = oplock_level;
	}

	x_smbd_open_t base;
};
X_DECLARE_MEMBER_TRAITS(posixfs_open_object_traits, posixfs_open_t, base.object_link)
X_DECLARE_MEMBER_TRAITS(posixfs_open_from_base_t, posixfs_open_t, base)

struct posixfs_ads_t
{
	posixfs_ads_t(bool exists, const std::u16string &name) : base(exists, name) {
		X_SMBD_COUNTER_INC_CREATE(ads, 1);
	}
	~posixfs_ads_t() {
		X_SMBD_COUNTER_INC_DELETE(ads, 1);
	}

	x_smbd_stream_meta_t &get_meta() {
		return base.sharemode.meta;
	}

	x_smbd_stream_t base;
	std::atomic<int> ref_count{1};
	std::string xattr_name;
};

static inline posixfs_ads_t *posixfs_ads_from_smbd_stream(x_smbd_stream_t *smbd_stream)
{
	return X_CONTAINER_OF(smbd_stream, posixfs_ads_t, base);
}

static inline const posixfs_ads_t *posixfs_ads_from_smbd_stream(const x_smbd_stream_t *smbd_stream)
{
	return X_CONTAINER_OF(smbd_stream, posixfs_ads_t, base);
}


struct posixfs_object_t
{
	posixfs_object_t(uint64_t h,
			const std::shared_ptr<x_smbd_volume_t> &smbd_volume,
			x_smbd_object_t *smbd_object,
			const std::u16string &path_base, long path_data);
	~posixfs_object_t() {
		if (fd != -1) {
			close(fd);
		}
	}

	x_smbd_object_meta_t &get_meta() {
		return base.meta;
	}

	const x_smbd_object_meta_t &get_meta() const {
		return base.meta;
	}

	x_smbd_object_t base;

	bool exists() const { return base.type != x_smbd_object_t::type_not_exist; }
	int fd = -1;
	bool statex_modified{false}; // TODO use flags

	std::string unix_path_base;
};
X_DECLARE_MEMBER_TRAITS(posixfs_object_from_base_t, posixfs_object_t, base)

static int posixfs_object_get_fd(x_smbd_object_t *smbd_object)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	return posixfs_object->fd;
}

static inline int posixfs_get_root_fd(x_smbd_volume_t &smbd_volume)
{
	return posixfs_object_get_fd(smbd_volume.root_object);
}

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


static bool convert_to_unix(std::string &ret, const std::u16string &req_path)
{
	/* we suppose file system support case insenctive */
	/* TODO does smb allow leading '/'? if so need to remove it */
	return x_str_convert(ret, req_path, [](char32_t uc) {
			return (uc == '\\') ? U'/' : uc;
		});
}

static bool convert_from_unix(std::u16string &ret, const std::string &req_path)
{
	/* we suppose file system support case insenctive */
	/* TODO does smb allow leading '/'? if so need to remove it */
	return x_str_convert(ret, req_path, [](char32_t uc) {
			return (uc == '/') ? U'\\' : uc;
		});
}

static inline void posixfs_object_update_type(posixfs_object_t *posixfs_object)
{
	x_smbd_object_update_type(&posixfs_object->base);
}

static inline bool posixfs_object_is_dir(const posixfs_object_t *posixfs_object)
{
	return x_smbd_object_is_dir(&posixfs_object->base);
}

static inline void posixfs_object_incref(posixfs_object_t *posixfs_object)
{
	posixfs_object->base.incref();
}

static inline void posixfs_object_decref(posixfs_object_t *posixfs_object)
{
	posixfs_object->base.decref();
}

static inline void posixfs_ads_incref(posixfs_ads_t *posixfs_ads)
{
	X_ASSERT(++posixfs_ads->ref_count > 1);
}

static bool lease_type_is_exclusive(const x_smbd_lease_t *smbd_lease,
		uint8_t oplock_level)
{
	if (smbd_lease) {
		uint8_t state = x_smbd_lease_get_state(smbd_lease);
		return (state & (X_SMB2_LEASE_READ | X_SMB2_LEASE_WRITE)) == 
			(X_SMB2_LEASE_READ | X_SMB2_LEASE_WRITE);
	} else {
		return oplock_level == X_SMB2_OPLOCK_LEVEL_EXCLUSIVE ||
			oplock_level == X_SMB2_OPLOCK_LEVEL_BATCH;
	}
}

static void break_others_to_none(x_smbd_object_t *smbd_object,
		x_smbd_sharemode_t *sharemode,
		const x_smbd_lease_t *smbd_lease,
		uint8_t oplock_level)
{
	if (lease_type_is_exclusive(smbd_lease, oplock_level)) {
		return;
	}

	/* break other to none */
	auto &open_list = sharemode->open_list;
	for (x_smbd_open_t *other_open = open_list.get_front(); other_open;
			other_open = open_list.next(other_open)) {
		if (smbd_lease && other_open->smbd_lease == smbd_lease) {
			continue;
		}
		if (other_open->smbd_lease) {
			x_smbd_open_break_lease(other_open, nullptr, nullptr, X_SMB2_LEASE_NONE);
		} else {
			/* This can break the open's self oplock II, but 
			 * Windows behave same
			 */
			auto other_oplock_level = other_open->open_state.oplock_level;
			X_ASSERT(other_oplock_level != X_SMB2_OPLOCK_LEVEL_BATCH);
			X_ASSERT(other_oplock_level != X_SMB2_OPLOCK_LEVEL_EXCLUSIVE);
			if (other_oplock_level == X_SMB2_OPLOCK_LEVEL_II) {
				x_smbd_open_break_oplock(smbd_object, other_open, X_SMB2_LEASE_NONE);
			}
		}
	}
}


static inline void posixfs_object_add_ads(posixfs_object_t *posixfs_object,
		posixfs_ads_t *posixfs_ads)
{
	posixfs_object->base.add_ads(&posixfs_ads->base);
}

static inline void posixfs_object_remove_ads(posixfs_object_t *posixfs_object,
		posixfs_ads_t *posixfs_ads)
{
	posixfs_object->base.remove_ads(&posixfs_ads->base);
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
	posixfs_ads->get_meta().end_of_file = new_size;
	if (new_size > orig_alloc) {
		ads_hdr->allocation_size = X_LE2H32(x_convert<uint32_t>(new_size));
		posixfs_ads->get_meta().allocation_size = new_size;
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
		posixfs_ads->get_meta().end_of_file = x_convert<uint32_t>(new_size);
	}

	posixfs_ads->get_meta().allocation_size = x_convert<uint32_t>(new_size);

	ret = fsetxattr(posixfs_object->fd, posixfs_ads->xattr_name.c_str(), content.data(), content.size(), 0);
	X_TODO_ASSERT(ret == 0);
	return NT_STATUS_OK;
}


/* samba vfs_set_filelen */
static NTSTATUS posixfs_set_end_of_file(
		posixfs_object_t *posixfs_object,
		posixfs_ads_t *posixfs_ads,
		posixfs_open_t *posixfs_open,
		uint64_t new_size)
{
	auto sharemode = x_smbd_open_get_sharemode(&posixfs_open->base);

	if (sharemode->meta.end_of_file == new_size) {
		return NT_STATUS_OK;
	}

	NTSTATUS status = NT_STATUS_OK;

	auto lock = std::lock_guard(posixfs_object->base.mutex);
	break_others_to_none(&posixfs_object->base, sharemode,
			posixfs_open->base.smbd_lease,
			posixfs_open->get_oplock_level());

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
			&posixfs_object->get_meta(),
			&posixfs_object->base.sharemode.meta);
	X_TODO_ASSERT(err == 0);
	if (!posixfs_ads) {
		posixfs_object->base.sharemode.meta.allocation_size =
			std::max(new_size, posixfs_object->base.sharemode.meta.allocation_size);
	}
	posixfs_object->statex_modified = false;

	return status;
}

/* caller hold the object multex */
static NTSTATUS posixfs_set_allocation_size_intl(
		posixfs_object_t *posixfs_object,
		x_smbd_stream_t *smbd_stream,
		uint64_t allocation_size,
		x_smbd_lease_t *smbd_lease,
		uint8_t oplock_level)
{
	auto sharemode = x_smbd_object_get_sharemode(
			&posixfs_object->base, smbd_stream);

	break_others_to_none(&posixfs_object->base, sharemode,
			smbd_lease, oplock_level);

	bool modified = false;
	NTSTATUS status = NT_STATUS_OK;

	if (sharemode->meta.end_of_file == allocation_size) {
		return NT_STATUS_OK;

	} else if (sharemode->meta.end_of_file <= allocation_size) {
		// TODO contend_level2_oplocks_begin(fsp, LEVEL2_CONTEND_ALLOC_GROW);
		/* we do not support set allocation size for base file */
		if (smbd_stream) {
			 status = posixfs_ads_set_alloc(posixfs_object,
					 posixfs_ads_from_smbd_stream(smbd_stream),
					 allocation_size);
		}
		sharemode->meta.allocation_size = allocation_size;
		// TODO contend_level2_oplocks_end(fsp, LEVEL2_CONTEND_ALLOC_GROW);

	 } else {
		 // TODO contend_level2_oplocks_begin(fsp, LEVEL2_CONTEND_ALLOC_SHRINK);
		 if (smbd_stream) {
			 status = posixfs_ads_set_alloc(posixfs_object,
					 posixfs_ads_from_smbd_stream(smbd_stream),
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
				&posixfs_object->get_meta(),
				&posixfs_object->base.sharemode.meta);
		X_TODO_ASSERT(err == 0);
		if (!smbd_stream) {
			sharemode->meta.allocation_size =
				allocation_size;
		}
		posixfs_object->statex_modified = false;
	}

	return status;
}

/* samba vfs_allocate_file_space */
static NTSTATUS posixfs_set_allocation_size(
		posixfs_object_t *posixfs_object,
		x_smbd_open_t *smbd_open,
		uint64_t allocation_size)
{
	if (!smbd_open->smbd_stream) {
		/* only round up for base file */
		allocation_size = roundup_allocation_size(allocation_size);
	}

	auto lock = std::lock_guard(posixfs_object->base.mutex);
	return posixfs_set_allocation_size_intl(posixfs_object,
			smbd_open->smbd_stream,
			allocation_size,
			smbd_open->smbd_lease,
			smbd_open->open_state.oplock_level);
}

NTSTATUS posixfs_op_rename_object(
		x_smbd_object_t *smbd_object,
                bool replace_if_exists,
		x_smbd_object_t *new_parent_object,
		const std::u16string &new_path_base)
{
	/* check if exists on file system */
	std::string new_unix_path_base;
	if (!convert_to_unix(new_unix_path_base, new_path_base)) {
		return NT_STATUS_ILLEGAL_CHARACTER;
	}

	int new_parent_fd = posixfs_object_get_fd(new_parent_object);
	int fd = openat(new_parent_fd, new_unix_path_base.c_str(), O_RDONLY);
	if (fd != -1) {
		close(fd);
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	int err = renameat(posixfs_object_get_fd(smbd_object->parent_object),
			posixfs_object->unix_path_base.c_str(),
			new_parent_fd, new_unix_path_base.c_str());
	if (err != 0) {
		return x_map_nt_error_from_unix(-err);
	}	
	posixfs_object->unix_path_base = new_unix_path_base;
	return NT_STATUS_OK;
}


NTSTATUS posixfs_op_rename_stream(
		x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream,
                bool replace_if_exists,
                const std::u16string &new_stream_name)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	posixfs_ads_t *posixfs_ads = posixfs_ads_from_smbd_stream(
			smbd_stream);
	auto &ads_list = posixfs_object->base.ads_list;
	x_smbd_stream_t *other_stream;
	for (other_stream = ads_list.get_front(); other_stream;
			other_stream = ads_list.next(other_stream)) {
		posixfs_ads_t *other_ads = posixfs_ads_from_smbd_stream(other_stream);
		if (other_ads == posixfs_ads) {
			continue;
		}
		if (x_strcase_equal(other_stream->name, new_stream_name)) {
			/* windows server behavior */
			return replace_if_exists ? NT_STATUS_INVALID_PARAMETER :
				NT_STATUS_OBJECT_NAME_COLLISION;
		}
	}

	bool collision = false;
	std::string new_name_utf8;
	if (!x_str_convert(new_name_utf8, new_stream_name)) {
		return NT_STATUS_ILLEGAL_CHARACTER;
	}
	posixfs_ads_foreach_1(posixfs_object, [=, &collision] (const char *xattr_name,
				const char *stream_name) {
			if (x_strcase_equal(stream_name, new_name_utf8)) {
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
	posixfs_ads->base.name = new_stream_name;
	posixfs_ads->xattr_name = new_xattr_name;

	/* notify_fname */
	return NT_STATUS_OK;
}

static void posixfs_object_set_fd(posixfs_object_t *posixfs_object,
		int fd)
{
	X_ASSERT(posixfs_object->fd == -1);
	posixfs_object->fd = fd;
	int mount_id;
	auto &file_handle = posixfs_object->base.file_handle;
	file_handle.base.handle_bytes = MAX_HANDLE_SZ;
	int err = name_to_handle_at(fd, "",
			&file_handle.base,
			&mount_id, AT_EMPTY_PATH);
	if (err != 0) {
		X_LOG_ERR("name_to_handle_at %s errno=%d",
				posixfs_object->unix_path_base.c_str(), errno);
		X_ASSERT(false);
	}
	posixfs_object_update_type(posixfs_object);
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
	auto lock = std::lock_guard(posixfs_object->base.mutex);
	return posixfs_object_get_sd__(posixfs_object, psd);
}

/* posixfs_object mutex is locked */
static NTSTATUS posixfs_object_set_delete_on_close(posixfs_object_t *posixfs_object,
		x_smbd_stream_t *smbd_stream,
		uint32_t access_mask,
		bool delete_on_close)
{
	auto sharemode = x_smbd_object_get_sharemode(
			&posixfs_object->base, smbd_stream);

	if (delete_on_close) {
		NTSTATUS status = x_smbd_can_set_delete_on_close(&posixfs_object->base,
				smbd_stream,
				posixfs_object->get_meta().file_attributes,
				access_mask);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		sharemode->meta.delete_on_close = true;
		if (posixfs_object->base.type == x_smbd_object_t::type_dir &&
				!smbd_stream) {
			auto &open_list = sharemode->open_list;
			x_smbd_open_t *curr_open;
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
					x_smbd_conn_post_cancel(x_smbd_chan_get_conn(requ_notify->smbd_chan),
							requ_notify, NT_STATUS_DELETE_PENDING);
				}
			}
		}
	} else {
		sharemode->meta.delete_on_close = false;
	}
	return NT_STATUS_OK;
}

static posixfs_open_t *posixfs_open_create(
		NTSTATUS *pstatus,
		x_smbd_tcon_t *smbd_tcon,
		posixfs_object_t *posixfs_object,
		x_smbd_stream_t *smbd_stream,
		x_smbd_lease_t *smbd_lease,
		const x_smbd_open_state_t &open_state,
		uint32_t create_options)
{
	posixfs_open_t *posixfs_open = new posixfs_open_t(&posixfs_object->base,
			smbd_tcon, smbd_stream,
			open_state);
	/* not need incref because it already do in lease_grant */
	posixfs_open->base.smbd_lease = smbd_lease;

	if (!x_smbd_open_store(&posixfs_open->base)) {
		if (posixfs_open->base.smbd_lease) {
			x_smbd_lease_close(posixfs_open->base.smbd_lease);
			posixfs_open->base.smbd_lease = nullptr;
		}
		delete posixfs_open;
		*pstatus = NT_STATUS_INSUFFICIENT_RESOURCES;
		return nullptr;
	}

	posixfs_object_incref(posixfs_object);
	if (smbd_stream) {
		posixfs_ads_t *posixfs_ads = posixfs_ads_from_smbd_stream(smbd_stream);
		posixfs_ads_incref(posixfs_ads);
		smbd_stream->sharemode.open_list.push_back(&posixfs_open->base);
	} else {
		posixfs_object->base.sharemode.open_list.push_back(&posixfs_open->base);
	}
	if (posixfs_object->base.num_active_open++ == 0) {
		x_smbd_object_t *parent_object = posixfs_object->base.parent_object;
		if (parent_object) {
			x_smbd_object_update_num_child(parent_object, 1);
		}
	}
	*pstatus = NT_STATUS_OK;
	return posixfs_open;
}

static posixfs_open_t *posixfs_open_create(
		NTSTATUS *pstatus,
		x_smbd_tcon_t *smbd_tcon,
		posixfs_object_t *posixfs_object,
		const x_smb2_state_create_t &state,
		x_smb2_create_action_t create_action,
		uint8_t oplock_level)
{
	return posixfs_open_create(pstatus, smbd_tcon, posixfs_object,
			state.smbd_stream, state.smbd_lease,
			x_smbd_open_state_t{X_SMBD_OPEN_ID_NON_DURABLE,
				state.granted_access,
				state.in_share_access,
				x_smbd_conn_curr_client_guid(),
				state.in_create_guid,
				x_smbd_tcon_get_user(smbd_tcon)->get_owner_sid(),
				state.lease.parent_key,
				state.open_priv_data,
				0,
				create_action,
				oplock_level},
			state.in_create_options);
}
#if 0
static int open_parent(const std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		const std::u16string &path)
{
	if (path.empty()) {
		return -1;
	}

	std::u16string parent_path;
	auto sep = path.rfind('\\');
	if (sep == std::u16string::npos) {
		return dup(posixfs_get_root_fd(*smbd_volume));
	}
	parent_path = path.substr(0, sep);
	std::string unix_path;
	X_ASSERT(convert_to_unix(unix_path, parent_path));
	int fd = openat(posixfs_get_root_fd(*smbd_volume), unix_path.c_str(), O_RDONLY | O_NOFOLLOW);
	return fd;
}
#endif
static NTSTATUS get_parent_sd(const posixfs_object_t *posixfs_object,
		std::shared_ptr<idl::security_descriptor> &psd)
{
	x_smbd_object_t *parent_object = posixfs_object->base.parent_object;
	if (!parent_object) {
		return NT_STATUS_OBJECT_PATH_NOT_FOUND;
	}

	posixfs_object_t *posixfs_parent_object = posixfs_object_from_base_t::container(parent_object);
	return posixfs_object_get_sd(posixfs_parent_object, psd);
}

static inline bool is_sd_empty(const idl::security_descriptor &sd)
{
	return !sd.owner_sid && !sd.group_sid && !sd.dacl && !sd.sacl;
}

static NTSTATUS posixfs_new_object(
		posixfs_object_t *posixfs_object,
		const x_smbd_user_t &smbd_user,
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

	uint32_t rejected_mask = 0;
	status = se_file_access_check(*parent_psd, smbd_user,
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
				smbd_user,
				FILE_GENERIC_ALL,
				state.in_create_options & X_SMB2_CREATE_OPTION_DIRECTORY_FILE);
		psd = state.in_security_descriptor;
	} else {
		status = make_child_sec_desc(psd, parent_psd,
				smbd_user,
				state.in_create_options & X_SMB2_CREATE_OPTION_DIRECTORY_FILE);
	}
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	std::vector<uint8_t> ntacl_blob;
	if (psd) {
		create_acl_blob(ntacl_blob, psd, idl::XATTR_SD_HASH_TYPE_NONE, std::array<uint8_t, idl::XATTR_SD_HASH_SIZE>());
	}

	/* if parent is not enable inherit, make_sec_desc */
	int fd = posixfs_create(posixfs_object_get_fd(posixfs_object->base.parent_object),
			state.in_create_options & X_SMB2_CREATE_OPTION_DIRECTORY_FILE,
			posixfs_object->unix_path_base.c_str(),
			&posixfs_object->get_meta(),
			&posixfs_object->base.sharemode.meta,
			file_attributes,
			allocation_size,
			ntacl_blob);

	if (fd < 0) {
		X_ASSERT(-fd == EEXIST);
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	posixfs_object->base.sharemode.meta.delete_on_close = false;
	X_ASSERT(posixfs_object->base.type == x_smbd_object_t::type_not_exist);
	posixfs_object_set_fd(posixfs_object, fd);

	return NT_STATUS_OK;
}

static bool can_delete_file_in_directory(
		posixfs_object_t *posixfs_object,
		const x_smbd_tcon_t *smbd_tcon,
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

static void posixfs_access_check_new(
		const idl::security_descriptor &sd,
		const x_smbd_user_t &smbd_user,
		x_smb2_state_create_t &state)
{
	state.out_maximal_access = se_calculate_maximal_access(sd, smbd_user);
	/* Windows server seem not do access check for create new object */
	if (state.in_desired_access & idl::SEC_FLAG_MAXIMUM_ALLOWED) {
		state.granted_access = state.out_maximal_access;
	} else {
		/* seems windows just grant the desired_access
		 * state.granted_access = state.out_maximal_access & state.in_desired_access;
		 */
		state.granted_access = state.in_desired_access;
	}
}

static posixfs_ads_t *posixfs_ads_open_exist(posixfs_object_t * posixfs_object,
		const std::u16string &name,
		const char *xattr_name)
{
	std::vector<uint8_t> data(64 * 1024);
	ssize_t err = fgetxattr(posixfs_object->fd, xattr_name,
			data.data(), data.size());
	X_TODO_ASSERT(err >= ssize_t(sizeof(posixfs_ads_header_t)));
	const posixfs_ads_header_t *header = (const posixfs_ads_header_t *)data.data();

	posixfs_ads_t *posixfs_ads = new posixfs_ads_t(true, name);
	posixfs_ads->xattr_name = xattr_name;
	posixfs_ads->get_meta().end_of_file = x_convert_assert<uint32_t>(err - (sizeof(posixfs_ads_header_t)));
	posixfs_ads->get_meta().allocation_size = X_LE2H32(header->allocation_size);

	return posixfs_ads;
}

static std::pair<bool, posixfs_ads_t *> posixfs_ads_open(
		posixfs_object_t *posixfs_object,
		const std::u16string &name,
		bool exist_only)
{
	posixfs_ads_t *posixfs_ads = nullptr;
	x_smbd_stream_t *smbd_stream = nullptr;
	auto &ads_list = posixfs_object->base.ads_list;
	for (smbd_stream = ads_list.get_front(); smbd_stream;
			smbd_stream = ads_list.next(smbd_stream)) {
		if (x_strcase_equal(smbd_stream->name, name)) {
			if (smbd_stream->exists || !exist_only) {
				posixfs_ads =  posixfs_ads_from_smbd_stream(smbd_stream);
				++posixfs_ads->ref_count;
				return { true, posixfs_ads };
			} else {
				return { true, nullptr };
			}
		}
	}
	
	if (posixfs_object->exists()) {
		std::string utf8_name;
		if (!x_str_convert(utf8_name, name)) {
			return { false, nullptr };
		}
		
		posixfs_ads_foreach_1(posixfs_object, [posixfs_object, &utf8_name, &name, &posixfs_ads] (const char *xattr_name,
					const char *stream_name) {
				if (x_strcase_equal(utf8_name, stream_name)) {
					posixfs_ads = posixfs_ads_open_exist(
							posixfs_object, name,
							xattr_name);
					return false;
				}
				return true;
			});
	}

	if (!posixfs_ads && !exist_only) {
		posixfs_ads = new posixfs_ads_t(false, name);
	}

	if (posixfs_ads) {
		posixfs_object_add_ads(posixfs_object, posixfs_ads);
	}
	return { true, posixfs_ads };
}

static void posixfs_ads_release(posixfs_object_t *posixfs_object,
		posixfs_ads_t *ads)
{
	if (--ads->ref_count == 0) {
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
	posixfs_ads->base.exists = true;
	// posixfs_ads->initialized = true;
	posixfs_ads->get_meta().allocation_size = allocation_size;
	posixfs_ads->get_meta().end_of_file = 0;
	X_TODO_ASSERT(ret >= 0);
}

/* TODO should not hold the posixfs_object's mutex */
NTSTATUS posixfs_object_op_unlink(x_smbd_object_t *smbd_object, int fd)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	int err = unlinkat(posixfs_object_get_fd(smbd_object->parent_object),
			posixfs_object->unix_path_base.c_str(),
			posixfs_object_is_dir(posixfs_object) ? AT_REMOVEDIR : 0);
	if (err != 0) {
		X_TODO_ASSERT(errno == ENOTEMPTY);
		return NT_STATUS_DIRECTORY_NOT_EMPTY;
	}

	err = close(posixfs_object->fd);
	X_ASSERT(err == 0);
	posixfs_object->fd = -1;
	posixfs_object->base.type = x_smbd_object_t::type_not_exist;
	posixfs_object->statex_modified = true;
	return NT_STATUS_OK;
}

struct posixfs_read_evt_t
{
	static void func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user)
	{
		posixfs_read_evt_t *evt = X_CONTAINER_OF(fdevt_user, posixfs_read_evt_t, base);
		x_smbd_requ_t *smbd_requ = evt->smbd_requ;
		X_LOG_DBG("evt=%p, requ=%p, smbd_conn=%p", evt, smbd_requ, smbd_conn);
		x_smbd_requ_async_done(smbd_conn, smbd_requ, evt->status);
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
		x_smb2_state_read_t &state, uint32_t delay_ms)
{
	if (delay_ms) {
		usleep(delay_ms * 1000);
	}
	uint32_t length = std::min(state.in_length, 1024u * 1024);
	state.out_buf = x_buf_alloc(length);
	ssize_t ret = pread(posixfs_object->fd, state.out_buf->data,
			length, state.in_offset);
	X_LOG_DBG("pread %u at %lu ret %ld", length, state.in_offset, ret);
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
	posixfs_read_job_t(posixfs_object_t *po, x_smbd_requ_t *r,
			uint32_t delay_ms);
	x_job_t base;
	posixfs_object_t *posixfs_object;
	x_smbd_requ_t *smbd_requ;
	const uint32_t delay_ms;
};

static x_job_t::retval_t posixfs_read_job_run(x_job_t *job, void *sche)
{
	posixfs_read_job_t *posixfs_read_job = X_CONTAINER_OF(job, posixfs_read_job_t, base);

	x_smbd_requ_t *smbd_requ = posixfs_read_job->smbd_requ;
	posixfs_object_t *posixfs_object = posixfs_read_job->posixfs_object;
	posixfs_read_job->smbd_requ = nullptr;
	posixfs_read_job->posixfs_object = nullptr;

	auto state = smbd_requ->get_requ_state<x_smb2_state_read_t>();

	NTSTATUS status = posixfs_do_read(posixfs_object, *state, posixfs_read_job->delay_ms);

	x_smbd_release_object(&posixfs_object->base);
	X_SMBD_CHAN_POST_USER(smbd_requ->smbd_chan,
			new posixfs_read_evt_t(smbd_requ, status));
	delete posixfs_read_job;
	return x_job_t::JOB_DONE;
}

inline posixfs_read_job_t::posixfs_read_job_t(posixfs_object_t *po, x_smbd_requ_t *r,
		uint32_t delay_ms)
	: base(posixfs_read_job_run), posixfs_object(po), smbd_requ(r)
	, delay_ms(delay_ms)
{
}

static void posixfs_read_cancel(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	x_smbd_conn_post_cancel(smbd_conn, smbd_requ, NT_STATUS_CANCELLED);
}

static NTSTATUS posixfs_ads_read(posixfs_object_t *posixfs_object,
		posixfs_ads_t *ads,
		x_smb2_state_read_t &state)
{
	if (state.in_length == 0) {
		state.out_buf_length = 0;
		return NT_STATUS_OK;
	}
	if (state.in_offset >= ads->get_meta().end_of_file) {
		state.out_buf_length = 0;
		return NT_STATUS_END_OF_FILE;
	}
	uint64_t max_read = ads->get_meta().end_of_file - state.in_offset;
	if (max_read > state.in_length) {
		max_read = state.in_length;
	}
	std::vector<uint8_t> content(0x10000);
	ssize_t ret = fgetxattr(posixfs_object->fd, ads->xattr_name.c_str(), content.data(), content.size());
	X_TODO_ASSERT(ret >= ssize_t(sizeof(posixfs_ads_header_t)));
	const posixfs_ads_header_t *ads_hdr = (const posixfs_ads_header_t *)content.data();
	uint32_t version = X_LE2H32(ads_hdr->version);
	X_TODO_ASSERT(version == 0);
	X_TODO_ASSERT(ret == ssize_t(ads->get_meta().end_of_file + sizeof(posixfs_ads_header_t)));
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
			posixfs_ads->get_meta().allocation_size = x_convert<uint32_t>(last_offset);
		}
		posixfs_ads->get_meta().end_of_file = x_convert<uint32_t>(last_offset);
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
		std::unique_ptr<x_smb2_state_read_t> &state,
		uint32_t delay_ms,
		bool all)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);

	/* TODO move this check into smb2_read */
	if (posixfs_object_is_dir(posixfs_object) &&
			!smbd_open->smbd_stream) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}

	{
		std::lock_guard<std::mutex> lock(smbd_object->mutex);
		if (x_smbd_check_io_brl_conflict(smbd_object, smbd_open, state->in_offset, state->in_length, false)) {
			return NT_STATUS_FILE_LOCK_CONFLICT;
		}

		if (smbd_open->smbd_stream) {
			posixfs_ads_t *posixfs_ads = posixfs_ads_from_smbd_stream(smbd_open->smbd_stream);
			return posixfs_ads_read(posixfs_object, posixfs_ads, *state);
		}
	}

	if (state->in_offset > posixfs_object->base.sharemode.meta.end_of_file) {
		return NT_STATUS_END_OF_FILE;
	}

	if (state->in_length == 0) {
		return NT_STATUS_OK;
	}

	if (state->in_offset == posixfs_object->base.sharemode.meta.end_of_file) {
		return NT_STATUS_END_OF_FILE;
	}

	/*
	 * [MS-SMB2] 3.3.5.15.6 Handling a Server-Side Data Copy Request
	 *   If the SourceOffset or SourceOffset + Length extends beyond
	 *   the end of file, the server SHOULD<240> treat this as a
	 *   STATUS_END_OF_FILE error.
	 * ...
	 *   <240> Section 3.3.5.15.6: Windows servers will return
	 *   STATUS_INVALID_VIEW_SIZE instead of STATUS_END_OF_FILE.
	 */
	if (all && state->in_offset + state->in_length > posixfs_object->base.sharemode.meta.end_of_file) {
		return NT_STATUS_INVALID_VIEW_SIZE;
	}

	/* TODO it should be able to do async if it is the last requ in compound,
	 * but smbtorture require the response is 8 byte aligned.
	 * so disable async for now
	 */
	if (!smbd_requ || smbd_requ->is_compound_followed() || smbd_requ->out_buf_head) {
		return posixfs_do_read(posixfs_object, *state,
				delay_ms);
	}
	posixfs_object_incref(posixfs_object);
	x_smbd_ref_inc(smbd_requ);
	posixfs_read_job_t *read_job = new posixfs_read_job_t(posixfs_object, smbd_requ,
			delay_ms);
	smbd_requ->save_requ_state(state);
	x_smbd_requ_async_insert(smbd_requ, posixfs_read_cancel, X_NSEC_PER_SEC);
	x_smbd_schedule_async(&read_job->base);
	return NT_STATUS_PENDING;
}

static NTSTATUS posixfs_do_write(posixfs_object_t *posixfs_object,
		posixfs_open_t *posixfs_open,
		x_smb2_state_write_t &state,
		uint32_t delay_ms)
{
	if (delay_ms) {
		usleep(delay_ms * 1000);
	}
	ssize_t ret = pwrite(posixfs_object->fd,
			state.in_buf->data + state.in_buf_offset,
			state.in_buf_length, state.in_offset);
	X_LOG_DBG("pwrite %u at %lu ret %ld", state.in_buf_length, state.in_offset, ret);
	if (ret <= 0) {
		return NT_STATUS_INTERNAL_ERROR;
	} else {
		/* TODO atomic */
		posixfs_object->statex_modified = true;
		posixfs_open->base.update_write_time = true;
		uint64_t end_of_write = state.in_offset + ret;
		if (posixfs_object->base.sharemode.meta.end_of_file < end_of_write) {
			posixfs_object->base.sharemode.meta.end_of_file = end_of_write;
			if (posixfs_object->base.sharemode.meta.allocation_size < end_of_write) {
				posixfs_object->base.sharemode.meta.allocation_size =
					roundup_allocation_size(end_of_write);
			}
		}

		state.out_count = x_convert_assert<uint32_t>(ret);
		state.out_remaining = 0;
		return NT_STATUS_OK;
	}
}

struct posixfs_write_evt_t
{
	static void func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user)
	{
		posixfs_write_evt_t *evt = X_CONTAINER_OF(fdevt_user, posixfs_write_evt_t, base);
		x_smbd_requ_t *smbd_requ = evt->smbd_requ;
		X_LOG_DBG("evt=%p, requ=%p, smbd_conn=%p", evt, smbd_requ, smbd_conn);
		x_smbd_requ_async_done(smbd_conn, smbd_requ, evt->status);
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
	posixfs_write_job_t(posixfs_object_t *po, x_smbd_requ_t *r,
			uint32_t delay_ms);
	x_job_t base;
	posixfs_object_t *posixfs_object;
	x_smbd_requ_t *smbd_requ;
	const uint32_t delay_ms;
};

static x_job_t::retval_t posixfs_write_job_run(x_job_t *job, void *data)
{
	posixfs_write_job_t *posixfs_write_job = X_CONTAINER_OF(job, posixfs_write_job_t, base);

	x_smbd_requ_t *smbd_requ = posixfs_write_job->smbd_requ;
	posixfs_object_t *posixfs_object = posixfs_write_job->posixfs_object;
	posixfs_open_t *posixfs_open = posixfs_open_from_base_t::container(smbd_requ->smbd_open);
	posixfs_write_job->smbd_requ = nullptr;
	posixfs_write_job->posixfs_object = nullptr;

	auto state = smbd_requ->get_requ_state<x_smb2_state_write_t>();
	NTSTATUS status = posixfs_do_write(posixfs_object, posixfs_open, *state,
			posixfs_write_job->delay_ms);

	x_smbd_release_object(&posixfs_object->base);
	X_SMBD_CHAN_POST_USER(smbd_requ->smbd_chan,
			new posixfs_write_evt_t(smbd_requ, status));
	delete posixfs_write_job;
	return x_job_t::JOB_DONE;
}

inline posixfs_write_job_t::posixfs_write_job_t(posixfs_object_t *po, x_smbd_requ_t *r,
		uint32_t delay_ms)
	: base(posixfs_write_job_run), posixfs_object(po), smbd_requ(r)
	, delay_ms(delay_ms)
{
}

static void posixfs_write_cancel(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	x_smbd_conn_post_cancel(smbd_conn, smbd_requ, NT_STATUS_CANCELLED);
}

NTSTATUS posixfs_object_op_write(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_write_t> &state,
		uint32_t delay_ms)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	posixfs_open_t *posixfs_open = posixfs_open_from_base_t::container(smbd_open);

	{
		std::lock_guard<std::mutex> lock(smbd_object->mutex);
		if (x_smbd_check_io_brl_conflict(smbd_object, smbd_open, state->in_offset, state->in_buf_length, true)) {
			return NT_STATUS_FILE_LOCK_CONFLICT;
		}

		x_smbd_break_others_to_none(smbd_object,
				x_smbd_open_get_sharemode(smbd_open),
				posixfs_open->base.smbd_lease,
				posixfs_open->get_oplock_level());

		if (smbd_open->smbd_stream) {
			posixfs_ads_t *ads = posixfs_ads_from_smbd_stream(smbd_open->smbd_stream);
			return posixfs_ads_write(posixfs_object, ads, *state);
		}
	}

	if (posixfs_object_is_dir(posixfs_object)) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}

	if (!smbd_requ || smbd_requ->is_compound_followed()) {
		return posixfs_do_write(posixfs_object, posixfs_open, *state,
				delay_ms);
	}
	posixfs_object_incref(posixfs_object);
	x_smbd_ref_inc(smbd_requ);
	posixfs_write_job_t *write_job = new posixfs_write_job_t(posixfs_object, smbd_requ,
			delay_ms);
	smbd_requ->save_requ_state(state);
	x_smbd_requ_async_insert(smbd_requ, posixfs_write_cancel, X_NSEC_PER_SEC);
	x_smbd_schedule_async(&write_job->base);
	return NT_STATUS_PENDING;
}

NTSTATUS posixfs_object_op_flush(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	int err = fsync(posixfs_object->fd);
	X_TODO_ASSERT(err == 0);
	return NT_STATUS_OK;
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
		const std::u16string &name,
		uint64_t size, uint64_t allocation_size)
{
	const std::u16string suffix = u":$DATA";

	uint32_t rec_size = x_convert_assert<uint32_t>(sizeof(x_smb2_file_stream_name_info_t) + name.size() * 2 + suffix.size() * 2);
	uint8_t *pbegin = marshall.get_begin(rec_size);
	if (!pbegin) {
		return false;
	}
	x_smb2_file_stream_name_info_t *info = (x_smb2_file_stream_name_info_t *)pbegin;
	info->next_offset = 0;
	info->name_length = X_H2LE32(x_convert_assert<uint32_t>(name.size() * 2 + suffix.size() * 2));
	info->size = X_H2LE64(size);
	info->allocation_size = X_H2LE64(allocation_size);
	char16_t *p = x_utf16le_encode(name, info->name);
	x_utf16le_encode(suffix, p);
	return true;
}

static NTSTATUS getinfo_stream_info(const posixfs_object_t *posixfs_object,
		x_smb2_state_getinfo_t &state)
{
	state.out_data.resize(state.in_output_buffer_length);
	x_smb2_chain_marshall_t marshall{state.out_data.data(), state.out_data.data() + state.out_data.size(), 8};

	if (!posixfs_object_is_dir(posixfs_object)) {
		auto &stream_meta = posixfs_object->base.sharemode.meta;
		if (!marshall_stream_info(marshall, u":",
					stream_meta.end_of_file,
					stream_meta.allocation_size)) {
			return NT_STATUS_BUFFER_OVERFLOW;
		}
	}

	bool marshall_ret = true;
	posixfs_ads_foreach_2(posixfs_object,
			[&marshall, &marshall_ret] (const char *stream_name, uint64_t eof, uint64_t alloc) {
			std::u16string name = u":";
			if (x_str_convert(name, std::string_view(stream_name))) {
				marshall_ret = marshall_stream_info(marshall, name, eof, alloc);
			} else {
				X_LOG_ERR("invalid stream_name '%s'", stream_name);
			}
			return marshall_ret;
		});
	if (!marshall_ret) {
		return NT_STATUS_BUFFER_OVERFLOW;
	}
	state.out_data.resize(marshall.get_size());
	return NT_STATUS_OK;
}

static void reload_statex_if(posixfs_object_t *posixfs_object)
{
	if (posixfs_object->statex_modified) {
		int err = posixfs_statex_get(posixfs_object->fd,
				&posixfs_object->get_meta(),
				&posixfs_object->base.sharemode.meta);
		X_TODO_ASSERT(err == 0);
		posixfs_object->statex_modified = false;
	}
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

	auto sharemode = x_smbd_open_get_sharemode(smbd_open);

	if (state.in_info_level == x_smb2_info_level_t::FILE_BASIC_INFORMATION) {
		if (state.in_output_buffer_length < sizeof(x_smb2_file_basic_info_t)) {
			RETURN_STATUS(NT_STATUS_INFO_LENGTH_MISMATCH);
		}
		if (!smbd_open->check_access_any(idl::SEC_FILE_READ_ATTRIBUTE)) {
			RETURN_STATUS(NT_STATUS_ACCESS_DENIED);
		}
		state.out_data.resize(sizeof(x_smb2_file_basic_info_t));
		x_smb2_file_basic_info_t *info =
			(x_smb2_file_basic_info_t *)state.out_data.data();

		reload_statex_if(posixfs_object);
		x_smbd_get_file_info(*info, posixfs_object->get_meta());

	} else if (state.in_info_level == x_smb2_info_level_t::FILE_STANDARD_INFORMATION) {
		if (state.in_output_buffer_length < sizeof(x_smb2_file_standard_info_t)) {
			RETURN_STATUS(NT_STATUS_INFO_LENGTH_MISMATCH);
		}
		state.out_data.resize(sizeof(x_smb2_file_standard_info_t));
		x_smb2_file_standard_info_t *info =
			(x_smb2_file_standard_info_t *)state.out_data.data();

		reload_statex_if(posixfs_object);
		x_smbd_get_file_info(*info, posixfs_object->get_meta(),
				sharemode->meta,
				smbd_open->open_state.access_mask,
				smbd_open->mode,
				smbd_open->open_state.current_offset);

	} else if (state.in_info_level == x_smb2_info_level_t::FILE_INTERNAL_INFORMATION) {
		if (state.in_output_buffer_length < sizeof(uint64_t)) {
			RETURN_STATUS(NT_STATUS_INFO_LENGTH_MISMATCH);
		}
		return getinfo_encode_le(uint64_t(posixfs_object->get_meta().inode), state);

	} else if (state.in_info_level == x_smb2_info_level_t::FILE_EA_INFORMATION) {
		/* TODO we do not support EA for now */
		return getinfo_encode_le(uint32_t(0), state);

	} else if (state.in_info_level == x_smb2_info_level_t::FILE_ACCESS_INFORMATION) {
		return getinfo_encode_le(smbd_open->open_state.access_mask, state);

	} else if (state.in_info_level == x_smb2_info_level_t::FILE_POSITION_INFORMATION) {
		return getinfo_encode_le(smbd_open->open_state.current_offset, state);

	} else if (state.in_info_level == x_smb2_info_level_t::FILE_MODE_INFORMATION) {
		return getinfo_encode_le(smbd_open->mode, state);

	} else if (state.in_info_level == x_smb2_info_level_t::FILE_ALIGNMENT_INFORMATION) {
		/* No alignment needed. */
		return getinfo_encode_le(uint32_t(0), state);

	} else if (state.in_info_level == x_smb2_info_level_t::FILE_FULL_EA_INFORMATION) {
		/* TODO we do not support EA for now */
		RETURN_STATUS(NT_STATUS_NO_EAS_ON_FILE);

	} else if (state.in_info_level == x_smb2_info_level_t::FILE_ALL_INFORMATION) {
		if (state.in_output_buffer_length < sizeof(x_smb2_file_all_info_t)) {
			RETURN_STATUS(NT_STATUS_INFO_LENGTH_MISMATCH);
		}
		if (!smbd_open->check_access_any(idl::SEC_FILE_READ_ATTRIBUTE)) {
			RETURN_STATUS(NT_STATUS_ACCESS_DENIED);
		}
		state.out_data.resize(sizeof(x_smb2_file_all_info_t));
		x_smb2_file_all_info_t *info =
			(x_smb2_file_all_info_t *)state.out_data.data();

		reload_statex_if(posixfs_object);
		x_smbd_get_file_info(*info, posixfs_object->get_meta(),
				sharemode->meta,
				smbd_open->open_state.access_mask,
				smbd_open->mode,
				smbd_open->open_state.current_offset);

	} else if (state.in_info_level == x_smb2_info_level_t::FILE_ALTERNATE_NAME_INFORMATION) {
		if (state.in_output_buffer_length < sizeof(x_smb2_file_alternate_name_info_t)) {
			RETURN_STATUS(NT_STATUS_INFO_LENGTH_MISMATCH);
		}
		/* TODO not support 8.3 name for now */
		RETURN_STATUS(NT_STATUS_OBJECT_NAME_NOT_FOUND);

	} else if (state.in_info_level == x_smb2_info_level_t::FILE_STREAM_INFORMATION) {
		if (state.in_output_buffer_length < sizeof(x_smb2_file_stream_name_info_t) + 8) {
			RETURN_STATUS(NT_STATUS_INFO_LENGTH_MISMATCH);
		}
		return getinfo_stream_info(posixfs_object, state);

	} else if (state.in_info_level == x_smb2_info_level_t::FILE_COMPRESSION_INFORMATION) {
		if (state.in_output_buffer_length < sizeof(x_smb2_file_compression_info_t) + 8) {
			RETURN_STATUS(NT_STATUS_INFO_LENGTH_MISMATCH);
		}
		state.out_data.resize(sizeof(x_smb2_file_compression_info_t));
		x_smb2_file_compression_info_t *info =
			(x_smb2_file_compression_info_t *)state.out_data.data();
		// TODO not support compression for now
		info->file_size = X_H2LE64(sharemode->meta.end_of_file);
		info->format = 0;
		info->unit_shift = 0;
		info->chunk_shift = 0;
		info->cluster_shift = 0;
		info->unused0 = 0;
		info->unused1 = 0;

	} else if (state.in_info_level == x_smb2_info_level_t::FILE_NETWORK_OPEN_INFORMATION) {
		if (state.in_output_buffer_length < sizeof(x_smb2_file_network_open_info_t)) {
			RETURN_STATUS(NT_STATUS_INFO_LENGTH_MISMATCH);
		}
		if (!smbd_open->check_access_any(idl::SEC_FILE_READ_ATTRIBUTE)) {
			RETURN_STATUS(NT_STATUS_ACCESS_DENIED);
		}
		state.out_data.resize(sizeof(x_smb2_file_network_open_info_t));
		x_smb2_file_network_open_info_t *info =
			(x_smb2_file_network_open_info_t *)state.out_data.data();
		
		reload_statex_if(posixfs_object);
		x_smbd_get_file_info(*info, posixfs_object->get_meta(),
				sharemode->meta);

	} else if (state.in_info_level == x_smb2_info_level_t::FILE_ATTRIBUTE_TAG_INFORMATION) {
		if (state.in_output_buffer_length < sizeof(x_smb2_file_attribute_tag_info_t)) {
			RETURN_STATUS(NT_STATUS_INFO_LENGTH_MISMATCH);
		}
		state.out_data.resize(sizeof(x_smb2_file_attribute_tag_info_t));
		x_smb2_file_attribute_tag_info_t *info =
			(x_smb2_file_attribute_tag_info_t *)state.out_data.data();
		
		info->file_attributes = X_H2LE32(posixfs_object->get_meta().file_attributes);
		info->reparse_tag = 0; // TODO not support for now

	} else if (state.in_info_level == x_smb2_info_level_t::FILE_NORMALIZED_NAME_INFORMATION) {
		if (x_smbd_conn_curr_dialect() < 0x311) {
			RETURN_STATUS(NT_STATUS_NOT_SUPPORTED);
		}
		if (state.in_output_buffer_length < sizeof(x_smb2_file_normalized_name_info_t)) {
			RETURN_STATUS(NT_STATUS_INFO_LENGTH_MISMATCH);
		}
		
		std::u16string path = x_smbd_object_get_path(&posixfs_object->base);
		size_t name_length = path.length();
		if (smbd_open->smbd_stream) {
			name_length += 1 + smbd_open->smbd_stream->name.length();
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
		buf = x_utf16le_encode(path, buf, buf_end);
		if (!buf) {
			return NT_STATUS_BUFFER_OVERFLOW;
		}

		if (smbd_open->smbd_stream) {
			if (buf == buf_end) {
				return NT_STATUS_BUFFER_OVERFLOW;
			}
			*buf++ = X_H2LE16(u':');
			buf = x_utf16le_encode(smbd_open->smbd_stream->name, buf, buf_end);
			if (!buf) {
				return NT_STATUS_BUFFER_OVERFLOW;
			}
		}

	} else {
		RETURN_STATUS(NT_STATUS_INVALID_LEVEL);
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
			return NT_STATUS_INVALID_EA_NAME;
		}
		eas.push_back({flags, name_length, value_length, name,
				in_data + 8 + name_length + 1});
		if (next_offset == 0) {
			break;
		}
	}

	if (!smbd_open->check_access_any(idl::SEC_FILE_WRITE_EA)) {
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
		x_smb2_state_setinfo_t &state)
{
	posixfs_open_t *posixfs_open = posixfs_open_from_base_t::container(smbd_open);

	if (state.in_info_level == x_smb2_info_level_t::FILE_BASIC_INFORMATION) {
		if (!smbd_open->check_access_any(idl::SEC_FILE_WRITE_ATTRIBUTE)) {
			return NT_STATUS_ACCESS_DENIED;
		}

		x_smb2_file_basic_info_t basic_info;
		if (!x_smb2_file_basic_info_decode(basic_info, state.in_data)) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		uint32_t notify_actions = 0;
		NTSTATUS status = posixfs_set_basic_info(posixfs_object->fd,
				notify_actions, basic_info,
				&posixfs_object->get_meta());
		if (NT_STATUS_IS_OK(status)) {
			if (notify_actions) {
				x_smbd_schedule_notify(
						NOTIFY_ACTION_MODIFIED,
						notify_actions,
						smbd_open->open_state.parent_lease_key,
						smbd_open->open_state.client_guid,
						posixfs_object->base.parent_object,
						nullptr,
						posixfs_object->base.path_base, {});
			}
			return NT_STATUS_OK;
		} else {
			return status;
		}
	} else if (state.in_info_level == x_smb2_info_level_t::FILE_ALLOCATION_INFORMATION) {
		if (!smbd_open->check_access_any(idl::SEC_FILE_WRITE_DATA)) {
			return NT_STATUS_ACCESS_DENIED;
		}

		uint64_t new_size;
		if (!decode_le(new_size, state.in_data)) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		if (!valid_write_range(new_size, 0)) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		return posixfs_set_allocation_size(posixfs_object,
				smbd_open, new_size);

	} else if (state.in_info_level == x_smb2_info_level_t::FILE_END_OF_FILE_INFORMATION) {
		if (!smbd_open->check_access_any(idl::SEC_FILE_WRITE_DATA)) {
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
		if (!smbd_open->smbd_stream) {
			posixfs_ads = nullptr;
		} else {
			posixfs_ads = posixfs_ads_from_smbd_stream(smbd_open->smbd_stream);
		}
		return posixfs_set_end_of_file(posixfs_object,
				posixfs_ads, posixfs_open, new_size);

	} else if (state.in_info_level == x_smb2_info_level_t::FILE_POSITION_INFORMATION) {
		uint64_t new_size;
		if (!decode_le(new_size, state.in_data)) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		smbd_open->open_state.current_offset = new_size;
		return NT_STATUS_OK;

	} else if (state.in_info_level == x_smb2_info_level_t::FILE_FULL_EA_INFORMATION) {
		return NT_STATUS_EAS_NOT_SUPPORTED;
		return posixfs_set_ea(posixfs_object, smbd_open, state);

	} else if (state.in_info_level == x_smb2_info_level_t::FILE_MODE_INFORMATION) {
		uint32_t mode;
		if (!decode_le(mode, state.in_data)) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		/* TODO [MS-FSCC] 2.4.26 */
		if (mode != 0 && mode != 2 && mode != 4 && mode != 6) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		smbd_open->mode = mode;
		return NT_STATUS_OK;

	} else {
		return NT_STATUS_INVALID_LEVEL;
	}
}

static NTSTATUS getinfo_fs(x_smbd_requ_t *smbd_requ,
		posixfs_object_t *posixfs_object,
		x_smb2_state_getinfo_t &state)
{
	const x_smbd_conf_t &smbd_conf = x_smbd_conf_get_curr();
	if (state.in_info_level == x_smb2_info_level_t::FS_VOLUME_INFORMATION) {
		if (state.in_output_buffer_length < sizeof(x_smb2_fs_volume_info_t)) {
			return NT_STATUS_INFO_LENGTH_MISMATCH;
		}

		std::u16string volume = x_smbd_tcon_get_volume_label(smbd_requ->smbd_tcon);
		size_t hash = std::hash<std::u16string>{}(volume + u":" + *smbd_conf.netbios_name_u16);

		uint32_t output_buffer_length = state.in_output_buffer_length & ~1;
		size_t buf_size = std::min(size_t(output_buffer_length),
				offsetof(x_smb2_fs_volume_info_t, label) +
				volume.length() * 2);

		state.out_data.resize(buf_size);
		x_smb2_fs_volume_info_t *info =
			(x_smb2_fs_volume_info_t *)state.out_data.data();
		info->creation_time = 0;
		info->serial_number = X_H2LE32(x_convert<uint32_t>(hash));
		info->unused = 0;
		info->label_length = X_H2LE32(8);
		char16_t *buf = info->label;
		char16_t *buf_end = (char16_t *)((char *)info + buf_size);
		buf = x_utf16le_encode(volume, buf, buf_end);
		if (!buf) {
			return NT_STATUS_BUFFER_OVERFLOW;
		}

	} else if (state.in_info_level == x_smb2_info_level_t::FS_LABEL_INFORMATION) {
		if (state.in_output_buffer_length < sizeof(x_smb2_fs_label_info_t)) {
			return NT_STATUS_INFO_LENGTH_MISMATCH;
		}

		std::u16string volume = x_smbd_tcon_get_volume_label(smbd_requ->smbd_tcon);

		uint32_t output_buffer_length = state.in_output_buffer_length & ~1;
		size_t buf_size = std::min(size_t(output_buffer_length),
				offsetof(x_smb2_fs_label_info_t, label) +
				volume.length() * 2);

		state.out_data.resize(buf_size);
		x_smb2_fs_label_info_t *info =
			(x_smb2_fs_label_info_t *)state.out_data.data();
		info->label_length = X_H2LE32(8);
		char16_t *buf = info->label;
		char16_t *buf_end = (char16_t *)((char *)info + buf_size);
		buf = x_utf16le_encode(volume, buf, buf_end);
		if (!buf) {
			return NT_STATUS_BUFFER_OVERFLOW;
		}

	} else if (state.in_info_level == x_smb2_info_level_t::FS_SIZE_INFORMATION) {
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

	} else if (state.in_info_level == x_smb2_info_level_t::FS_DEVICE_INFORMATION) {
		if (state.in_output_buffer_length < sizeof(x_smb2_fs_device_info_t)) {
			return NT_STATUS_INFO_LENGTH_MISMATCH;
		}

		state.out_data.resize(sizeof(x_smb2_fs_device_info_t));
		x_smb2_fs_device_info_t *info = (x_smb2_fs_device_info_t *)state.out_data.data();
		info->device_type = X_H2LE32(X_SMB2_FILE_DEVICE_DISK);
		info->characteristics = X_H2LE32(X_SMB2_FILE_DEVICE_IS_MOUNTED);
		/* TODO if readonly characteristics |= FILE_READ_ONLY_DEVICE */

	} else if (state.in_info_level == x_smb2_info_level_t::FS_ATTRIBUTE_INFORMATION) {
		if (state.in_output_buffer_length < sizeof(x_smb2_fs_attr_info_t)) {
			return NT_STATUS_INFO_LENGTH_MISMATCH;
		}

		struct statvfs fsstat;
		int err = fstatvfs(posixfs_object->fd, &fsstat);
		assert(err == 0);

		uint32_t fs_cap = X_SMB2_FS_ATTRIBUTE_FILE_CASE_SENSITIVE_SEARCH | X_SMB2_FS_ATTRIBUTE_FILE_CASE_PRESERVED_NAMES;
		if (fsstat.f_flag & ST_RDONLY) {
			fs_cap |= X_SMB2_FS_ATTRIBUTE_FILE_READ_ONLY_VOLUME;
		}

		fs_cap |= X_SMB2_FS_ATTRIBUTE_FILE_VOLUME_QUOTAS;
		fs_cap |= X_SMB2_FS_ATTRIBUTE_FILE_SUPPORTS_SPARSE_FILES;
		fs_cap |= (X_SMB2_FS_ATTRIBUTE_FILE_SUPPORTS_REPARSE_POINTS | X_SMB2_FS_ATTRIBUTE_FILE_SUPPORTS_SPARSE_FILES);
		fs_cap |= X_SMB2_FS_ATTRIBUTE_FILE_NAMED_STREAMS;
		fs_cap |= X_SMB2_FS_ATTRIBUTE_FILE_PERSISTENT_ACLS;;
		fs_cap |= X_SMB2_FS_ATTRIBUTE_FILE_SUPPORTS_OBJECT_IDS | X_SMB2_FS_ATTRIBUTE_FILE_UNICODE_ON_DISK;
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
			return NT_STATUS_BUFFER_OVERFLOW;
		}

	} else if (state.in_info_level == x_smb2_info_level_t::FS_FULL_SIZE_INFORMATION) {
		if (state.in_output_buffer_length < sizeof(x_smb2_fs_full_size_info_t)) {
			return NT_STATUS_INFO_LENGTH_MISMATCH;
		}
		struct statvfs fsstat;
		int err = fstatvfs(posixfs_object->fd, &fsstat);
		assert(err == 0);
		state.out_data.resize(sizeof(x_smb2_fs_full_size_info_t));
		x_smb2_fs_full_size_info_t *info =
			(x_smb2_fs_full_size_info_t *)state.out_data.data();
		info->total_allocation_units = X_H2LE64(fsstat.f_blocks);
		info->caller_available_allocation_units = X_H2LE64(fsstat.f_bfree);
		info->actual_available_allocation_units = X_H2LE64(fsstat.f_bfree);
		info->sectors_per_allocation_unit = X_H2LE32(x_convert_assert<uint32_t>(fsstat.f_bsize / 512));
		info->bytes_per_sector = X_H2LE32(512);

	} else if (state.in_info_level == x_smb2_info_level_t::FS_SECTOR_SIZE_INFORMATION) {
		if (state.in_output_buffer_length < sizeof(x_smb2_fs_sector_size_info_t)) {
			return NT_STATUS_INFO_LENGTH_MISMATCH;
		}

		state.out_data.resize(sizeof(x_smb2_fs_sector_size_info_t));
		x_smb2_fs_sector_size_info_t *info =
			(x_smb2_fs_sector_size_info_t *)state.out_data.data();
		uint32_t bytes_per_sector = 512;
		info->logical_bytes_per_sector = X_H2LE32(bytes_per_sector);
		info->physical_bytes_per_sector_for_atomicity = X_H2LE32(bytes_per_sector);
		info->physical_bytes_per_sector_for_performance = X_H2LE32(bytes_per_sector);
		info->file_system_effective_physical_bytes_per_sector_for_atomicity = X_H2LE32(bytes_per_sector);
		info->flags = X_H2LE32(X_SMB2_SSINFO_FLAGS_ALIGNED_DEVICE
				| X_SMB2_SSINFO_FLAGS_PARTITION_ALIGNED_ON_DEVICE);
		info->byte_offset_for_sector_alignment = 0;
		info->byte_offset_for_partition_alignment = 0;

	} else {
		return NT_STATUS_INVALID_LEVEL;
	}
	
	return NT_STATUS_OK;
}

static NTSTATUS getinfo_security(posixfs_object_t *posixfs_object,
		x_smbd_open_t *smbd_open,
		x_smb2_state_getinfo_t &state)
{
	if ((state.in_additional & idl::SECINFO_SACL) &&
			!smbd_open->check_access_any(idl::SEC_FLAG_SYSTEM_SECURITY)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	if ((state.in_additional & (idl::SECINFO_DACL|idl::SECINFO_OWNER|idl::SECINFO_GROUP)) &&
			!smbd_open->check_access_any(idl::SEC_STD_READ_CONTROL)) {
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

	/* TODO ndr_push should fail when buffer is not enough */
	auto ndr_ret = idl::x_ndr_push(*psd, state.out_data, 0);
	if (ndr_ret < 0) {
		return x_map_nt_error_from_ndr_err(idl::x_ndr_err_code_t(-ndr_ret));
	}
	if (state.out_data.size() > state.in_output_buffer_length) {
		return NT_STATUS_BUFFER_TOO_SMALL;
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
			smbd_requ->smbd_open->open_state.access_mask,
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
	x_smbd_schedule_notify(
			NOTIFY_ACTION_MODIFIED, FILE_NOTIFY_CHANGE_SECURITY,
			posixfs_open->base.open_state.parent_lease_key,
			posixfs_open->base.open_state.client_guid,
			posixfs_object->base.parent_object, nullptr,
			posixfs_object->base.path_base, {});
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

	if (state->in_info_class == x_smb2_info_class_t::FILE) {
		return getinfo_file(posixfs_object, smbd_open, *state);
	} else if (state->in_info_class == x_smb2_info_class_t::FS) {
		return getinfo_fs(smbd_requ, posixfs_object, *state);
	} else if (state->in_info_class == x_smb2_info_class_t::SECURITY) {
		return getinfo_security(posixfs_object, smbd_open, *state);
	} else if (state->in_info_class == x_smb2_info_class_t::QUOTA) {
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

	if (state->in_info_class == x_smb2_info_class_t::FILE) {
		return setinfo_file(posixfs_object, smbd_requ->smbd_open, *state);
#if 0
	} else if (state->in_info_class == x_smb2_info_class_t::FS) {
		return setinfo_fs(posixfs_object, smbd_requ, *state);
#endif
	} else if (state->in_info_class == x_smb2_info_class_t::SECURITY) {
		return setinfo_security(posixfs_object, smbd_requ, *state);
	} else {
		return NT_STATUS_INVALID_PARAMETER;
	}
}

NTSTATUS posixfs_object_op_ioctl(
		x_smbd_object_t *smbd_object,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_ioctl_t> &state)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	switch (state->ctl_code) {
	case X_SMB2_FSCTL_CREATE_OR_GET_OBJECT_ID:
		if (state->in_max_output_length < sizeof(x_smb2_file_object_id_buffer_t)) {
			return NT_STATUS_BUFFER_TOO_SMALL;
		}
		{
			state->out_buf = x_buf_alloc(sizeof(x_smb2_file_object_id_buffer_t));
			state->out_buf_length = sizeof(x_smb2_file_object_id_buffer_t);
			x_smb2_file_object_id_buffer_t *data = (x_smb2_file_object_id_buffer_t *)state->out_buf->data;
			data->object_id.data[0] = X_H2LE64(posixfs_object->get_meta().fsid);
			data->object_id.data[1] = X_H2LE64(posixfs_object->get_meta().inode);
			auto volume_uuid = smbd_object->smbd_volume->uuid;
			data->birth_volume_id.data[0] = X_H2LE64(volume_uuid.data[0]); 
			data->birth_volume_id.data[1] = X_H2LE64(volume_uuid.data[1]); 
			data->birth_volume_id = data->object_id;
			data->domain_id = {0, 0};
			return NT_STATUS_OK;
		}
	case X_SMB2_FSCTL_SRV_ENUMERATE_SNAPSHOTS:
		if (state->in_max_output_length < 16) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		{
			/* TODO enumerate snapshots from filesystem */
			state->out_buf = x_buf_alloc(16);
			state->out_buf_length = 16;
			uint32_t *p = (uint32_t *)state->out_buf->data;
			*p++ = 0;
			*p++ = 0;
			*p++ = X_H2LE32(2);
			*p = 0;
			return NT_STATUS_OK;
		}
	}

	return NT_STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS posixfs_object_op_query_allocated_ranges(
		x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream,
		std::vector<x_smb2_file_range_t> &ranges,
		uint64_t off, uint64_t max_off)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	while (off < max_off) {
		off_t data_off = lseek(posixfs_object->fd, off, SEEK_DATA);
		if (data_off == -1) {
			if (errno == ENXIO) {
				break;
			}
			return x_map_nt_error_from_unix(errno);
		}
		if (uint64_t(data_off) > max_off) {
			break;
		}
		off_t hole_off = lseek(posixfs_object->fd, data_off, SEEK_HOLE);
		if (hole_off == -1) {
			return x_map_nt_error_from_unix(errno);
		}
		if (hole_off <= data_off) {
			X_LOG_ERR("lseek inconsistent: hole %ld at or before data %ld\n",
					hole_off, data_off);
			return NT_STATUS_INTERNAL_ERROR;
		}
		ranges.push_back({uint64_t(data_off), std::min(uint64_t(hole_off), max_off) - data_off});
		off = hole_off;
	}
	return NT_STATUS_OK;
}

#include <linux/falloc.h>
NTSTATUS posixfs_object_op_set_zero_data(x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		uint64_t begin_offset,
		uint64_t end_offset)
{
	if (smbd_open->smbd_stream) {
		return NT_STATUS_NOT_SUPPORTED; // TODO
	}
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	std::lock_guard<std::mutex> lock(smbd_object->mutex);
	if (x_smbd_check_io_brl_conflict(smbd_object, smbd_open, begin_offset,
				end_offset - begin_offset, true)) {
		return NT_STATUS_FILE_LOCK_CONFLICT;
	}

	int err = fallocate(posixfs_object->fd,
			FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE,
			begin_offset, end_offset - begin_offset);
	if (err < 0) {
		X_LOG_ERR("fallocate %lu-%lu errno=%d",
				begin_offset, end_offset, errno);
		return x_map_nt_error_from_unix(errno);
	}
	return NT_STATUS_OK;
}

NTSTATUS posixfs_object_op_set_attribute(x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream,
		uint32_t attributes_modify,
		uint32_t attributes_value,
		bool &modified)
{
	if (smbd_stream) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	dos_attr_t dos_attr = { 0 };
	auto &object_meta = smbd_object->meta;
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	auto lock = std::lock_guard(posixfs_object->base.mutex);
	uint32_t new_attr = object_meta.file_attributes;
	new_attr &= ~attributes_modify;
	new_attr |= attributes_value;
	if (new_attr != object_meta.file_attributes) {
		dos_attr.attr_mask |= DOS_SET_FILE_ATTR;
		dos_attr.file_attrs = new_attr;
		posixfs_dos_attr_set(posixfs_object->fd, &dos_attr);

		x_smbd_stream_meta_t stream_meta;
		posixfs_statex_get(posixfs_object->fd, &object_meta, &stream_meta);
	}

	return NT_STATUS_OK;
}

static long posixfs_qdir_filldents(posixfs_qdir_t *posixfs_qdir,
		posixfs_object_t *posixfs_object)
{
	auto lock = std::lock_guard(posixfs_object->base.mutex);
	lseek(posixfs_object->fd, posixfs_qdir->base.pos.filepos, SEEK_SET);
	return syscall(SYS_getdents64, posixfs_object->fd,
			posixfs_qdir->data, sizeof(posixfs_qdir->data));
}

static inline bool is_dot_or_dotdot(const char *name)
{
	return name[0] == '.' && (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'));
}

static const char *posixfs_qdir_get_fs_entry(
		posixfs_qdir_t *posixfs_qdir, x_smbd_qdir_pos_t &pos,
		posixfs_object_t *posixfs_object)
{
	const char *ent_name;
	if (posixfs_qdir->save_errno != 0) {
		return nullptr;
	}
	auto &curr_pos = posixfs_qdir->base.pos;
	for (;;) {
		if (curr_pos.offset_in_block >= posixfs_qdir->data_length) {
			long retval = posixfs_qdir_filldents(posixfs_qdir, posixfs_object);
			if (retval > 0) {
				posixfs_qdir->data_length = x_convert_assert<uint32_t>(retval);
				curr_pos.offset_in_block = 0;
			} else if (retval == 0) {
				posixfs_qdir->save_errno = ENOENT;
				return nullptr;
			} else {
				posixfs_qdir->save_errno = errno;
				return nullptr;
			}
		}
		struct dirent *dp = (struct dirent *)&posixfs_qdir->data[curr_pos.offset_in_block];
		pos = curr_pos;
		++curr_pos.file_number;
		curr_pos.offset_in_block += dp->d_reclen;
		curr_pos.filepos = dp->d_off;

		ent_name = dp->d_name;
		if (is_dot_or_dotdot(ent_name) || strcmp(ent_name, ":streams") == 0) {
			continue;
		}
		break;
	}
	return ent_name;
}

bool posixfs_qdir_get_entry(x_smbd_qdir_t *smbd_qdir,
		x_smbd_qdir_pos_t &qdir_pos,
		std::u16string &ret_name,
		x_smbd_object_meta_t &object_meta,
		x_smbd_stream_meta_t &stream_meta,
		std::shared_ptr<idl::security_descriptor> *ppsd,
		const char *pseudo_entries[],
		uint32_t pseudo_entry_count,
		posixfs_qdir_entry_func_t *process_entry_func)
{
	posixfs_qdir_t *posixfs_qdir = X_CONTAINER_OF(smbd_qdir, posixfs_qdir_t,
			base);
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(
			smbd_qdir->smbd_open->smbd_object);
	for (;;) {
		const char *ent_name;
		if (smbd_qdir->pos.file_number >= pseudo_entry_count) {
			ent_name = posixfs_qdir_get_fs_entry(posixfs_qdir, qdir_pos,
					posixfs_object);
			if (!ent_name) {
				return false;
			}
		} else {
			ent_name = pseudo_entries[smbd_qdir->pos.file_number];
			qdir_pos = smbd_qdir->pos;
			++smbd_qdir->pos.file_number;
		}
		X_LOG_DBG("get_entry ent_name '%s'", ent_name);

		std::u16string name;
		if (!x_str_convert(name, std::string_view(ent_name))) {
			X_LOG_WARN("qdir_process_entry invalid name '%s'",
					ent_name);
			continue;
		}
		if (smbd_qdir->fnmatch && !x_fnmatch_match(*smbd_qdir->fnmatch,
					ent_name)) {
			continue;
		}

		if (!process_entry_func(&object_meta, &stream_meta, ppsd,
					posixfs_object, ent_name, qdir_pos.file_number)) {
			X_LOG_WARN("qdir_process_entry %s %d,0x%lx %d errno=%d",
					ent_name, qdir_pos.file_number, qdir_pos.filepos,
					qdir_pos.offset_in_block, errno);
			continue;
		}
		std::swap(ret_name, name);
		break;

	}
	return true;
}

x_smbd_qdir_t *posixfs_qdir_create(x_smbd_open_t *smbd_open, const x_smbd_qdir_ops_t *ops)
{
	posixfs_qdir_t *posixfs_qdir = new posixfs_qdir_t(smbd_open, ops);
	return &posixfs_qdir->base;
}

void posixfs_qdir_rewind(x_smbd_qdir_t *smbd_qdir)
{
	posixfs_qdir_t *posixfs_qdir = X_CONTAINER_OF(smbd_qdir, posixfs_qdir_t,
			base);
	posixfs_qdir->data_length = 0;
	posixfs_qdir->save_errno = 0;
	smbd_qdir->pos = { };
}

void posixfs_qdir_destroy(x_smbd_qdir_t *smbd_qdir)
{
	posixfs_qdir_t *posixfs_qdir = X_CONTAINER_OF(smbd_qdir, posixfs_qdir_t,
			base);
	delete posixfs_qdir;
}

/* caller hold the smbd_object->mutex */
NTSTATUS posixfs_object_op_set_delete_on_close(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		bool delete_on_close)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	return posixfs_object_set_delete_on_close(posixfs_object,
			smbd_open->smbd_stream,
			smbd_open->open_state.access_mask, delete_on_close);
}

static void posixfs_object_release_stream(posixfs_object_t *posixfs_object,
		x_smbd_stream_t *smbd_stream)
{
	if (smbd_stream) {
		posixfs_ads_t *posixfs_ads = posixfs_ads_from_smbd_stream(smbd_stream);
		auto lock = std::lock_guard(posixfs_object->base.mutex);
		posixfs_ads_release(posixfs_object, posixfs_ads);
	}
}

static NTSTATUS posixfs_open_object_by_handle(posixfs_object_t **ret,
		std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		const x_smbd_file_handle_t &file_handle)
{
	int fd = open_by_handle_at(posixfs_get_root_fd(*smbd_volume),
			(struct file_handle *)&file_handle.base, O_RDWR);
	if (fd < 0) {
		X_ASSERT(errno == ESTALE);
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}
	std::string unix_path;
	NTSTATUS status = x_smbd_volume_get_fd_path(unix_path, *smbd_volume, fd);
	if (!NT_STATUS_IS_OK(status)) {
		close(fd);
		return status;
	}

	std::u16string path;
	if (!convert_from_unix(path, unix_path)) {
		close(fd);
		return NT_STATUS_ILLEGAL_CHARACTER;
	}

	/* TODO reuse the fd previous opened */
	x_smbd_object_t *smbd_object;
       	status = x_smbd_open_object(&smbd_object, smbd_volume, path, 0, true);
	if (!NT_STATUS_IS_OK(status)) {
		close(fd);
		return status;
	}

	if (smbd_object->file_handle.cmp(file_handle) != 0) {
		close(fd);
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	close(fd);
	
	*ret = posixfs_object_from_base_t::container(smbd_object);
	return NT_STATUS_OK;
}

NTSTATUS posixfs_op_open_durable(x_smbd_open_t *&smbd_open,
		std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		const x_smbd_durable_t &smbd_durable)
{
	posixfs_object_t *posixfs_object;
	NTSTATUS status = posixfs_open_object_by_handle(&posixfs_object,
			smbd_volume, smbd_durable.file_handle);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
#if 0
	TODO lease
	x_smbd_lease_t *smbd_lease = nullptr;
	if (smbd_durable->oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE) {
		smbd_lease = x_smbd_lease_find(
				smbd_durable.client_guid,
				smbd_durable.lease_key,
				smbd_durable.lease.version,
				true);
		bool new_lease = false;
		posixfs_stream_t *posixfs_stream = posixfs_object->default_stream;
		bool ret = x_smbd_lease_grant(smbd_lease,
				smbd_durable.lease,
				smbd_durable.lease.state,
				smbd_durable.lease.state,
				&posixfs_object->base, &posixfs_stream->base,
				new_lease);
		if (new_lease) {
			/* it hold the ref of object, so it is ok the incref after lease
			 * TODO eventually it should incref inside x_smbd_lease_grant
			 */
			posixfs_object_incref(posixfs_object);
			posixfs_stream_incref(posixfs_stream);
		}
	}
	x_smbd_open_state_t open_state{
		smbd_durable.open_state.client_guid,
		smbd_durable.open_state.create_guid,
		smbd_durable.open_state.owner,
		smbd_durable.open_state.parent_lease_key,
		smbd_durable.open_state.priv_data,
		X_SMB2_OPLOCK_LEVEL_NONE, // TODO
		smbd_durable.open_state.delete_on_close,
		smbd_durable.open_state.durable_timeout_msec,
		smbd_durable.open_state.current_offset};
#endif

	posixfs_open_t *posixfs_open = posixfs_open_create(&status,
			nullptr,
			posixfs_object, nullptr,
			nullptr, smbd_durable.open_state, 0);
	
	if (posixfs_open) {
		smbd_open = &posixfs_open->base;
		return NT_STATUS_OK;
	} else {
		smbd_open = nullptr;
		return status;
	}

	return NT_STATUS_INTERNAL_ERROR;
}


void posixfs_op_release_object(x_smbd_object_t *smbd_object, x_smbd_stream_t *smbd_stream)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	if (smbd_stream) {
		posixfs_object_release_stream(posixfs_object, smbd_stream);
	}
	x_smbd_release_object(&posixfs_object->base);
}

static NTSTATUS posixfs_delete_object(posixfs_object_t *posixfs_object)
{
	int err = unlinkat(posixfs_object_get_fd(posixfs_object->base.parent_object),
			posixfs_object->unix_path_base.c_str(),
			posixfs_object_is_dir(posixfs_object) ? AT_REMOVEDIR : 0);
	if (err != 0) {
		X_TODO_ASSERT(errno == ENOTEMPTY);
		return NT_STATUS_DIRECTORY_NOT_EMPTY;
	}

	err = close(posixfs_object->fd);
	X_ASSERT(err == 0);
	posixfs_object->fd = -1;
	posixfs_object->statex_modified = true;
	return NT_STATUS_OK;
}

NTSTATUS posixfs_op_object_delete(x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream,
		x_smbd_open_t *smbd_open)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	if (!smbd_stream) {
		posixfs_ads_foreach_1(posixfs_object, [smbd_object, smbd_open] (
					const char *xattr_name,
					const char *stream_name) {
				std::u16string u16_name;
				if (x_str_convert(u16_name, std::string_view(stream_name))) {
					x_smbd_schedule_notify(
							NOTIFY_ACTION_REMOVED_STREAM,
							FILE_NOTIFY_CHANGE_STREAM_NAME,
							smbd_open->open_state.parent_lease_key,
							smbd_open->open_state.client_guid,
							smbd_object->parent_object,
							nullptr,
							smbd_object->path_base + u':' + u16_name,
							{});
				} else {
					X_LOG_ERR("invalid stream_name '%s'", stream_name);
				}
				return true;
			});

		NTSTATUS status = posixfs_delete_object(posixfs_object);
		if (!NT_STATUS_IS_OK(status)) {
			X_LOG_WARN("fail to unlink %s status=%x",
					posixfs_object->unix_path_base.c_str(),
					NT_STATUS_V(status));
			return status;
		}
	} else {
		posixfs_ads_t *posixfs_ads = posixfs_ads_from_smbd_stream(
				smbd_stream);
		int ret = fremovexattr(posixfs_object->fd, posixfs_ads->xattr_name.c_str());
		X_TODO_ASSERT(ret == 0);
	}

	return NT_STATUS_OK;
}

uint32_t posixfs_op_get_attributes(const x_smbd_object_t *smbd_object)
{
	const posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	return posixfs_object->get_meta().file_attributes;
}

posixfs_object_t::posixfs_object_t(
		uint64_t h,
		const std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		x_smbd_object_t *parent_object,
		const std::u16string &path_base, long path_data)
	: base(smbd_volume, parent_object, path_data, h, path_base)
{
}

int x_smbd_posixfs_init(size_t max_open)
{
	x_smbd_posixfs_init_dev();
	return 0;
}

int posixfs_object_get_statex(const posixfs_object_t *posixfs_object,
		x_smbd_object_meta_t *object_meta,
		x_smbd_stream_meta_t *stream_meta)
{
	*object_meta = posixfs_object->get_meta();
	*stream_meta = posixfs_object->base.sharemode.meta;
	return 0;
}

/* posixfs_object must be directory */
int posixfs_object_get_parent_statex(const posixfs_object_t *dir_obj,
		x_smbd_object_meta_t *object_meta,
		x_smbd_stream_meta_t *stream_meta)
{
	x_smbd_object_t *parent_object = dir_obj->base.parent_object;
	if (parent_object) {
		dir_obj = posixfs_object_from_base_t::container(parent_object);
	}
	return posixfs_object_get_statex(dir_obj, object_meta, stream_meta);
}

int posixfs_object_statex_getat(posixfs_object_t *dir_obj, const char *name,
		x_smbd_object_meta_t *object_meta,
		x_smbd_stream_meta_t *stream_meta,
		std::shared_ptr<idl::security_descriptor> *ppsd)
{
	return posixfs_statex_getat(dir_obj->fd, name, object_meta, stream_meta, ppsd);
}
#if 0
int posixfs_mktld(const std::shared_ptr<x_smbd_user_t> &smbd_user,
		const x_smbd_volume_t &smbd_volume,
		const std::string &name,
		std::vector<uint8_t> &ntacl_blob)
{
	std::shared_ptr<idl::security_descriptor> top_psd, psd;
	NTSTATUS status = posixfs_get_sd(smbd_volume.rootdir_fd, top_psd);
	X_ASSERT(NT_STATUS_IS_OK(status));

	status = make_child_sec_desc(psd, top_psd,
			*smbd_user, true);
	X_ASSERT(NT_STATUS_IS_OK(status));

	create_acl_blob(ntacl_blob, psd, idl::XATTR_SD_HASH_TYPE_NONE, std::array<uint8_t, idl::XATTR_SD_HASH_SIZE>());

	x_smbd_object_meta_t object_meta;
	x_smbd_stream_meta_t stream_meta;
	/* if parent is not enable inherit, make_sec_desc */
	int fd = posixfs_create(smbd_volume.rootdir_fd,
			true,
			name.c_str(),
			&object_meta, &stream_meta,
			0, 0,
			ntacl_blob);

	X_ASSERT(fd != -1);
	close(fd);
	return 0;
}
#endif
NTSTATUS x_smbd_posixfs_create_object(x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream,
		const x_smbd_user_t &smbd_user,
		x_smb2_state_create_t &state,
		uint32_t file_attributes,
		uint64_t allocation_size)
{
	NTSTATUS status;
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	std::shared_ptr<idl::security_descriptor> psd;
	uint32_t create_count = 0;
	if (!posixfs_object->exists()) {
		status = posixfs_new_object(posixfs_object, smbd_user,
				state, file_attributes,
				allocation_size, psd);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		++create_count;
		x_smbd_schedule_notify(
				NOTIFY_ACTION_ADDED,
				uint16_t((state.in_create_options & X_SMB2_CREATE_OPTION_DIRECTORY_FILE) ? FILE_NOTIFY_CHANGE_DIR_NAME : FILE_NOTIFY_CHANGE_FILE_NAME),
				state.lease.parent_key,
				x_smbd_conn_curr_client_guid(),
				smbd_object->parent_object,
				nullptr,
				smbd_object->path_base,
				{});

	} else {
		status = posixfs_object_get_sd__(posixfs_object, psd);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	if (smbd_stream && !smbd_stream->exists) {
		// TODO should it fail for large in_allocation_size?
		++create_count;
		uint32_t allocation_size = x_convert_assert<uint32_t>(
				std::min(state.in_allocation_size, posixfs_ads_max_length));
		posixfs_ads_t *posixfs_ads = posixfs_ads_from_smbd_stream(smbd_stream);
		posixfs_ads->xattr_name = posixfs_get_ads_xattr_name(
				x_str_convert_assert<std::string>(smbd_stream->name));
		posixfs_ads_reset(posixfs_object, posixfs_ads, allocation_size);

		x_smbd_schedule_notify(
				NOTIFY_ACTION_ADDED_STREAM,
				FILE_NOTIFY_CHANGE_STREAM_NAME,
				state.lease.parent_key,
				x_smbd_conn_curr_client_guid(),
				smbd_object->parent_object,
				nullptr,
				smbd_object->path_base + u":" + smbd_stream->name,
				{});
	}

	X_ASSERT(create_count > 0);
	posixfs_access_check_new(*psd, smbd_user, state);
	return status;
}

static uint32_t posixfs_access_check(
		posixfs_object_t *posixfs_object,
		uint32_t &granted_access,
		uint32_t &maximal_access,
		x_smbd_tcon_t *smbd_tcon,
		const x_smbd_user_t &smbd_user,
		const idl::security_descriptor &sd,
		const uint32_t in_desired_access,
		bool overwrite)
{
	uint32_t share_access = x_smbd_tcon_get_share_access(smbd_tcon);
	uint32_t out_maximal_access = se_calculate_maximal_access(sd, smbd_user);
	out_maximal_access &= share_access;

	if (overwrite && (out_maximal_access & idl::SEC_FILE_WRITE_DATA) == 0) {
		return idl::SEC_FILE_WRITE_DATA;
	}

	// No access check needed for attribute opens.
	if ((in_desired_access & ~(idl::SEC_FILE_READ_ATTRIBUTE | idl::SEC_STD_SYNCHRONIZE)) == 0) {
		granted_access = in_desired_access;
		maximal_access = out_maximal_access;
		return 0;
	}

	uint32_t desired_access = in_desired_access & ~idl::SEC_FLAG_MAXIMUM_ALLOWED;

	uint32_t granted = out_maximal_access;
	if (in_desired_access & idl::SEC_FLAG_MAXIMUM_ALLOWED) {
		if (posixfs_object->get_meta().file_attributes & X_SMB2_FILE_ATTRIBUTE_READONLY) {
			granted &= ~(idl::SEC_FILE_WRITE_DATA | idl::SEC_FILE_APPEND_DATA);
		}
		granted |= idl::SEC_FILE_READ_ATTRIBUTE;
		if (!(granted & idl::SEC_STD_DELETE)) {
			if (can_delete_file_in_directory(posixfs_object,
						smbd_tcon, smbd_user)) {
				granted |= idl::SEC_STD_DELETE;
			}
		}
	} else {
		granted = (desired_access & out_maximal_access);
	}

	uint32_t rejected_mask = desired_access & ~granted;
	if ((rejected_mask & idl::SEC_STD_DELETE) && !(in_desired_access
				& idl::SEC_FLAG_MAXIMUM_ALLOWED)) {
		if (can_delete_file_in_directory(posixfs_object,
					smbd_tcon, smbd_user)) {
			granted |= idl::SEC_STD_DELETE;
			rejected_mask &= ~idl::SEC_STD_DELETE;
		}
	}
	granted_access = granted;
	maximal_access = out_maximal_access;
	return rejected_mask;
}

NTSTATUS x_smbd_posixfs_op_access_check(x_smbd_object_t *smbd_object,
		uint32_t &granted_access,
		uint32_t &maximal_access,
		x_smbd_tcon_t *smbd_tcon,
		const x_smbd_user_t &smbd_user,
		uint32_t desired_access,
		bool overwrite)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	std::shared_ptr<idl::security_descriptor> psd;
	NTSTATUS status = posixfs_object_get_sd__(posixfs_object, psd);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	uint32_t rejected_mask = posixfs_access_check(posixfs_object, 
			granted_access, maximal_access,
			smbd_tcon, smbd_user,
			*psd,
			desired_access, overwrite);

	if (rejected_mask & idl::SEC_FLAG_SYSTEM_SECURITY) {
		if (smbd_user.priviledge_mask & idl::SEC_PRIV_SECURITY_BIT) {
			granted_access |= idl::SEC_FLAG_SYSTEM_SECURITY;
			rejected_mask &= ~idl::SEC_FLAG_SYSTEM_SECURITY;
		} else {
			return NT_STATUS_PRIVILEGE_NOT_HELD;
		}
	}

        if (rejected_mask & idl::SEC_STD_WRITE_OWNER) {
		if (smbd_user.priviledge_mask & idl::SEC_PRIV_TAKE_OWNERSHIP_BIT) {
			granted_access |= idl::SEC_STD_WRITE_OWNER;
			rejected_mask &= ~idl::SEC_STD_WRITE_OWNER;
		}
        }

	if (rejected_mask != 0) {
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_OK;
}

static uint32_t filter_attributes(uint32_t new_attr, uint32_t curr_attr)
{
	new_attr &= X_NXSMB_FILE_ATTRIBUTE_MASK;
	new_attr &= ~(X_SMB2_FILE_ATTRIBUTE_NORMAL);
	if ((curr_attr & X_SMB2_FILE_ATTRIBUTE_DIRECTORY) != 0) {
		if (new_attr & (X_SMB2_FILE_ATTRIBUTE_ARCHIVE
					| X_SMB2_FILE_ATTRIBUTE_TEMPORARY)) {
			return 0;
		}
		new_attr |= X_SMB2_FILE_ATTRIBUTE_DIRECTORY;
	} else {
		if (new_attr & X_SMB2_FILE_ATTRIBUTE_DIRECTORY) {
			return 0;
		}
		new_attr |= X_SMB2_FILE_ATTRIBUTE_ARCHIVE;
	}
	return new_attr;
}

/* smbd_object's mutex is locked */
NTSTATUS x_smbd_posixfs_create_open(x_smbd_open_t **psmbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state,
		bool overwrite,
		x_smb2_create_action_t create_action,
		uint8_t oplock_level)
{
	NTSTATUS status;
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(state->smbd_object);

	posixfs_open_t *posixfs_open = nullptr;

	posixfs_open = posixfs_open_create(&status, smbd_requ->smbd_tcon,
			posixfs_object, *state, create_action, oplock_level);
	if (!posixfs_open) {
		return status;
	}

	bool reload_meta = false;
	if (overwrite) {
		// TODO DELETE_ALL_STREAM;
		uint32_t notify_actions = 0;
		if (state->smbd_object->type == x_smbd_object_t::type_file) {
			int err = ftruncate(posixfs_object->fd, 0);
			X_TODO_ASSERT(err == 0);
			notify_actions |= FILE_NOTIFY_CHANGE_SIZE;
		}

		if (state->in_file_attributes != 0) {
			auto &meta = posixfs_object->get_meta();
			auto curr_attr = meta.file_attributes;
			auto file_attr = filter_attributes(state->in_file_attributes,
					curr_attr);
			if (file_attr != 0 && file_attr != curr_attr) {
				dos_attr_t dos_attr = { 0 };
				dos_attr.attr_mask = DOS_SET_FILE_ATTR;
				dos_attr.file_attrs = file_attr;
				dos_attr.create_time = x_nttime_to_timespec(meta.creation);
				posixfs_dos_attr_set(posixfs_object->fd, &dos_attr);
				notify_actions |= FILE_NOTIFY_CHANGE_ATTRIBUTES;
			}
		}
		x_smbd_schedule_notify(
				NOTIFY_ACTION_MODIFIED,
				notify_actions,
				state->lease.parent_key,
				x_smbd_conn_curr_client_guid(),
				state->smbd_object->parent_object, nullptr,
				posixfs_object->base.path_base, {});
		reload_meta = true;
	} else if (create_action != x_smb2_create_action_t::WAS_CREATED
			&& (state->in_contexts & X_SMB2_CONTEXT_FLAG_ALSI)) {
		status = posixfs_set_allocation_size_intl(posixfs_object,
				nullptr,
				state->in_allocation_size,
				state->smbd_lease,
				oplock_level);
		X_TODO_ASSERT(NT_STATUS_IS_OK(status));
	}

	if (reload_meta) {
		int err = posixfs_statex_get(posixfs_object->fd,
				&posixfs_object->get_meta(),
				&posixfs_object->base.sharemode.meta);
		X_TODO_ASSERT(err == 0);
		if ((state->in_contexts & X_SMB2_CONTEXT_FLAG_ALSI)) {
			posixfs_object->base.sharemode.meta.allocation_size =
				state->in_allocation_size;
		}
		posixfs_object->statex_modified = false;
	}

	*psmbd_open = &posixfs_open->base;
	return NT_STATUS_OK;
}

void x_smbd_posixfs_op_lease_granted(x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	posixfs_object_incref(posixfs_object);
	if (smbd_stream) {
		posixfs_ads_t *posixfs_ads = posixfs_ads_from_smbd_stream(smbd_stream);
		posixfs_ads_incref(posixfs_ads);
	}
}

ssize_t posixfs_object_getxattr(x_smbd_object_t *smbd_object,
		const char *xattr_name, void *buf, size_t bufsize)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	return fgetxattr(posixfs_object->fd, xattr_name, buf, bufsize);
}

static int smbd_volume_read(int vol_fd,
		uint16_t &vol_id,
		int &rootdir_fd, x_smbd_durable_db_t *&durable_db)
{
	uint16_t id;
	int err = x_smbd_volume_read_id(vol_fd, id);
	if (err) {
		return err;
	}

	int rfd = openat(vol_fd, "root", O_RDONLY);
	if (rfd < 0) {
		X_LOG_ERR("cannot open rootdir, errno=%d", errno);
		return -errno;
	}

	struct stat st;
	X_ASSERT(fstat(rfd, &st) == 0);
	if (!S_ISDIR(st.st_mode)) {
		X_LOG_ERR("root is not directory");
		close(rfd);
		return -EINVAL;
	}

	int durable_fd = openat(vol_fd, "durable.db", O_RDWR | O_CREAT, 0644);
	X_ASSERT(durable_fd != 0);

	durable_db = x_smbd_durable_db_init(durable_fd,
			0x100000); /* TODO the number */

	vol_id = id;
	rootdir_fd = rfd;
	return 0;
}

static posixfs_object_t *posixfs_create_root_object(
		std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		int rootdir_fd)
{
	posixfs_object_t *posixfs_object = new posixfs_object_t(0, smbd_volume, nullptr,
			u"", 0);

	auto lock = std::lock_guard(posixfs_object->base.mutex);
	int err = posixfs_statex_get(rootdir_fd,
			&posixfs_object->get_meta(),
			&posixfs_object->base.sharemode.meta);
	X_ASSERT(err == 0);
	posixfs_object_set_fd(posixfs_object, rootdir_fd);
	posixfs_object->base.flags = x_smbd_object_t::flag_initialized;
	return posixfs_object;
}

int posixfs_op_init_volume(std::shared_ptr<x_smbd_volume_t> &smbd_volume)
{
	uint16_t vol_id = 0xffffu;
	int rootdir_fd = -1;
	x_smbd_durable_db_t *durable_db;

	if (!smbd_volume->path.empty()) {
		int vol_fd = open(smbd_volume->path.c_str(), O_RDONLY);
		if (vol_fd < 0) {
			X_LOG_ERR("cannot open volume %s, %d",
					smbd_volume->name_8.c_str(), errno);
			return -1;
		}

		int ret = smbd_volume_read(vol_fd, vol_id, rootdir_fd, durable_db);
		close(vol_fd);
		if (ret < 0) {
			X_LOG_ERR("cannot read volume %s, %d",
					smbd_volume->name_8.c_str(), -ret);
			return -1;
		}
	}

	X_LOG_NOTICE("volume '%s' with id=0x%x",
			smbd_volume->name_8.c_str(), vol_id);

	smbd_volume->volume_id = vol_id;
	smbd_volume->smbd_durable_db = durable_db;

	posixfs_object_t *posixfs_root_object = posixfs_create_root_object(smbd_volume, rootdir_fd);
	smbd_volume->root_object = &posixfs_root_object->base;

	x_smbd_volume_restore_durable(smbd_volume);
	return 0;
}

NTSTATUS posixfs_op_allocate_object(x_smbd_object_t **p_smbd_object,
		const std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		long priv_data,
		uint64_t hash,
		x_smbd_object_t *parent_object,
		const std::u16string &path_base)
{
	posixfs_object_t *posixfs_object = new posixfs_object_t(hash,
			smbd_volume, parent_object, path_base, priv_data);
	*p_smbd_object = &posixfs_object->base;
	return NT_STATUS_OK;
}

void posixfs_op_destroy_object(x_smbd_object_t *smbd_object)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	delete posixfs_object;
}

NTSTATUS posixfs_op_initialize_object(x_smbd_object_t *smbd_object)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	std::string unix_path_base;
	X_ASSERT(convert_to_unix(unix_path_base, smbd_object->path_base));

	int fd = posixfs_openat(posixfs_object_get_fd(smbd_object->parent_object),
			unix_path_base.c_str(),
			&posixfs_object->get_meta(),
			&posixfs_object->base.sharemode.meta);
	posixfs_object->unix_path_base = unix_path_base;
	if (fd < 0) {
		posixfs_object->base.type = x_smbd_object_t::type_not_exist;
		if (errno == ENOENT) {
		} else {
			X_ASSERT(errno == ENOTDIR);
			return NT_STATUS_OBJECT_PATH_NOT_FOUND;
		}
	} else {
		posixfs_object_set_fd(posixfs_object, fd);
	}
	return NT_STATUS_OK;
}

NTSTATUS posixfs_op_open_stream(x_smbd_object_t *smbd_object,
		x_smbd_stream_t **p_smbd_stream,
		const std::u16string &ads_name)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	auto [ok, posixfs_ads] = posixfs_ads_open(
			posixfs_object, ads_name, false);
	if (!ok) {
		return NT_STATUS_ILLEGAL_CHARACTER;
	}
	*p_smbd_stream = &posixfs_ads->base;
	return NT_STATUS_OK;
}

void posixfs_op_release_stream(
		x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream)
{
	posixfs_object_t *posixfs_object = posixfs_object_from_base_t::container(smbd_object);
	posixfs_object_release_stream(posixfs_object, smbd_stream);
}

void posixfs_op_destroy_open(x_smbd_open_t *smbd_open)
{
	posixfs_open_t *posixfs_open = posixfs_open_from_base_t::container(smbd_open);
	delete posixfs_open;
}


