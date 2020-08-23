
#include "smbd.hxx"
#include "include/charset.hxx"
#include "include/hashtable.hxx"
#include <functional>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define FS_IOC_GET_DOS_ATTR             _IOR('t', 1, dos_attr_t)
#define FS_IOC_SET_DOS_ATTR             _IOW('t', 2, dos_attr_t)
typedef struct dos_attr_s {
	uint32_t attr_mask;
	uint32_t file_attrs;
	struct timespec create_time;
	char scan_stamp[32];
} dos_attr_t;

#if 0
enum x_smbd_path_type_t {
	t_normal,
	t_shard_root,
	t_tld,
};
#endif
enum {
	PATH_FLAG_ROOT,
	PATH_FLAG_TLD,
};

struct x_smbd_statex_t
{
	x_smbd_statex_t() {
		stat.st_nlink = 0;
	}
	bool is_valid() const {
		return stat.st_nlink != 0;
	}
	void invalidate() {
		stat.st_nlink = 0;
	}
	struct stat stat;
	struct timespec birth_time;
	uint32_t file_attributes;
};

struct x_smbd_disk_object_t
{
#if 0
	void incref() {
		X_ASSERT(refcnt++ > 0);
	}
#endif
	void decref();

	x_smbd_disk_object_t(const uuid_t &u, const std::string &p) : share_uuid(u), path(p) { }
	~x_smbd_disk_object_t() {
		if (fd != -1) {
			close(fd);
		}
		statex.invalidate();
	}

	bool exists() const { return fd != -1; }
#if 0
	void clear() {
		if (fd != -1) {
			close(fd);
		}
		fd = -1;
	}
#endif
	x_dqlink_t hash_link;
	x_dlink_t free_link;
	std::mutex mutex;
	int fd = -1;
	int open_count = 0;

	enum {
		flag_unknown = 1,
		flag_not_exist = 2,
		flag_delete_on_close = 0x1000,
	};

	uint32_t flags;
	// bool delete_on_close = false;
	x_smbd_statex_t statex;
	const uuid_t share_uuid;
	const std::string path; // TODO duplicated, it is also a key in map
};
X_DECLARE_MEMBER_TRAITS(smbd_disk_object_hash_traits, x_smbd_disk_object_t, hash_link)
X_DECLARE_MEMBER_TRAITS(smbd_disk_object_free_traits, x_smbd_disk_object_t, free_link)

struct x_smbd_disk_object_pool_t
{
	x_smbd_disk_object_t *find_or_create(const uuid_t &share_uuid, const std::string &path);
	void release(x_smbd_disk_object_t *disk_object);

	x_hashtable_t<smbd_disk_object_hash_traits> hashtable;
	x_tp_ddlist_t<smbd_disk_object_free_traits> free_list;
	uint32_t capacity, count = 0;
	// std::map<std::string, std::shared_ptr<x_smbd_disk_object_t>> objects;
	std::mutex mutex;
};

static x_smbd_disk_object_pool_t smbd_disk_object_pool;

x_smbd_disk_object_t *x_smbd_disk_object_pool_t::find_or_create(
		const uuid_t &share_uuid,
		const std::string &path)
{
	auto hash = std::hash<std::string>()(path);
	std::unique_lock<std::mutex> lock(mutex);
	x_smbd_disk_object_t *disk_object = hashtable.find(hash, [&share_uuid, &path](const x_smbd_disk_object_t &o) {
			return o.share_uuid == share_uuid && o.path == path;
			});

	if (!disk_object) {
		if (count == capacity) {
			disk_object = free_list.get_front();
			if (!disk_object) {
				return nullptr;
			}
			disk_object->~x_smbd_disk_object_t();
			new (disk_object) x_smbd_disk_object_t(share_uuid, path);
			return disk_object;
		}
		disk_object = new x_smbd_disk_object_t(share_uuid, path);
		++count;
		smbd_disk_object_pool.hashtable.insert(disk_object, hash);
	}

	++disk_object->open_count;
	return disk_object;
}

void x_smbd_disk_object_pool_t::release(x_smbd_disk_object_t *disk_object)
{
	{
		std::unique_lock<std::mutex> lock(mutex);
		X_ASSERT(disk_object->open_count > 0);
		if (--disk_object->open_count) {
			return;
		}
		free_list.push_back(disk_object);
	}
	std::unique_lock<std::mutex> lock(disk_object->mutex);
	if (disk_object->flags & x_smbd_disk_object_t::flag_delete_on_close) {
		int err = unlink(disk_object->path.c_str());
		X_ASSERT(err == 0);
		err = close(disk_object->fd);
		X_ASSERT(err == 0);
		disk_object->fd = -1;
		disk_object->flags = x_smbd_disk_object_t::flag_not_exist;
	}
}

void x_smbd_disk_object_t::decref()
{
	smbd_disk_object_pool.release(this);
}

struct x_smbd_disk_open_t
{
	x_smbd_disk_open_t(x_auto_ref_t<x_smbd_disk_object_t> &disk_object)
		: disk_object(std::move(disk_object)) { }

	x_smbd_tcon_t *get_tcon() const {
		return base.smbd_tcon.get();
	}

	x_smbd_open_t base;
	std::string in_path;
	// std::string unix_path;
	// uint32_t path_flags = 0;

	x_auto_ref_t<x_smbd_disk_object_t> disk_object;
};

static inline x_smbd_disk_open_t *from_smbd_open(x_smbd_open_t *smbd_open)
{
	return X_CONTAINER_OF(smbd_open, x_smbd_disk_open_t, base);
}

static NTSTATUS x_smbd_disk_open_read(x_smbd_open_t *smbd_open, const x_smb2_requ_read_t &requ,
			std::vector<uint8_t> &output)
{
	X_TODO;
	return NT_STATUS_OK;
}

static NTSTATUS x_smbd_disk_open_write(x_smbd_open_t *smbd_open,
		const x_smb2_requ_write_t &requ,
		const uint8_t *data, x_smb2_resp_write_t &resp)
{
	X_TODO;
	return NT_STATUS_OK;
}

static NTSTATUS x_smbd_disk_open_getinfo(x_smbd_open_t *smbd_open, const x_smb2_requ_getinfo_t &requ, std::vector<uint8_t> &output)
{
	X_TODO;
	return NT_STATUS_OK;
}

static NTSTATUS x_smbd_disk_open_ioctl(x_smbd_open_t *smbd_open,
		uint32_t ctl_code,
		const uint8_t *in_input_data,
		uint32_t in_input_size,
		uint32_t in_max_output,
		std::vector<uint8_t> &output)
{
	X_TODO;
	return NT_STATUS_OK;
}

static void reply_requ_create(x_smb2_requ_create_t &requ_create,
		const x_smbd_disk_object_t *disk_object,
		uint32_t create_action)
{
	requ_create.out_oplock_level = 0;
	requ_create.out_create_flags = 0;
	requ_create.out_create_action = create_action;
	requ_create.out_create_ts = x_timespec_to_nttime(disk_object->statex.birth_time);
	requ_create.out_last_access_ts = x_timespec_to_nttime(disk_object->statex.stat.st_atim);
	requ_create.out_last_write_ts = x_timespec_to_nttime(disk_object->statex.stat.st_mtim);
	requ_create.out_change_ts = x_timespec_to_nttime(disk_object->statex.stat.st_ctim);
	requ_create.out_file_attributes = disk_object->statex.file_attributes;
	requ_create.out_allocation_size = disk_object->statex.stat.st_blocks * 512;
	requ_create.out_end_of_file = disk_object->statex.stat.st_size;
}

static NTSTATUS x_smbd_disk_open_close(x_smbd_open_t *smbd_open,
		const x_smb2_requ_close_t &requ, x_smb2_resp_close_t &resp)
{
	x_smbd_disk_open_t *disk_open = from_smbd_open(smbd_open);
	x_auto_ref_t<x_smbd_disk_object_t> disk_object{std::move(disk_open->disk_object)};
	X_ASSERT(disk_object);

	if (requ.flags & SMB2_CLOSE_FLAGS_FULL_INFORMATION) {
		std::unique_lock<std::mutex> lock(disk_object->mutex);
		resp.out_create_ts = x_timespec_to_nttime(disk_object->statex.birth_time);
		resp.out_last_access_ts = x_timespec_to_nttime(disk_object->statex.stat.st_atim);
		resp.out_last_write_ts = x_timespec_to_nttime(disk_object->statex.stat.st_mtim);
		resp.out_change_ts = x_timespec_to_nttime(disk_object->statex.stat.st_ctim);
		resp.out_file_attributes = disk_object->statex.file_attributes;
		resp.out_allocation_size = disk_object->statex.stat.st_blocks * 512;
		resp.out_end_of_file = disk_object->statex.stat.st_size;
	}
	resp.struct_size = 0x3c;

	return NT_STATUS_OK;
}


static void x_smbd_disk_open_destroy(x_smbd_open_t *smbd_open)
{
	x_smbd_disk_open_t *disk_open = from_smbd_open(smbd_open);
	delete disk_open;
}

static const x_smbd_open_ops_t x_smbd_disk_open_ops = {
	x_smbd_disk_open_read,
	x_smbd_disk_open_write,
	x_smbd_disk_open_getinfo,
	nullptr,
	x_smbd_disk_open_ioctl,
	x_smbd_disk_open_close,
	x_smbd_disk_open_destroy,
};

static NTSTATUS resolve_path(x_smbd_tcon_t *tcon, const char *in_path,
		std::string &out_path, uint32_t &flags)
{
	flags = 0;
	if (!*in_path) {
		flags |= PATH_FLAG_ROOT;
	} else {
		out_path = in_path;
		for (size_t i = 0; i < out_path.length(); ++i) {
			if (out_path[i] == '\\') {
				out_path[i] = '/';
			}
		}
	}
#if 0
	if (disk_open->base.smbd_tcon->get_share_type() == TYPE_HOME) {
		if (*path == '\0') {
			disk_open->type = t_shard_root;
		} else {
			disk_open->type = ...;
		}
		return NT_STATUS_OK;
	} else if (disk_conn->smbd_tcon->get_share_type() == DEFAULT) {
		// TODO
	}
#endif
	return NT_STATUS_OK;
}

static NTSTATUS check_parent_access(uint32_t access)
{
	// TODO
	return NT_STATUS_OK;
}

static NTSTATUS check_access(x_smbd_disk_object_t *disk_object, uint32_t access)
{
	// TODO
	return NT_STATUS_OK;
}

static int get_full_path(const x_smbd_tcon_t *tcon,
		const x_smbd_disk_object_t *disk_object, std::string &full_path)
{
	full_path = tcon->smbd_share->path;
	if (disk_object->path.length()) {
		full_path += '/';
		full_path += disk_object->path;
	}
	return 0;
}

static int get_metadata(x_smbd_disk_object_t *disk_object)
{
	// get stats as well as dos attr ...
	X_ASSERT(fstat(disk_object->fd, &disk_object->statex.stat) == 0);
	dos_attr_t dos_attr;
	int err = ioctl(disk_object->fd, FS_IOC_GET_DOS_ATTR, &dos_attr);
	X_ASSERT(err == 0);
	disk_object->statex.birth_time = dos_attr.create_time;
	disk_object->statex.file_attributes = dos_attr.file_attrs;

	return 0;
}

static NTSTATUS create_dir(x_smbd_tcon_t *smbd_tcon,
		x_smbd_disk_object_t *disk_object)
{
	std::string full_path;
	X_ASSERT(get_full_path(smbd_tcon, disk_object, full_path) == 0);
	int err = mkdir(full_path.c_str(), 0777);
	if (err == 0) {
		int fd = open(full_path.c_str(), O_RDONLY);
		X_ASSERT(fd >= 0);
		disk_object->fd = fd;

		get_metadata(disk_object);
		return NT_STATUS_OK;
	}

	X_ASSERT(errno == EEXIST);
	return NT_STATUS_OBJECT_NAME_COLLISION;
}

static NTSTATUS create_file(x_smbd_tcon_t *smbd_tcon,
		x_smbd_disk_object_t *disk_object)
{
	std::string full_path;
	X_ASSERT(get_full_path(smbd_tcon, disk_object, full_path) == 0);
	int fd = open(full_path.c_str(), O_RDWR | O_CREAT | O_EXCL, 0666);
	if (fd >= 0) {
		disk_object->fd = fd;
		get_metadata(disk_object);
		return NT_STATUS_OK;
	}

	X_ASSERT(errno == EEXIST);
	return NT_STATUS_OBJECT_NAME_COLLISION;
}

static int open_exist_path(x_smbd_disk_object_t *disk_object, const std::string &full_path)
{
	X_ASSERT(disk_object->fd == -1);

	int fd = open(full_path.c_str(), O_RDWR);
	if (fd >= 0) {
		disk_object->fd = fd;
		return 0;
	}
	if (errno != EISDIR) {
		return -errno;
	}
	fd = open(full_path.c_str(), O_RDONLY);
	if (fd >= 0) {
		disk_object->fd = fd;
		return 0;
	}
	return -errno;
}

static x_smbd_open_t *create_disk_open(std::shared_ptr<x_smbd_tcon_t>& smbd_tcon,
		x_auto_ref_t<x_smbd_disk_object_t> &disk_object)
{
	x_smbd_disk_open_t *disk_open = new x_smbd_disk_open_t{disk_object};
	disk_open->base.ops = &x_smbd_disk_open_ops;
	disk_open->base.smbd_tcon = smbd_tcon;
	return &disk_open->base;
}

static x_smbd_open_t *open_object_new(
		std::shared_ptr<x_smbd_tcon_t> &smbd_tcon,
		x_auto_ref_t<x_smbd_disk_object_t> &disk_object,
		x_smb2_requ_create_t &requ_create,
		NTSTATUS &status)
{
	status = check_parent_access(idl::SEC_DIR_ADD_FILE);
	if (!NT_STATUS_IS_OK(status)) {
		return nullptr;
	}

	if (requ_create.in_create_options & FILE_DIRECTORY_FILE) {
		status = create_dir(smbd_tcon.get(), disk_object);
	} else {
		status = create_file(smbd_tcon.get(), disk_object);
	}

	if (!NT_STATUS_IS_OK(status)) {
		return nullptr;
	}

	reply_requ_create(requ_create, disk_object, FILE_WAS_CREATED);
	return create_disk_open(smbd_tcon, disk_object);
}

static x_smbd_open_t *open_object_exist(
		std::shared_ptr<x_smbd_tcon_t> &smbd_tcon,
		x_auto_ref_t<x_smbd_disk_object_t> &disk_object,
		x_smb2_requ_create_t &requ_create,
		NTSTATUS &status)
{
	status = check_access(disk_object, requ_create.in_desired_access);
	if (!NT_STATUS_IS_OK(status)) {
		return nullptr;
	}
	reply_requ_create(requ_create, disk_object, FILE_WAS_OPENED);
	return create_disk_open(smbd_tcon, disk_object);
}

/*
 * if CREATE then
 * 	if is root then
 * 		return NT_STATUS_OBJECT_NAME_COLLISION
 * 	if not check parent access then
 * 		return DENINED
 * 	disk_object = find_or_create disk object
 * 	if disk_object has object
 * 		return NT_STATUS_OBJECT_NAME_COLLISION
 * 	returen create disk_open(disk_object)
 * else if OPEN then
 * 	disk_object = find_or_create
 * 	if disk_object is not valid
 * 		return OBJECT_NAME_NOT_FOUND
 * 	if not check acces
 * 		return DENIED
 * 	return disk_open
 */
static x_smbd_open_t *x_smbd_tcon_disk_op_create(std::shared_ptr<x_smbd_tcon_t>& smbd_tcon,
		NTSTATUS &status, uint32_t in_hdr_flags,
		x_smb2_requ_create_t &requ_create)
{
	std::string in_name = x_convert_utf16_to_utf8(requ_create.in_name);
	const char *path = in_name.data();
	if (in_hdr_flags & SMB2_HDR_FLAG_DFS) {
		/* MAC uses DFS path in \hostname\share\path format. */
		if (*path == '\\') {
			++path;
		}
		const char *sep = strchr(path, '\\');
		if (!sep) {
			status = NT_STATUS_OBJECT_PATH_NOT_FOUND;
			return nullptr;
		}
		/* TODO is_remote or local, and check service */
		sep = strchr(sep + 1, '\\');
		if (sep) {
			path = sep + 1;
		} else {
			path = "";
		}
	}

	std::string unix_path;
	uint32_t flags{0};

	status = resolve_path(smbd_tcon.get(), path, unix_path, flags);
	if (!NT_STATUS_IS_OK(status)) {
		return nullptr;
	}

	x_auto_ref_t<x_smbd_disk_object_t> disk_object{smbd_disk_object_pool.find_or_create(
			smbd_tcon->smbd_share->uuid, path)};
	{
		std::unique_lock<std::mutex> lock(disk_object->mutex);
		if (disk_object->flags & x_smbd_disk_object_t::flag_unknown) {
			std::string full_path;
			X_ASSERT(get_full_path(smbd_tcon.get(), disk_object, full_path) == 0);
			int err = open_exist_path(disk_object, full_path);
			if (!err) {
				get_metadata(disk_object);
				disk_object->flags = 0;
			} else {
				disk_object->flags = x_smbd_disk_object_t::flag_not_exist;
			}
		}
	}

	if (requ_create.in_create_disposition == FILE_CREATE) {
		std::unique_lock<std::mutex> lock(disk_object->mutex);
		if (disk_object->exists()) {
			status = NT_STATUS_OBJECT_NAME_COLLISION;
			return nullptr;
		} else {
			return open_object_new(smbd_tcon, disk_object, requ_create, status);
		}

	} else if (requ_create.in_create_disposition == FILE_OPEN) {
		std::unique_lock<std::mutex> lock(disk_object->mutex);
		if (disk_object->exists()) {
			return open_object_exist(smbd_tcon, disk_object, requ_create, status);
		} else {
			status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
			return nullptr;
		}

	} else if (requ_create.in_create_disposition == FILE_OPEN_IF) {
		std::unique_lock<std::mutex> lock(disk_object->mutex);
		if (disk_object->exists()) {
			return open_object_exist(smbd_tcon, disk_object, requ_create, status);
		} else {
			return open_object_new(smbd_tcon, disk_object, requ_create, status);
		}
	} else {
		X_TODO;
	}

	return nullptr;
}

static const x_smbd_tcon_ops_t x_smbd_tcon_disk_ops = {
	x_smbd_tcon_disk_op_create,
};

void x_smbd_tcon_init_disk(x_smbd_tcon_t *smbd_tcon)
{
	smbd_tcon->ops = &x_smbd_tcon_disk_ops;
}

int x_smbd_disk_init(size_t max_open)
{
	size_t bucket_size = x_next_2_power(max_open);
	smbd_disk_object_pool.hashtable.init(bucket_size);
	smbd_disk_object_pool.capacity = max_open;
	return 0;
}

