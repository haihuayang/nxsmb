
#include "smbd.hxx"
#include "core.hxx"
#include "include/charset.hxx"
#include "include/hashtable.hxx"
#include <functional>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <dirent.h>

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

	uint64_t get_end_of_file() const {
		if (S_ISDIR(stat.st_mode)) {
			return 0;
		}
		return stat.st_size;
	}

	uint64_t get_allocation() const {
		if (S_ISDIR(stat.st_mode)) {
			return 0;
		}
		return stat.st_blocks * 512;
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

	x_smbd_disk_object_t(const uuid_t &u, const std::string &p) : share_uuid(u), req_path(p) { }
	~x_smbd_disk_object_t() {
		if (fd != -1) {
			close(fd);
		}
		statex.invalidate();
	}

	bool exists() const { return fd != -1; }
	bool is_dir() const {
		X_ASSERT(fd != -1);
		return S_ISDIR(statex.stat.st_mode);
	}
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
		flag_initialized = 1,
		flag_not_exist = 2,
		flag_root = 4,
		flag_delete_on_close = 0x1000,
	};

	uint32_t flags = 0;
	uint32_t path_flags = 0;
	x_smbd_statex_t statex;
	const uuid_t share_uuid;
	const std::string req_path; // TODO duplicated, it is also a key in map
	std::string unix_path;
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
			return o.share_uuid == share_uuid && o.req_path == path;
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
		int err = unlink(disk_object->unix_path.c_str());
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

static int get_metadata(int fd, x_smbd_statex_t *statex)
{
	// get stats as well as dos attr ...
	X_ASSERT(fstat(fd, &statex->stat) == 0);
	dos_attr_t dos_attr;
	int err = ioctl(fd, FS_IOC_GET_DOS_ATTR, &dos_attr);
	X_ASSERT(err == 0);
	statex->birth_time = dos_attr.create_time;
	statex->file_attributes = dos_attr.file_attrs;

	return 0;
}

static int get_metadata(x_smbd_disk_object_t *disk_object)
{
	return get_metadata(disk_object->fd, &disk_object->statex);
}

static uint8_t *put_find_timespec(uint8_t *p, struct timespec ts)
{
	auto nttime = x_timespec_to_nttime(ts);
	memcpy(p, &nttime, sizeof nttime); // TODO byte order
	return p + sizeof nttime;
}

struct qdir_t
{
	uint64_t filepos = 0;
	int save_errno = 0;
	uint32_t file_number = 0;
	uint16_t data_length = 0, data_offset = 0;
	uint8_t data[32 * 1024];
};

struct qdir_pos_t
{
	uint32_t file_number;
	uint32_t data_offset;
	uint64_t filepos;
};

static const char *pseudo_entries[] = {
	".",
	"..",
	".snapshot",
};
#define PSEUDO_ENTRIES_COUNT    ARRAY_SIZE(pseudo_entries)

static int qdir_filldents(qdir_t &qdir, x_smbd_disk_object_t *disk_object)
{
	std::unique_lock<std::mutex> lock(disk_object->mutex);
	lseek(disk_object->fd, qdir.filepos, SEEK_SET);
	return syscall(SYS_getdents64, disk_object->fd, qdir.data, sizeof(qdir.data));
}

static inline bool is_dot_or_dotdot(const char *name)
{
	return name[0] == '.' && (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'));
}

static const char *qdir_get(qdir_t &qdir, qdir_pos_t &pos, x_smbd_disk_object_t *disk_object)
{
	const char *ent_name;
	if ((qdir.save_errno != 0)) {
		return nullptr;
	} else if (qdir.file_number >= PSEUDO_ENTRIES_COUNT) {
		for (;;) {
			if (qdir.data_offset >= qdir.data_length) {
				int retval = qdir_filldents(qdir, disk_object);
				if (retval > 0) {
					qdir.data_length = retval;
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

	qdir_t *qdir = nullptr;
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

static NTSTATUS getinfo_file(x_smbd_disk_open_t *disk_open, const x_smb2_requ_getinfo_t &requ, std::vector<uint8_t> &output)
{
	if (requ.info_level == 34) {
		if (requ.output_buffer_length < 56) {
			return STATUS_BUFFER_OVERFLOW;
		}
		output.resize(56);
		uint8_t *p = output.data();
		
		const auto statex = &disk_open->disk_object->statex;
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

static NTSTATUS getinfo_fs(x_smbd_disk_open_t *disk_open, const x_smb2_requ_getinfo_t &requ, std::vector<uint8_t> &output)
{
	return NT_STATUS_INVALID_LEVEL;
}
static NTSTATUS getinfo_security(x_smbd_disk_open_t *disk_open, const x_smb2_requ_getinfo_t &requ, std::vector<uint8_t> &output)
{
	return NT_STATUS_INVALID_LEVEL;
}
static NTSTATUS getinfo_quota(x_smbd_disk_open_t *disk_open, const x_smb2_requ_getinfo_t &requ, std::vector<uint8_t> &output)
{
	return NT_STATUS_INVALID_LEVEL;
}

static NTSTATUS x_smbd_disk_open_getinfo(x_smbd_open_t *smbd_open, const x_smb2_requ_getinfo_t &requ, std::vector<uint8_t> &output)
{
	x_smbd_disk_open_t *disk_open = from_smbd_open(smbd_open);
	X_ASSERT(disk_open->disk_object);
	if (requ.info_class == SMB2_GETINFO_FILE) {
		return getinfo_file(disk_open, requ, output);
	} else if (requ.info_class == SMB2_GETINFO_FS) {
		return getinfo_fs(disk_open, requ, output);
	} else if (requ.info_class == SMB2_GETINFO_SECURITY) {
		return getinfo_security(disk_open, requ, output);
	} else if (requ.info_class == SMB2_GETINFO_QUOTA) {
		return getinfo_quota(disk_open, requ, output);
	} else {
		return NT_STATUS_INVALID_PARAMETER;
	}
}

static bool get_dirent_meta(x_smbd_statex_t *statex,
		x_smbd_disk_object_t *dir_obj,
		const char *ent_name)
{
	int fd = openat(dir_obj->fd, ent_name, O_NOFOLLOW);
	if (fd < 0) {
		return false;
	}

	get_metadata(fd, statex);
	X_ASSERT(close(fd) == 0);
	return true;
}

static bool get_dirent_meta_special(x_smbd_statex_t *statex,
		x_smbd_disk_object_t *dir_obj,
		const char *ent_name)
{
	/* TODO for special fs, home share root, .snapshot, ... */
	return get_dirent_meta(statex, dir_obj, ent_name);
}

static bool process_entry(x_smbd_statex_t *statex,
		x_smbd_disk_object_t *dir_obj,
		const char *ent_name,
		uint32_t file_number)
{
	/* TODO match pattern */

	bool ret = true;
	if (file_number >= PSEUDO_ENTRIES_COUNT) {
		/* TODO check ntacl if ABE is enabled */
		ret = get_dirent_meta(statex, dir_obj, ent_name);
	} else if (file_number == 0) {
		/* TODO should lock dir_obj */
		*statex = dir_obj->statex;
	} else if (file_number == 1) {
		if (dir_obj->flags & x_smbd_disk_object_t::flag_root) {
			/* TODO should lock dir_obj */
			*statex = dir_obj->statex;
		} else {
			ret = get_dirent_meta_special(statex, dir_obj, ent_name);
		}

	} else {
		/* .snapshot */
		if (!(dir_obj->flags & x_smbd_disk_object_t::flag_root)) {
			return false;
		}
		/* TODO if snapshot browsable */
		ret = get_dirent_meta_special(statex, dir_obj, ent_name);
	}

	return ret;
}


static uint8_t *marshall_entry(x_smbd_statex_t *statex, const char *fname,
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
		x_put_le32(p, name.size() * 2); p += 4;
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
			uint32_t len = p - pbegin;
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
		x_put_le32(p, name.size() * 2); p += 4;
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
			uint32_t len = p - pbegin;
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

static NTSTATUS x_smbd_disk_open_find(x_smbd_open_t *smbd_open,
		const x_smb2_requ_find_t &requ,
		std::vector<uint8_t> &output)
{
	x_smbd_disk_open_t *disk_open = from_smbd_open(smbd_open);
	X_ASSERT(disk_open->disk_object);
	x_smbd_disk_object_t *disk_object = disk_open->disk_object;
	if (!disk_object->is_dir()) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	if (requ.in_flags & (SMB2_CONTINUE_FLAG_REOPEN | SMB2_CONTINUE_FLAG_RESTART)) {
		if (disk_open->qdir) {
			delete disk_open->qdir;
			disk_open->qdir = nullptr;
		}
	}

	if (!disk_open->qdir) {
		disk_open->qdir = new qdir_t;
	}

	uint32_t max_count = 0x7fffffffu;
	if (requ.in_flags & SMB2_CONTINUE_FLAG_SINGLE) {
		max_count = 1;
	}

	qdir_t *qdir = disk_open->qdir;
	output.resize(requ.in_output_buffer_length);
	uint8_t *pbegin = output.data();
	uint8_t *pend = output.data() + output.size();
	uint8_t *pcurr =  pbegin, *plast = nullptr;
	uint32_t num = 0, matched_count = 0;
	while (num < max_count) {
		qdir_pos_t qdir_pos;
		const char *ent_name = qdir_get(*qdir, qdir_pos, disk_object);
		if (!ent_name) {
			break;
		}

		x_smbd_statex_t statex;
		if (!process_entry(&statex, disk_object, ent_name, qdir_pos.file_number)) {
			X_LOG_WARN("process_entry %s %d,0x%x %d errno=%d",
					ent_name, qdir_pos.file_number, qdir_pos.filepos,
					qdir_pos.data_offset, errno);
			continue;
		}

		++matched_count;
		uint8_t *p = marshall_entry(&statex, ent_name, pcurr, pend, 8, requ.in_info_level);
		if (p) {
			++num;
			if (plast) {
				x_put_le32(plast, pcurr - plast);
			}
			plast = pcurr;
			pcurr = p;
		} else {
			qdir_unget(*qdir, qdir_pos);
			max_count = num;
		}
	}

	if (num > 0) {
		output.resize(pcurr - pbegin);
		// x_put_le32(plast, 0);
		return NT_STATUS_OK;
	}
	
	output.resize(0);
	if (matched_count > 0) {
		return NT_STATUS_INFO_LENGTH_MISMATCH;
	} else {
		return STATUS_NO_MORE_FILES;
	}
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

static void fill_out_info(x_smb2_create_close_info_t &info, const x_smbd_statex_t &statex)
{
	info.out_create_ts = x_timespec_to_nttime(statex.birth_time);
	info.out_last_access_ts = x_timespec_to_nttime(statex.stat.st_atim);
	info.out_last_write_ts = x_timespec_to_nttime(statex.stat.st_mtim);
	info.out_change_ts = x_timespec_to_nttime(statex.stat.st_ctim);
	info.out_file_attributes = statex.file_attributes;
	info.out_allocation_size = statex.get_allocation();
	info.out_end_of_file = statex.get_end_of_file();
}

static void reply_requ_create(x_smb2_requ_create_t &requ_create,
		const x_smbd_disk_object_t *disk_object,
		uint32_t create_action)
{
	requ_create.out_oplock_level = 0;
	requ_create.out_create_flags = 0;
	requ_create.out_create_action = create_action;
	fill_out_info(requ_create.out_info, disk_object->statex);
}

static NTSTATUS x_smbd_disk_open_close(x_smbd_open_t *smbd_open,
		const x_smb2_requ_close_t &requ, x_smb2_resp_close_t &resp)
{
	x_smbd_disk_open_t *disk_open = from_smbd_open(smbd_open);
	x_auto_ref_t<x_smbd_disk_object_t> disk_object{std::move(disk_open->disk_object)};
	X_ASSERT(disk_object);

	if (requ.flags & SMB2_CLOSE_FLAGS_FULL_INFORMATION) {
		std::unique_lock<std::mutex> lock(disk_object->mutex);
		fill_out_info(resp.out_info, disk_object->statex);
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
	x_smbd_disk_open_find,
	x_smbd_disk_open_ioctl,
	x_smbd_disk_open_close,
	x_smbd_disk_open_destroy,
};

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
#if 0
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
#endif
static uint32_t resolve_unix_path(x_smbd_tcon_t *tcon, const char *in_path,
		std::string &out_path)
{
	out_path = tcon->smbshare->path;
	if (!*in_path) {
		return PATH_FLAG_ROOT;
	}
	out_path.push_back('/');
	for ( ; *in_path; ++in_path) {
		if (*in_path == '\\') {
			out_path.push_back('/');
		} else {
			out_path.push_back(*in_path);
		}
	}

	return 0;
}

static NTSTATUS create_dir(x_smbd_tcon_t *smbd_tcon,
		x_smbd_disk_object_t *disk_object)
{
	int err = mkdir(disk_object->unix_path.c_str(), 0777);
	if (err == 0) {
		int fd = open(disk_object->unix_path.c_str(), O_RDONLY);
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
	int fd = open(disk_object->unix_path.c_str(), O_RDWR | O_CREAT | O_EXCL, 0666);
	if (fd >= 0) {
		disk_object->fd = fd;
		get_metadata(disk_object);
		return NT_STATUS_OK;
	}

	X_ASSERT(errno == EEXIST);
	return NT_STATUS_OBJECT_NAME_COLLISION;
}

static int open_exist_path(x_smbd_disk_object_t *disk_object)
{
	X_ASSERT(disk_object->fd == -1);

	int fd = open(disk_object->unix_path.c_str(), O_RDWR);
	if (fd >= 0) {
		disk_object->fd = fd;
		return 0;
	}
	if (errno != EISDIR) {
		return -errno;
	}
	fd = open(disk_object->unix_path.c_str(), O_RDONLY);
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

static NTSTATUS normalize_path(const char *path)
{
	return NT_STATUS_OK;
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
	/* TODO case insenctive */
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

	status = normalize_path(path);
	if (!NT_STATUS_IS_OK(status)) {
		return nullptr;
	}

	/*
	std::string unix_path;
	uint32_t flags{0};

	status = resolve_path(smbd_tcon.get(), path, unix_path, flags);
*/
	x_auto_ref_t<x_smbd_disk_object_t> disk_object{smbd_disk_object_pool.find_or_create(
			smbd_tcon->smbshare->uuid, path)};
	{
		std::unique_lock<std::mutex> lock(disk_object->mutex);
		if (!(disk_object->flags & x_smbd_disk_object_t::flag_initialized)) {
			disk_object->path_flags = resolve_unix_path(smbd_tcon.get(), path, disk_object->unix_path);
			int err = open_exist_path(disk_object);
			if (!err) {
				get_metadata(disk_object);
				disk_object->flags = x_smbd_disk_object_t::flag_initialized;
			} else {
				disk_object->flags = x_smbd_disk_object_t::flag_not_exist | x_smbd_disk_object_t::flag_initialized;
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

