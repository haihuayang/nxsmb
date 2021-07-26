
#include "smbd_open.hxx"
#include "smbd_vfs.hxx"
#include "core.hxx"
#include "include/charset.hxx"
#include "include/hashtable.hxx"
#include <functional>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/statvfs.h>
#include <dirent.h>
#include "include/librpc/xattr.hxx"
#include "smbd_ntacl.hxx"

#define X_NOTIFY_FLAG_VALID		0x80000000u
#define X_NOTIFY_FLAG_WATCH_TREE	0x40000000u

#if 0
enum x_smbd_path_type_t {
	t_normal,
	t_shard_root,
	t_tld,
};
#endif
enum {
	PATH_FLAG_ROOT = 1,
	PATH_FLAG_TLD = 2,
};

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

struct x_smbd_disk_object_t;
struct x_smbd_disk_open_t
{
	x_smbd_disk_open_t(const x_auto_ref_t<x_smbd_disk_object_t> &disk_object)
		: disk_object(disk_object) { }
#if 0
	x_smbd_tcon_t *get_tcon() const {
		return base.smbd_tcon.get();
	}
#endif
	x_smbd_open_t base;
	x_dlink_t object_link;
	std::string in_path;

	qdir_t *qdir = nullptr;
	x_auto_ref_t<x_smbd_disk_object_t> disk_object;
	x_dlink_t link_disk_object;

	bool update_write_time = false;
	uint32_t notify_filter = 0;
	x_tp_ddlist_t<requ_async_traits> notify_requ_list;
	/* notify_changes protected by disk_object->mutex */
	std::vector<std::pair<uint32_t, std::u16string>> notify_changes;
};
X_DECLARE_MEMBER_TRAITS(smbd_open_object_traits, x_smbd_disk_open_t, object_link)

struct x_smbd_disk_object_t
{
	void incref() {
		X_ASSERT(refcnt++ > 0);
	}
	void decref() {
		X_ASSERT(refcnt > 0);
		if (--refcnt == 0) {
			delete this;
		}
	}

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
	uint32_t refcnt = 1;
	x_tp_ddlist_t<smbd_open_object_traits> open_list;
	int fd = -1;

	enum {
		flag_initialized = 1,
		flag_not_exist = 2,
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
	void release(x_smbd_disk_object_t *disk_object);

	x_hashtable_t<smbd_disk_object_hash_traits> hashtable;
	x_tp_ddlist_t<smbd_disk_object_free_traits> free_list;
	uint32_t capacity, count = 0;
	std::mutex mutex;
};

static x_smbd_disk_object_pool_t smbd_disk_object_pool;

static NTSTATUS check_parent_access(uint32_t access)
{
	// TODO
	return NT_STATUS_OK;
}

static bool check_open_access(x_smbd_disk_open_t *disk_open, uint32_t access)
{
	return (disk_open->base.access_mask & access);
}

static inline bool check_object_access(x_smbd_disk_object_t *disk_object, uint32_t access)
{
	// TODO smbd_check_access_rights
	// return (disk_object->statex.file_attributes & access);
	return true;
}

static x_smbd_disk_object_t *x_smbd_disk_object_pool_find(
		x_smbd_disk_object_pool_t &pool,
		const uuid_t &share_uuid,
		const std::string &path,
		bool create)
{
	auto hash = std::hash<std::string>()(path);
	std::unique_lock<std::mutex> lock(pool.mutex);
	x_smbd_disk_object_t *disk_object = pool.hashtable.find(hash, [&share_uuid, &path](const x_smbd_disk_object_t &o) {
			return o.share_uuid == share_uuid && o.req_path == path;
			});

	if (!disk_object) {
		if (!create) {
			return nullptr;
		}
		if (pool.count == pool.capacity) {
			disk_object = pool.free_list.get_front();
			if (!disk_object) {
				return nullptr;
			}
			X_ASSERT(disk_object->refcnt == 0);
			disk_object->~x_smbd_disk_object_t();
			new (disk_object) x_smbd_disk_object_t(share_uuid, path);
			return disk_object;
		}
		disk_object = new x_smbd_disk_object_t(share_uuid, path);
		++pool.count;
		smbd_disk_object_pool.hashtable.insert(disk_object, hash);
	}

	disk_object->incref();
	return disk_object;
}

static void x_smbd_disk_object_pool_release(
	       x_smbd_disk_object_pool_t &pool,
	       x_smbd_disk_object_t *disk_object)
{
	{
		std::lock_guard<std::mutex> lock(pool.mutex);
		pool.hashtable.remove(disk_object);
	}
	--pool.count;
	disk_object->decref();
}

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

static x_smbd_disk_object_t *x_smbd_disk_object_pool_find_and_open(
		x_smbd_disk_object_pool_t &pool,
		x_smbd_tcon_t *smbd_tcon,
		const std::string &path)
{
	x_smbd_disk_object_t *disk_object{x_smbd_disk_object_pool_find(
			smbd_disk_object_pool,
			smbd_tcon->smbshare->uuid, path,
			true)};
	std::unique_lock<std::mutex> lock(disk_object->mutex);
	if (!(disk_object->flags & x_smbd_disk_object_t::flag_initialized)) {
		disk_object->path_flags = resolve_unix_path(smbd_tcon, path.c_str(), disk_object->unix_path);
		int fd = x_smbd_vfs_open(disk_object->unix_path.c_str(),
				&disk_object->statex);
		if (fd < 0) {
			disk_object->flags = x_smbd_disk_object_t::flag_not_exist | x_smbd_disk_object_t::flag_initialized;
		} else {
			disk_object->fd = fd;
			disk_object->flags = x_smbd_disk_object_t::flag_initialized;
		}
	}
	return disk_object;
}

static NTSTATUS disk_object_get_sd(x_smbd_disk_object_t *disk_object,
		std::shared_ptr<idl::security_descriptor> &psd)
{
	std::vector<uint8_t> blob;
	int err = x_smbd_vfs_get_ntacl_blob(disk_object->fd, blob);
	if (err < 0) {
		return x_map_nt_error_from_unix(-err);
	}

	uint16_t hash_type;
	uint16_t version;
	std::array<uint8_t, idl::XATTR_SD_HASH_SIZE> hash;
	return parse_acl_blob(blob, psd, &hash_type, &version, hash);
}

static void notify_fname(
		x_smbd_disk_object_t *disk_object,
		uint32_t action,
		uint32_t notify_filter);
#if 0
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
#endif
static void x_smbd_disk_object_remove(x_smbd_disk_object_t *disk_object,
		x_smbd_disk_open_t *disk_open)
{
	std::unique_lock<std::mutex> lock(disk_object->mutex);
	disk_object->open_list.remove(disk_open);
	if (disk_object->open_list.empty()) {
		if (disk_object->flags & x_smbd_disk_object_t::flag_delete_on_close) {
			auto notify_filter = disk_object->is_dir() ? FILE_NOTIFY_CHANGE_DIR_NAME : FILE_NOTIFY_CHANGE_FILE_NAME;

			int err = unlink(disk_object->unix_path.c_str());
			X_ASSERT(err == 0);
			err = close(disk_object->fd);
			X_ASSERT(err == 0);
			disk_object->fd = -1;
			disk_object->flags = x_smbd_disk_object_t::flag_not_exist;
			notify_fname(disk_object, NOTIFY_ACTION_REMOVED,
					notify_filter);
		}

		x_smbd_disk_object_pool_release(smbd_disk_object_pool, disk_object);
	}
}

#if 0
void x_smbd_disk_object_t::decref()
{
	smbd_disk_object_pool.release(this);
}
#endif
static bool operator<(const timespec &t1, const timespec &t2)
{
	if (t1.tv_sec < t2.tv_sec) {
		return true;
	} else if (t1.tv_sec == t2.tv_sec) {
		return t1.tv_nsec < t2.tv_nsec;
	} else {
		return false;
	}
}

static std::vector<std::pair<uint32_t, std::u16string>> get_notify_changes(x_smbd_disk_open_t *disk_open)
{
	std::vector<std::pair<uint32_t, std::u16string>> ret;
	std::unique_lock<std::mutex> lock(disk_open->disk_object->mutex);
	std::swap(ret, disk_open->notify_changes);
	return ret;
}

static NTSTATUS notify_marshall(
		const std::vector<std::pair<uint32_t, std::u16string>> &notify_changes,
		uint32_t max_offset,
		std::vector<uint8_t> &output)
{
	output.resize(std::min(max_offset, 1024u));

	uint32_t offset = 0;
	uint32_t rec_size = 0;
	for (const auto &change: notify_changes) {
		uint32_t pad_len = x_pad_len(rec_size, 4);
		rec_size = 12 + 2 * change.second.size();
		uint32_t new_size = offset + pad_len + rec_size;
		if (new_size > max_offset) {
			offset = rec_size = 0;
			break;
		}
		if (new_size > output.size()) {
			output.resize(new_size);
		}
		x_put_le32(output.data() + offset, pad_len); // last rec's next offset
		offset += pad_len;
		x_put_le32(output.data() + offset + 4, change.first);
		x_put_le32(output.data() + offset + 8, change.second.size() * 2);
		memcpy(output.data () + offset + 12, change.second.data(), change.second.size() * 2);
	}
	output.resize(offset + rec_size);
	return output.empty() ?  NT_STATUS_NOTIFY_ENUM_DIR : NT_STATUS_OK;
}

struct smbd_notify_evt_t
{
	x_fdevt_user_t base;
	x_smbd_disk_open_t *disk_open;
};

static void smbd_notify_func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user, bool cancelled)
{
	smbd_notify_evt_t *evt = X_CONTAINER_OF(fdevt_user, smbd_notify_evt_t, base);

	x_smbd_disk_open_t *disk_open = evt->disk_open;
	if (cancelled || disk_open->notify_requ_list.empty()) {
#if 0
		if (disk_open->notify_output_size == 0) {
			disk_open->notifies.clear();
		}
#endif
	} else {
		x_smbd_requ_t *smbd_requ = disk_open->notify_requ_list.get_front();
		disk_open->notify_requ_list.remove(smbd_requ);
		x_smbd_requ_remove(smbd_requ);

		std::unique_ptr<x_smb2_state_notify_t> state{(x_smb2_state_notify_t *)smbd_requ->requ_state};
		smbd_requ->requ_state = nullptr;

		NTSTATUS status = notify_marshall(get_notify_changes(disk_open),
				state->in_output_buffer_length, state->out_data);
		state->done(smbd_conn, smbd_requ, status);
	}

	disk_open->base.decref();
	delete evt;
}


static void x_smbd_disk_open_append_notify(x_smbd_disk_open_t *disk_open,
		uint32_t action,
		const std::u16string &path)
{
	disk_open->notify_changes.push_back(std::make_pair(action, path));
	smbd_notify_evt_t *evt = new smbd_notify_evt_t;
	evt->base.func = smbd_notify_func;
	disk_open->base.incref();
	evt->disk_open = disk_open;
	x_smbd_conn_post_user(disk_open->base.smbd_tcon->smbd_sess->smbd_conn, &evt->base);
}

static void notify_fname_one(const uuid_t &share_uuid, const std::string &path,
		const std::string &fullpath,
		uint32_t action,
		uint32_t notify_filter,
		bool last_level)
{
	x_auto_ref_t<x_smbd_disk_object_t> disk_object{x_smbd_disk_object_pool_find(
			smbd_disk_object_pool,
			share_uuid, path,
			false)};

	if (!disk_object) {
		return;
	}

	std::u16string subpath;
	/* TODO change to read lock */
	std::unique_lock<std::mutex> lock(disk_object->mutex);
	auto &open_list = disk_object->open_list;
	x_smbd_disk_open_t *disk_open;
	for (disk_open = open_list.get_front(); disk_open; disk_open = open_list.next(disk_open)) {
		if (!(disk_open->notify_filter & notify_filter)) {
			continue;
		}
		if (!last_level && !(disk_open->notify_filter & X_NOTIFY_FLAG_WATCH_TREE)) {
			continue;
		}
		if (subpath.empty()) {
			if (path.empty()) {
				subpath = x_convert_utf8_to_utf16(fullpath);
			} else {
				subpath = x_convert_utf8_to_utf16(fullpath.substr(path.size() + 1));
			}
		}
		x_smbd_disk_open_append_notify(disk_open, action, subpath);
	}
}

static void notify_fname(
		x_smbd_disk_object_t *disk_object,
		uint32_t action,
		uint32_t notify_filter)
{
	std::size_t curr_pos = 0, last_sep_pos = 0;
	for (;;) {
		auto found = disk_object->req_path.find('\\', curr_pos);
		if (found == std::string::npos) {
			break;
		}
		
		notify_fname_one(disk_object->share_uuid,
				disk_object->req_path.substr(0, last_sep_pos),
				disk_object->req_path,
				action, notify_filter, false);
		last_sep_pos = found;
		curr_pos = found + 1;
	}

	notify_fname_one(disk_object->share_uuid,
			disk_object->req_path.substr(0, last_sep_pos),
			disk_object->req_path,
			action, notify_filter, true);
}

static uint8_t *put_find_timespec(uint8_t *p, struct timespec ts)
{
	auto nttime = x_timespec_to_nttime(ts);
	memcpy(p, &nttime, sizeof nttime); // TODO byte order
	return p + sizeof nttime;
}

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

static inline x_smbd_disk_open_t *from_smbd_open(x_smbd_open_t *smbd_open)
{
	return X_CONTAINER_OF(smbd_open, x_smbd_disk_open_t, base);
}
#if 0
static x_job_t::retval_t async_read_run(x_job_t *job)
{
	x_smb2_read_t *smb2_read = X_CONTAINER_OF(job, x_smb2_read_t, job);
	x_buf_t *buf = x_buf_alloc(smb2_read->in_length);
	if (!buf) {
		x_smbd_async_reply(&smb2_read->requ, NT_STATUS_NO_MEMORY, nullptr);
		return x_job_t::STATE_DONE;
	}
	ssize_t ret = pread(smb2_read->disk_open->disk_object->fd,
			buf->data, smb2_read->length, smb2_read->offset);
	if (ret > 0) {
		smb2_read->status = NT_STATUS_OK;
		smb2_read->length = ret;
	} else if (ret == 0) {
		smb2_read->status = NT_STATUS_END_OF_FILE;
	} else {
		smb2_read->status = map_nt_error_from_unix(errno);
	}
	return x_job_t::STATE_DONE;
}

static void async_read_done(x_job_t *job)
{
	x_smb2_read_t *smb2_read = X_CONTAINER_OF(job, x_smb2_read_t, job);
	x_smb2_requ_release(&smb2_read->requ);
}

static const x_job_ops_t async_read_job_ops = {
	async_read_run,
	async_read_done,
};
#endif
static NTSTATUS x_smbd_disk_open_read(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_read_t> &state)
{
	x_smbd_disk_open_t *disk_open = from_smbd_open(smbd_requ->smbd_open);
	X_ASSERT(disk_open->disk_object);
	uint32_t length = std::min(state->in_length, 1024u * 1024);

#if 0
	++smb2_read->requ.refcount;
	smb2_read->job.ops = &async_read_job_ops;
	x_smbd_schedule_async(&smb2_read->job);

	return X_NT_STATUS_INTERNAL_BLOCKED;
#else
	state->out_data.resize(length);
	ssize_t ret = pread(disk_open->disk_object->fd, state->out_data.data(),
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

static NTSTATUS x_smbd_disk_open_write(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_write_t> &state)
{
	x_smbd_disk_open_t *disk_open = from_smbd_open(smbd_requ->smbd_open);
	X_ASSERT(disk_open->disk_object);

	ssize_t ret = pwrite(disk_open->disk_object->fd, state->in_data.data(),
			state->in_data.size(), state->in_offset);
	if (ret < 0) {
		X_TODO;
	} else {
		state->out_count = ret;
		state->out_remaining = 0;
	}
	return NT_STATUS_OK;
}

static NTSTATUS getinfo_file(x_smbd_disk_open_t *disk_open,
		x_smb2_state_getinfo_t &state)
{
	if (state.in_info_level == SMB2_FILE_INFO_FILE_NETWORK_OPEN_INFORMATION) {
		if (state.in_output_buffer_length < 56) {
			return STATUS_BUFFER_OVERFLOW;
		}
		state.out_data.resize(56);
		uint8_t *p = state.out_data.data();
		
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

static bool decode_setinfo_basic(x_smb2_basic_info_t &basic_info,
		const std::vector<uint8_t> &in_data)
{
	/* TODO bigendian */
	memcpy(&basic_info, in_data.data(), 0x24);
	return true;
}
#if 0
struct x_smb2_rename_info_t
{
	bool overwrite;
	std::string file_name;
};

static NTSTATUS decode_setinfo_rename(x_smb2_rename_info_t &rename_info,
		const std::vector<uint8_t> &in_data)
{
	if (in_data.size() < 12) {
		return NT_STATUS_INFO_LENGTH_MISMATCH;
	}
	rename_info.overwrite = in_data[0];
	uint32_t root_fid = x_get_le32(in_data.data() + 4);
	if (root_fid != 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	uint32_t name_length = x_get_le32(in_data.data() + 8);
	if (name_length == 0 || (name_length & 1) || name_length > in_data.size() - 12) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	rename_info.file_name = x_convert_utf16_to_utf8(
			(char16_t *)(in_data.data() + 12),
			(char16_t *)(in_data.data() + 12 + name_length));
	return NT_STATUS_OK;
}
#endif
static NTSTATUS setinfo_file(x_smbd_disk_open_t *disk_open,
		x_smbd_requ_t *smbd_requ,
		x_smb2_state_setinfo_t &state)
{
	if (state.in_info_level == SMB2_FILE_INFO_FILE_BASIC_INFORMATION) {
		if (state.in_data.size() < 0x24) {
			return NT_STATUS_INFO_LENGTH_MISMATCH;
		}
		if (!check_open_access(disk_open, idl::SEC_FILE_WRITE_ATTRIBUTE)) {
			return NT_STATUS_ACCESS_DENIED;
		}

		x_smb2_basic_info_t basic_info;
		if (!decode_setinfo_basic(basic_info, state.in_data)) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		uint32_t notify_actions = 0;
		int err = x_smbd_vfs_set_basic_info(disk_open->disk_object->fd,
				notify_actions, basic_info,
				&disk_open->disk_object->statex);
		if (err == 0) {
			if (notify_actions) {
				notify_fname(disk_open->disk_object, NOTIFY_ACTION_MODIFIED, notify_actions);
			}
			return NT_STATUS_OK;
		} else {
			X_TODO;
			return NT_STATUS_INTERNAL_ERROR;
		}
#if 0
	} else if (state.in_info_level == SMB2_FILE_INFO_FILE_RENAME_INFORMATION) {
		/* MS-FSA 2.1.5.14.11 */
		x_smb2_rename_info_t rename;
		status = decode_setinfo_rename(rename, state.in_data);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
#endif
	} else if (state.in_info_level == SMB2_FILE_INFO_FILE_DISPOSITION_INFORMATION) {
		/* MS-FSA 2.1.5.14.3 */
		if (state.in_data.size() < 1) {
			return NT_STATUS_INFO_LENGTH_MISMATCH;
		}
		if (!check_open_access(disk_open, idl::SEC_STD_DELETE)) {
			return NT_STATUS_ACCESS_DENIED;
		}
		bool delete_on_close = (state.in_data[0] != 0);
		if (delete_on_close) {
			if (disk_open->disk_object->statex.file_attributes & FILE_ATTRIBUTE_READONLY) {
				return NT_STATUS_CANNOT_DELETE;
			}
			if (true /*!is_stream_open(disk_open) */) {
				disk_open->disk_object->flags |= x_smbd_disk_object_t::flag_delete_on_close;
			} else {
				X_TODO;
			}
		} else {
			/* TODO handle streams */
			disk_open->disk_object->flags &= ~x_smbd_disk_object_t::flag_delete_on_close;
		}
		return NT_STATUS_OK;
	} else {
		return NT_STATUS_INVALID_LEVEL;
	}
}

static NTSTATUS getinfo_fs(x_smbd_disk_open_t *disk_open,
		x_smb2_state_getinfo_t &state)
{
	if (state.in_info_level == SMB2_FILE_INFO_FS_SIZE_INFORMATION) {
		if (state.in_output_buffer_length < 24) {
			return STATUS_BUFFER_OVERFLOW;
		}
		struct statvfs fsstat;
		int err = fstatvfs(disk_open->disk_object->fd, &fsstat);
		assert(err == 0);
		state.out_data.resize(24);
		uint8_t *p = state.out_data.data();
		x_put_le64(p, fsstat.f_blocks); p += 8;
		x_put_le64(p, fsstat.f_bfree); p += 8;
		x_put_le32(p, fsstat.f_bsize / 512); p += 4;
		x_put_le32(p, 512); p += 4;

		return NT_STATUS_OK;
	} else if (state.in_info_level == SMB2_FILE_INFO_FS_ATTRIBUTE_INFORMATION) {
		/* 20 = 4 + 4 + 4 + 'NTFS' */
		if (state.in_output_buffer_length < 20) {
			return STATUS_BUFFER_OVERFLOW;
		}
		struct statvfs fsstat;
		int err = fstatvfs(disk_open->disk_object->fd, &fsstat);
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

static NTSTATUS getinfo_security(x_smbd_disk_open_t *disk_open,
		x_smb2_state_getinfo_t &state)
{
	std::shared_ptr<idl::security_descriptor> psd;
	NTSTATUS status = disk_object_get_sd(disk_open->disk_object, psd);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	auto ndr_ret = idl::x_ndr_push(*psd, state.out_data, state.in_output_buffer_length);
	if (ndr_ret < 0) {
		return x_map_nt_error_from_ndr_err(idl::x_ndr_err_code_t(-ndr_ret));
	}
	return NT_STATUS_OK;
}

static NTSTATUS setinfo_security(x_smbd_disk_open_t *disk_open,
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
	int err = x_smbd_vfs_get_ntacl_blob(disk_open->disk_object->fd, old_blob);
	if (err < 0) {
		return x_map_nt_error_from_unix(-err);
	}

	std::vector<uint8_t> new_blob;
	status = create_acl_blob_from_old(new_blob, old_blob, sd, security_info_sent);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	err = x_smbd_vfs_set_ntacl_blob(disk_open->disk_object->fd, new_blob);
	if (err < 0) {
		return x_map_nt_error_from_unix(-err);
	}

	notify_fname(disk_open->disk_object, NOTIFY_ACTION_MODIFIED,
			FILE_NOTIFY_CHANGE_SECURITY);
	return NT_STATUS_OK;
}

static NTSTATUS getinfo_quota(x_smbd_disk_open_t *disk_open,
		x_smb2_state_getinfo_t &state)
{
	return NT_STATUS_INVALID_LEVEL;
}

static NTSTATUS x_smbd_disk_open_getinfo(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_getinfo_t> &state)
{
	x_smbd_disk_open_t *disk_open = from_smbd_open(smbd_requ->smbd_open);
	X_ASSERT(disk_open->disk_object);
	if (state->in_info_class == SMB2_GETINFO_FILE) {
		return getinfo_file(disk_open, *state);
	} else if (state->in_info_class == SMB2_GETINFO_FS) {
		return getinfo_fs(disk_open, *state);
	} else if (state->in_info_class == SMB2_GETINFO_SECURITY) {
		return getinfo_security(disk_open, *state);
	} else if (state->in_info_class == SMB2_GETINFO_QUOTA) {
		return getinfo_quota(disk_open, *state);
	} else {
		return NT_STATUS_INVALID_PARAMETER;
	}
}

static NTSTATUS x_smbd_disk_open_setinfo(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_setinfo_t> &state)
{
	x_smbd_disk_open_t *disk_open = from_smbd_open(smbd_requ->smbd_open);
	X_ASSERT(disk_open->disk_object);

	if (state->in_info_class == SMB2_GETINFO_FILE) {
		return setinfo_file(disk_open, smbd_requ, *state);
#if 0
	} else if (state->in_info_class == SMB2_GETINFO_FS) {
		return setinfo_fs(disk_open, smbd_requ, *state);
#endif
	} else if (state->in_info_class == SMB2_GETINFO_SECURITY) {
		return setinfo_security(disk_open, smbd_requ, *state);
	} else {
		return NT_STATUS_INVALID_PARAMETER;
	}
}

static bool get_dirent_meta(x_smbd_statex_t *statex,
		x_smbd_disk_object_t *dir_obj,
		const char *ent_name)
{
	return x_smbd_vfs_get_statex(dir_obj->fd, ent_name, statex) == 0;
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
		if (dir_obj->path_flags & PATH_FLAG_ROOT) {
			/* TODO should lock dir_obj */
			/* not go beyond share root */
			*statex = dir_obj->statex;
		} else {
			ret = get_dirent_meta_special(statex, dir_obj, ent_name);
		}

	} else {
		return false; // TODO not support snapshot for now
		/* .snapshot */
		if (dir_obj->path_flags & PATH_FLAG_ROOT) {
			/* TODO if snapshot browsable */
			ret = get_dirent_meta_special(statex, dir_obj, ent_name);
		} else {
			return false;
		}
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

static NTSTATUS x_smbd_disk_open_find(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_find_t> &state)
{
	x_smbd_disk_open_t *disk_open = from_smbd_open(smbd_requ->smbd_open);
	X_ASSERT(disk_open->disk_object);
	x_smbd_disk_object_t *disk_object = disk_open->disk_object;
	if (!disk_object->is_dir()) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	if (state->in_flags & (SMB2_CONTINUE_FLAG_REOPEN | SMB2_CONTINUE_FLAG_RESTART)) {
		if (disk_open->qdir) {
			delete disk_open->qdir;
			disk_open->qdir = nullptr;
		}
	}

	if (!disk_open->qdir) {
		disk_open->qdir = new qdir_t;
	}

	uint32_t max_count = 0x7fffffffu;
	if (state->in_flags & SMB2_CONTINUE_FLAG_SINGLE) {
		max_count = 1;
	}

	qdir_t *qdir = disk_open->qdir;
	state->out_data.resize(state->in_output_buffer_length);
	uint8_t *pbegin = state->out_data.data();
	uint8_t *pend = state->out_data.data() + state->out_data.size();
	uint8_t *pcurr =  pbegin, *plast = nullptr;
	uint32_t num = 0, matched_count = 0;

	x_fnmatch_t *fnmatch = x_fnmatch_create(state->in_name, true);
	while (num < max_count) {
		qdir_pos_t qdir_pos;
		const char *ent_name = qdir_get(*qdir, qdir_pos, disk_object);
		if (!ent_name) {
			break;
		}

		if (fnmatch && !x_fnmatch_match(fnmatch, ent_name)) {
			continue;
		}

		x_smbd_statex_t statex;
		if (!process_entry(&statex, disk_object, ent_name, qdir_pos.file_number)) {
			X_LOG_WARN("process_entry %s %d,0x%x %d errno=%d",
					ent_name, qdir_pos.file_number, qdir_pos.filepos,
					qdir_pos.data_offset, errno);
			continue;
		}

		++matched_count;
		uint8_t *p = marshall_entry(&statex, ent_name, pcurr, pend, 8, state->in_info_level);
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

static NTSTATUS x_smbd_disk_open_ioctl(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_ioctl_t> &state)
{
	return NT_STATUS_NOT_SUPPORTED;
	X_TODO;
}

struct smbd_notify_cancel_evt_t
{
	x_fdevt_user_t base;
	x_smbd_requ_t *smbd_requ;
};

static void smbd_notify_cancel_func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user, bool cancelled)
{
	smbd_notify_cancel_evt_t *evt = X_CONTAINER_OF(fdevt_user, smbd_notify_cancel_evt_t, base);

	x_smbd_requ_t *smbd_requ = evt->smbd_requ;
	if (!cancelled) {
		std::unique_ptr<x_smb2_state_notify_t> state{(x_smb2_state_notify_t *)smbd_requ->requ_state};
		smbd_requ->requ_state = nullptr;

		state->done(smbd_conn, smbd_requ, NT_STATUS_CANCELLED);
	}

	smbd_requ->decref();
	delete evt;
}

static void notify_cancel(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	x_smbd_disk_open_t *disk_open = from_smbd_open(smbd_requ->smbd_open);
	disk_open->notify_requ_list.remove(smbd_requ);

	smbd_notify_cancel_evt_t *evt = new smbd_notify_cancel_evt_t;
	evt->base.func = smbd_notify_cancel_func;
	evt->smbd_requ = smbd_requ;
	x_smbd_conn_post_user(disk_open->base.smbd_tcon->smbd_sess->smbd_conn, &evt->base);
}

static NTSTATUS x_smbd_disk_open_notify(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_notify_t> &state)
{
	x_smbd_disk_open_t *disk_open = from_smbd_open(smbd_requ->smbd_open);
	X_ASSERT(disk_open->disk_object);
	x_smbd_disk_object_t *disk_object = disk_open->disk_object;
	if (!disk_object->is_dir()) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (disk_open->notify_filter == 0) {
		disk_open->notify_filter = state->in_filter | X_NOTIFY_FLAG_VALID;;
		if (state->in_flags & SMB2_WATCH_TREE) {
			disk_open->notify_filter |= X_NOTIFY_FLAG_WATCH_TREE;
		}
	}

	auto notify_changes = get_notify_changes(disk_open);
	if (notify_changes.empty()) {
		// TODO smbd_conn add Cancels
		smbd_requ->requ_state = state.release();
		smbd_requ->incref();
		disk_open->notify_requ_list.push_back(smbd_requ);
		x_smbd_conn_set_async(smbd_conn, smbd_requ, notify_cancel);
		return NT_STATUS_PENDING;
	} else {
		return notify_marshall(notify_changes, state->in_output_buffer_length, state->out_data);
	}
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

static NTSTATUS x_smbd_disk_open_close(x_smbd_conn_t *smbd_conn,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_close_t> &state)
{
	x_smbd_disk_open_t *disk_open = from_smbd_open(smbd_open);
	x_auto_ref_t<x_smbd_disk_object_t> disk_object{std::move(disk_open->disk_object)};
	X_ASSERT(disk_object);

	if (smbd_requ) {
		/* Windows server send NT_STATUS_NOTIFY_CLEANUP
		   when tree disconect.
		   while samba not send.
		   for simplicity we do not either for now
		 */

		for (x_smbd_requ_t *requ_notify = disk_open->notify_requ_list.get_front();
				requ_notify; ) {
			disk_open->notify_requ_list.remove(requ_notify);
			std::unique_ptr<x_smb2_state_notify_t> notify_state{(x_smb2_state_notify_t *)requ_notify->requ_state};
			requ_notify->requ_state = nullptr;

			notify_state->done(smbd_conn, requ_notify, NT_STATUS_NOTIFY_CLEANUP);
		}

		if (state->in_flags & SMB2_CLOSE_FLAGS_FULL_INFORMATION) {
			state->out_flags = SMB2_CLOSE_FLAGS_FULL_INFORMATION;
			std::unique_lock<std::mutex> lock(disk_object->mutex);
			fill_out_info(state->out_info, disk_object->statex);
		}
	}

	x_smbd_disk_object_remove(disk_object, disk_open);
	return NT_STATUS_OK;
}

static void x_smbd_disk_open_destroy(x_smbd_open_t *smbd_open)
{
	x_smbd_disk_open_t *disk_open = from_smbd_open(smbd_open);
	delete disk_open;
}

static std::string x_smbd_disk_open_get_path(x_smbd_open_t *smbd_open)
{
	x_smbd_disk_open_t *disk_open = from_smbd_open(smbd_open);
	return disk_open->disk_object->req_path;
}

static const x_smbd_open_ops_t x_smbd_disk_open_ops = {
	x_smbd_disk_open_read,
	x_smbd_disk_open_write,
	x_smbd_disk_open_getinfo,
	x_smbd_disk_open_setinfo,
	x_smbd_disk_open_find,
	x_smbd_disk_open_ioctl,
	x_smbd_disk_open_notify,
	x_smbd_disk_open_close,
	x_smbd_disk_open_destroy,
	x_smbd_disk_open_get_path,
};

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
static x_smbd_open_t *create_disk_open(
		x_smbd_tcon_t *smbd_tcon,
		x_auto_ref_t<x_smbd_disk_object_t> &disk_object,
		const x_smb2_state_create_t &state)
{
	x_smbd_disk_open_t *disk_open = new x_smbd_disk_open_t{disk_object};
	disk_open->base.ops = &x_smbd_disk_open_ops;
	disk_open->base.smbd_tcon = smbd_tcon;
	disk_open->base.share_access = state.in_share_access;
	disk_open->base.access_mask = state.in_desired_access;

	disk_object->open_list.push_back(disk_open);
	return &disk_open->base;
}

static void reply_requ_create(x_smb2_state_create_t &state,
		const x_smbd_disk_object_t *disk_object,
		uint32_t create_action)
{
	state.out_oplock_level = 0;
	state.out_create_flags = 0;
	state.out_create_action = create_action;
	fill_out_info(state.out_info, disk_object->statex);
}

/* TODO pass sec_desc context
#define SMB2_CREATE_TAG_SECD "SecD"
 */
static x_smbd_open_t *open_object_new(
		x_smbd_tcon_t *smbd_tcon,
		x_auto_ref_t<x_smbd_disk_object_t> &disk_object,
		x_smb2_state_create_t &state,
		NTSTATUS &status)
{
	if (disk_object->path_flags & PATH_FLAG_ROOT) {
		status = NT_STATUS_OBJECT_NAME_COLLISION;
		return nullptr;
	}
	
	auto sep = disk_object->req_path.rfind('\\');
	std::string parent_path;
	if (sep != std::string::npos) {
		parent_path = disk_object->req_path.substr(0, sep);
	}

	x_auto_ref_t<x_smbd_disk_object_t> parent_disk_object{x_smbd_disk_object_pool_find_and_open(
			smbd_disk_object_pool,
			smbd_tcon, parent_path)};

	if (!parent_disk_object->exists()) {
		status = NT_STATUS_OBJECT_PATH_NOT_FOUND;
		return nullptr;
	}

	status = check_parent_access(idl::SEC_DIR_ADD_FILE);
	if (!NT_STATUS_IS_OK(status)) {
		return nullptr;
	}

	std::shared_ptr<idl::security_descriptor> parent_psd;
	status = disk_object_get_sd(parent_disk_object, parent_psd);
	if (!NT_STATUS_IS_OK(status)) {
		return nullptr;
	}

	auto smbd_user = smbd_tcon->smbd_sess->smbd_user;
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
	int fd = x_smbd_vfs_create(
			state.in_create_options & FILE_DIRECTORY_FILE,
			disk_object->unix_path.c_str(),
			&disk_object->statex,
			ntacl_blob);

	if (fd < 0) {
		X_ASSERT(-fd == EEXIST);
		status = NT_STATUS_OBJECT_NAME_COLLISION;
		return nullptr;
	}

	X_ASSERT(disk_object->fd == -1);
	X_ASSERT(disk_object->flags & x_smbd_disk_object_t::flag_not_exist);
	disk_object->fd = fd;
	disk_object->flags &= ~(x_smbd_disk_object_t::flag_not_exist);

	reply_requ_create(state, disk_object, FILE_WAS_CREATED);
	return create_disk_open(smbd_tcon, disk_object, state);
}

static x_smbd_open_t *open_object_exist(
		x_smbd_tcon_t *smbd_tcon,
		x_auto_ref_t<x_smbd_disk_object_t> &disk_object,
		x_smb2_state_create_t &state,
		NTSTATUS &status)
{
	if (!check_object_access(disk_object, state.in_desired_access)) {
		status = NT_STATUS_ACCESS_DENIED;
		return nullptr;
	}
	reply_requ_create(state, disk_object, FILE_WAS_OPENED);
	return create_disk_open(smbd_tcon, disk_object, state);
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
static x_smbd_open_t *x_smbd_tcon_disk_op_create(
		x_smbd_tcon_t *smbd_tcon,
		NTSTATUS &status,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state)
{
	/* TODO case insenctive */
	std::string in_name = x_convert_utf16_to_utf8(state->in_name);
	const char *path = in_name.data();
	if (smbd_requ->in_hdr_flags & SMB2_HDR_FLAG_DFS) {
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
	x_smbd_open_t *ret = nullptr;
	x_auto_ref_t<x_smbd_disk_object_t> disk_object{x_smbd_disk_object_pool_find_and_open(
			smbd_disk_object_pool,
			smbd_tcon, path)};

	if (state->in_create_disposition == FILE_CREATE) {
		std::unique_lock<std::mutex> lock(disk_object->mutex);

		if (disk_object->exists()) {
			status = NT_STATUS_OBJECT_NAME_COLLISION;
		} else {
			ret = open_object_new(smbd_tcon, disk_object, *state, status);
		}

	} else if (state->in_create_disposition == FILE_OPEN) {
		std::unique_lock<std::mutex> lock(disk_object->mutex);
		if (disk_object->exists()) {
			ret = open_object_exist(smbd_tcon, disk_object, *state, status);
		} else {
			status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}

	} else if (state->in_create_disposition == FILE_OPEN_IF) {
		std::unique_lock<std::mutex> lock(disk_object->mutex);
		if (disk_object->exists()) {
			ret = open_object_exist(smbd_tcon, disk_object, *state, status);
		} else {
			ret = open_object_new(smbd_tcon, disk_object, *state, status);
		}

	} else if (state->in_create_disposition == FILE_OVERWRITE_IF ||
			state->in_create_disposition == FILE_SUPERSEDE) {
		/* TODO
		 * Currently we're using FILE_SUPERSEDE as the same as
		 * FILE_OVERWRITE_IF but they really are
		 * different. FILE_SUPERSEDE deletes an existing file
		 * (requiring delete access) then recreates it.
		 */
		std::unique_lock<std::mutex> lock(disk_object->mutex);
		if (disk_object->exists()) {
			int err = ftruncate(disk_object->fd, 0);
			X_ASSERT(err == 0); // TODO
			ret = open_object_exist(smbd_tcon, disk_object, *state, status);
		} else {
			ret = open_object_new(smbd_tcon, disk_object, *state, status);
		}

	} else {
		X_TODO;
	}

	if (ret && state->out_create_action == FILE_WAS_CREATED) {
		notify_fname(disk_object, NOTIFY_ACTION_ADDED,
				(state->in_create_options & FILE_DIRECTORY_FILE) ? FILE_NOTIFY_CHANGE_DIR_NAME : FILE_NOTIFY_CHANGE_FILE_NAME);
	}
	return ret;
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

