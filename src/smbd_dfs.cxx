
#include "smbd.hxx"
#include "smbd_share.hxx"
#include "smbd_conf.hxx"
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <attr/xattr.h>
#include "smbd_posixfs.hxx"
#include "smbd_posixfs_utils.hxx"
#include <sys/file.h>

static const char *pesudo_tld_dir = ".tlds";

enum {
	dfs_object_type_none,
	dfs_object_type_dfs_root,
	dfs_object_type_dfs_top_level,
	dfs_object_type_dfs_denied,

	dfs_object_type_volume_root,
	dfs_object_type_volume_top_level,
	dfs_object_type_volume_normal,
};

enum {
	dfs_open_type_none,
	dfs_open_type_dfs_root,
	dfs_open_type_tld_manager,
	dfs_open_type_under_tld_manager,
	dfs_open_type_normal,
};

static const char *pseudo_entries[] = {
	".",
	"..",
//	".snapshot",
};
#define PSEUDO_ENTRIES_COUNT    X_ARRAY_SIZE(pseudo_entries)

/*
static std::pair<std::string, std::string> find_node_by_volume(const x_smbd_conf_t &smbd_conf,
		const std::string &volume)
{
	const x_smbd_volume_t *vol = x_smbd_find_volume(smbd_conf, volume);
	X_ASSERT(vol);
	return { vol->owner_node, vol->path };
}
*/
struct dfs_share_t : x_smbd_share_t
{
	dfs_share_t(const x_smbd_conf_t &smbd_conf,
			const std::string &name,
			uint32_t share_flags,
			const std::vector<std::shared_ptr<x_smbd_volume_t>> &volumes);
	uint8_t get_type() const override { return X_SMB2_SHARE_TYPE_DISK; }
	bool is_dfs() const override { return true; }
	NTSTATUS resolve_path(std::shared_ptr<x_smbd_volume_t> &smbd_volume,
			std::u16string &out_path,
			long &path_priv_data,
			long &open_priv_data,
			bool dfs,
			const char16_t *in_path_begin,
			const char16_t *in_path_end,
			const std::string &volume) override;

	NTSTATUS create_open(x_smbd_open_t **psmbd_open,
			x_smbd_requ_t *smbd_requ,
			const std::string &volume,
			std::unique_ptr<x_smb2_state_create_t> &state,
			std::vector<x_smb2_change_t> &changes) override;

	NTSTATUS get_dfs_referral(x_dfs_referral_resp_t &dfs_referral,
			const char16_t *in_full_path_begin,
			const char16_t *in_full_path_end,
			const char16_t *in_server_begin,
			const char16_t *in_server_end,
			const char16_t *in_share_begin,
			const char16_t *in_share_end) const override;
	virtual NTSTATUS delete_object(x_smbd_object_t *smbd_object,
			x_smbd_open_t *smbd_open, int fd,
			std::vector<x_smb2_change_t> &changes) override;

	std::shared_ptr<x_smbd_volume_t> find_volume(const std::string &name) const {
		for (auto &vol: volumes) {
			if (vol->name == name) {
				return vol;
			}
		}
		return nullptr;
	}

	const std::vector<std::shared_ptr<x_smbd_volume_t>> volumes;
	std::shared_ptr<x_smbd_volume_t> root_volume;
	std::map<std::string, std::shared_ptr<x_smbd_volume_t>> local_data_volume;
};

static NTSTATUS dfs_root_resolve_path(
		const dfs_share_t &dfs_share,
		std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		std::u16string &path,
		long &path_priv_data,
		long &open_priv_data,
		bool dfs,
		const char16_t *in_path_begin,
		const char16_t *in_path_end)
{
	const char16_t *path_start;
	if (dfs) {
		/* TODO we just skip the first 2 components for now */
		auto sep = x_next_sep(in_path_begin, in_path_end, u'\\');
		if (sep == in_path_end) {
			X_LOG_ERR("Invalid dfs_root path '%s'",
					x_convert_utf16_to_utf8_safe(in_path_begin,
						in_path_end).c_str());
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}

		sep = x_next_sep(sep + 1, in_path_end, u'\\');
		if (sep == in_path_end) {
			path_start = in_path_end;
		} else {
			path_start = sep + 1;
		}
	} else {
		path_start = in_path_begin;
	}

	if (path_start == in_path_end) {
		path_priv_data = dfs_object_type_dfs_root;
		open_priv_data = dfs_open_type_dfs_root;
		smbd_volume = dfs_share.root_volume;
		path.clear();
		return NT_STATUS_OK;
	}

	auto sep = x_next_sep(path_start, in_path_end, u'\\');
	std::string utf8_top_level;
	if (!x_convert_utf16_to_utf8_new(path_start, sep,
				utf8_top_level, x_tolower)) {
		return NT_STATUS_ILLEGAL_CHARACTER;
	}
	if (sep == in_path_end) {
		if (utf8_top_level == pesudo_tld_dir) {
			open_priv_data = dfs_open_type_tld_manager;
			path_priv_data = dfs_object_type_dfs_root;
			/* the pesudo_tld_dir actually ref to the root */
			path.clear();
		} else {
			open_priv_data = dfs_open_type_normal;
			path_priv_data = dfs_object_type_dfs_top_level;
			path.assign(path_start, in_path_end);
		}
		smbd_volume = dfs_share.root_volume;
		return NT_STATUS_OK;
	}

	if (utf8_top_level == pesudo_tld_dir) {
		auto sep2 = x_next_sep(sep + 1, in_path_end, u'\\');
		if (sep2 != in_path_end) {
			path_priv_data = dfs_object_type_dfs_denied;
		} else {
			path_priv_data = dfs_object_type_dfs_top_level;
		}
		open_priv_data = dfs_open_type_under_tld_manager;
		path.assign(sep + 1, in_path_end);
		smbd_volume = dfs_share.root_volume;
		return NT_STATUS_OK;
	}

	return NT_STATUS_OBJECT_NAME_NOT_FOUND;
}

static NTSTATUS dfs_volume_resolve_path(
		dfs_share_t &dfs_share,
		std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		std::u16string &path,
		long &path_priv_data,
		long &open_priv_data,
		bool dfs,
		const char16_t *in_path_begin,
		const char16_t *in_path_end,
		const std::string &volume)
{
	auto it = dfs_share.local_data_volume.find(volume);
	if (it == dfs_share.local_data_volume.end()) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	const char16_t *path_start;
	if (dfs) {
		/* TODO we just skip the first 2 components for now */
		auto sep = x_next_sep(in_path_begin, in_path_end, u'\\');
		X_ASSERT(sep != in_path_end);
		sep = x_next_sep(sep + 1, in_path_end, u'\\');
		if (sep == in_path_end) {
			path_start = sep;
		} else {
			path_start = sep + 1;
		}
	} else {
		path_start = in_path_begin;
	}

	if (path_start == in_path_end) {
		/* shoule we deny open the volume root directly? */
		path_priv_data = dfs_object_type_volume_root;
	} else {
		auto sep = x_next_sep(path_start, in_path_end, u'\\');
		if (sep == in_path_end) {
			path_priv_data = dfs_object_type_volume_top_level;
		} else {
			path_priv_data = dfs_object_type_volume_normal;
		}
	}
	open_priv_data = dfs_open_type_none;
	path.assign(path_start, in_path_end);
	smbd_volume = it->second;
	return NT_STATUS_OK;
}

static void set_tld_target(int fd, const std::string &volume, const std::string &uuid)
{
	std::string val = volume + ':' + uuid;
	ssize_t err = fsetxattr(fd, XATTR_TLD_PATH, val.c_str(), val.length() + 1, 0);
	X_ASSERT(err == 0);
}

static int get_tld_target(int fd, std::string &volume, std::string &uuid)
{
	char buf[1024];
	ssize_t err = fgetxattr(fd, XATTR_TLD_PATH, buf, sizeof buf - 1);
	if (err < 0) {
		return -1;
	}

	buf[err] = '\0';
	const char *sep = strchr(buf, ':');
	X_ASSERT(sep);
	volume.assign(buf, sep - buf);
	uuid = sep + 1;
	return 0;
}

enum class top_level_object_state_t {
	not_exist,
	is_file,
	is_dir,
};

static inline top_level_object_state_t get_tlo_state(
		const std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		const std::string &tld)
{
	int fd = openat(smbd_volume->rootdir_fd, tld.c_str(), O_NOFOLLOW);
	if (fd < 0) {
		return top_level_object_state_t::not_exist;
	}
	
	struct stat st;
	int err = fstat(fd, &st);
	X_ASSERT(!err);

	return S_ISDIR(st.st_mode) ? top_level_object_state_t::is_dir :
		top_level_object_state_t::is_file;
}

static bool dfs_root_process_entry(
		x_smbd_object_meta_t *object_meta,
		x_smbd_stream_meta_t *stream_meta,
		std::shared_ptr<idl::security_descriptor> *ppsd,
		posixfs_object_t *dir_obj,
		const char *ent_name,
		uint32_t file_number)
{
	/* TODO match pattern */
	int ret = 0;
	if (file_number >= PSEUDO_ENTRIES_COUNT) {
		ret = posixfs_object_statex_getat(dir_obj, ent_name,
				object_meta, stream_meta, ppsd);
		if (ret != 0) {
			return false;
		}
		if (object_meta->file_attributes & X_SMB2_FILE_ATTRIBUTE_DIRECTORY && strcmp(ent_name, pesudo_tld_dir) != 0) {
			object_meta->file_attributes |= X_SMB2_FILE_ATTRIBUTE_REPARSE_POINT;
		}
	} else {
		/* TODO should lock dir_obj */
		/* since this is root dir, .. is same as . */
		ret = posixfs_object_get_statex(dir_obj, object_meta, stream_meta);
	}

	return ret == 0;
}

static bool dfs_tld_manager_process_entry(
		x_smbd_object_meta_t *object_meta,
		x_smbd_stream_meta_t *stream_meta,
		std::shared_ptr<idl::security_descriptor> *ppsd,
		posixfs_object_t *dir_obj,
		const char *ent_name,
		uint32_t file_number)
{
	/* TODO match pattern */

	int ret = 0;
	if (file_number >= PSEUDO_ENTRIES_COUNT) {
		if (strcmp(ent_name, pesudo_tld_dir) == 0) {
			return false;
		}
		ret = posixfs_object_statex_getat(dir_obj, ent_name,
				object_meta, stream_meta, ppsd);
		if (ret != 0) {
			return false;
		}
		if (!(object_meta->file_attributes & X_SMB2_FILE_ATTRIBUTE_DIRECTORY)) {
			return false;
		}
		object_meta->file_attributes &= ~X_SMB2_FILE_ATTRIBUTE_REPARSE_POINT;
	} else if (file_number == 0) {
		/* TODO should lock dir_obj */
		ret = posixfs_object_get_statex(dir_obj, object_meta, stream_meta);
	} else {
		X_ASSERT(file_number == 1);
		ret = posixfs_object_get_parent_statex(dir_obj, object_meta, stream_meta);
	}

	return ret == 0;
}

static inline void create_new_tld(dfs_share_t &dfs_share,
		x_smbd_requ_t *smbd_requ,
		x_smbd_object_t *smbd_object)
{
	// tld creation is started from the node host the share root
	X_ASSERT(dfs_share.root_volume);
	const std::u16string &u16name = smbd_object->path;
	auto name = x_convert_utf16_to_utf8_assert(u16name);

	uint8_t uuid[16];
	x_rand_bytes(uuid, sizeof uuid);
	size_t volume_idx = 1 + uuid[0] % (dfs_share.volumes.size() - 1);
	char uuid_str[33];
	for (uint32_t i = 0; i < 16; ++i) {
		snprintf(&uuid_str[2 * i], 3, "%02x", uuid[i]);
	}

	const auto &data_volume = dfs_share.volumes[volume_idx];

	auto &root_volume = dfs_share.root_volume;
	/* TODO, make the 3 step mkdirat, openat and flock be atomic */
	int err = mkdirat(root_volume->rootdir_fd, name.c_str(), 0777);
	X_ASSERT(err == 0);
	int fd = openat(root_volume->rootdir_fd, name.c_str(), O_RDONLY);
	err = flock(fd, LOCK_EX);
	X_ASSERT(err == 0);

	std::vector<uint8_t> ntacl_blob;
	/* TODO single node from now, for multi node, it should send msg to
	   the node hosting tld to create it
	 */
	auto smbd_conf = x_smbd_conf_get();
	if (data_volume->owner_node == smbd_conf->node) {
		posixfs_mktld(x_smbd_sess_get_user(smbd_requ->smbd_sess), *data_volume,
				uuid_str, ntacl_blob);
	} else {
		X_TODO;
	}
	x_smbd_posixfs_object_init(smbd_object, fd, true,
			name, ntacl_blob);
#if 0
	x_smbd_object_meta_t object_meta;
	x_smbd_stream_meta_t stream_meta;
	posixfs_post_create(fd, FILE_ATTRIBUTE_DIRECTORY,
			&object_meta, &stream_meta, ntacl_blob);
	close(fd);
#endif
	set_tld_target(fd, data_volume->name, uuid_str);
}

static NTSTATUS dfs_root_object_op_rename(x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		const std::u16string &new_path,
		std::unique_ptr<x_smb2_state_rename_t> &state)
{
	if (smbd_open->open_state.priv_data == dfs_open_type_dfs_root) {
		/* should not reach here because we do not grant delete permission
		 * on it
		 */
		X_ASSERT(false);
		return NT_STATUS_UNSUCCESSFUL;

	} else if (smbd_open->open_state.priv_data == dfs_open_type_tld_manager) {
		/* should not reach here because we do not grant delete permission
		 * on it
		 */
		X_ASSERT(false);
		return NT_STATUS_UNSUCCESSFUL;

	} else if (smbd_open->open_state.priv_data == dfs_open_type_under_tld_manager) {
		/* we do not allow to open the top level dir directly, so it must be tld */
		auto sep = new_path.find(u'\\');
		if (sep == std::u16string::npos) {
			return NT_STATUS_ACCESS_DENIED;
		}
		std::string first_level;
		if (!x_convert_utf16_to_utf8_new(new_path.data(),
				new_path.data() + sep, first_level, x_tolower)) {
			return NT_STATUS_ILLEGAL_CHARACTER;
		}
		if (first_level != pesudo_tld_dir) {
			return NT_STATUS_ACCESS_DENIED;
		}

		auto sep2 = new_path.find(u'\\', sep + 1);
		if (sep2 != std::u16string::npos) {
			return NT_STATUS_ACCESS_DENIED;
		}

		auto old_path = new_path.substr(0, sep + 1) + smbd_object->path;
		NTSTATUS status =  posixfs_object_op_rename(smbd_object,
				smbd_open,
				smbd_requ,
				new_path.substr(sep + 1),
				state);
		if (NT_STATUS_IS_OK(status)) {
			state->out_changes.push_back(x_smb2_change_t{NOTIFY_ACTION_OLD_NAME, 
					FILE_NOTIFY_CHANGE_DIR_NAME,
					smbd_open->open_state.parent_lease_key,
					old_path,
					new_path});
		}
		return status;
	} else {
		X_ASSERT(smbd_open->open_state.priv_data == dfs_open_type_normal);
		auto sep = new_path.find(u'\\');
		if (sep != std::u16string::npos) {
			return NT_STATUS_ACCESS_DENIED;
		}
		return posixfs_object_op_rename(smbd_object, smbd_open, smbd_requ,
				new_path, state);
	}
}


/* smbd_object->mutex is already locked */
NTSTATUS dfs_share_t::delete_object(x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open, int fd,
		std::vector<x_smb2_change_t> &changes)
{
	if (smbd_open->open_state.priv_data == dfs_open_type_dfs_root) {
		X_ASSERT(false);
		return NT_STATUS_UNSUCCESSFUL;
	} else if (smbd_open->open_state.priv_data == dfs_open_type_tld_manager) {
		X_ASSERT(false);
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	X_ASSERT(smbd_object->type != x_smbd_object_t::type_not_exist);
	if (smbd_object->type == x_smbd_object_t::type_dir) {
		std::string volume, uuid;
		int err = get_tld_target(fd, volume, uuid);
		if (err != 0) {
			return NT_STATUS_UNSUCCESSFUL;
		}

		auto smbd_volume = find_volume(volume);
		// auto [host_node, volume_path] = find_node_by_volume(*smbd_conf, volume);

		/* TODO first mark dir fd in deleting */
		/* TODO single node from now, for multi node, it should send msg to
		   the node hosting tld to delete it
		 */
		auto smbd_conf = x_smbd_conf_get();
		if (smbd_volume->owner_node == smbd_conf->node) {
			auto data_volume = local_data_volume[volume];
			X_ASSERT(data_volume);
			err = unlinkat(data_volume->rootdir_fd, uuid.c_str(), AT_REMOVEDIR);
			if (err != 0) {
				if (errno == ENOTEMPTY) {
					return NT_STATUS_DIRECTORY_NOT_EMPTY;
				} else {
					return NT_STATUS_INTERNAL_ERROR;
				}
			}
			std::u16string path = x_convert_utf8_to_utf16_assert(pesudo_tld_dir);
			path += u'\\';
			path += smbd_object->path;
			changes.push_back(x_smb2_change_t{NOTIFY_ACTION_REMOVED,
					FILE_NOTIFY_CHANGE_DIR_NAME,
					smbd_open->open_state.parent_lease_key,
					path,
					{}});
		} else {
			X_TODO;
		}

		return posixfs_object_op_unlink(smbd_object, fd);
	} else {
		return posixfs_object_op_unlink(smbd_object, fd);
	}
}

static NTSTATUS dfs_root_object_op_read(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_read_t> &state)
{
	if (smbd_open->open_state.priv_data != dfs_open_type_normal) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return posixfs_object_op_read(smbd_object, smbd_open, smbd_requ, state);
}

static NTSTATUS dfs_root_object_op_write(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_write_t> &state)
{
	if (smbd_open->open_state.priv_data != dfs_open_type_normal) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return posixfs_object_op_write(smbd_object, smbd_open, smbd_requ, state);
}

static NTSTATUS dfs_root_object_op_lock(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_lock_t> &state)
{
	if (smbd_open->open_state.priv_data != dfs_open_type_normal) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return posixfs_object_op_lock(smbd_object, smbd_open, smbd_conn, smbd_requ, state);
}


static bool dfs_tld_process_entry(
		x_smbd_object_meta_t *object_meta,
		x_smbd_stream_meta_t *stream_meta,
		std::shared_ptr<idl::security_descriptor> *ppsd,
		posixfs_object_t *dir_obj,
		const char *ent_name,
		uint32_t file_number)
{
	/* TODO match pattern */
	int ret = 0;
	if (file_number >= PSEUDO_ENTRIES_COUNT) {
		return false;
	} else {
		/* TODO parent dir should be pesudo_tld_dir */
		ret = posixfs_object_get_statex(dir_obj, object_meta, stream_meta);
	}

	return ret == 0;
}

static NTSTATUS dfs_root_object_op_qdir(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_qdir_t> &state)
{
	if (smbd_open->open_state.priv_data == dfs_open_type_dfs_root) {
		return posixfs_object_qdir(smbd_object, smbd_conn, smbd_requ, state,
				pseudo_entries, PSEUDO_ENTRIES_COUNT,
				dfs_root_process_entry);
	} else if (smbd_open->open_state.priv_data == dfs_open_type_tld_manager) {
		return posixfs_object_qdir(smbd_object, smbd_conn, smbd_requ, state,
				pseudo_entries, PSEUDO_ENTRIES_COUNT,
				dfs_tld_manager_process_entry);
	} else if (smbd_open->open_state.priv_data == dfs_open_type_under_tld_manager) {
		return posixfs_object_qdir(smbd_object, smbd_conn, smbd_requ, state,
				pseudo_entries, PSEUDO_ENTRIES_COUNT,
				dfs_tld_process_entry);
	} else {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
}

static NTSTATUS dfs_root_object_op_set_delete_on_close(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		bool delete_on_close)
{
	if (smbd_open->open_state.priv_data == dfs_open_type_dfs_root) {
		return NT_STATUS_ACCESS_DENIED;
	} else if (smbd_open->open_state.priv_data == dfs_open_type_tld_manager) {
		return NT_STATUS_ACCESS_DENIED;
	} else if (smbd_open->open_state.priv_data == dfs_open_type_under_tld_manager) {
		return posixfs_object_op_set_delete_on_close(smbd_object,
				smbd_open, smbd_requ, delete_on_close);
	} else {
		return posixfs_object_op_set_delete_on_close(smbd_object,
				smbd_open, smbd_requ, delete_on_close);
	}
}

static void dfs_root_notify_change(std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		const std::u16string &path,
		const std::u16string &fullpath,
		const std::u16string *new_fullpath,
		uint32_t notify_action,
		uint32_t notify_filter,
		const x_smb2_lease_key_t &ignore_lease_key,
		bool last_level)
{
	NTSTATUS status;
	x_smbd_object_t *smbd_object = nullptr;
	long open_priv_data;
	if (path.empty()) {
		open_priv_data = dfs_open_type_dfs_root;
		smbd_object = smbd_volume->ops->open_object(&status,
				smbd_volume, path, dfs_object_type_dfs_root, false);
	} else {
		open_priv_data = dfs_open_type_tld_manager;
		std::string utf8_path = x_convert_utf16_to_utf8_assert(path, x_tolower);
		if (utf8_path != pesudo_tld_dir) {
			return;
		}
		smbd_object = smbd_volume->ops->open_object(&status,
				smbd_volume, std::u16string(), dfs_object_type_dfs_root, false);
	}

	if (!smbd_object) {
		return;
	}

	posixfs_object_notify_change(smbd_object, notify_action, notify_filter,
			path.empty() ? 0: x_convert<uint32_t>(path.length() + 1),
			fullpath, new_fullpath, ignore_lease_key,
			last_level,
			open_priv_data);
	x_smbd_object_release(smbd_object, nullptr);
}

static inline void dfs_root_op_lease_break(
		x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream)
{
	X_TODO;
}


static x_smbd_object_t *dfs_root_op_open_object(NTSTATUS *pstatus,
		std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		const std::u16string &path,
		long path_priv_data,
		bool create_if)
{
	if (path_priv_data == dfs_object_type_dfs_denied) {
		*pstatus = NT_STATUS_ACCESS_DENIED;
		return nullptr;
	}

	return x_smbd_posixfs_open_object(
			pstatus, smbd_volume,
			path, path_priv_data, create_if);
}

static NTSTATUS dfs_root_create_open(dfs_share_t &dfs_share,
		x_smbd_open_t **psmbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state,
		std::vector<x_smb2_change_t> &changes)
{
	x_smbd_object_t *smbd_object = state->smbd_object;
	std::lock_guard lock(smbd_object->mutex);
	if (state->open_priv_data == dfs_open_type_dfs_root) {
		if (state->in_ads_name.size() > 0) {
			return NT_STATUS_ACCESS_DENIED;
		}
		return x_smbd_posixfs_create_open(psmbd_open, smbd_requ,
				state, changes);

	} else if (state->open_priv_data == dfs_open_type_tld_manager) {
		if (state->in_ads_name.size() > 0) {
			return NT_STATUS_ACCESS_DENIED;
		}
		return x_smbd_posixfs_create_open(psmbd_open, smbd_requ,
				state, changes);

	} else if (state->open_priv_data == dfs_open_type_under_tld_manager) {
		if (smbd_object->type == x_smbd_object_t::type_dir) {
			return x_smbd_posixfs_create_open(psmbd_open,
					smbd_requ, state, changes);
		} else {
			X_ASSERT(smbd_object->type == x_smbd_object_t::type_not_exist);
			if (state->in_create_disposition != x_smb2_create_disposition_t::OPEN_IF
					&& state->in_create_disposition != x_smb2_create_disposition_t::CREATE) {
				return NT_STATUS_OBJECT_NAME_NOT_FOUND;
			} else if (!(state->in_create_options & X_SMB2_CREATE_OPTION_DIRECTORY_FILE)) {
				return NT_STATUS_ACCESS_DENIED;
			} else {
				// TODO create new tld
				// not support SecD
				create_new_tld(dfs_share, smbd_requ, smbd_object);
				state->in_create_disposition = x_smb2_create_disposition_t::OPEN_IF;
				NTSTATUS status = x_smbd_posixfs_create_open(psmbd_open,
						smbd_requ,
						state, changes);
				if (NT_STATUS_IS_OK(status)) {
					state->out_create_action = x_smb2_create_action_t::WAS_CREATED;
				}
				changes.push_back(x_smb2_change_t{NOTIFY_ACTION_ADDED, 
						FILE_NOTIFY_CHANGE_DIR_NAME,
						x_smb2_lease_key_t{0, 0},
						smbd_object->path,
						{}});
				changes.push_back(x_smb2_change_t{NOTIFY_ACTION_ADDED, 
						FILE_NOTIFY_CHANGE_DIR_NAME,
						state->lease.parent_key,
						u".tlds\\" + smbd_object->path,
						{}});
				return status;
			}
		}
	} else {
		X_ASSERT(state->open_priv_data == dfs_open_type_normal);
		if (smbd_object->type == x_smbd_object_t::type_dir) {
			return NT_STATUS_PATH_NOT_COVERED;
		} else if (smbd_object->type == x_smbd_object_t::type_file) {
			return x_smbd_posixfs_create_open(psmbd_open,
					smbd_requ,
					state, changes);
		} else {
			X_ASSERT(smbd_object->type == x_smbd_object_t::type_not_exist);
			if ((state->in_create_options & X_SMB2_CREATE_OPTION_DIRECTORY_FILE)) {
				return NT_STATUS_ACCESS_DENIED;
			}

			if (state->end_with_sep) {
				return NT_STATUS_OBJECT_NAME_INVALID;
			}
			return x_smbd_posixfs_create_open(psmbd_open,
					smbd_requ,
					state, changes);
		}
	}

	X_TODO;
	return NT_STATUS_UNSUCCESSFUL;
}

static const x_smbd_object_ops_t dfs_root_object_ops = {
	dfs_root_op_open_object,
	posixfs_op_open_durable,
	posixfs_object_op_close,
	dfs_root_object_op_read,
	dfs_root_object_op_write,
	posixfs_object_op_flush,
	dfs_root_object_op_lock,
	posixfs_object_op_getinfo,
	posixfs_object_op_setinfo,
	posixfs_object_op_ioctl,
	dfs_root_object_op_qdir,
	posixfs_object_op_notify,
	posixfs_object_op_lease_break,
	posixfs_object_op_oplock_break,
	dfs_root_object_op_rename,
	dfs_root_object_op_set_delete_on_close,
	dfs_root_notify_change,
	posixfs_object_op_destroy,
	posixfs_op_release_object,
	posixfs_op_get_meta,
	posixfs_op_get_path,
};

static bool dfs_volume_process_entry(
		x_smbd_object_meta_t *object_meta,
		x_smbd_stream_meta_t *stream_meta,
		std::shared_ptr<idl::security_descriptor> *ppsd,
		posixfs_object_t *dir_obj,
		const char *ent_name,
		uint32_t file_number)
{
	/* TODO match pattern */

	int ret = 0;
	if (file_number >= X_ARRAY_SIZE(pseudo_entries)) {
		ret = posixfs_object_statex_getat(dir_obj, ent_name,
				object_meta, stream_meta, ppsd);
	} else if (file_number == 0) {
		/* TODO should lock dir_obj */
		ret = posixfs_object_get_statex(dir_obj, object_meta, stream_meta);
	} else if (file_number == 1) {
		ret = posixfs_object_get_parent_statex(dir_obj, object_meta, stream_meta);
	} else {
		return -1; // TODO not support snapshot for now
#if 0
		/* .snapshot */
		if (dir_obj->flags & posixfs_object_t::flag_topdir) {
			/* TODO if snapshot browsable */
			ret = qdir_get_dirent_meta_special(statex, dir_obj, ent_name);
		} else {
			return false;
		}
#endif
	}

	return ret == 0;
}

static NTSTATUS dfs_volume_object_op_qdir(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_qdir_t> &state)
{
	return posixfs_object_qdir(smbd_object, smbd_conn, smbd_requ, state,
			pseudo_entries, X_ARRAY_SIZE(pseudo_entries),
			dfs_volume_process_entry);
}

static NTSTATUS dfs_volume_create_open(x_smbd_open_t **psmbd_open,
		x_smbd_requ_t *smbd_requ,
		const std::string &volume,
		std::unique_ptr<x_smb2_state_create_t> &state,
		std::vector<x_smb2_change_t> &changes)
{
	x_smbd_object_t *smbd_object = state->smbd_object;
	if (smbd_object->priv_data != dfs_object_type_volume_normal) {
		/* we do not allow create/delete top level object */
		if (state->in_create_disposition == x_smb2_create_disposition_t::CREATE ||
				state->in_create_disposition == x_smb2_create_disposition_t::OVERWRITE ||
				state->in_create_disposition == x_smb2_create_disposition_t::OVERWRITE_IF ||
				state->in_create_disposition == x_smb2_create_disposition_t::SUPERSEDE) {
			return NT_STATUS_ACCESS_DENIED;
		}
		if (state->in_desired_access & idl::SEC_STD_DELETE) {
			return NT_STATUS_ACCESS_DENIED;
		}
		state->in_create_disposition = x_smb2_create_disposition_t::OPEN;
	}

	std::lock_guard lock(smbd_object->mutex);
	return x_smbd_posixfs_create_open(psmbd_open,
			smbd_requ,
			state, changes);
}

static NTSTATUS dfs_volume_object_op_rename(x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		const std::u16string &new_path,
		std::unique_ptr<x_smb2_state_rename_t> &state)
{
	/* not allow rename to top level */
	if (new_path.find(u'\\') == std::u16string::npos) {
		return NT_STATUS_ACCESS_DENIED;
	}
	return posixfs_object_op_rename(smbd_object, smbd_open, smbd_requ,
			new_path, state);
}

static const x_smbd_object_ops_t dfs_volume_object_ops = {
	x_smbd_posixfs_open_object,
	posixfs_op_open_durable,
	posixfs_object_op_close,
	posixfs_object_op_read,
	posixfs_object_op_write,
	posixfs_object_op_flush,
	posixfs_object_op_lock,
	posixfs_object_op_getinfo,
	posixfs_object_op_setinfo,
	posixfs_object_op_ioctl,
	dfs_volume_object_op_qdir,
	posixfs_object_op_notify,
	posixfs_object_op_lease_break,
	posixfs_object_op_oplock_break,
	dfs_volume_object_op_rename,
	posixfs_object_op_set_delete_on_close,
	posixfs_simple_notify_change,
	posixfs_object_op_destroy,
	posixfs_op_release_object,
	posixfs_op_get_meta,
	posixfs_op_get_path,
};

NTSTATUS dfs_share_t::resolve_path(std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		std::u16string &out_path,
		long &path_priv_data,
		long &open_priv_data,
		bool dfs,
		const char16_t *in_path_begin,
		const char16_t *in_path_end,
		const std::string &volume)
{
	if (volume.empty()) {
		return NT_STATUS_PATH_NOT_COVERED;
	} else if (volume == "-") {
		return dfs_root_resolve_path(*this, smbd_volume, out_path,
				path_priv_data, open_priv_data,
				dfs, in_path_begin, in_path_end);
	} else {
		return dfs_volume_resolve_path(*this, smbd_volume, out_path,
				path_priv_data, open_priv_data,
				dfs, in_path_begin, in_path_end,
				volume);
	}
}

static NTSTATUS dfs_root_referral(const dfs_share_t &dfs_share,
		const x_smbd_conf_t &smbd_conf,
		x_dfs_referral_resp_t &dfs_referral_resp,
		const char16_t *in_full_path_begin,
		const char16_t *in_full_path_end,
		const char16_t *in_server_begin,
		const char16_t *in_server_end,
		const char16_t *in_share_begin,
		const char16_t *in_share_end)
{
	const auto &first = dfs_share.volumes[0];

	std::u16string alt_path(in_full_path_begin, in_share_end);
	std::string node = "\\";
	node += first->owner_node + "." + smbd_conf.dns_domain + "\\-";
	std::u16string node16 = x_convert_utf8_to_utf16_assert(node);
	node16.append(in_share_begin, in_share_end);
	dfs_referral_resp.referrals.push_back(x_referral_t{DFS_SERVER_ROOT, 0,
			dfs_share.dfs_referral_ttl, alt_path, node16});
	dfs_referral_resp.header_flags = DFS_HEADER_FLAG_REFERAL_SVR | DFS_HEADER_FLAG_STORAGE_SVR;
	dfs_referral_resp.path_consumed = x_convert_assert<uint16_t>(alt_path.length() * 2);
	return NT_STATUS_OK;
}

static NTSTATUS dfs_volume_referral(const dfs_share_t &dfs_share,
		const x_smbd_conf_t &smbd_conf,
		x_dfs_referral_resp_t &dfs_referral_resp,
		const char16_t *in_full_path_begin,
		const char16_t *in_full_path_end,
		const char16_t *in_server_begin,
		const char16_t *in_server_end,
		const char16_t *in_share_begin,
		const char16_t *in_share_end,
		const char16_t *in_tld_end,
		const std::string &volume,
		const std::string &uuid)
{
	const auto &first_vol = dfs_share.volumes[0];
	auto node_name = first_vol->owner_node;

	std::u16string alt_path(in_full_path_begin, in_tld_end);
	std::string node = "\\" + node_name + "." + smbd_conf.dns_domain + "\\--" + volume + "\\" + uuid;
	std::u16string node16 = x_convert_utf8_to_utf16_assert(node);
	dfs_referral_resp.referrals.push_back(x_referral_t{0, 0,
			dfs_share.dfs_referral_ttl, alt_path, node16});
	dfs_referral_resp.header_flags = DFS_HEADER_FLAG_STORAGE_SVR;
	dfs_referral_resp.path_consumed = x_convert_assert<uint16_t>(alt_path.length() * 2);
	return NT_STATUS_OK;
}

static NTSTATUS dfs_share_get_dfs_referral(const dfs_share_t &dfs_share,
		const x_smbd_conf_t &smbd_conf,
		x_dfs_referral_resp_t &dfs_referral_resp,
		const char16_t *in_full_path_begin,
		const char16_t *in_full_path_end,
		const char16_t *in_server_begin,
		const char16_t *in_server_end,
		const char16_t *in_share_begin,
		const char16_t *in_share_end)
{
	if (!dfs_share.root_volume || in_share_end == in_full_path_end) {
		return dfs_root_referral(dfs_share, smbd_conf,
				dfs_referral_resp,
				in_full_path_begin, in_full_path_end,
				in_server_begin, in_server_end,
				in_share_begin, in_share_end);
	}
	
	const char16_t *in_tld_begin, *in_tld_end;
	in_tld_begin = x_skip_sep(in_share_end + 1, in_full_path_end, u'\\');
	in_tld_end = x_next_sep(in_tld_begin, in_full_path_end, u'\\');

	std::string tld;
	if (!x_convert_utf16_to_utf8_new(in_tld_begin, in_tld_end, tld, x_tolower)) {
		return NT_STATUS_ILLEGAL_CHARACTER;
	}

	if (tld == pesudo_tld_dir) {
		return dfs_root_referral(dfs_share, smbd_conf,
				dfs_referral_resp,
				in_full_path_begin, in_full_path_end,
				in_server_begin, in_server_end,
				in_share_begin, in_share_end);
	}

	int fd = openat(dfs_share.root_volume->rootdir_fd, tld.c_str(), O_NOFOLLOW);
	if (fd < 0) {
		return NT_STATUS_NOT_FOUND;
	}
	
	struct stat st;
	std::string volume, uuid;
	int err = fstat(fd, &st);
	X_ASSERT(!err);

	if (S_ISDIR(st.st_mode)) {
		int err = get_tld_target(fd, volume, uuid);
		X_ASSERT(err == 0);
	}
	close(fd);

	if (volume.size() == 0) {
		return dfs_root_referral(dfs_share, smbd_conf,
				dfs_referral_resp,
				in_full_path_begin, in_full_path_end,
				in_server_begin, in_server_end,
				in_share_begin, in_share_end);
	}

	return dfs_volume_referral(dfs_share, smbd_conf,
			dfs_referral_resp,
			in_full_path_begin, in_full_path_end,
			in_server_begin, in_server_end,
			in_share_begin, in_share_end,
			in_tld_end, volume, uuid);
}

NTSTATUS dfs_share_t::get_dfs_referral(x_dfs_referral_resp_t &dfs_referral_resp,
		const char16_t *in_full_path_begin,
		const char16_t *in_full_path_end,
		const char16_t *in_server_begin,
		const char16_t *in_server_end,
		const char16_t *in_share_begin,
		const char16_t *in_share_end) const
{
	return dfs_share_get_dfs_referral(*this,
			*x_smbd_conf_get(),
			dfs_referral_resp,
			in_full_path_begin,
			in_full_path_end,
			in_server_begin,
			in_server_end,
			in_share_begin,
			in_share_end);
}

NTSTATUS dfs_share_t::create_open(x_smbd_open_t **psmbd_open,
		x_smbd_requ_t *smbd_requ,
		const std::string &volume,
		std::unique_ptr<x_smb2_state_create_t> &state,
		std::vector<x_smb2_change_t> &changes)
{
	X_ASSERT(!volume.empty());
	if (volume == "-") {
		return dfs_root_create_open(*this, psmbd_open,
				smbd_requ, state, changes);
	} else {
		return dfs_volume_create_open(psmbd_open,
				smbd_requ, volume, state, changes);
	}
}

dfs_share_t::dfs_share_t(const x_smbd_conf_t &smbd_conf,
		const std::string &name,
		uint32_t share_flags,
		const std::vector<std::shared_ptr<x_smbd_volume_t>> &smbd_volumes)
	: x_smbd_share_t(name, share_flags), volumes(smbd_volumes)
{
	X_ASSERT(smbd_volumes.size() > 1);
	bool first = true;
	for (const auto &smbd_volume: smbd_volumes) {
		if (smbd_volume->owner_node == smbd_conf.node) {
			if (first) {
				smbd_volume->set_ops(&dfs_root_object_ops);
				root_volume = smbd_volume;
			} else {
				smbd_volume->set_ops(&dfs_volume_object_ops);
				local_data_volume[smbd_volume->name] = smbd_volume;
			}
		}
		first = false;
	}
}

std::shared_ptr<x_smbd_share_t> x_smbd_dfs_share_create(
		const x_smbd_conf_t &smbd_conf,
		const std::string &name,
		uint32_t share_flags,
		const std::vector<std::shared_ptr<x_smbd_volume_t>> &smbd_volumes)
{
	return std::make_shared<dfs_share_t>(smbd_conf, name, share_flags,
			smbd_volumes);
}

