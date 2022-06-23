
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

static const uint32_t default_referral_ttl = 10;
static const char *volumes_dir = "/data/volumes";
static const char *pesudo_tld_dir = ".tlds";

static const char *pseudo_entries[] = {
	".",
	"..",
//	".snapshot",
};
#define PSEUDO_ENTRIES_COUNT    ARRAY_SIZE(pseudo_entries)

static bool find_node_by_volume(const x_smbd_conf_t &smbd_conf,
		std::string &node,
		const std::string &volume)
{
	const auto it = smbd_conf.volume_map.find(volume);
	if (it == smbd_conf.volume_map.end()) {
		return false;
	}
	node = it->second.first;
	return true;
}

struct dfs_share_t : x_smbd_share_t
{
	dfs_share_t(const x_smbd_conf_t &smbd_conf,
			const std::string &name,
			const std::vector<std::string> &volumes)
		: x_smbd_share_t(name), volumes(volumes)
	{
		auto first_volume = volumes[0];
		std::string root_node;
		X_ASSERT(find_node_by_volume(smbd_conf, root_node, first_volume));
		if (root_node == smbd_conf.node) {
			std::string path = volumes_dir;
			path += "/" + first_volume + "/root";
			root_dir = x_smbd_topdir_create(path);
		}
		for (const auto &volume: volumes) {
			std::string node;
			X_ASSERT(find_node_by_volume(smbd_conf, node, volume));
			if (node == smbd_conf.node) {
				std::string path = volumes_dir;
				path += "/" + volume + "/data";
				local_volume_data_dir[volume] = x_smbd_topdir_create(path);
			}
		}
	}

	uint8_t get_type() const override { return SMB2_SHARE_TYPE_DISK; }
	bool is_dfs() const override { return true; }
	bool abe_enabled() const override { return false; }
	NTSTATUS create_open(x_smbd_open_t **psmbd_open,
			x_smbd_requ_t *smbd_requ,
			const std::string &volume,
			std::unique_ptr<x_smb2_state_create_t> &state) override;
	NTSTATUS get_dfs_referral(x_dfs_referral_resp_t &dfs_referral,
			const char16_t *in_full_path_begin,
			const char16_t *in_full_path_end,
			const char16_t *in_server_begin,
			const char16_t *in_server_end,
			const char16_t *in_share_begin,
			const char16_t *in_share_end) const override;
	const std::vector<std::string> volumes;
	uint32_t referral_ttl = default_referral_ttl;
	std::shared_ptr<x_smbd_topdir_t> root_dir;
	std::map<std::string, std::shared_ptr<x_smbd_topdir_t>> local_volume_data_dir;
};

static NTSTATUS dfs_root_resolve_path(
		dfs_share_t &dfs_share,
		const std::u16string &in_path,
		bool dfs,
		std::shared_ptr<x_smbd_topdir_t> &topdir,
		std::u16string &path,
		bool &end_with_sep)
{
	size_t path_start = 0;
	if (dfs) {
		/* TODO we just skip the first 2 components for now */
		auto pos = in_path.find(u'\\');
		X_ASSERT(pos != std::u16string::npos);
		pos = in_path.find(u'\\', pos + 1);
		if (pos == std::u16string::npos) {
			path_start = in_path.size();
		} else {
			path_start = pos + 1;
		}
	}
	size_t path_end = in_path.size();
	for ( ; path_end > path_start; --path_end) {
		if (in_path[path_end - 1] != u'\\') {
			break;
		}
	}
	path = in_path.substr(path_start, path_end);
	end_with_sep = path_end != in_path.size();
	topdir = dfs_share.root_dir;
	return NT_STATUS_OK;
}

static NTSTATUS dfs_volume_resolve_path(
		dfs_share_t &dfs_share,
		const std::string &volume,
		const std::u16string &in_path,
		bool dfs,
		std::shared_ptr<x_smbd_topdir_t> &topdir,
		std::u16string &path,
		bool &end_with_sep)
{
	size_t path_start = 0;
	if (dfs) {
		/* TODO we just skip the first 2 components for now */
		auto pos = in_path.find(u'\\');
		X_ASSERT(pos != std::u16string::npos);
		pos = in_path.find(u'\\', pos + 1);
		if (pos == std::u16string::npos) {
			path_start = in_path.size();
		} else {
			path_start = pos + 1;
		}
	}
	size_t path_end = in_path.size();
	for ( ; path_end > path_start; --path_end) {
		if (in_path[path_end - 1] != u'\\') {
			break;
		}
	}
	if (path_start == path_end) {
		/* we do not allow open the volume root */
		return NT_STATUS_ACCESS_DENIED;
	}
	path = in_path.substr(path_start, path_end);
	end_with_sep = path_end != in_path.size();
	auto it = dfs_share.local_volume_data_dir.find(volume);
	X_TODO_ASSERT(it != dfs_share.local_volume_data_dir.end());
	topdir = it->second;
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

static top_level_object_state_t get_tlo_state(const std::shared_ptr<x_smbd_topdir_t> &topdir, const std::string &tld)
{
	int fd = openat(topdir->fd, tld.c_str(), O_NOFOLLOW);
	if (fd < 0) {
		return top_level_object_state_t::not_exist;
	}
	
	struct stat st;
	int err = fstat(fd, &st);
	X_ASSERT(!err);

	return S_ISDIR(st.st_mode) ? top_level_object_state_t::is_dir :
		top_level_object_state_t::is_file;
}

static bool dfs_root_process_entry(posixfs_statex_t *statex,
		posixfs_object_t *dir_obj,
		const char *ent_name,
		uint32_t file_number)
{
	/* TODO match pattern */
	int ret = 0;
	if (file_number >= PSEUDO_ENTRIES_COUNT) {
		/* TODO check ntacl if ABE is enabled */
		ret = posixfs_object_statex_getat(dir_obj, ent_name, statex);
		if (ret != 0) {
			return false;
		}
		if (statex->file_attributes & FILE_ATTRIBUTE_DIRECTORY && strcmp(ent_name, pesudo_tld_dir) != 0) {
			statex->file_attributes |= FILE_ATTRIBUTE_REPARSE_POINT;
		}
	} else {
		/* TODO should lock dir_obj */
		/* since this is root dir, .. is same as . */
		ret = posixfs_object_get_statex(dir_obj, statex);
	}

	return ret == 0;
}

static NTSTATUS dfs_root_object_op_qdir(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_qdir_t> &state)
{
	return posixfs_object_qdir(smbd_object, smbd_conn, smbd_requ, state,
			pseudo_entries, PSEUDO_ENTRIES_COUNT,
			dfs_root_process_entry);
}

static const x_smbd_object_ops_t dfs_root_object_ops = {
	posixfs_object_op_close,
	nullptr,
	nullptr,
	posixfs_object_op_getinfo,
	posixfs_object_op_setinfo,
	posixfs_object_op_ioctl,
	dfs_root_object_op_qdir,
	posixfs_object_op_notify,
	nullptr, // TODO posixfs_object_op_lease_break,
	nullptr, // posixfs_object_op_oplock_break,
	nullptr, // rename
	nullptr, // set_delete_on_close
	nullptr, // unlink
	posixfs_object_op_get_path,
	posixfs_object_op_destroy,
};

static bool dfs_tld_manager_process_entry(posixfs_statex_t *statex,
		posixfs_object_t *dir_obj,
		const char *ent_name,
		uint32_t file_number)
{
	/* TODO match pattern */

	int ret = 0;
	if (file_number >= PSEUDO_ENTRIES_COUNT) {
		/* TODO check ntacl if ABE is enabled */
		if (strcmp(ent_name, pesudo_tld_dir) == 0) {
			return false;
		}
		ret = posixfs_object_statex_getat(dir_obj, ent_name, statex);
		if (ret != 0) {
			return false;
		}
		if (!(statex->file_attributes & FILE_ATTRIBUTE_DIRECTORY)) {
			return false;
		}
		statex->file_attributes &= uint32_t(~FILE_ATTRIBUTE_REPARSE_POINT);
	} else if (file_number == 0) {
		/* TODO should lock dir_obj */
		ret = posixfs_object_get_statex(dir_obj, statex);
	} else {
		X_ASSERT(file_number == 1);
		ret = posixfs_object_get_parent_statex(dir_obj, statex);
	}

	return ret == 0;
}

static NTSTATUS dfs_tld_manager_object_op_qdir(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_qdir_t> &state)
{
	x_smbd_object_t *parent_object = x_smbd_posixfs_object_open_parent(
			&dfs_root_object_ops,
			smbd_object);
	NTSTATUS status = posixfs_object_qdir(parent_object, smbd_conn, smbd_requ, state,
			pseudo_entries, PSEUDO_ENTRIES_COUNT,
			dfs_tld_manager_process_entry);
	// TODO release object x_smbd_object_release(parent_object);
	return status;
}

static const x_smbd_object_ops_t dfs_tld_manager_object_ops = {
	posixfs_object_op_close,
	nullptr,
	nullptr,
	posixfs_object_op_getinfo,
	posixfs_object_op_setinfo,
	posixfs_object_op_ioctl,
	dfs_tld_manager_object_op_qdir,
	posixfs_object_op_notify,
	nullptr, // TODO posixfs_object_op_lease_break,
	nullptr, // posixfs_object_op_oplock_break,
	nullptr, // rename
	nullptr, // set_delete_on_close
	nullptr, // unlink
	posixfs_object_op_get_path,
	posixfs_object_op_destroy,
};

static void create_new_tld(dfs_share_t &dfs_share,
		x_smbd_requ_t *smbd_requ,
		const std::string &name)
{
	// tld creation is started from the node host the share root
	X_ASSERT(dfs_share.root_dir);

	uint8_t uuid[16];
	generate_random_buffer(uuid, sizeof uuid);
	size_t volume_idx = uuid[0] % dfs_share.volumes.size();
	char uuid_str[33];
	for (uint32_t i = 0; i < 16; ++i) {
		snprintf(&uuid_str[2 * i], 3, "%02x", uuid[i]);
	}

	const auto &volume = dfs_share.volumes[volume_idx];

	auto smbd_conf = x_smbd_conf_get();
	std::string host_node;
	X_ASSERT(find_node_by_volume(*smbd_conf, host_node, volume));

	auto &topdir = dfs_share.root_dir;
	/* TODO, make the 3 step mkdirat, openat and flock be atomic */
	int err = mkdirat(topdir->fd, name.c_str(), 0777);
	X_ASSERT(err == 0);
	int fd = openat(topdir->fd, name.c_str(), O_RDONLY);
	err = flock(fd, LOCK_EX);
	X_ASSERT(err == 0);

	std::vector<uint8_t> ntacl_blob;
	/* TODO single node from now, for multi node, it should send msg to
	   the node hosting tld to create it
	 */
	if (host_node == smbd_conf->node) {
		auto data_dir = dfs_share.local_volume_data_dir[volume];
		X_ASSERT(data_dir);
		posixfs_mktld(x_smbd_sess_get_user(smbd_requ->smbd_sess), *data_dir,
				uuid_str, ntacl_blob);
	} else {
		X_TODO;
	}
	posixfs_statex_t statex;
	posixfs_post_create(fd, FILE_ATTRIBUTE_DIRECTORY,
			&statex, ntacl_blob);

	set_tld_target(fd, volume, uuid_str);
	close(fd);
}

static NTSTATUS dfs_tld_object_op_rename(x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		bool replace_if_exists,
		const std::u16string &new_path)
{
	auto sep = new_path.find(u'\\');
	if (sep == std::u16string::npos) {
		return NT_STATUS_ACCESS_DENIED;
	}
	std::string first_level = x_convert_utf16_to_lower_utf8(new_path.begin(),
			new_path.begin() + sep);
	if (first_level != pesudo_tld_dir) {
		return NT_STATUS_ACCESS_DENIED;
	}

	auto sep2 = new_path.find(u'\\', sep + 1);
	if (sep2 != std::u16string::npos) {
		return NT_STATUS_ACCESS_DENIED;
	}

	dfs_share_t &share = dynamic_cast<dfs_share_t &>(*x_smbd_tcon_get_share(smbd_requ->smbd_tcon));
	return posixfs_object_rename(smbd_object, smbd_requ,
			share.root_dir, new_path.substr(sep + 1), replace_if_exists);
}


static NTSTATUS dfs_tld_object_op_unlink(x_smbd_object_t *smbd_object, int fd)
{
	std::string volume, uuid;
	int err = get_tld_target(fd, volume, uuid);
	if (err != 0) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	X_TODO;
	return NT_STATUS_UNSUCCESSFUL;
#if 0
	auto sep = tld_target.find('\\');
	X_ASSERT(sep != std::string::npos);
	std::shared_ptr<x_smbd_share_t> smbd_share = x_smbd_find_share(
			tld_target.substr(0, sep), nullptr);
	X_ASSERT(smbd_share);

	err = x_smbd_simplefs_rmtld(smbd_share, tld_target.substr(sep + 1));
	if (err != 0) {
		return NT_STATUS_UNSUCCESSFUL;
	}
	return posixfs_object_op_unlink(smbd_object, fd);
#endif
}

static bool dfs_tld_process_entry(posixfs_statex_t *statex,
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
		ret = posixfs_object_get_statex(dir_obj, statex);
	}

	return ret == 0;
}

static NTSTATUS dfs_tld_object_op_qdir(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_qdir_t> &state)
{
	return posixfs_object_qdir(smbd_object, smbd_conn, smbd_requ, state,
			pseudo_entries, PSEUDO_ENTRIES_COUNT,
			dfs_tld_process_entry);
}


static const x_smbd_object_ops_t dfs_tld_object_ops = {
	posixfs_object_op_close,
	nullptr,
	nullptr,
	posixfs_object_op_getinfo,
	posixfs_object_op_setinfo,
	posixfs_object_op_ioctl,
	dfs_tld_object_op_qdir,
	nullptr,
	posixfs_object_op_lease_break,
	posixfs_object_op_oplock_break,
	dfs_tld_object_op_rename,
	posixfs_object_op_set_delete_on_close,
	dfs_tld_object_op_unlink,
	posixfs_object_op_get_path,
	posixfs_object_op_destroy,
};

static const x_smbd_object_ops_t dfs_file_object_ops = {
	posixfs_object_op_close,
	posixfs_object_op_read,
	posixfs_object_op_write,
	posixfs_object_op_getinfo,
	posixfs_object_op_setinfo,
	posixfs_object_op_ioctl,
	nullptr,
	nullptr,
	posixfs_object_op_lease_break,
	posixfs_object_op_oplock_break,
	nullptr, // TODO rename
	posixfs_object_op_set_delete_on_close,
	posixfs_object_op_unlink,
	posixfs_object_op_get_path,
	posixfs_object_op_destroy,
};

static NTSTATUS dfs_root_create_open(dfs_share_t &dfs_share,
		x_smbd_open_t **psmbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state)
{
	std::u16string path;
	std::shared_ptr<x_smbd_topdir_t> topdir;
	bool end_with_sep; // TODO when end_with_sep is true, return STATUS_OBJECT_NAME_INVALID if the object is a file
	NTSTATUS status = dfs_root_resolve_path(dfs_share, state->in_name,
			smbd_requ->in_hdr_flags & SMB2_HDR_FLAG_DFS,
			topdir, path, end_with_sep);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (path.size() == 0) {
		return posixfs_create_open(&dfs_root_object_ops, psmbd_open,
				topdir, path, 
				smbd_requ, state);
	}
	
	std::string utf8_path = x_convert_utf16_to_lower_utf8(path);
	if (utf8_path == pesudo_tld_dir) {
		if (state->in_desired_access & idl::SEC_STD_DELETE) {
			*psmbd_open = nullptr;
			return NT_STATUS_ACCESS_DENIED;
		}
		return posixfs_create_open(&dfs_tld_manager_object_ops, psmbd_open,
				topdir, path, 
				smbd_requ, state);
	}

	std::string first_level;
	auto sep = utf8_path.find('\\');
	if (sep != std::string::npos) {
		first_level = utf8_path.substr(0, sep);
	} else {
		first_level = utf8_path;
	}

	if (first_level == pesudo_tld_dir) {
		/* since we check utf8_path == pesudo_tld_dir, there is must a sep */
		auto sep2 = utf8_path.find('\\', sep + 1);
		if (sep2 != std::string::npos) {
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}

		std::string tld = utf8_path.substr(sep + 1);

		auto tlo_state = get_tlo_state(topdir, tld);
		if (tlo_state == top_level_object_state_t::is_file) {
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}

		if (tlo_state == top_level_object_state_t::is_dir) {
			if (state->in_create_disposition == FILE_CREATE) {
				return NT_STATUS_OBJECT_NAME_COLLISION;
			}
			return posixfs_create_open(&dfs_tld_object_ops, psmbd_open,
					topdir, x_convert_utf8_to_utf16(tld),
					smbd_requ, state);
		}

		if (state->in_create_disposition != FILE_OPEN_IF && state->in_create_disposition != FILE_CREATE) {
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}

		if (!(state->in_create_options & FILE_DIRECTORY_FILE)) {
			return NT_STATUS_ACCESS_DENIED;
		}

		create_new_tld(dfs_share, smbd_requ, tld);
		state->in_create_disposition = FILE_OPEN_IF;
		return posixfs_create_open(&dfs_tld_object_ops, psmbd_open,
				topdir, x_convert_utf8_to_utf16(tld),
				smbd_requ, state);
	}

	if (get_tlo_state(topdir, first_level) == top_level_object_state_t::is_dir) {
		return NT_STATUS_PATH_NOT_COVERED;
	}

	if (sep != std::string::npos) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (!(state->in_create_options & FILE_DIRECTORY_FILE)) {
		return posixfs_create_open(&dfs_file_object_ops, psmbd_open,
				topdir, path,
				smbd_requ, state);
	}

	return NT_STATUS_ACCESS_DENIED;
#if 0
	if (state->in_create_disposition == FILE_OPEN_IF || state->in_create_disposition == FILE_CREATE) {
		create_new_tld(*this, first_level);
		return NT_STATUS_PATH_NOT_COVERED;
	}
	return NT_STATUS_INTERNAL_ERROR;
#endif
}

static bool dfs_volume_process_entry(posixfs_statex_t *statex,
		posixfs_object_t *dir_obj,
		const char *ent_name,
		uint32_t file_number)
{
	/* TODO match pattern */

	int ret = 0;
	if (file_number >= ARRAY_SIZE(pseudo_entries)) {
		/* TODO check ntacl if ABE is enabled */
		ret = posixfs_object_statex_getat(dir_obj, ent_name, statex);
	} else if (file_number == 0) {
		/* TODO should lock dir_obj */
		ret = posixfs_object_get_statex(dir_obj, statex);
	} else if (file_number == 1) {
		ret = posixfs_object_get_parent_statex(dir_obj, statex);
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
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_qdir_t> &state)
{
	return posixfs_object_qdir(smbd_object, smbd_conn, smbd_requ, state,
			pseudo_entries, ARRAY_SIZE(pseudo_entries),
			dfs_volume_process_entry);
}

static const x_smbd_object_ops_t dfs_volume_object_ops = {
	posixfs_object_op_close,
	posixfs_object_op_read,
	posixfs_object_op_write,
	posixfs_object_op_getinfo,
	posixfs_object_op_setinfo,
	posixfs_object_op_ioctl,
	dfs_volume_object_op_qdir,
	posixfs_object_op_notify,
	posixfs_object_op_lease_break,
	posixfs_object_op_oplock_break,
	posixfs_object_op_rename,
	posixfs_object_op_set_delete_on_close,
	posixfs_object_op_unlink,
	posixfs_object_op_get_path,
	posixfs_object_op_destroy,
};

static NTSTATUS dfs_volume_create_open(dfs_share_t &dfs_share,
		x_smbd_open_t **psmbd_open,
		x_smbd_requ_t *smbd_requ,
		const std::string &volume,
		std::unique_ptr<x_smb2_state_create_t> &state)
{
	std::u16string path;
	std::shared_ptr<x_smbd_topdir_t> topdir;
	bool end_with_sep; // TODO when end_with_sep is true, return STATUS_OBJECT_NAME_INVALID if the object is a file
	NTSTATUS status = dfs_volume_resolve_path(dfs_share, volume, state->in_name,
			smbd_requ->in_hdr_flags & SMB2_HDR_FLAG_DFS,
			topdir, path, end_with_sep);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	auto pos = path.find(u'\\');
	if (pos == std::u16string::npos) {
		/* we do not allow create/delete top level object */
		if (state->in_create_disposition == FILE_CREATE ||
				state->in_create_disposition == FILE_OVERWRITE ||
				state->in_create_disposition == FILE_OVERWRITE_IF ||
				state->in_create_disposition == FILE_SUPERSEDE) {
			return NT_STATUS_ACCESS_DENIED;
		}
		if (state->in_desired_access & idl::SEC_STD_DELETE) {
			return NT_STATUS_ACCESS_DENIED;
		}
		state->in_create_disposition = FILE_OPEN;
	}

	return posixfs_create_open(&dfs_volume_object_ops,
			psmbd_open,
			topdir, path,
			smbd_requ, state);
}

NTSTATUS dfs_share_t::create_open(x_smbd_open_t **psmbd_open,
		x_smbd_requ_t *smbd_requ,
		const std::string &volume,
		std::unique_ptr<x_smb2_state_create_t> &state)
{
	if (volume == "-") {
		return dfs_root_create_open(*this, psmbd_open, smbd_requ, state);
	} else if (volume.empty()) {
		return NT_STATUS_PATH_NOT_COVERED;
	} else {
		return dfs_volume_create_open(*this, psmbd_open, smbd_requ, volume, state);
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
	const auto it = smbd_conf.volume_map.find(first);
	X_ASSERT(it != smbd_conf.volume_map.end()); // TODO
	auto node_name = it->second.first;

	std::u16string alt_path(in_full_path_begin, in_share_end);
	std::string node = "\\";
	node += node_name + "." + smbd_conf.dns_domain + "\\-";
	std::u16string node16 = x_convert_utf8_to_utf16(node);
	node16.append(in_share_begin, in_share_end);
	dfs_referral_resp.referrals.push_back(x_referral_t{DFS_SERVER_ROOT, 0,
			dfs_share.referral_ttl, alt_path, node16});
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
	const auto &first = dfs_share.volumes[0];
	const auto it = smbd_conf.volume_map.find(first);
	X_ASSERT(it != smbd_conf.volume_map.end()); // TODO
	auto node_name = it->second.first;

	std::u16string alt_path(in_full_path_begin, in_tld_end);
	std::string node = "\\" + node_name + "." + smbd_conf.dns_domain + "\\--" + volume + "\\" + uuid;
	std::u16string node16 = x_convert_utf8_to_utf16(node);
	dfs_referral_resp.referrals.push_back(x_referral_t{0, 0,
			dfs_share.referral_ttl, alt_path, node16});
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
	if (!dfs_share.root_dir || in_share_end == in_full_path_end) {
		return dfs_root_referral(dfs_share, smbd_conf,
				dfs_referral_resp,
				in_full_path_begin, in_full_path_end,
				in_server_begin, in_server_end,
				in_share_begin, in_share_end);
	}
	
	const char16_t *in_tld_begin, *in_tld_end;
	in_tld_begin = x_skip_sep(in_share_end + 1, in_full_path_end);
	in_tld_end = x_next_sep(in_tld_begin, in_full_path_end);

	std::string tld = x_convert_utf16_to_lower_utf8(in_tld_begin, in_tld_end);
	if (tld == pesudo_tld_dir) {
		return dfs_root_referral(dfs_share, smbd_conf,
				dfs_referral_resp,
				in_full_path_begin, in_full_path_end,
				in_server_begin, in_server_end,
				in_share_begin, in_share_end);
	}

	int fd = openat(dfs_share.root_dir->fd, tld.c_str(), O_NOFOLLOW);
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

std::shared_ptr<x_smbd_share_t> x_smbd_dfs_share_create(const x_smbd_conf_t &smbd_conf,
		const std::string &name,
		const std::vector<std::string> &volumes)
{
	return std::make_shared<dfs_share_t>(smbd_conf, name, volumes);
}
#if 0
NTSTATUS x_smbd_dfs_resolve_path(
		const std::shared_ptr<x_smbd_share_t> &smbd_share,
		const std::u16string &in_path,
		bool dfs,
		std::shared_ptr<x_smbd_topdir_t> &topdir,
		std::u16string &path)
{
	if (smbd_share->my_distribute_root.size() > 0) {
		return NT_STATUS_PATH_NOT_COVERED;
	}
	if (smbd_share->my_distribute_vgs.size() > 0) {
		if (!dfs) {
			X_TODO;
		}
	}

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
	topdir = smbd_share->root_dir;
	return NT_STATUS_OK;
}

std::shared_ptr<x_smbd_share_t> x_smbd_dfs_root_create(const std::string &name,
		const std::string &path, const std::vector<std::string> &vgs)
{
	return std::make_shared<dfs_root_t>(name, path, vgs);
}


struct dfs_link_t : x_smbd_share_t
{
	dfs_link_t(const std::string &name, const std::string &dfs_root)
		: x_smbd_share_t(name), dfs_root(dfs_root)
	{
	}
	uint8_t get_type() const override { return SMB2_SHARE_TYPE_DISK; }
	bool is_dfs() const override { return true; }
	bool abe_enabled() const override { return false; }
	NTSTATUS create_open(x_smbd_open_t **psmbd_open,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_create_t> &state) override
	{
		return NT_STATUS_PATH_NOT_COVERED;
	}
	NTSTATUS get_dfs_referral(x_dfs_referral_resp_t &dfs_referral,
			const char16_t *in_full_path_begin,
			const char16_t *in_full_path_end,
			const char16_t *in_server_begin,
			const char16_t *in_server_end,
			const char16_t *in_share_begin,
			const char16_t *in_share_end) const override;
	const std::string dfs_root;
	uint32_t max_referral_ttl = default_referral_ttl;
};

NTSTATUS dfs_link_t::get_dfs_referral(x_dfs_referral_resp_t &dfs_referral_resp,
		const char16_t *in_full_path_begin,
		const char16_t *in_full_path_end,
		const char16_t *in_server_begin,
		const char16_t *in_server_end,
		const char16_t *in_share_begin,
		const char16_t *in_share_end) const
{
	/* distribute namespace */
	std::u16string alt_path(in_full_path_begin, in_share_end);
	std::u16string node = u'\\' + std::u16string(in_server_begin, in_server_end)
		+ u'\\' + x_convert_utf8_to_utf16(dfs_root);
	dfs_referral_resp.referrals.push_back(x_referral_t{DFS_SERVER_ROOT, 0,
			max_referral_ttl, alt_path, node});
	dfs_referral_resp.header_flags = DFS_HEADER_FLAG_REFERAL_SVR | DFS_HEADER_FLAG_STORAGE_SVR;
	dfs_referral_resp.path_consumed = x_convert_assert<uint16_t>(alt_path.length() * 2);
	return NT_STATUS_OK;
}

std::shared_ptr<x_smbd_share_t> x_smbd_dfs_link_create(const std::string &name,
		const std::string &dfs_root)
{
	return std::make_shared<dfs_link_t>(name, dfs_root);
}

struct dfs_root_t : x_smbd_share_t
{
	dfs_root_t(const std::string &name, const std::string &path,
			const std::vector<std::string> &vgs)
		: x_smbd_share_t(name), vgs(vgs)
	{
		root_dir = x_smbd_topdir_create(path);
	}
	uint8_t get_type() const override { return SMB2_SHARE_TYPE_DISK; }
	bool is_dfs() const override { return true; }
	/* TODO not support ABE for now */
	bool abe_enabled() const override { return false; }
	NTSTATUS create_open(x_smbd_open_t **psmbd_open,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_create_t> &state) override;
	NTSTATUS get_dfs_referral(x_dfs_referral_resp_t &dfs_referral,
			const char16_t *in_full_path_begin,
			const char16_t *in_full_path_end,
			const char16_t *in_server_begin,
			const char16_t *in_server_end,
			const char16_t *in_share_begin,
			const char16_t *in_share_end) const override;

	std::shared_ptr<x_smbd_topdir_t> root_dir;
	std::vector<std::string> vgs;
	uint32_t max_referral_ttl = default_referral_ttl;
};

static std::u16string resolve_tld(const dfs_root_t &dfs_root,
		const char16_t *in_tld_begin, const char16_t *in_tld_end)
{
	std::u16string ret;
	if (in_tld_end == in_tld_begin) {
		return ret;
	}

	auto topdir = dfs_root.root_dir;
	X_ASSERT(topdir);
	std::string tld = x_convert_utf16_to_lower_utf8(in_tld_begin, in_tld_end);
	/* pseudo dir for all tld */
	if (tld == pesudo_tld_dir) {
		return ret;
	}

	/* TODO reuse posixfs_open */
	int fd = openat(topdir->fd, tld.c_str(), O_NOFOLLOW);
	if (fd < 0) {
		return ret;
	}
	
	struct stat st;
	int err = fstat(fd, &st);
	X_ASSERT(!err);

	if (S_ISDIR(st.st_mode)) {
		std::string path;
		int err = get_tld_target(fd, path);
		if (err == 0) {
			ret = x_convert_utf8_to_utf16(path);
		}
	}

	close(fd);
	return ret;
}

NTSTATUS dfs_root_t::get_dfs_referral(x_dfs_referral_resp_t &dfs_referral_resp,
		const char16_t *in_full_path_begin,
		const char16_t *in_full_path_end,
		const char16_t *in_server_begin,
		const char16_t *in_server_end,
		const char16_t *in_share_begin,
		const char16_t *in_share_end) const
{
	/* distribute root */
	std::u16string alt_path;
	std::u16string node;
	std::u16string vg_path;
	const char16_t *in_tld_begin, *in_tld_end;
	if (in_share_end == in_full_path_end) {
		in_tld_begin = in_tld_end = in_full_path_end;
	} else {
		in_tld_begin = x_skip_sep(in_share_end + 1, in_full_path_end);
		in_tld_end = x_next_sep(in_tld_begin, in_full_path_end);
	}
	if ((vg_path = resolve_tld(*this, in_tld_begin, in_tld_end)).size()) {
		alt_path.assign(in_full_path_begin, in_tld_end);
		node = u'\\' + std::u16string(in_server_begin, in_server_end) + 
			u'\\' + vg_path;
		dfs_referral_resp.referrals.push_back(x_referral_t{0, 0,
				max_referral_ttl, alt_path, node});
		dfs_referral_resp.header_flags = DFS_HEADER_FLAG_STORAGE_SVR;
	} else {
		/* no tld, referral to itself */
		alt_path.assign(in_full_path_begin, in_share_end);
		node = u'\\' + std::u16string(in_server_begin, in_server_end)
			+ std::u16string(in_share_begin - 1, in_share_end);
		dfs_referral_resp.referrals.push_back(x_referral_t{DFS_SERVER_ROOT, 0,
				max_referral_ttl, alt_path, node});
		dfs_referral_resp.header_flags = DFS_HEADER_FLAG_REFERAL_SVR | DFS_HEADER_FLAG_STORAGE_SVR;
	}
	dfs_referral_resp.path_consumed = x_convert_assert<uint16_t>(alt_path.length() * 2);
	return NT_STATUS_OK;
}
#endif
