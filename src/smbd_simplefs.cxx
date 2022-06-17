
#include "smbd_share.hxx"
#include "smbd_posixfs.hxx"
#include <fcntl.h>

static const char *pseudo_entries[] = {
	".",
	"..",
//	".snapshot",
};
#define PSEUDO_ENTRIES_COUNT    ARRAY_SIZE(pseudo_entries)

static bool simplefs_process_entry(posixfs_statex_t *statex,
		posixfs_object_t *dir_obj,
		const char *ent_name,
		uint32_t file_number)
{
	/* TODO match pattern */

	int ret = 0;
	if (file_number >= PSEUDO_ENTRIES_COUNT) {
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

static NTSTATUS simplefs_object_op_qdir(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_qdir_t> &state)
{
	return posixfs_object_qdir(smbd_object, smbd_conn, smbd_requ, state,
			pseudo_entries, PSEUDO_ENTRIES_COUNT,
			simplefs_process_entry);
}

static NTSTATUS simplefs_object_op_rename(x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		bool replace_if_exists,
		const std::u16string &new_path);

static const x_smbd_object_ops_t simplefs_object_ops = {
	posixfs_object_op_close,
	posixfs_object_op_read,
	posixfs_object_op_write,
	posixfs_object_op_getinfo,
	posixfs_object_op_setinfo,
	posixfs_object_op_ioctl,
	simplefs_object_op_qdir,
	posixfs_object_op_notify,
	posixfs_object_op_lease_break,
	posixfs_object_op_oplock_break,
	simplefs_object_op_rename,
	posixfs_object_op_set_delete_on_close,
	posixfs_object_op_unlink,
	posixfs_object_op_get_path,
	posixfs_object_op_destroy,
};

struct simplefs_share_t : x_smbd_share_t
{
	simplefs_share_t(const std::string &name,
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

	NTSTATUS create_open(x_smbd_open_t **psmbd_open,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_create_t> &state) override;
	NTSTATUS get_dfs_referral(x_dfs_referral_resp_t &dfs_referral,
			x_smbd_tcon_type_t tcon_type,
			const char16_t *in_full_path_begin,
			const char16_t *in_full_path_end,
			const char16_t *in_server_begin,
			const char16_t *in_server_end,
			const char16_t *in_share_begin,
			const char16_t *in_share_end) const override
	{
		return NT_STATUS_FS_DRIVER_REQUIRED;
	}

	std::shared_ptr<x_smbd_topdir_t> root_dir;
};

static NTSTATUS simplefs_resolve_path(
		const simplefs_share_t &share,
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
	topdir = share.root_dir;
	return NT_STATUS_OK;
}

static NTSTATUS simplefs_create_open(simplefs_share_t &simplefs_share,
		x_smbd_open_t **psmbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state)
{
	std::u16string path;
	std::shared_ptr<x_smbd_topdir_t> topdir;
	NTSTATUS status = simplefs_resolve_path(
			simplefs_share,
			state->in_name,
			smbd_requ->in_hdr_flags & SMB2_HDR_FLAG_DFS,
			topdir, path);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return posixfs_create_open(&simplefs_object_ops, psmbd_open,
			topdir, path, 
			smbd_requ, state);
}

NTSTATUS simplefs_share_t::create_open(x_smbd_open_t **psmbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state)
{
	return simplefs_create_open(*this, psmbd_open, smbd_requ, state);
}

std::shared_ptr<x_smbd_share_t> x_smbd_simplefs_share_create(
		const std::string &name,
		const std::string &path)
{
	return std::make_shared<simplefs_share_t>(name, path);
}

static NTSTATUS simplefs_object_op_rename(x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		bool replace_if_exists,
		const std::u16string &new_path)
{
	std::u16string path;
	auto smbd_share = x_smbd_tcon_get_share(smbd_requ->smbd_tcon);
	auto &simplefs_share = dynamic_cast<simplefs_share_t &>(*smbd_share);

	return posixfs_object_rename(smbd_object, smbd_requ, 
			simplefs_share.root_dir, new_path, replace_if_exists);
}

int x_smbd_simplefs_mktld(const std::shared_ptr<x_smbd_user_t> &smbd_user,
		std::shared_ptr<x_smbd_share_t> &smbd_share,
		const std::string &name,
		std::vector<uint8_t> &ntacl_blob)
{
	simplefs_share_t &simplefs_share = dynamic_cast<simplefs_share_t &>(*smbd_share);
	auto topdir = simplefs_share.root_dir;

	std::shared_ptr<idl::security_descriptor> top_psd, psd;
	NTSTATUS status = posixfs_get_sd(topdir->fd, top_psd);
	X_ASSERT(NT_STATUS_IS_OK(status));

	status = make_child_sec_desc(psd, top_psd,
			*smbd_user, true);
	X_ASSERT(NT_STATUS_IS_OK(status));

	create_acl_blob(ntacl_blob, psd, idl::XATTR_SD_HASH_TYPE_NONE, std::array<uint8_t, idl::XATTR_SD_HASH_SIZE>());

	posixfs_statex_t statex;
	/* if parent is not enable inherit, make_sec_desc */
	int fd = posixfs_create(topdir->fd,
			true,
			name.c_str(),
			&statex,
			ntacl_blob);

	X_ASSERT(fd != -1);
	close(fd);
	return 0;
}

int x_smbd_simplefs_rmtld(std::shared_ptr<x_smbd_share_t> &smbd_share,
		const std::string &name)
{
	simplefs_share_t &simplefs_share = dynamic_cast<simplefs_share_t &>(*smbd_share);
	return unlinkat(simplefs_share.root_dir->fd, name.c_str(), AT_REMOVEDIR);
}

