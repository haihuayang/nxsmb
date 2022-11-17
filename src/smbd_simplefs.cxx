
#include "smbd_share.hxx"
#include "smbd_posixfs.hxx"
#include <fcntl.h>

static const char *pseudo_entries[] = {
	".",
	"..",
//	".snapshot",
};
#define PSEUDO_ENTRIES_COUNT    ARRAY_SIZE(pseudo_entries)

static bool simplefs_process_entry(
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

static NTSTATUS simplefs_object_op_qdir(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_qdir_t> &state)
{
	return posixfs_object_qdir(smbd_object, smbd_conn, smbd_requ, state,
			pseudo_entries, PSEUDO_ENTRIES_COUNT,
			simplefs_process_entry);
}

static x_smbd_object_t *simplefs_open_object(NTSTATUS *pstatus,
		std::shared_ptr<x_smbd_topdir_t> &topdir,
		const std::u16string &path, long path_data,
		bool create_if)
{
	x_smbd_object_t *smbd_object = posixfs_open_object(topdir, path,
			path_data, create_if);
	if (!smbd_object) {
		*pstatus = NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}
	return smbd_object;
}

static const x_smbd_object_ops_t simplefs_object_ops = {
	simplefs_open_object,
	posixfs_object_op_close,
	posixfs_object_op_read,
	posixfs_object_op_write,
	posixfs_object_op_flush,
	posixfs_object_op_lock,
	posixfs_object_op_getinfo,
	posixfs_object_op_setinfo,
	posixfs_object_op_ioctl,
	simplefs_object_op_qdir,
	posixfs_object_op_notify,
	posixfs_object_op_lease_break,
	posixfs_object_op_oplock_break,
	posixfs_object_op_rename,
	posixfs_object_op_set_delete_on_close,
	posixfs_simple_notify_change,
	posixfs_object_op_destroy,
	posixfs_op_release_object,
	posixfs_op_get_path,
};

struct simplefs_share_t : x_smbd_share_t
{
	simplefs_share_t(const std::string &name,
			bool abe,
			const std::string &path)
		: x_smbd_share_t(name), abe(abe)
	{
		root_dir = x_smbd_topdir_create(path, &simplefs_object_ops, name);
	}
					
	uint8_t get_type() const override {
		return SMB2_SHARE_TYPE_DISK;
	}
	bool is_dfs() const override { return false; }
	bool abe_enabled() const override { return abe; }

	NTSTATUS create_open(x_smbd_open_t **psmbd_open,
			x_smbd_requ_t *smbd_requ,
			const std::string &volume,
			std::unique_ptr<x_smb2_state_create_t> &state,
			std::vector<x_smb2_change_t> &changes) override;

	NTSTATUS resolve_path(std::shared_ptr<x_smbd_topdir_t> &topdir,
			std::u16string &out_path,
			long &path_priv_data,
			long &open_priv_data,
			bool dfs,
			const char16_t *in_path_begin,
			const char16_t *in_path_end,
			const std::string &volume) override;
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

	virtual NTSTATUS delete_object(x_smbd_object_t *smbd_object,
			x_smbd_open_t *smbd_open, int fd,
			std::vector<x_smb2_change_t> &changes) override
	{
		return posixfs_object_op_unlink(smbd_object, fd);
	}
	std::shared_ptr<x_smbd_topdir_t> root_dir;
	const bool abe;
};

NTSTATUS simplefs_share_t::resolve_path(
		std::shared_ptr<x_smbd_topdir_t> &topdir,
		std::u16string &out_path,
		long &path_priv_data,
		long &open_priv_data,
		bool dfs,
		const char16_t *in_path_begin,
		const char16_t *in_path_end,
		const std::string &volume)
{
	const char16_t *path_start;
	if (dfs) {
		/* TODO we just skip the first 2 components for now */
		auto sep = x_next_sep(in_path_begin, in_path_end, u'\\');
		X_ASSERT(sep != in_path_end);
		path_start = x_next_sep(sep + 1, in_path_end, u'\\');
		if (path_start != in_path_end) {
			++path_start;
		}
	} else {
		path_start = in_path_begin;
	}
	out_path.assign(path_start, in_path_end);

	topdir = this->root_dir;
	path_priv_data = 0;
	open_priv_data = 0;
	return NT_STATUS_OK;
}

NTSTATUS simplefs_share_t::create_open(x_smbd_open_t **psmbd_open,
		x_smbd_requ_t *smbd_requ,
		const std::string &volume,
		std::unique_ptr<x_smb2_state_create_t> &state,
		std::vector<x_smb2_change_t> &changes)
{
	std::lock_guard<std::mutex> lock(state->smbd_object->mutex);
	return x_smbd_posixfs_create_open(psmbd_open, smbd_requ,
			state, changes);
}

std::shared_ptr<x_smbd_share_t> x_smbd_simplefs_share_create(
		const std::string &name,
		bool abe,
		const std::string &path)
{
	return std::make_shared<simplefs_share_t>(name, abe, path);
}

