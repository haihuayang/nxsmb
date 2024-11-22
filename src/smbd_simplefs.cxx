
#include "smbd_share.hxx"
#include "smbd_posixfs.hxx"
#include <fcntl.h>

static const char *pseudo_entries[] = {
	".",
	"..",
//	".snapshot",
};
#define PSEUDO_ENTRIES_COUNT    X_ARRAY_SIZE(pseudo_entries)

static bool simplefs_process_entry(
		x_smbd_object_meta_t *object_meta,
		x_smbd_stream_meta_t *stream_meta,
		std::shared_ptr<idl::security_descriptor> *ppsd,
		posixfs_object_t *dir_obj,
		const char *ent_name,
		uint64_t file_number)
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
		object_meta->inode = 0;
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

static NTSTATUS simplefs_qdir_op_get_entry(x_smbd_qdir_t *smbd_qdir,
		std::u16string &name,
		x_smbd_object_meta_t &object_meta,
		x_smbd_stream_meta_t &stream_meta,
		std::shared_ptr<idl::security_descriptor> *ppsd)
{
	return posixfs_qdir_get_entry(smbd_qdir, name,
			object_meta, stream_meta, ppsd,
			pseudo_entries, PSEUDO_ENTRIES_COUNT,
			simplefs_process_entry);
}

static const x_smbd_qdir_ops_t simplefs_qdir_ops = {
	simplefs_qdir_op_get_entry,
	posixfs_qdir_op_unget_entry,
	posixfs_qdir_op_rewind,
	posixfs_qdir_op_tell,
	posixfs_qdir_op_seek,
	posixfs_qdir_op_destroy,
};

static x_smbd_qdir_t *simplefs_op_qdir_create(x_smbd_open_t *smbd_open,
		const std::shared_ptr<x_smbd_user_t> &smbd_user)
{
	return posixfs_qdir_create(smbd_open, &simplefs_qdir_ops, smbd_user);
}



#if 0
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
#endif
static const x_smbd_object_ops_t simplefs_object_ops = {
	posixfs_op_open_root_object,
	x_smbd_posixfs_create_object,
	posixfs_op_create_open,
	posixfs_op_open_durable,
	posixfs_object_op_read,
	posixfs_object_op_write,
	posixfs_object_op_flush,
	posixfs_object_op_getinfo,
	posixfs_object_op_setinfo,
	posixfs_object_op_ioctl,
	posixfs_object_op_query_allocated_ranges,
	posixfs_object_op_set_zero_data,
	posixfs_object_op_set_attribute,
	posixfs_object_op_update_mtime,
	simplefs_op_qdir_create,
	posixfs_object_op_set_delete_on_close,
	x_smbd_simple_notify_change,
	posixfs_op_object_delete,
	x_smbd_posixfs_op_lease_granted,
	posixfs_op_init_volume,
	posixfs_op_allocate_object,
	posixfs_op_destroy_object,
	posixfs_op_initialize_object,
	posixfs_op_rename_object,
	posixfs_op_rename_stream,
	posixfs_op_release_stream,
	posixfs_op_destroy_open,
};


struct simplefs_share_t : x_smbd_share_t
{
	simplefs_share_t(const x_smb2_uuid_t &uuid,
			const std::string &name,
			std::u16string &&name_16,
			std::u16string &&name_l16,
			uint32_t share_flags,
			x_smbd_feature_option_t smb_encrypt,
			const std::vector<std::shared_ptr<x_smbd_volume_t>> &smbd_volumes)
		: x_smbd_share_t(uuid, name, std::move(name_16),
				std::move(name_l16), share_flags,
				smb_encrypt)
		, smbd_volumes(smbd_volumes)
	{
	}
					
	uint8_t get_type() const override {
		return X_SMB2_SHARE_TYPE_DISK;
	}
	bool is_dfs() const override { return false; }

	NTSTATUS resolve_path(std::shared_ptr<x_smbd_volume_t> &smbd_volume,
			std::u16string &out_path,
			long &path_priv_data,
			long &open_priv_data,
			bool dfs,
			const char16_t *in_path_begin,
			const char16_t *in_path_end,
			const std::shared_ptr<x_smbd_volume_t> &tcon_volume) override;
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
	std::shared_ptr<x_smbd_volume_t> find_volume(const char16_t *in_share_s, const char16_t *in_share_e) const override
	{
		X_TODO;
		return nullptr;
#if 0
		if (in_share_s[0] == u'-') {
			return nullptr;
		}
		return smbd_volume;
#endif
	}

	std::vector<std::shared_ptr<x_smbd_volume_t>> smbd_volumes;
};

NTSTATUS simplefs_share_t::resolve_path(
		std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		std::u16string &out_path,
		long &path_priv_data,
		long &open_priv_data,
		bool dfs,
		const char16_t *in_path_begin,
		const char16_t *in_path_end,
		const std::shared_ptr<x_smbd_volume_t> &tcon_volume)
{
	out_path.assign(in_path_begin, in_path_end);
#if 0
	smbd_volume = this->smbd_volume;
	path_priv_data = 0;
	open_priv_data = 0;
#endif
	return NT_STATUS_OK;
}

std::shared_ptr<x_smbd_share_t> x_smbd_simplefs_share_create(
		const std::string &node_name,
		const x_smb2_uuid_t &uuid,
		const std::string &name,
		std::u16string &&name_16,
		std::u16string &&name_l16,
		uint32_t share_flags,
		x_smbd_feature_option_t smb_encrypt,
		std::vector<std::shared_ptr<x_smbd_volume_t>> &&smbd_volumes)
{
	X_ASSERT(smbd_volumes.size() > 0);
	for (auto &smbd_volume: smbd_volumes) {
		int err = x_smbd_volume_init(smbd_volume, &simplefs_object_ops,
				node_name == smbd_volume->owner_node);
		X_TODO_ASSERT(err == 0);
	}
	std::shared_ptr<simplefs_share_t> ret =
		std::make_shared<simplefs_share_t>(uuid, name,
			std::move(name_16), std::move(name_l16),
			share_flags, smb_encrypt, std::move(smbd_volumes));

	auto &volumes = ret->smbd_volumes;
	auto &root_volume = volumes[0];
	if (root_volume->owner_node == node_name) {
		ret->root_object = root_volume->ops->open_root_object(root_volume);
	} else {
		/* TODO */
		ret->root_object = nullptr;
	}

	for (auto &volume: volumes) {
		if (node_name == volume->owner_node) {
			x_smbd_volume_restore_durable(ret, volume);
		}
	}

	return ret;
}

