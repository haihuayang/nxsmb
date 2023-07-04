
#ifndef __smbd_posixfs__hxx__
#define __smbd_posixfs__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "smbd_open.hxx"
#include "smbd_posixfs_utils.hxx"

struct posixfs_open_t;
struct posixfs_object_t;

NTSTATUS posixfs_create_open(x_smbd_open_t **psmbd_open,
		std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		const std::u16string &path, uint64_t path_data,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state);
NTSTATUS posixfs_object_op_close(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_close_t> &state,
		std::vector<x_smb2_change_t> &changes);
NTSTATUS posixfs_object_op_read(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_read_t> &state,
		uint32_t delay_ms,
		bool all);
NTSTATUS posixfs_object_op_write(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_write_t> &state,
		uint32_t delay_ms);
NTSTATUS posixfs_object_op_flush(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ);
NTSTATUS posixfs_object_op_getinfo(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_getinfo_t> &state);
NTSTATUS posixfs_object_op_setinfo(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_setinfo_t> &state,
		std::vector<x_smb2_change_t> &changes);
NTSTATUS posixfs_object_op_ioctl(
		x_smbd_object_t *smbd_object,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_ioctl_t> &state);
NTSTATUS posixfs_object_op_query_allocated_ranges(
		x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream,
		std::vector<x_smb2_file_range_t> &ranges,
		uint64_t offset, uint64_t length);
NTSTATUS posixfs_object_op_set_zero_data(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		uint64_t begin_offset, uint64_t end_offset);
NTSTATUS posixfs_object_op_set_attribute(x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream,
		uint32_t attributes_modify,
		uint32_t attributes_value,
		bool &modified);
NTSTATUS posixfs_object_op_set_delete_on_close(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		bool delete_on_close);
NTSTATUS posixfs_object_op_unlink(x_smbd_object_t *smbd_object, int fd);
void posixfs_notify_fname(
		std::shared_ptr<x_smbd_volume_t> smbd_volume,
		const std::u16string req_path,
		uint32_t action,
		uint32_t notify_filter,
		const std::u16string *new_name_path);
void posixfs_object_op_destroy(x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open);
NTSTATUS posixfs_object_op_rename(x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		const std::u16string &new_path,
		std::unique_ptr<x_smb2_state_rename_t> &state);
void posixfs_op_release_object(x_smbd_object_t *smbd_object, x_smbd_stream_t *smbd_stream);
uint32_t posixfs_op_get_attributes(const x_smbd_object_t *smbd_object);
NTSTATUS posixfs_op_object_delete(
		x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream,
		x_smbd_open_t *smbd_open,
		std::vector<x_smb2_change_t> &changes);
NTSTATUS posixfs_op_open_durable(x_smbd_open_t *&smbd_open,
		std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		const x_smbd_durable_t &durable);


int posixfs_object_get_statex(const posixfs_object_t *posixfs_object,
		x_smbd_object_meta_t *object_meta,
		x_smbd_stream_meta_t *stream_meta);
int posixfs_object_get_parent_statex(const posixfs_object_t *dir_obj,
		x_smbd_object_meta_t *object_meta,
		x_smbd_stream_meta_t *stream_meta);
int posixfs_object_statex_getat(posixfs_object_t *dir_obj, const char *name,
		x_smbd_object_meta_t *object_meta,
		x_smbd_stream_meta_t *stream_meta,
		std::shared_ptr<idl::security_descriptor> *ppsd);

typedef bool posixfs_qdir_entry_func_t(x_smbd_object_meta_t *object_meta,
		x_smbd_stream_meta_t *stream_meta,
		std::shared_ptr<idl::security_descriptor> *ppsd,
		posixfs_object_t *dir_obj,
		const char *ent_name,
		uint32_t file_number);


NTSTATUS x_smbd_posixfs_open_object(x_smbd_object_t **psmbd_object,
		x_smbd_stream_t **psmbd_stream,
		std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		const std::u16string &path,
		const std::u16string &ads_name,
		long path_data,
		bool create_if);

NTSTATUS x_smbd_posixfs_op_create_open(x_smbd_open_t *&smbd_open,
		x_smbd_requ_t *smbd_requ,
		const std::shared_ptr<x_smbd_share_t> &smbd_share,
		const std::string &volume_name,
		std::unique_ptr<x_smb2_state_create_t> &state,
		std::vector<x_smb2_change_t> &changes);

NTSTATUS x_smbd_posixfs_op_access_check(x_smbd_object_t *smbd_object,
		uint32_t &granted_access,
		uint32_t &maximal_access,
		x_smbd_tcon_t *smbd_tcon,
		const x_smbd_user_t &smbd_user,
		uint32_t desired_access,
		bool overwrite);

void x_smbd_posixfs_op_lease_granted(x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream);

x_smbd_object_t *x_smbd_posixfs_open_object_by_handle(NTSTATUS *pstatus,
		std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		x_smbd_file_handle_t *file_handle);

NTSTATUS x_smbd_posixfs_create_open(x_smbd_open_t **psmbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state,
		bool overwrite,
		x_smb2_create_action_t create_action,
		uint8_t oplock_level,
		std::vector<x_smb2_change_t> &changes);
NTSTATUS x_smbd_posixfs_create_object(x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream,
		const x_smbd_user_t &smbd_user,
		x_smb2_state_create_t &state,
		uint32_t file_attributes,
		uint64_t allocation_size,
		std::vector<x_smb2_change_t> &changes);
NTSTATUS x_smbd_posixfs_object_init(x_smbd_object_t *smbd_object,
		int fd, bool is_dir,
		const std::string &unix_path,
		const std::vector<uint8_t> &ntacl_blob);

x_smbd_object_t *x_smbd_posixfs_object_open_parent(const x_smbd_object_t *child_object);

int posixfs_mktld(const std::shared_ptr<x_smbd_user_t> &smbd_user,
		const x_smbd_volume_t &smbd_volume,
		const std::string &name,
		std::vector<uint8_t> &ntacl_blob);

ssize_t posixfs_object_getxattr(x_smbd_object_t *smbd_object,
		const char *xattr_name, void *buf, size_t bufsize);

x_smbd_qdir_t *posixfs_qdir_create(x_smbd_open_t *smbd_open, const x_smbd_qdir_ops_t *ops);
void posixfs_qdir_rewind(x_smbd_qdir_t *smbd_qdir);
void posixfs_qdir_destroy(x_smbd_qdir_t *smbd_qdir);
bool posixfs_qdir_get_entry(x_smbd_qdir_t *smbd_qdir,
		x_smbd_qdir_pos_t &qdir_pos,
		std::u16string &name,
		x_smbd_object_meta_t &object_meta,
		x_smbd_stream_meta_t &stream_meta,
		std::shared_ptr<idl::security_descriptor> *ppsd,
		const char *pseudo_entries[],
		uint32_t pseudo_entry_count,
		posixfs_qdir_entry_func_t *process_entry_func);

#endif /* __smbd_posixfs__hxx__ */

