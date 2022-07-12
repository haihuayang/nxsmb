
#ifndef __smbd_posixfs__hxx__
#define __smbd_posixfs__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "smbd_open.hxx"
#include "smbd_posixfs_utils.hxx"

struct posixfs_open_t;
struct posixfs_object_t;

NTSTATUS posixfs_create_open(const x_smbd_object_ops_t *ops,
		x_smbd_open_t **psmbd_open,
		std::shared_ptr<x_smbd_topdir_t> &topdir,
		const std::u16string &path,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state);
NTSTATUS posixfs_object_op_close(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_close_t> &state);
NTSTATUS posixfs_object_op_read(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_read_t> &state);
NTSTATUS posixfs_object_op_write(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_write_t> &state);
NTSTATUS posixfs_object_op_lock(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_lock_t> &state);
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
		std::unique_ptr<x_smb2_state_setinfo_t> &state);
NTSTATUS posixfs_object_op_ioctl(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_ioctl_t> &state);
NTSTATUS posixfs_object_op_notify(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_notify_t> &state);
NTSTATUS posixfs_object_op_lease_break(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		x_smbd_lease_t *smbd_lease,
		std::unique_ptr<x_smb2_state_lease_break_t> &state);
NTSTATUS posixfs_object_op_oplock_break(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_oplock_break_t> &state);
NTSTATUS posixfs_object_op_set_delete_on_close(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		bool delete_on_close);
NTSTATUS posixfs_object_op_unlink(x_smbd_object_t *smbd_object, int fd);
std::string posixfs_object_op_get_path(
		const x_smbd_object_t *smbd_object);
void posixfs_object_op_destroy(x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open);
NTSTATUS posixfs_object_op_rename(x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		bool replace_if_exists,
		const std::u16string &new_path);


int posixfs_object_get_statex(const posixfs_object_t *posixfs_object, posixfs_statex_t *statex);
int posixfs_object_get_parent_statex(const posixfs_object_t *dir_obj, posixfs_statex_t *statex);
int posixfs_object_statex_getat(posixfs_object_t *dir_obj, const char *name,
		posixfs_statex_t *statex);
NTSTATUS posixfs_object_qdir(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_qdir_t> &state,
		const char *pseudo_entries[],
		uint32_t pseudo_entry_count,
		bool (*process_entry_func)(posixfs_statex_t *statex,
			posixfs_object_t *dir_obj,
			const char *ent_name,
			uint32_t file_number));
NTSTATUS posixfs_object_rename(x_smbd_object_t *smbd_object,
		x_smbd_requ_t *smbd_requ,
		const std::u16string &dst_path,
		bool replace_if_exists);

x_smbd_object_t *x_smbd_posixfs_object_open_parent(const x_smbd_object_ops_t *ops,
		const x_smbd_object_t *child_object);

int posixfs_mktld(const std::shared_ptr<x_smbd_user_t> &smbd_user,
		const x_smbd_topdir_t &topdir,
		const std::string &name,
		std::vector<uint8_t> &ntacl_blob);

#endif /* __smbd_posixfs__hxx__ */

