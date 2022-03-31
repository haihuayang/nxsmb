
#ifndef __smbd_object__hxx__
#define __smbd_object__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "defines.hxx"
#include "smbd.hxx"

struct x_smbd_open_t;
struct x_smbd_object_t;
struct x_smbd_object_ops_t
{
	NTSTATUS (*close)(x_smbd_object_t *smbd_object,
			x_smbd_conn_t *smbd_conn,
			x_smbd_open_t *smbd_open,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_close_t> &state);
	NTSTATUS (*read)(x_smbd_object_t *smbd_object,
			x_smbd_conn_t *smbd_conn,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_read_t> &state);
	NTSTATUS (*write)(x_smbd_object_t *smbd_object,
			x_smbd_conn_t *smbd_conn,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_write_t> &state);
	NTSTATUS (*getinfo)(x_smbd_object_t *smbd_object,
			x_smbd_conn_t *smbd_conn,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_getinfo_t> &state);
	NTSTATUS (*setinfo)(x_smbd_object_t *smbd_object,
			x_smbd_conn_t *smbd_conn,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_setinfo_t> &state);
	NTSTATUS (*ioctl)(x_smbd_object_t *smbd_object,
			x_smbd_conn_t *smbd_conn,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_ioctl_t> &state);
	NTSTATUS (*qdir)(x_smbd_object_t *smbd_object,
			x_smbd_conn_t *smbd_conn,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_qdir_t> &state);
	NTSTATUS (*notify)(x_smbd_object_t *smbd_object,
			x_smbd_conn_t *smbd_conn,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_notify_t> &state);
	NTSTATUS (*lease_break)(x_smbd_object_t *smbd_object,
			x_smbd_conn_t *smbd_conn,
			x_smbd_requ_t *smbd_requ,
			x_smbd_lease_t *smbd_lease,
			std::unique_ptr<x_smb2_state_lease_break_t> &state);
	NTSTATUS (*oplock_break)(x_smbd_object_t *smbd_object,
			x_smbd_conn_t *smbd_conn,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_oplock_break_t> &state);
	std::string (*get_path)(const x_smbd_object_t *smbd_object);
};

struct x_smbd_object_t
{
	x_smbd_object_t(const x_smbd_object_ops_t *ops) : ops(ops) { }
	const x_smbd_object_ops_t *ops;
};

static inline NTSTATUS x_smbd_object_op_close(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_close_t> &state)
{
	return smbd_object->ops->close(smbd_object, smbd_conn, smbd_open,
			smbd_requ, state);
}

static inline NTSTATUS x_smbd_object_op_read(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_read_t> &state)
{
	if (!smbd_object->ops->read) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return smbd_object->ops->read(smbd_object, smbd_conn,
			smbd_requ, state);
}

static inline NTSTATUS x_smbd_object_op_write(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_write_t> &state)
{
	if (!smbd_object->ops->write) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return smbd_object->ops->write(smbd_object, smbd_conn,
			smbd_requ, state);
}

static inline NTSTATUS x_smbd_object_op_ioctl(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_ioctl_t> &state)
{
	if (!smbd_object->ops->ioctl) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return smbd_object->ops->ioctl(smbd_object, smbd_conn,
			smbd_requ, state);
}

static inline NTSTATUS x_smbd_object_op_qdir(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_qdir_t> &state)
{
	if (!smbd_object->ops->qdir) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return smbd_object->ops->qdir(smbd_object, smbd_conn,
			smbd_requ, state);
}

static inline NTSTATUS x_smbd_object_op_notify(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_notify_t> &state)
{
	if (!smbd_object->ops->notify) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return smbd_object->ops->notify(smbd_object, smbd_conn,
			smbd_requ, state);
}

static inline NTSTATUS x_smbd_object_op_lease_break(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		x_smbd_lease_t *smbd_lease,
		std::unique_ptr<x_smb2_state_lease_break_t> &state)
{
	if (!smbd_object->ops->lease_break) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return smbd_object->ops->lease_break(smbd_object, smbd_conn,
			smbd_requ, smbd_lease, state);
}

static inline NTSTATUS x_smbd_object_op_oplock_break(
		x_smbd_object_t *smbd_object,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_oplock_break_t> &state)
{
	if (!smbd_object->ops->oplock_break) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return smbd_object->ops->oplock_break(smbd_object, smbd_conn,
			smbd_requ, state);
}

static inline std::string x_smbd_object_op_get_path(
		const x_smbd_object_t *smbd_object)
{
	return smbd_object->ops->get_path(smbd_object);
}

#endif /* __smbd_object__hxx__ */

