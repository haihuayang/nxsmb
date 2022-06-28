
#ifndef __smbd_open__hxx__
#define __smbd_open__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "smbd.hxx"
#include "defines.hxx"
#include "smb2.hxx"
#include "smbd_lease.hxx"


struct x_smbd_open_t
{
	x_smbd_open_t(x_smbd_object_t *so, x_smbd_tcon_t *st,
			uint32_t am, uint32_t sa);
	~x_smbd_open_t();
	x_smbd_open_t(const x_smbd_open_t &) = delete;
	x_smbd_open_t(x_smbd_open_t &&) = delete;
	x_smbd_open_t &operator=(const x_smbd_open_t &) = delete;
	x_smbd_open_t &operator=(x_smbd_open_t &&) = delete;

	bool check_access(uint32_t access) const {
		return (access_mask & access);
	}

	x_dlink_t tcon_link; // protected by the mutex of smbd_tcon
	x_smbd_object_t * const smbd_object;
	x_smbd_tcon_t * const smbd_tcon;
	uint64_t id; // TODO we use it for both volatile and persisten id
	enum {
		S_ACTIVE,
		S_DONE,
	};
	std::atomic<uint32_t> state{S_ACTIVE};

	const uint32_t access_mask, share_access;
};

struct x_smbd_object_t;
struct x_smbd_object_ops_t
{
	NTSTATUS (*close)(x_smbd_object_t *smbd_object,
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
			x_smbd_open_t *smbd_open,
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
	NTSTATUS (*rename)(x_smbd_object_t *smbd_object,
			x_smbd_open_t *smbd_open,
			x_smbd_requ_t *smbd_requ,
			bool replace_if_exists,
			const std::u16string &new_path);
	NTSTATUS (*set_delete_on_close)(x_smbd_object_t *smbd_object,
			x_smbd_open_t *smbd_open,
			x_smbd_requ_t *smbd_requ,
			bool delete_on_close);
	NTSTATUS (*unlink)(x_smbd_object_t *smbd_object, int fd);
	std::string (*get_path)(const x_smbd_object_t *smbd_object);
	void (*destroy)(x_smbd_object_t *smbd_object, x_smbd_open_t *smbd_open);
};

struct x_smbd_object_t
{
	x_smbd_object_t(const x_smbd_object_ops_t *ops);
	~x_smbd_object_t();
	const x_smbd_object_ops_t *ops;
};

static inline NTSTATUS x_smbd_open_op_close(
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_close_t> &state)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	return smbd_object->ops->close(smbd_object, smbd_open,
			smbd_requ, state);
}

static inline NTSTATUS x_smbd_open_op_read(
		x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_read_t> &state)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	if (!smbd_object->ops->read) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return smbd_object->ops->read(smbd_object, smbd_conn,
			smbd_requ, state);
}

static inline NTSTATUS x_smbd_open_op_write(
		x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_write_t> &state)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	if (!smbd_object->ops->write) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return smbd_object->ops->write(smbd_object, smbd_conn,
			smbd_requ, state);
}

static inline NTSTATUS x_smbd_open_op_getinfo(x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_getinfo_t> &state)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	return smbd_object->ops->getinfo(smbd_object, smbd_open,
			smbd_conn, smbd_requ, state);
}

static inline NTSTATUS x_smbd_open_op_setinfo(x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_setinfo_t> &state)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	return smbd_object->ops->setinfo(smbd_object,
			smbd_conn, smbd_requ, state);
}

static inline NTSTATUS x_smbd_open_op_ioctl(
		x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_ioctl_t> &state)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	if (!smbd_object->ops->ioctl) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return smbd_object->ops->ioctl(smbd_object, smbd_conn,
			smbd_requ, state);
}

static inline NTSTATUS x_smbd_open_op_qdir(
		x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_qdir_t> &state)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	if (!smbd_object->ops->qdir) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return smbd_object->ops->qdir(smbd_object, smbd_conn,
			smbd_requ, state);
}

static inline NTSTATUS x_smbd_open_op_notify(
		x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_notify_t> &state)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	if (!smbd_object->ops->notify) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return smbd_object->ops->notify(smbd_object, smbd_conn,
			smbd_requ, state);
}

static inline NTSTATUS x_smbd_lease_op_break(
		x_smbd_lease_t *smbd_lease,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_lease_break_t> &state)
{
	x_smbd_object_t *smbd_object = smbd_lease->smbd_object;
	if (!smbd_object->ops->lease_break) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return smbd_object->ops->lease_break(smbd_object, smbd_conn,
			smbd_requ, smbd_lease, state);
}

static inline NTSTATUS x_smbd_open_op_oplock_break(
		x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_oplock_break_t> &state)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	if (!smbd_object->ops->oplock_break) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return smbd_object->ops->oplock_break(smbd_object, smbd_conn,
			smbd_requ, state);
}

static inline NTSTATUS x_smbd_open_op_rename(
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		bool replace_if_exists,
		const std::u16string &new_path)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	return smbd_object->ops->rename(smbd_object, smbd_open,
			smbd_requ, replace_if_exists, new_path);
}

static inline NTSTATUS x_smbd_open_op_set_delete_on_close(
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		bool delete_on_close)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	return smbd_object->ops->set_delete_on_close(smbd_object, smbd_open,
			smbd_requ, delete_on_close);
}

static inline NTSTATUS x_smbd_object_unlink(
		x_smbd_object_t *smbd_object,
		int fd)
{
	return smbd_object->ops->unlink(smbd_object, fd);
}

static inline std::string x_smbd_open_op_get_path(
		const x_smbd_open_t *smbd_open)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	return smbd_object->ops->get_path(smbd_object);
}

static inline void x_smbd_open_op_destroy(
		x_smbd_open_t *smbd_open)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	return smbd_object->ops->destroy(smbd_object, smbd_open);
}

static inline void x_smbd_open_get_id(x_smbd_open_t *smbd_open, uint64_t &id_persistent,
		uint64_t &id_volatile)
{
	id_persistent = smbd_open->id;
	id_volatile = smbd_open->id;
}

#endif /* __smbd_open__hxx__ */

