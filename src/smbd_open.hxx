
#ifndef __smbd_open__hxx__
#define __smbd_open__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "smbd.hxx"
#include "defines.hxx"
#include "smb2.hxx"
#include "smbd_lease.hxx"
#include "smbd_share.hxx"


struct x_smbd_open_t
{
	x_smbd_open_t(x_smbd_object_t *so, x_smbd_tcon_t *st,
			uint32_t am, uint32_t sa,
			long priv_data);
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
	const long priv_data;
};

struct x_smbd_object_t;
struct x_smbd_object_ops_t
{
	x_smbd_object_t *(*open_object)(NTSTATUS *pstatus,
			std::shared_ptr<x_smbd_topdir_t> &topdir,
			const std::u16string &path,
			long path_priv_data,
			bool create_if_missed);
#if 0
	std::unique_lock<std::mutex> (*lock_object)(x_smbd_object_t *smbd_object);
	NTSTATUS (*create_open)(x_smbd_open_t **psmbd_open,
			x_smbd_object_t *smbd_object,
			x_smbd_requ_t *smbd_requ,
			const std::string &volume,
			std::unique_ptr<x_smb2_state_create_t> &state,
			long open_priv_data);
#endif
	NTSTATUS (*close)(x_smbd_object_t *smbd_object,
			x_smbd_open_t *smbd_open,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_close_t> &state,
			std::vector<x_smb2_change_t> &changes);
	NTSTATUS (*read)(x_smbd_object_t *smbd_object,
			x_smbd_open_t *smbd_open,
			x_smbd_conn_t *smbd_conn,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_read_t> &state);
	NTSTATUS (*write)(x_smbd_object_t *smbd_object,
			x_smbd_open_t *smbd_open,
			x_smbd_conn_t *smbd_conn,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_write_t> &state);
	NTSTATUS (*lock)(x_smbd_object_t *smbd_object,
			x_smbd_open_t *smbd_open,
			x_smbd_conn_t *smbd_conn,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_lock_t> &state);
	NTSTATUS (*getinfo)(x_smbd_object_t *smbd_object,
			x_smbd_open_t *smbd_open,
			x_smbd_conn_t *smbd_conn,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_getinfo_t> &state);
	NTSTATUS (*setinfo)(x_smbd_object_t *smbd_object,
			x_smbd_conn_t *smbd_conn,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_setinfo_t> &state,
			std::vector<x_smb2_change_t> &changes);
	NTSTATUS (*ioctl)(x_smbd_object_t *smbd_object,
			x_smbd_conn_t *smbd_conn,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_ioctl_t> &state);
	NTSTATUS (*qdir)(x_smbd_object_t *smbd_object,
			x_smbd_open_t *smbd_open,
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
			const std::u16string &new_path,
			std::vector<x_smb2_change_t> &changes);
	NTSTATUS (*set_delete_on_close)(x_smbd_object_t *smbd_object,
			x_smbd_open_t *smbd_open,
			x_smbd_requ_t *smbd_requ,
			bool delete_on_close);
	NTSTATUS (*unlink)(x_smbd_object_t *smbd_object, int fd);
	void (*notify_change)(x_smbd_object_t *smbd_object,
			uint32_t notify_action,
			uint32_t notify_filter,
			const std::u16string &path,
			const std::u16string *new_name_path,
			bool last_level);
	void (*destroy)(x_smbd_object_t *smbd_object, x_smbd_open_t *smbd_open);
	void (*release_object)(x_smbd_object_t *smbd_object);
	uint32_t (*get_attributes)(const x_smbd_object_t *smbd_object);
};

struct x_smbd_object_t
{
	x_smbd_object_t(const std::shared_ptr<x_smbd_topdir_t> &topdir, long priv_data,
			const std::u16string &path);
	~x_smbd_object_t();
	std::shared_ptr<x_smbd_topdir_t> topdir;
	const long priv_data;
	//uint32_t attributes = FILE_ATTRIBUTE_INVALID;
	std::mutex mutex;
	enum {
		flag_initialized = 0x1,
		flag_modified = 0x2,
		flag_delete_on_close = 0x4,
	};
	uint16_t flags = 0;
	enum {
		type_not_exist = 0,
		type_file = 1,
		type_dir = 2,
	};
	uint16_t type = type_not_exist;
	std::u16string path;
};
#if 0
static inline std::unique_lock<std::mutex> x_smbd_lock_object(x_smbd_object_t *smbd_object)
{
	return smbd_object->topdir->ops->lock_object(smbd_object);
}
#endif
static inline NTSTATUS x_smbd_open_op_close(
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_close_t> &state)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	auto topdir = smbd_object->topdir;
	std::vector<x_smb2_change_t> changes;
	auto status = topdir->ops->close(smbd_object, smbd_open,
			smbd_requ, state, changes);
	if (NT_STATUS_IS_OK(status)) {
		x_smbd_notify_change(topdir, changes);
	}
	return status;
}

static inline NTSTATUS x_smbd_open_op_read(
		x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_read_t> &state)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	auto op_fn = smbd_object->topdir->ops->read;
	if (!op_fn) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return op_fn(smbd_object, smbd_open, smbd_conn, smbd_requ, state);
}

static inline NTSTATUS x_smbd_open_op_write(
		x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_write_t> &state)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	auto op_fn = smbd_object->topdir->ops->write;
	if (!op_fn) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return op_fn(smbd_object, smbd_open, smbd_conn, smbd_requ, state);
}

static inline NTSTATUS x_smbd_open_op_lock(
		x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_lock_t> &state)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	auto op_fn = smbd_object->topdir->ops->lock;
	if (!op_fn) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return op_fn(smbd_object, smbd_open, smbd_conn, smbd_requ, state);
}

static inline NTSTATUS x_smbd_open_op_getinfo(x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_getinfo_t> &state)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	return smbd_object->topdir->ops->getinfo(smbd_object, smbd_open,
			smbd_conn, smbd_requ, state);
}

static inline NTSTATUS x_smbd_open_op_setinfo(x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_setinfo_t> &state,
		std::vector<x_smb2_change_t> &changes)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	return smbd_object->topdir->ops->setinfo(smbd_object,
			smbd_conn, smbd_requ, state, changes);
}

static inline NTSTATUS x_smbd_open_op_ioctl(
		x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_ioctl_t> &state)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	auto op_fn = smbd_object->topdir->ops->ioctl;
	if (!op_fn) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return op_fn(smbd_object, smbd_conn, smbd_requ, state);
}

static inline NTSTATUS x_smbd_open_op_qdir(
		x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_qdir_t> &state)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	auto op_fn = smbd_object->topdir->ops->qdir;
	if (!op_fn) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return op_fn(smbd_object, smbd_open, smbd_conn, smbd_requ, state);
}

static inline NTSTATUS x_smbd_open_op_notify(
		x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_notify_t> &state)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	auto op_fn = smbd_object->topdir->ops->notify;
	if (!op_fn) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return op_fn(smbd_object, smbd_conn, smbd_requ, state);
}

static inline NTSTATUS x_smbd_lease_op_break(
		x_smbd_lease_t *smbd_lease,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_lease_break_t> &state)
{
	x_smbd_object_t *smbd_object = smbd_lease->smbd_object;
	auto op_fn = smbd_object->topdir->ops->lease_break;
	if (!op_fn) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return op_fn(smbd_object, smbd_conn, smbd_requ, smbd_lease, state);
}

static inline NTSTATUS x_smbd_open_op_oplock_break(
		x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_oplock_break_t> &state)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	auto op_fn = smbd_object->topdir->ops->oplock_break;
	if (!op_fn) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return op_fn(smbd_object, smbd_conn, smbd_requ, state);
}

static inline NTSTATUS x_smbd_open_op_rename(
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		bool replace_if_exists,
		const std::u16string &new_path,
		std::vector<x_smb2_change_t> &changes)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	return smbd_object->topdir->ops->rename(smbd_object, smbd_open,
			smbd_requ, replace_if_exists, new_path, changes);
}

static inline NTSTATUS x_smbd_open_op_set_delete_on_close(
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		bool delete_on_close)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	return smbd_object->topdir->ops->set_delete_on_close(smbd_object, smbd_open,
			smbd_requ, delete_on_close);
}

static inline void x_smbd_object_notify_change(x_smbd_object_t *smbd_object,
			uint32_t notify_action,
			uint32_t notify_filter,
			const std::u16string &path,
			const std::u16string *new_path,
			bool last_level)
{
	return smbd_object->topdir->ops->notify_change(smbd_object,
			notify_action, notify_filter, path, new_path, last_level);
}

static inline NTSTATUS x_smbd_object_unlink(
		x_smbd_object_t *smbd_object,
		int fd)
{
	return smbd_object->topdir->ops->unlink(smbd_object, fd);
}

static inline std::string x_smbd_object_get_path(
		const x_smbd_object_t *smbd_object)
{
	return x_convert_utf16_to_utf8(smbd_object->path);
}

static inline std::string x_smbd_open_op_get_path(
		const x_smbd_open_t *smbd_open)
{
	return x_smbd_object_get_path(smbd_open->smbd_object);
}

static inline void x_smbd_open_op_destroy(
		x_smbd_open_t *smbd_open)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	return smbd_object->topdir->ops->destroy(smbd_object, smbd_open);
}

static inline void x_smbd_open_get_id(x_smbd_open_t *smbd_open, uint64_t &id_persistent,
		uint64_t &id_volatile)
{
	id_persistent = smbd_open->id;
	id_volatile = smbd_open->id;
}

static inline void x_smbd_object_release(x_smbd_object_t *smbd_object)
{
	smbd_object->topdir->ops->release_object(smbd_object);
}

static inline uint32_t x_smbd_object_get_attributes(const x_smbd_object_t *smbd_object)
{
	return smbd_object->topdir->ops->get_attributes(smbd_object);
}

#endif /* __smbd_open__hxx__ */

