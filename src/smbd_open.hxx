
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
#include "smbd_file.hxx"

struct x_smbd_open_t
{
	x_smbd_open_t(x_smbd_object_t *so, x_smbd_stream_t *ss,
			x_smbd_tcon_t *st,
			const x_smbd_open_state_t &open_state);
	~x_smbd_open_t();
	x_smbd_open_t(const x_smbd_open_t &) = delete;
	x_smbd_open_t(x_smbd_open_t &&) = delete;
	x_smbd_open_t &operator=(const x_smbd_open_t &) = delete;
	x_smbd_open_t &operator=(x_smbd_open_t &&) = delete;

	bool check_access(uint32_t access) const {
		return (open_state.access_mask & access);
	}

	x_dlink_t tcon_link; // protected by the mutex of smbd_tcon
	const x_tick_t tick_create;
	x_smbd_object_t * const smbd_object;
	x_smbd_stream_t * const smbd_stream; // not null if it is ADS
	x_smbd_tcon_t * smbd_tcon = nullptr;
	uint64_t id_persistent = 0xfffffffeu; // resolve id for non durable
	uint64_t id_volatile;
	enum {
		S_ACTIVE,
		S_INACTIVE, /* durable handle waiting reconnect */
		S_DONE,
	};
	std::atomic<uint32_t> state{S_ACTIVE};
	enum {
		DH_NONE,
		DH_DURABLE,
		DH_PERSISTENT,
	} dh_mode = DH_NONE;
	x_timerq_entry_t durable_timer;
	/* ideally it should not use timerq for durable timer because opens'
	 * timeout are not same. so it also check durable_timeout_tick
	 * if it is really expired
	 */
	x_tick_t durable_expire_tick;

	x_smbd_open_state_t open_state;
	uint32_t notify_filter = 0;
	uint32_t notify_buffer_length;
};

struct x_smbd_object_t;
struct x_smbd_object_ops_t
{
	x_smbd_object_t *(*open_object)(NTSTATUS *pstatus,
			std::shared_ptr<x_smbd_volume_t> &smbd_volume,
			const std::u16string &path,
			long path_priv_data,
			bool create_if);

	NTSTATUS (*open_durable)(x_smbd_open_t *&smbd_open,
			std::shared_ptr<x_smbd_volume_t> &smbd_volume,
			const x_smbd_durable_t &durable);

	NTSTATUS (*close)(x_smbd_object_t *smbd_object,
			x_smbd_open_t *smbd_open,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_close_t> &state,
			std::vector<x_smb2_change_t> &changes);
	NTSTATUS (*read)(x_smbd_object_t *smbd_object,
			x_smbd_open_t *smbd_open,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_read_t> &state);
	NTSTATUS (*write)(x_smbd_object_t *smbd_object,
			x_smbd_open_t *smbd_open,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_write_t> &state);
	NTSTATUS (*flush)(x_smbd_object_t *smbd_object,
			x_smbd_open_t *smbd_open,
			x_smbd_requ_t *smbd_requ);
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
	void (*lease_break)(x_smbd_object_t *smbd_object,
			x_smbd_stream_t *smbd_stream);
	NTSTATUS (*oplock_break)(x_smbd_object_t *smbd_object,
			x_smbd_conn_t *smbd_conn,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_oplock_break_t> &state);
	NTSTATUS (*rename)(x_smbd_object_t *smbd_object,
			x_smbd_open_t *smbd_open,
			x_smbd_requ_t *smbd_requ,
			const std::u16string &new_path,
			std::unique_ptr<x_smb2_state_rename_t> &state);
	NTSTATUS (*set_delete_on_close)(x_smbd_object_t *smbd_object,
			x_smbd_open_t *smbd_open,
			x_smbd_requ_t *smbd_requ,
			bool delete_on_close);
	void (*notify_change)(std::shared_ptr<x_smbd_volume_t> &smbd_volume,
			const std::u16string &path,
			const std::u16string &fullpath,
			const std::u16string *new_fullpath,
			uint32_t notify_action,
			uint32_t notify_filter,
			const x_smb2_lease_key_t &ignore_lease_key,
			bool last_level);
	void (*destroy)(x_smbd_object_t *smbd_object, x_smbd_open_t *smbd_open);
	void (*release_object)(x_smbd_object_t *smbd_object, x_smbd_stream_t *smbd_stream);
	std::u16string (*get_path)(const x_smbd_object_t *smbd_object,
			const x_smbd_open_t *smbd_open);
};

struct x_smbd_object_t
{
	x_smbd_object_t(const std::shared_ptr<x_smbd_volume_t> &smbd_volume,
			long priv_data,
			const std::u16string &path);
	~x_smbd_object_t();
	std::shared_ptr<x_smbd_volume_t> smbd_volume;
	const long priv_data;
	std::mutex mutex;
	enum {
		flag_initialized = 0x1,
		flag_modified = 0x2,
		// flag_delete_on_close = 0x4,
	};
	uint16_t flags = 0;
	enum {
		type_not_exist = 0,
		type_file = 1,
		type_dir = 2,
	};
	uint16_t type = type_not_exist;
	std::u16string path;
	x_smbd_file_handle_t file_handle;
};

struct x_smbd_stream_t
{
};

static inline bool x_smbd_open_is_data(const x_smbd_open_t *smbd_open)
{
	return smbd_open->smbd_stream || smbd_open->smbd_object->type
		== x_smbd_object_t::type_file;
}

NTSTATUS x_smbd_open_op_close(
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_close_t> &state);

static inline NTSTATUS x_smbd_open_op_read(
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_read_t> &state)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	auto op_fn = smbd_object->smbd_volume->ops->read;
	if (!op_fn) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return op_fn(smbd_object, smbd_open, smbd_requ, state);
}

static inline NTSTATUS x_smbd_open_op_write(
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_write_t> &state)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	auto op_fn = smbd_object->smbd_volume->ops->write;
	if (!op_fn) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return op_fn(smbd_object, smbd_open, smbd_requ, state);
}

static inline NTSTATUS x_smbd_open_op_flush(
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	auto op_fn = smbd_object->smbd_volume->ops->flush;
	if (!op_fn) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return op_fn(smbd_object, smbd_open, smbd_requ);
}

static inline NTSTATUS x_smbd_open_op_lock(
		x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_lock_t> &state)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	auto op_fn = smbd_object->smbd_volume->ops->lock;
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
	return smbd_object->smbd_volume->ops->getinfo(smbd_object, smbd_open,
			smbd_conn, smbd_requ, state);
}

static inline NTSTATUS x_smbd_open_op_setinfo(x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_setinfo_t> &state,
		std::vector<x_smb2_change_t> &changes)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	return smbd_object->smbd_volume->ops->setinfo(smbd_object,
			smbd_conn, smbd_requ, state, changes);
}

static inline NTSTATUS x_smbd_open_op_ioctl(
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_ioctl_t> &state)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	auto op_fn = smbd_object->smbd_volume->ops->ioctl;
	if (!op_fn) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return op_fn(smbd_object, smbd_requ, state);
}

static inline NTSTATUS x_smbd_open_op_qdir(
		x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_qdir_t> &state)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	auto op_fn = smbd_object->smbd_volume->ops->qdir;
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
	auto op_fn = smbd_object->smbd_volume->ops->notify;
	if (!op_fn) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return op_fn(smbd_object, smbd_conn, smbd_requ, state);
}

static inline void x_smbd_object_op_break_lease(
		x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream)
{
	auto op_fn = smbd_object->smbd_volume->ops->lease_break;
	X_ASSERT(op_fn);
	op_fn(smbd_object, smbd_stream);
}

static inline NTSTATUS x_smbd_lease_op_break(
		x_smbd_lease_t *smbd_lease,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_lease_break_t> &state)
{
	X_TODO;
	return NT_STATUS_INVALID_DEVICE_REQUEST;
#if 0
	x_smbd_object_t *smbd_object = smbd_lease->smbd_object;
	auto op_fn = smbd_object->smbd_volume->ops->lease_break;
	if (!op_fn) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return op_fn(smbd_object, smbd_conn, smbd_requ, smbd_lease, state);
#endif
}

static inline NTSTATUS x_smbd_open_op_oplock_break(
		x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_oplock_break_t> &state)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	auto op_fn = smbd_object->smbd_volume->ops->oplock_break;
	if (!op_fn) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return op_fn(smbd_object, smbd_conn, smbd_requ, state);
}

static inline NTSTATUS x_smbd_open_op_rename(
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_rename_t> &state)
{
	auto smbd_open = smbd_requ->smbd_open;
	auto smbd_object = smbd_open->smbd_object;
	return smbd_object->smbd_volume->ops->rename(smbd_object, smbd_open, smbd_requ,
			state->in_path, state);
}

static inline NTSTATUS x_smbd_open_op_set_delete_on_close(
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		bool delete_on_close)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	return smbd_object->smbd_volume->ops->set_delete_on_close(smbd_object, smbd_open,
			smbd_requ, delete_on_close);
}
#if 0
static inline void x_smbd_object_notify_change(x_smbd_object_t *smbd_object,
		uint32_t notify_action,
		uint32_t notify_filter,
		const std::u16string &path,
		const std::u16string *new_path,
		const x_smb2_lease_key_t &ignore_lease_key,
		bool last_level)
{
	return smbd_object->smbd_volume->ops->notify_change(smbd_object,
			notify_action, notify_filter, path, new_path,
			ignore_lease_key, last_level);
}
#endif
static inline std::string x_smbd_open_op_get_path(
		const x_smbd_open_t *smbd_open)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	std::u16string path = smbd_object->smbd_volume->ops->get_path(
			smbd_object, smbd_open);
	return x_convert_utf16_to_utf8_safe(path);
}

static inline void x_smbd_open_op_destroy(
		x_smbd_open_t *smbd_open)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	return smbd_object->smbd_volume->ops->destroy(smbd_object, smbd_open);
}

static inline std::pair<uint64_t, uint64_t> x_smbd_open_get_id(x_smbd_open_t *smbd_open)
{
	return { smbd_open->id_persistent, smbd_open->id_volatile };
}

static inline void x_smbd_object_release(x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream)
{
	smbd_object->smbd_volume->ops->release_object(smbd_object, smbd_stream);
}

static inline NTSTATUS x_smbd_open_durable(x_smbd_open_t *&smbd_open,
		std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		const x_smbd_durable_t &durable)
{
	return smbd_volume->ops->open_durable(smbd_open, smbd_volume, durable);
}

#if 0
	uint32_t (*get_attributes)(const x_smbd_object_t *smbd_object);
static inline uint32_t x_smbd_object_get_attributes(const x_smbd_object_t *smbd_object)
{
	return smbd_object->smbd_volume->ops->get_attributes(smbd_object);
}
#endif

#endif /* __smbd_open__hxx__ */

