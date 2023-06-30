
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

/* TODO make it general */
struct x_smbd_qdir_pos_t
{
	uint32_t file_number = 0;
	uint32_t offset_in_block = 0;
	uint64_t filepos = 0;
};

struct x_smbd_qdir_ops_t
{
	bool (*get_entry)(x_smbd_qdir_t *smbd_qdir,
			x_smbd_qdir_pos_t &qdir_pos,
			std::u16string &name,
			x_smbd_object_meta_t &object_meta,
			x_smbd_stream_meta_t &stream_meta,
			std::shared_ptr<idl::security_descriptor> *ppsd);
	void (*rewind)(x_smbd_qdir_t *smbd_qdir);
	void (*destroy)(x_smbd_qdir_t *smbd_qdir);
};

struct x_smbd_qdir_t
{
	x_smbd_qdir_t(x_smbd_open_t *smbd_open, const x_smbd_qdir_ops_t *ops);
	~x_smbd_qdir_t();

	x_job_t base;
	const x_smbd_qdir_ops_t *const ops;
	x_smbd_open_t * const smbd_open;
	x_tp_ddlist_t<requ_async_traits> requ_list;
	x_smbd_qdir_pos_t pos;
	uint64_t compound_id_blocking = 0;
	NTSTATUS error_status = NT_STATUS_OK;
	uint32_t total_count = 0;
	const uint32_t delay_ms;
	std::atomic<bool> closed = false;
	x_fnmatch_t *fnmatch = nullptr;
};

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

	bool check_access_any(uint32_t access) const {
		return (open_state.access_mask & access);
	}

	bool check_access_all(uint32_t access) const {
		return (open_state.access_mask & access) == access;
	}

	bool is_disconnected() const {
		return smbd_tcon == nullptr;
	}

	x_dlink_t tcon_link; // protected by the mutex of smbd_tcon
	x_dlink_t object_link;
	const x_tick_t tick_create;
	x_smbd_object_t * const smbd_object;
	x_smbd_stream_t * const smbd_stream; // not null if it is ADS
	x_smbd_tcon_t * smbd_tcon = nullptr;
	uint64_t id_persistent = 0xfffffffeu; // resolve id for non durable
	uint64_t id_volatile;
	x_timer_job_t durable_timer;

	uint32_t state;

	enum {
		OPLOCK_BREAK_NOT_SENT,
		OPLOCK_BREAK_TO_NONE_SENT,
		OPLOCK_BREAK_TO_LEVEL_II_SENT,
	} oplock_break_sent = OPLOCK_BREAK_NOT_SENT;
	x_timer_job_t oplock_break_timer;

	x_smbd_open_state_t open_state;
	uint32_t notify_filter = 0;
	uint32_t notify_buffer_length;
	x_smbd_lease_t *smbd_lease{};

	x_smbd_qdir_t *smbd_qdir{};

	uint8_t lock_sequency_array[64];
	uint32_t mode = 0; // [MS-FSCC] 2.4.26
	bool update_write_time = false;
	/* pending_requ_list and notify_changes protected by posixfs_object->mutex */
	x_tp_ddlist_t<requ_async_traits> pending_requ_list;
	std::vector<std::pair<uint32_t, std::u16string>> notify_changes;
	std::vector<x_smb2_lock_element_t> locks;

	enum { LOCK_SEQUENCE_MAX = 64 };
	uint8_t lock_sequence_array[LOCK_SEQUENCE_MAX] = { 0 };

	uint64_t request_count = 0, pre_request_count = 0;
};

struct x_smbd_object_t;
struct x_smbd_object_ops_t
{
	NTSTATUS (*open_object)(x_smbd_object_t **psmbd_object,
			x_smbd_stream_t **psmbd_stream,
			std::shared_ptr<x_smbd_volume_t> &smbd_volume,
			const std::u16string &path,
			const std::u16string &ads_name,
			long path_priv_data,
			bool create_if);

	NTSTATUS (*create_object)(x_smbd_object_t *smbd_object,
			x_smbd_stream_t *smbd_stream,
			const x_smbd_user_t &smbd_user,
			x_smb2_state_create_t &state,
			uint32_t file_attributes,
			uint64_t allocation_size,
			std::vector<x_smb2_change_t> &changes);

	NTSTATUS (*create_open)(x_smbd_open_t **psmbd_open,
			x_smbd_requ_t *smbd_requ,
			x_smbd_share_t &smbd_share,
			std::unique_ptr<x_smb2_state_create_t> &state,
			bool overwrite,
			x_smb2_create_action_t create_action,
			uint8_t oplock_level,
			std::vector<x_smb2_change_t> &changes);

	NTSTATUS (*open_durable)(x_smbd_open_t *&smbd_open,
			std::shared_ptr<x_smbd_volume_t> &smbd_volume,
			const x_smbd_durable_t &durable);
	NTSTATUS (*read)(x_smbd_object_t *smbd_object,
			x_smbd_open_t *smbd_open,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_read_t> &state,
			uint32_t delay_ms,
			bool all);
	NTSTATUS (*write)(x_smbd_object_t *smbd_object,
			x_smbd_open_t *smbd_open,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_write_t> &state,
			uint32_t delay_ms);
	NTSTATUS (*flush)(x_smbd_object_t *smbd_object,
			x_smbd_open_t *smbd_open,
			x_smbd_requ_t *smbd_requ);
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
	NTSTATUS (*query_allocated_ranges)(x_smbd_object_t *smbd_object,
			x_smbd_stream_t *smbd_stream,
			std::vector<x_smb2_file_range_t> &ranges,
			uint64_t offset, uint64_t max_offset);
	NTSTATUS (*set_attribute)(x_smbd_object_t *smbd_object,
			x_smbd_stream_t *smbd_stream,
			uint32_t attributes_modify,
			uint32_t attributes_value,
			bool &modified);
	x_smbd_qdir_t *(*qdir_create)(x_smbd_open_t *smbd_open);
#if 0
	bool (*qdir_get_entry)(x_smbd_qdir_t *smbd_qdir,
			x_smbd_qdir_pos_t &qdir_pos,
			std::u16string &name,
			x_smbd_object_meta_t &object_meta,
			x_smbd_stream_meta_t &stream_meta,
			std::shared_ptr<idl::security_descriptor> *ppsd);
	void (*qdir_unget_entry)(x_smbd_qdir_t *smbd_qdir,
			const x_smbd_qdir_pos_t &qdir_pos);
	NTSTATUS (*qdir)(x_smbd_object_t *smbd_object,
			x_smbd_open_t *smbd_open,
			x_smbd_conn_t *smbd_conn,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_qdir_t> &state);
#endif
	NTSTATUS (*rename)(x_smbd_object_t *smbd_object,
			x_smbd_open_t *smbd_open,
			x_smbd_requ_t *smbd_requ,
			const std::u16string &new_path,
			std::unique_ptr<x_smb2_state_rename_t> &state);
	NTSTATUS (*set_delete_on_close)(x_smbd_object_t *smbd_object,
			x_smbd_open_t *smbd_open,
			bool delete_on_close);
	void (*notify_change)(std::shared_ptr<x_smbd_volume_t> &smbd_volume,
			const std::u16string &path,
			const std::u16string &fullpath,
			const std::u16string *new_fullpath,
			uint32_t notify_action,
			uint32_t notify_filter,
			const x_smb2_lease_key_t &ignore_lease_key,
			const x_smb2_uuid_t &client_guid,
			bool last_level);
	void (*destroy)(x_smbd_object_t *smbd_object, x_smbd_open_t *smbd_open);
	void (*release_object)(x_smbd_object_t *smbd_object, x_smbd_stream_t *smbd_stream);
	NTSTATUS (*delete_object)(x_smbd_object_t *smbd_object,
			x_smbd_stream_t *smbd_stream,
			x_smbd_open_t *smbd_open,
			std::vector<x_smb2_change_t> &changes);
	NTSTATUS (*access_check)(x_smbd_object_t *smbd_object,
			uint32_t &granted_access,
			uint32_t &maximal_access,
			x_smbd_tcon_t *smbd_tcon,
			const x_smbd_user_t &smbd_user,
			uint32_t desired_access,
			bool overwrite);
	void (*lease_granted)(x_smbd_object_t *smbd_object,
			x_smbd_stream_t *smbd_stream);
};

X_DECLARE_MEMBER_TRAITS(x_smbd_open_object_traits, x_smbd_open_t, object_link)

struct x_smbd_sharemode_t
{
	x_smbd_stream_meta_t meta;
	x_tp_ddlist_t<x_smbd_open_object_traits> open_list;
	x_tp_ddlist_t<requ_async_traits> defer_open_list;
	x_tp_ddlist_t<requ_async_traits> defer_rename_list;
};

struct x_smbd_stream_t
{
	x_smbd_stream_t(bool exists, const std::u16string &name)
		: exists(exists), name(name)
	{
	}

	x_dlink_t object_link; // link into object
	bool exists;
	x_smbd_sharemode_t sharemode;
	std::u16string name;
};
X_DECLARE_MEMBER_TRAITS(x_smbd_stream_object_traits, x_smbd_stream_t, object_link)

struct x_smbd_object_t
{
	x_smbd_object_t(const std::shared_ptr<x_smbd_volume_t> &smbd_volume,
			long priv_data,
			const std::u16string &path);
	~x_smbd_object_t();

	bool exists() const { return type != type_not_exist; }

	void add_ads(x_smbd_stream_t *smbd_stream)
	{
		ads_list.push_front(smbd_stream);
	}

	void remove_ads(x_smbd_stream_t *smbd_stream)
	{
		ads_list.remove(smbd_stream);
	}

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
		type_pipe = 3,
	};
	uint16_t type = type_not_exist;
	std::u16string path;
	x_smbd_file_handle_t file_handle;
	x_smbd_object_meta_t meta;
	x_smbd_sharemode_t sharemode;
	x_tp_ddlist_t<x_smbd_stream_object_traits> ads_list;
};

static inline void x_smbd_object_update_type(x_smbd_object_t *smbd_object)
{
	if (smbd_object->meta.isdir()) {
		smbd_object->type = x_smbd_object_t::type_dir;
	} else {
		/* TODO we only support dir and file for now */
		smbd_object->type = x_smbd_object_t::type_file;
	}
}

static inline bool x_smbd_object_is_dir(const x_smbd_object_t *smbd_object)
{
	return smbd_object->type == x_smbd_object_t::type_dir;
}

static inline bool x_smbd_open_is_data(const x_smbd_open_t *smbd_open)
{
	return smbd_open->smbd_stream ||
		smbd_open->smbd_object->type == x_smbd_object_t::type_file ||
		smbd_open->smbd_object->type == x_smbd_object_t::type_pipe;
}
#if 0
static inline const x_smbd_sharemode_t *x_smbd_object_get_sharemode(
		const x_smbd_object_t *smbd_object,
		const x_smbd_stream_t *smbd_stream)
{
	if (!smbd_stream) {
		return &smbd_object->sharemode;
	} else {
		return &smbd_stream->sharemode;
	}
}
#endif
static inline x_smbd_sharemode_t *x_smbd_object_get_sharemode(
		x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream)
{
	if (!smbd_stream) {
		return &smbd_object->sharemode;
	} else {
		return &smbd_stream->sharemode;
	}
}

static inline x_smbd_sharemode_t *x_smbd_open_get_sharemode(
		const x_smbd_open_t *smbd_open)
{
	return x_smbd_object_get_sharemode(smbd_open->smbd_object,
			smbd_open->smbd_stream);
}

NTSTATUS x_smbd_open_op_close(
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_close_t> &state);

static inline NTSTATUS x_smbd_open_op_read(
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_read_t> &state,
		uint32_t delay_ms,
		bool all)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	auto op_fn = smbd_object->smbd_volume->ops->read;
	if (!op_fn) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return op_fn(smbd_object, smbd_open, smbd_requ, state, delay_ms, all);
}

static inline NTSTATUS x_smbd_open_op_write(
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_write_t> &state,
		uint32_t delay_ms)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	auto op_fn = smbd_object->smbd_volume->ops->write;
	if (!op_fn) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return op_fn(smbd_object, smbd_open, smbd_requ, state, delay_ms);
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
#if 0
static inline NTSTATUS x_smbd_open_op_qdir(
		x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_qdir_t> &state)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	return op_fn(smbd_object, smbd_open, smbd_conn, smbd_requ, state);
}
#endif
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
		bool delete_on_close)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	return smbd_object->smbd_volume->ops->set_delete_on_close(smbd_object, smbd_open,
			delete_on_close);
}

static inline std::pair<const x_smbd_object_meta_t *, const x_smbd_stream_meta_t *>
x_smbd_open_op_get_meta(const x_smbd_open_t *smbd_open)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	x_smbd_sharemode_t *sharemode = x_smbd_open_get_sharemode(smbd_open);
	return { &smbd_object->meta, &sharemode->meta };
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

static inline NTSTATUS x_smbd_object_delete(
		x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream,
		x_smbd_open_t *smbd_open,
		std::vector<x_smb2_change_t> &changes)
{
	return smbd_object->smbd_volume->ops->delete_object(smbd_object,
			smbd_stream, smbd_open, changes);
}

static inline NTSTATUS x_smbd_open_object(x_smbd_object_t **psmbd_object,
		x_smbd_stream_t **psmbd_stream,
		std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		const std::u16string &path,
		const std::u16string &ads_name,
		long path_priv_data,
		bool create_if)
{
	return smbd_volume->ops->open_object(psmbd_object, psmbd_stream,
			smbd_volume, path, ads_name, path_priv_data,
			create_if);
}

static inline NTSTATUS x_smbd_create_object(x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream,
		const x_smbd_user_t &smbd_user,
		x_smb2_state_create_t &state,
		uint32_t file_attributes,
		uint64_t allocation_size,
		std::vector<x_smb2_change_t> &changes)
{
	return smbd_object->smbd_volume->ops->create_object(smbd_object,
			smbd_stream,
			smbd_user, state,
			file_attributes,
			allocation_size,
			changes);
}

static inline NTSTATUS x_smbd_open_durable(x_smbd_open_t *&smbd_open,
		std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		const x_smbd_durable_t &durable)
{
	return smbd_volume->ops->open_durable(smbd_open, smbd_volume, durable);
}

static inline void x_smbd_object_lease_granted(x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream)
{
	smbd_object->smbd_volume->ops->lease_granted(smbd_object, smbd_stream);
}

static inline NTSTATUS x_smbd_object_query_allocated_ranges(
		x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream,
		std::vector<x_smb2_file_range_t> &ranges,
		uint64_t offset, uint64_t max_offset)
{
	return smbd_object->smbd_volume->ops->query_allocated_ranges(
			smbd_object,
			smbd_stream,
			ranges,
			offset, max_offset);
}

static inline NTSTATUS x_smbd_object_set_attribute(x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream,
		uint32_t attributes_modify,
		uint32_t attributes_value,
		bool &modified)
{
	return smbd_object->smbd_volume->ops->set_attribute(smbd_object,
			smbd_stream, attributes_modify, attributes_value,
			modified);
}

bool x_smbd_open_has_space();
x_smbd_open_t *x_smbd_open_lookup(uint64_t id_presistent, uint64_t id_volatile,
		const x_smbd_tcon_t *smbd_tcon);
bool x_smbd_open_store(x_smbd_open_t *smbd_open);
void x_smbd_open_unlinked(x_dlink_t *link,
		bool shutdown);

NTSTATUS x_smbd_open_create(x_smbd_open_t **psmbd_open,
		x_smbd_requ_t *smbd_requ,
		x_smbd_share_t &smbd_share,
		std::unique_ptr<x_smb2_state_create_t> &state,
		std::vector<x_smb2_change_t> &changes);

x_smbd_open_t *x_smbd_open_reopen(NTSTATUS &status,
		uint64_t id_presistent, uint64_t id_volatile,
		x_smbd_tcon_t *smbd_tcon,
		x_smb2_state_create_t &state);

NTSTATUS x_smbd_open_op_create(x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state);
NTSTATUS x_smbd_open_op_reconnect(x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state);

void x_smbd_open_break_lease(x_smbd_open_t *smbd_open,
		const x_smb2_lease_key_t *ignore_lease_key,
		const x_smb2_uuid_t *client_guid,
		uint8_t break_to);

void x_smbd_open_break_oplock(x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		uint8_t break_to);

void x_smbd_break_lease(x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream);

NTSTATUS x_smbd_break_oplock(
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		x_smb2_state_oplock_break_t &state);

void x_smbd_break_others_to_none(x_smbd_object_t *smbd_object,
		x_smbd_sharemode_t *sharemode,
		const x_smbd_lease_t *smbd_lease,
		uint8_t oplock_level);

bool x_smbd_check_io_brl_conflict(x_smbd_object_t *smbd_object,
		const x_smbd_open_t *smbd_open,
		uint64_t offset, uint64_t length, bool is_write);
void x_smbd_lock_retry(x_smbd_sharemode_t *sharemode);

bool x_smbd_open_match_get_lease(const x_smbd_open_t *smbd_open,
		x_smb2_lease_t &lease);

static inline x_smbd_qdir_t *x_smbd_qdir_create(x_smbd_open_t *smbd_open)
{
	return smbd_open->smbd_object->smbd_volume->ops->qdir_create(smbd_open);
}

static inline void x_smbd_qdir_unget_entry(x_smbd_qdir_t *smbd_qdir,
			const x_smbd_qdir_pos_t &qdir_pos)
{
	X_ASSERT(smbd_qdir->pos.file_number == qdir_pos.file_number + 1);
	smbd_qdir->pos = qdir_pos;
}

void x_smbd_qdir_close(x_smbd_qdir_t *smbd_qdir);

#if 0
	uint32_t (*get_attributes)(const x_smbd_object_t *smbd_object);
static inline uint32_t x_smbd_object_get_attributes(const x_smbd_object_t *smbd_object)
{
	return smbd_object->smbd_volume->ops->get_attributes(smbd_object);
}
#endif

#endif /* __smbd_open__hxx__ */

