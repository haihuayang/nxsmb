
#ifndef __smbd_open__hxx__
#define __smbd_open__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "smbd.hxx"
#include "smbd_requ.hxx"
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
	x_smbd_qdir_t(x_smbd_open_t *smbd_open, const x_smbd_qdir_ops_t *ops,
			const std::shared_ptr<x_smbd_user_t> &smbd_user);
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
	const std::shared_ptr<x_smbd_user_t> smbd_user;
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

	uint8_t get_oplock_level() const
	{
		return open_state.oplock_level;
	}

	void set_oplock_level(uint8_t oplock_level)
	{
		open_state.oplock_level = oplock_level;
	}

	x_dlink_t tcon_link; // protected by the mutex of smbd_tcon
	x_dlink_t object_link;
	const x_tick_t tick_create;
	x_smbd_object_t * const smbd_object;
	x_smbd_stream_t * const smbd_stream; // not null if it is ADS
	x_smbd_tcon_t * smbd_tcon = nullptr;
	uint64_t id_persistent = X_SMBD_OPEN_ID_NON_DURABLE;
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

	uint32_t mode = 0; // [MS-FSCC] 2.4.26
	bool update_write_time_on_close = false;
	bool sticky_write_time = false;
	/* pending_requ_list and notify_changes protected by posixfs_object->mutex */
	x_tp_ddlist_t<requ_async_traits> pending_requ_list;
	std::vector<std::pair<uint32_t, std::u16string>> notify_changes;

	enum { LOCK_SEQUENCE_MAX = 64 };
	uint8_t lock_sequence_array[LOCK_SEQUENCE_MAX] = { 0 };

	uint64_t request_count = 0, pre_request_count = 0;
	x_nxfsd_requ_id_list_t oplock_pending_list; // pending on oplock
};

struct x_smbd_object_t;
struct x_smbd_object_ops_t
{
	x_smbd_object_t *(*open_root_object)(
			std::shared_ptr<x_smbd_volume_t> &smbd_volume);

	NTSTATUS (*create_object)(x_smbd_object_t *smbd_object,
			x_smbd_stream_t *smbd_stream,
			const x_smbd_user_t &smbd_user,
			x_smbd_requ_state_create_t &state,
			uint32_t file_attributes,
			uint64_t allocation_size);

	NTSTATUS (*create_open)(x_smbd_open_t **psmbd_open,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smbd_requ_state_create_t> &state);

	NTSTATUS (*open_durable)(x_smbd_open_t *&smbd_open,
			std::shared_ptr<x_smbd_share_t> &smbd_share,
			std::shared_ptr<x_smbd_volume_t> &smbd_volume,
			const x_smbd_durable_t &durable);
	NTSTATUS (*read)(x_smbd_object_t *smbd_object,
			x_smbd_open_t *smbd_open,
			x_nxfsd_requ_t *nxfsd_requ,
			std::unique_ptr<x_smbd_requ_state_read_t> &state,
			uint32_t delay_ms,
			bool all);
	NTSTATUS (*write)(x_smbd_object_t *smbd_object,
			x_smbd_open_t *smbd_open,
			x_nxfsd_requ_t *nxfsd_requ,
			std::unique_ptr<x_smbd_requ_state_write_t> &state,
			uint32_t delay_ms);
	NTSTATUS (*flush)(x_smbd_object_t *smbd_object,
			x_smbd_open_t *smbd_open,
			x_smbd_requ_t *smbd_requ);
	NTSTATUS (*getinfo)(x_smbd_object_t *smbd_object,
			x_smbd_open_t *smbd_open,
			x_smbd_conn_t *smbd_conn,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smbd_requ_state_getinfo_t> &state);
	NTSTATUS (*setinfo)(x_smbd_object_t *smbd_object,
			x_smbd_conn_t *smbd_conn,
			x_nxfsd_requ_t *nxfsd_requ,
			std::unique_ptr<x_smbd_requ_state_setinfo_t> &state);
	NTSTATUS (*ioctl)(x_smbd_object_t *smbd_object,
			x_nxfsd_requ_t *nxfsd_requ,
			std::unique_ptr<x_smbd_requ_state_ioctl_t> &state);
	NTSTATUS (*query_allocated_ranges)(x_smbd_object_t *smbd_object,
			x_smbd_stream_t *smbd_stream,
			std::vector<x_smb2_file_range_t> &ranges,
			uint64_t offset, uint64_t max_offset);
	NTSTATUS (*set_zero_data)(x_smbd_object_t *smbd_object,
			x_smbd_open_t *smbd_open,
			uint64_t begin_offset, uint64_t end_offset);
	NTSTATUS (*set_attribute)(x_smbd_object_t *smbd_object,
			x_smbd_stream_t *smbd_stream,
			uint32_t attributes_modify,
			uint32_t attributes_value,
			bool &modified);
	NTSTATUS (*update_mtime)(x_smbd_object_t *smbd_object);
	x_smbd_qdir_t *(*qdir_create)(x_smbd_open_t *smbd_open,
			const std::shared_ptr<x_smbd_user_t> &smbd_user);
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
			std::unique_ptr<x_smbd_requ_state_qdir_t> &state);
#endif
	NTSTATUS (*set_delete_on_close)(x_smbd_object_t *smbd_object,
			x_smbd_open_t *smbd_open,
			bool delete_on_close);
	void (*notify_change)(const std::shared_ptr<x_smbd_volume_t> &smbd_volume,
			const std::u16string &path,
			const std::u16string &fullpath,
			const std::u16string *new_fullpath,
			uint32_t notify_action,
			uint32_t notify_filter,
			const x_smb2_lease_key_t &ignore_lease_key,
			const x_smb2_uuid_t &client_guid,
			bool last_level);
	// void (*destroy)(x_smbd_object_t *smbd_object, x_smbd_open_t *smbd_open);
	// void (*release_object)(x_smbd_object_t *smbd_object, x_smbd_stream_t *smbd_stream);
	NTSTATUS (*delete_object)(x_smbd_object_t *smbd_object,
			x_smbd_stream_t *smbd_stream,
			x_smbd_open_t *smbd_open);
	NTSTATUS (*access_check)(x_smbd_object_t *smbd_object,
			uint32_t &granted_access,
			uint32_t &maximal_access,
			x_smbd_tcon_t *smbd_tcon,
			const x_smbd_user_t &smbd_user,
			uint32_t desired_access,
			bool overwrite);
	void (*lease_granted)(x_smbd_object_t *smbd_object,
			x_smbd_stream_t *smbd_stream);

	int (*init_volume)(std::shared_ptr<x_smbd_volume_t> &smbd_volume);

	NTSTATUS (*allocate_object)(
			x_smbd_object_t **p_smbd_object,
			const std::shared_ptr<x_smbd_volume_t> &smbd_volume,
			long priv_data,
			uint64_t path_hash,
			x_smbd_object_t *parent_object,
			const std::u16string &path_base);

	void (*destroy_object)(x_smbd_object_t *smbd_object);

	NTSTATUS (*initialize_object)(
			x_smbd_object_t *smbd_object);

	NTSTATUS (*rename_object)(
			x_smbd_object_t *smbd_object,
			bool replace_if_exists,
			x_smbd_object_t *new_parent_object,
			const std::u16string &new_path);

	NTSTATUS (*rename_stream)(
			x_smbd_object_t *smbd_object,
			x_smbd_stream_t *smbd_stream,
			bool replace_if_exists,
			const std::u16string &new_stream_name);

	void (*release_stream)(x_smbd_object_t *smbd_object,
			x_smbd_stream_t *smbd_stream);

	void (*destroy_open)(x_smbd_open_t *smbd_open);
};

X_DECLARE_MEMBER_TRAITS(x_smbd_open_object_traits, x_smbd_open_t, object_link)

struct x_smbd_sharemode_t
{
	x_smbd_stream_meta_t meta;
	x_tp_ddlist_t<x_smbd_open_object_traits> open_list;
};

struct x_smbd_stream_t
{
	x_smbd_stream_t(bool exists, const std::u16string &name);
	~x_smbd_stream_t();

	x_dlink_t object_link; // link into object
	bool exists;
	x_smbd_sharemode_t sharemode;
	std::u16string name;
};
X_DECLARE_MEMBER_TRAITS(x_smbd_stream_object_traits, x_smbd_stream_t, object_link)

struct x_smbd_object_t
{
	x_smbd_object_t(const std::shared_ptr<x_smbd_volume_t> &smbd_volume,
			x_smbd_object_t *parent_object,
			long priv_data,
			uint64_t path_hash,
			const std::u16string &path);
	~x_smbd_object_t();

	bool is_root() const
	{
		return !parent_object;
	}

	bool exists() const { return type != type_not_exist; }

	void incref()
	{
		X_ASSERT(++use_count > 1);
	}

	void decref()
	{
		X_ASSERT(--use_count > 0);
	}

	void add_ads(x_smbd_stream_t *smbd_stream)
	{
		ads_list.push_front(smbd_stream);
	}

	void remove_ads(x_smbd_stream_t *smbd_stream)
	{
		ads_list.remove(smbd_stream);
	}

	auto lock()
	{
		/* we use smbd_object mutex to protect open */
		return std::lock_guard(mutex);
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
	std::atomic<int> use_count{1};
	uint32_t num_active_open{0}; // include open on streams
	x_dlink_t path_hash_link;
	x_dlink_t parent_link; // used by parent's active_child_object_list
	uint64_t path_hash, fileid_hash;
	x_smbd_object_t *parent_object = nullptr;
	std::u16string path_base;
	x_smbd_file_handle_t file_handle;
	x_smbd_object_meta_t meta;
	x_smbd_sharemode_t sharemode;
	std::shared_ptr<idl::security_descriptor> psd;
	x_ddlist_t active_child_object_list;
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
		x_smb2_create_close_info_t *info);

static inline NTSTATUS x_smbd_open_op_read(
		x_smbd_open_t *smbd_open,
		x_nxfsd_requ_t *nxfsd_requ,
		std::unique_ptr<x_smbd_requ_state_read_t> &state,
		uint32_t delay_ms,
		bool all)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	auto op_fn = smbd_object->smbd_volume->ops->read;
	if (!op_fn) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return op_fn(smbd_object, smbd_open, nxfsd_requ, state, delay_ms, all);
}

static inline NTSTATUS x_smbd_open_op_write(
		x_smbd_open_t *smbd_open,
		x_nxfsd_requ_t *nxfsd_requ,
		std::unique_ptr<x_smbd_requ_state_write_t> &state,
		uint32_t delay_ms)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	auto op_fn = smbd_object->smbd_volume->ops->write;
	if (!op_fn) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return op_fn(smbd_object, smbd_open, nxfsd_requ, state, delay_ms);
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
		std::unique_ptr<x_smbd_requ_state_getinfo_t> &state)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	return smbd_object->smbd_volume->ops->getinfo(smbd_object, smbd_open,
			smbd_conn, smbd_requ, state);
}

static inline NTSTATUS x_smbd_open_op_setinfo(x_smbd_open_t *smbd_open,
		x_smbd_conn_t *smbd_conn,
		x_nxfsd_requ_t *nxfsd_requ,
		std::unique_ptr<x_smbd_requ_state_setinfo_t> &state)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	return smbd_object->smbd_volume->ops->setinfo(smbd_object,
			smbd_conn, nxfsd_requ, state);
}

static inline NTSTATUS x_smbd_open_op_ioctl(
		x_smbd_open_t *smbd_open,
		x_nxfsd_requ_t *nxfsd_requ,
		std::unique_ptr<x_smbd_requ_state_ioctl_t> &state)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	auto op_fn = smbd_object->smbd_volume->ops->ioctl;
	if (!op_fn) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	return op_fn(smbd_object, nxfsd_requ, state);
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
#if 0
static inline void x_smbd_open_op_destroy(
		x_smbd_open_t *smbd_open)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	return smbd_object->smbd_volume->ops->destroy(smbd_object, smbd_open);
}
#endif
static inline std::pair<uint64_t, uint64_t> x_smbd_open_get_id(x_smbd_open_t *smbd_open)
{
	return { smbd_open->id_persistent, smbd_open->id_volatile };
}

static inline NTSTATUS x_smbd_object_delete(
		x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream,
		x_smbd_open_t *smbd_open)
{
	return smbd_object->smbd_volume->ops->delete_object(smbd_object,
			smbd_stream, smbd_open);
}

static inline NTSTATUS x_smbd_create_object(x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream,
		const x_smbd_user_t &smbd_user,
		x_smbd_requ_state_create_t &state,
		uint32_t file_attributes,
		uint64_t allocation_size)
{
	return smbd_object->smbd_volume->ops->create_object(smbd_object,
			smbd_stream,
			smbd_user, state,
			file_attributes,
			allocation_size);
}

static inline NTSTATUS x_smbd_open_durable(x_smbd_open_t *&smbd_open,
		std::shared_ptr<x_smbd_share_t> &smbd_share,
		std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		const x_smbd_durable_t &durable)
{
	return smbd_volume->ops->open_durable(smbd_open, smbd_share, smbd_volume, durable);
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

static inline NTSTATUS x_smbd_object_set_zero_data(
		x_smbd_open_t *smbd_open,
		uint64_t begin_offset, uint64_t end_offset)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	return smbd_object->smbd_volume->ops->set_zero_data(
			smbd_object,
			smbd_open,
			begin_offset, end_offset);
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

static inline NTSTATUS x_smbd_object_update_mtime(x_smbd_object_t *smbd_object)
{
	return smbd_object->smbd_volume->ops->update_mtime(smbd_object);
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
		std::unique_ptr<x_smbd_requ_state_create_t> &state);

x_smbd_open_t *x_smbd_open_reopen(NTSTATUS &status,
		uint64_t id_presistent, uint64_t id_volatile,
		x_smbd_tcon_t *smbd_tcon,
		x_smbd_requ_state_create_t &state);

NTSTATUS x_smbd_open_op_create(x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smbd_requ_state_create_t> &state);
NTSTATUS x_smbd_open_op_reconnect(x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smbd_requ_state_create_t> &state);

bool x_smbd_open_break_lease(x_smbd_open_t *smbd_open,
		const x_smb2_lease_key_t *ignore_lease_key,
		const x_smb2_uuid_t *client_guid,
		uint8_t break_mask,
		uint8_t delay_mask,
		x_nxfsd_requ_t *nxfsd_requ,
		bool block_breaking);

bool x_smbd_open_break_oplock(x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		uint8_t break_mask,
		x_nxfsd_requ_t *nxfsd_requ);

NTSTATUS x_smbd_break_oplock(
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		x_smbd_requ_state_oplock_break_t &state);

void x_smbd_break_others_to_none(x_smbd_object_t *smbd_object,
		x_smbd_sharemode_t *sharemode,
		const x_smbd_lease_t *smbd_lease,
		uint8_t oplock_level);

bool x_smbd_check_io_brl_conflict(x_smbd_object_t *smbd_object,
		const x_smbd_open_t *smbd_open,
		uint64_t offset, uint64_t length, bool is_write);
void x_smbd_lock_retry(x_smbd_sharemode_t *sharemode);

bool x_smbd_open_match_get_lease(const x_smbd_open_t *smbd_open,
		const x_smb2_uuid_t &client_guid,
		x_smb2_lease_t &lease);

static inline x_smbd_qdir_t *x_smbd_qdir_create(x_smbd_open_t *smbd_open,
		const std::shared_ptr<x_smbd_user_t> &smbd_user)
{
	return smbd_open->smbd_object->smbd_volume->ops->qdir_create(smbd_open,
			smbd_user);
}

static inline void x_smbd_qdir_unget_entry(x_smbd_qdir_t *smbd_qdir,
			const x_smbd_qdir_pos_t &qdir_pos)
{
	X_ASSERT(smbd_qdir->pos.file_number == qdir_pos.file_number + 1);
	smbd_qdir->pos = qdir_pos;
}

void x_smbd_qdir_close(x_smbd_qdir_t *smbd_qdir);

NTSTATUS x_smbd_object_lookup(x_smbd_object_t **p_smbd_object,
		const std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		x_smbd_object_t *parent_object,
		const std::u16string &path_base,
		uint64_t path_data,
		bool create_if,
		uint64_t path_hash,
		bool ncase);

void x_smbd_release_object_and_stream(x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream);

void x_smbd_release_object(x_smbd_object_t *smbd_object);

NTSTATUS x_smbd_open_object(x_smbd_object_t **psmbd_object,
		const std::shared_ptr<x_smbd_share_t> &smbd_share,
		const std::u16string &path,
		long path_priv_data,
		bool create_if);

NTSTATUS x_smbd_object_rename(x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_nxfsd_requ_t *nxfsd_requ,
		std::unique_ptr<x_smbd_requ_state_rename_t> &state);

static inline NTSTATUS x_smbd_open_rename(
		x_nxfsd_requ_t *nxfsd_requ,
		std::unique_ptr<x_smbd_requ_state_rename_t> &state)
{
	auto smbd_open = nxfsd_requ->smbd_open;
	auto smbd_object = smbd_open->smbd_object;
	return x_smbd_object_rename(smbd_object, smbd_open, nxfsd_requ,
			state);
}

NTSTATUS x_smbd_open_create(
		x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smbd_requ_state_create_t> &state,
		x_smb2_create_action_t &create_action,
		uint8_t &out_oplock_level,
		bool overwrite);

NTSTATUS x_smbd_object_set_delete_pending_intl(x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_nxfsd_requ_t *nxfsd_requ,
		std::unique_ptr<x_smbd_requ_state_disposition_t> &state);

NTSTATUS x_smbd_object_set_delete_pending(x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_nxfsd_requ_t *nxfsd_requ,
		std::unique_ptr<x_smbd_requ_state_disposition_t> &state);

static inline NTSTATUS x_smbd_open_set_delete_pending(
		x_nxfsd_requ_t *nxfsd_requ,
		std::unique_ptr<x_smbd_requ_state_disposition_t> &state)
{
	auto smbd_open = nxfsd_requ->smbd_open;
	auto smbd_object = smbd_open->smbd_object;
	return x_smbd_object_set_delete_pending(smbd_object, smbd_open,
			nxfsd_requ, state);
}

std::u16string x_smbd_object_get_path(const x_smbd_object_t *smbd_object);

std::pair<bool, uint64_t> x_smbd_hash_path(const x_smbd_volume_t &smbd_volume,
		const x_smbd_object_t *dir_object,
		const std::u16string &path);

void x_smbd_save_durable(x_smbd_open_t *smbd_open,
		x_smbd_tcon_t *smbd_tcon,
		const x_smbd_requ_state_create_t &state);

void x_smbd_open_release(x_smbd_open_t *smbd_open);

void x_smbd_wakeup_requ_list(const x_nxfsd_requ_id_list_t &requ_list);

template <typename T>
static inline T *x_smbd_getinfo_alloc(std::vector<uint8_t> &out_data)
{
	out_data.resize(sizeof(T));
	return (T *)out_data.data();
}

template<typename T>
static NTSTATUS x_smbd_getinfo_encode_le(T val,
		x_smbd_requ_state_getinfo_t &state)
{
	if (state.in_output_buffer_length < sizeof(T)) {
		return NT_STATUS_INFO_LENGTH_MISMATCH;
	}

	state.out_data.resize(sizeof(T));
	T *info = (T *)state.out_data.data();
	*info = x_h2le(val);
	return NT_STATUS_OK;
}

template <typename T>
NTSTATUS x_smbd_open_getinfo_file(x_smbd_conn_t *smbd_conn, x_smbd_open_t *smbd_open,
		x_smbd_requ_state_getinfo_t &state, const T &op)
{
	if (state.in_info_level == x_smb2_info_level_t::FILE_BASIC_INFORMATION) {
		if (state.in_output_buffer_length < sizeof(x_smb2_file_basic_info_t)) {
			RETURN_STATUS(NT_STATUS_INFO_LENGTH_MISMATCH);
		}
		if (!smbd_open->check_access_any(idl::SEC_FILE_READ_ATTRIBUTE)) {
			RETURN_STATUS(NT_STATUS_ACCESS_DENIED);
		}
		auto info = x_smbd_getinfo_alloc<x_smb2_file_basic_info_t>(state.out_data);
		x_smbd_get_file_info(*info, op.get_object_meta(smbd_open));

	} else if (state.in_info_level == x_smb2_info_level_t::FILE_STANDARD_INFORMATION) {
		if (state.in_output_buffer_length < sizeof(x_smb2_file_standard_info_t)) {
			RETURN_STATUS(NT_STATUS_INFO_LENGTH_MISMATCH);
		}
		auto info = x_smbd_getinfo_alloc<x_smb2_file_standard_info_t>(state.out_data);
		x_smbd_get_file_info(*info, op.get_object_meta(smbd_open),
				op.get_stream_meta(smbd_open),
				smbd_open->open_state.access_mask,
				smbd_open->mode,
				smbd_open->open_state.current_offset);

	} else if (state.in_info_level == x_smb2_info_level_t::FILE_INTERNAL_INFORMATION) {
		if (state.in_output_buffer_length < sizeof(uint64_t)) {
			RETURN_STATUS(NT_STATUS_INFO_LENGTH_MISMATCH);
		}
		return x_smbd_getinfo_encode_le(uint64_t(op.get_object_meta(smbd_open).inode), state);

	} else if (state.in_info_level == x_smb2_info_level_t::FILE_EA_INFORMATION) {
		/* TODO we do not support EA for now */
		return x_smbd_getinfo_encode_le(uint32_t(0), state);

	} else if (state.in_info_level == x_smb2_info_level_t::FILE_ACCESS_INFORMATION) {
		return x_smbd_getinfo_encode_le(smbd_open->open_state.access_mask, state);

	} else if (state.in_info_level == x_smb2_info_level_t::FILE_POSITION_INFORMATION) {
		return x_smbd_getinfo_encode_le(smbd_open->open_state.current_offset, state);

	} else if (state.in_info_level == x_smb2_info_level_t::FILE_MODE_INFORMATION) {
		return x_smbd_getinfo_encode_le(smbd_open->mode, state);

	} else if (state.in_info_level == x_smb2_info_level_t::FILE_ALIGNMENT_INFORMATION) {
		/* No alignment needed. */
		return x_smbd_getinfo_encode_le(uint32_t(0), state);

	} else if (state.in_info_level == x_smb2_info_level_t::FILE_FULL_EA_INFORMATION) {
		/* TODO we do not support EA for now */
		RETURN_STATUS(NT_STATUS_NO_EAS_ON_FILE);

	} else if (state.in_info_level == x_smb2_info_level_t::FILE_ALL_INFORMATION) {
		if (state.in_output_buffer_length < sizeof(x_smb2_file_all_info_t)) {
			RETURN_STATUS(NT_STATUS_INFO_LENGTH_MISMATCH);
		}
		if (!smbd_open->check_access_any(idl::SEC_FILE_READ_ATTRIBUTE)) {
			RETURN_STATUS(NT_STATUS_ACCESS_DENIED);
		}
		auto info = x_smbd_getinfo_alloc<x_smb2_file_all_info_t>(state.out_data);
		x_smbd_get_file_info(*info, op.get_object_meta(smbd_open),
				op.get_stream_meta(smbd_open),
				smbd_open->open_state.access_mask,
				smbd_open->mode,
				smbd_open->open_state.current_offset);

	} else if (state.in_info_level == x_smb2_info_level_t::FILE_ALTERNATE_NAME_INFORMATION) {
		if (state.in_output_buffer_length < sizeof(x_smb2_file_alternate_name_info_t)) {
			RETURN_STATUS(NT_STATUS_INFO_LENGTH_MISMATCH);
		}
		/* TODO not support 8.3 name for now */
		RETURN_STATUS(NT_STATUS_OBJECT_NAME_NOT_FOUND);

	} else if (state.in_info_level == x_smb2_info_level_t::FILE_STREAM_INFORMATION) {
		if (state.in_output_buffer_length < sizeof(x_smb2_file_stream_name_info_t) + 8) {
			RETURN_STATUS(NT_STATUS_INFO_LENGTH_MISMATCH);
		}
		return op.get_stream_info(smbd_open, state);

	} else if (state.in_info_level == x_smb2_info_level_t::FILE_COMPRESSION_INFORMATION) {
		if (state.in_output_buffer_length < sizeof(x_smb2_file_compression_info_t)) {
			RETURN_STATUS(NT_STATUS_INFO_LENGTH_MISMATCH);
		}
		auto info = x_smbd_getinfo_alloc<x_smb2_file_compression_info_t>(state.out_data);
		x_smbd_get_file_info(*info, op.get_stream_meta(smbd_open));

	} else if (state.in_info_level == x_smb2_info_level_t::FILE_NETWORK_OPEN_INFORMATION) {
		if (state.in_output_buffer_length < sizeof(x_smb2_file_network_open_info_t)) {
			RETURN_STATUS(NT_STATUS_INFO_LENGTH_MISMATCH);
		}
		if (!smbd_open->check_access_any(idl::SEC_FILE_READ_ATTRIBUTE)) {
			RETURN_STATUS(NT_STATUS_ACCESS_DENIED);
		}
		auto info = x_smbd_getinfo_alloc<x_smb2_file_network_open_info_t>(state.out_data);
		x_smbd_get_file_info(*info, op.get_object_meta(smbd_open),
				op.get_stream_meta(smbd_open));

	} else if (state.in_info_level == x_smb2_info_level_t::FILE_ATTRIBUTE_TAG_INFORMATION) {
		if (state.in_output_buffer_length < sizeof(x_smb2_file_attribute_tag_info_t)) {
			RETURN_STATUS(NT_STATUS_INFO_LENGTH_MISMATCH);
		}
		auto info = x_smbd_getinfo_alloc<x_smb2_file_attribute_tag_info_t>(state.out_data);
		x_smbd_get_file_info(*info, op.get_object_meta(smbd_open));

	} else if (state.in_info_level == x_smb2_info_level_t::FILE_NORMALIZED_NAME_INFORMATION) {
		if (x_smbd_conn_get_dialect(smbd_conn) < X_SMB2_DIALECT_311) {
			RETURN_STATUS(NT_STATUS_NOT_SUPPORTED);
		}
		if (state.in_output_buffer_length < sizeof(x_smb2_file_normalized_name_info_t)) {
			RETURN_STATUS(NT_STATUS_INFO_LENGTH_MISMATCH);
		}
		
		std::u16string path = x_smbd_object_get_path(smbd_open->smbd_object);

		size_t name_length = path.length();
		if (smbd_open->smbd_stream) {
			name_length += 1 + smbd_open->smbd_stream->name.length();
		}
		name_length <<= 1;

		uint32_t output_buffer_length = state.in_output_buffer_length & ~1;
		size_t buf_size = std::min(size_t(output_buffer_length),
				offsetof(x_smb2_file_normalized_name_info_t, name) +
				name_length);
		state.out_data.resize(buf_size);
		x_smb2_file_normalized_name_info_t *info =
			(x_smb2_file_normalized_name_info_t *)state.out_data.data();
		info->name_length = X_H2LE32(x_convert_assert<uint32_t>(name_length));

		char16_t *buf = info->name;
		char16_t *buf_end = (char16_t *)((char *)info + buf_size);
		buf = x_utf16le_encode(path, buf, buf_end);
		if (!buf) {
			return NT_STATUS_BUFFER_OVERFLOW;
		}

		if (smbd_open->smbd_stream) {
			if (buf == buf_end) {
				return NT_STATUS_BUFFER_OVERFLOW;
			}
			*buf++ = X_H2LE16(u':');
			buf = x_utf16le_encode(smbd_open->smbd_stream->name, buf, buf_end);
			if (!buf) {
				return NT_STATUS_BUFFER_OVERFLOW;
			}
		}

	} else {
		RETURN_STATUS(NT_STATUS_INVALID_LEVEL);
	}
	return NT_STATUS_OK;
}

NTSTATUS x_smbd_open_getinfo_security(x_smbd_open_t *smbd_open,
		x_smbd_requ_state_getinfo_t &state);

#endif /* __smbd_open__hxx__ */

