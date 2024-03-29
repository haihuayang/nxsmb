
#include "smbd.hxx"
#include "smbd_ctrl.hxx"
#include "smbd_stats.hxx"
#include "smbd_open.hxx"
#include "smbd_replay.hxx"
#include "include/idtable.hxx"
#include "smbd_access.hxx"
#include "smbd_dcerpc_srvsvc.hxx"

enum {
	SMBD_OPEN_S_INIT,
	SMBD_OPEN_S_ACTIVE,
	SMBD_OPEN_S_DISCONNECTED, /* durable handle waiting reconnect */
	SMBD_OPEN_S_DONE,
};

struct smbd_open_deleter
{
	void operator()(x_smbd_open_t *smbd_open) const {
		auto smbd_object = smbd_open->smbd_object;
		smbd_object->smbd_volume->ops->destroy_open(smbd_open);
	}
};

struct smbd_open_idtable_traits_t
{
	enum {
		index_max = 0x1ffff8u,
		index_null = 0x1fffffu,
		id_invalid = uint64_t(-1),
	};
	using id_type = uint64_t;
	using gen_type = uint32_t;
	using index_type = uint32_t;
	static constexpr uint32_t entry_to_gen(uint64_t val) {
		return val & 0x7fful;
	}
	static constexpr uint64_t build_id(uint32_t gen, uint32_t index) {
		return uint64_t(index) << 11 | gen;
	}
	static constexpr uint32_t id_to_index(uint64_t id) {
		return uint32_t(id >> 11);
	}
	static constexpr uint32_t id_to_gen(uint64_t id) {
		return uint32_t(id & 0x7ffu);
	}
	static constexpr uint32_t inc_gen(uint32_t gen) {
		return (gen + 1) & 0x7ffu;
	}
};

using smbd_open_table_t = x_idtable_t<x_smbd_open_t, smbd_open_idtable_traits_t, smbd_open_deleter>;
static smbd_open_table_t *g_smbd_open_table;

/* allocate extra count of open, so it unlikely exceed the hard limit when multiple thread
 * create the open in the same time, because each of them call x_smbd_open_has_space
 * before create it
 */
static constexpr uint32_t g_smbd_open_extra = 32;
bool x_smbd_open_has_space()
{
	return g_smbd_open_table->alloc_count + g_smbd_open_extra < g_smbd_open_table->count;
}

template <>
x_smbd_open_t *x_smbd_ref_inc(x_smbd_open_t *smbd_open)
{
	g_smbd_open_table->incref(smbd_open->id_volatile);
	return smbd_open;
}

template <>
void x_smbd_ref_dec(x_smbd_open_t *smbd_open)
{
	g_smbd_open_table->decref(smbd_open->id_volatile);
}

/* we use smbd_object mutex to protect open */
static inline auto smbd_object_lock(x_smbd_object_t *smbd_object)
{
	return std::lock_guard(smbd_object->mutex);
}


int x_smbd_open_table_init(uint32_t count)
{
	X_ASSERT(count + g_smbd_open_extra < smbd_open_idtable_traits_t::index_max);
	g_smbd_open_table = new smbd_open_table_t(count + g_smbd_open_extra);
	return 0;
}

bool x_smbd_open_store(x_smbd_open_t *smbd_open)
{
	return g_smbd_open_table->store(smbd_open, smbd_open->id_volatile);
}

static bool clear_replay_cache(x_smbd_open_state_t &open_state)
{
	/* From Samba smb2srv_open_lookup,
	 * Clear the replay cache for this create_guid if it exists:
	 * This is based on the assumption that this lookup will be
	 * triggered by a client request using the file-id for lookup.
	 * Hence the client has proven that it has in fact seen the
	 * reply to its initial create call. So subsequent create replays
	 * should be treated as invalid. Hence the index for create_guid
	 * lookup needs to be removed.
	 */

	/* TODO atomic */
	if (open_state.replay_cached) {
		x_smbd_replay_cache_clear(open_state.client_guid,
				open_state.create_guid);
		open_state.replay_cached = false;
		return true;
	}
	return false;
}

x_smbd_open_t *x_smbd_open_lookup(uint64_t id_persistent, uint64_t id_volatile,
		const x_smbd_tcon_t *smbd_tcon)
{
	auto [found, smbd_open] = g_smbd_open_table->lookup(id_volatile);
	if (found) {
		auto smbd_object = smbd_open->smbd_object;
		{
			auto lock = smbd_object_lock(smbd_object);
			if (smbd_open->open_state.id_persistent == id_persistent &&
					smbd_open->state == SMBD_OPEN_S_ACTIVE &&
					(smbd_open->smbd_tcon == smbd_tcon ||
					 !smbd_tcon)) {
				if (clear_replay_cache(smbd_open->open_state) &&
						smbd_open->open_state.dhmode !=
						x_smbd_dhmode_t::NONE) {
					/* update durable */
					x_smbd_volume_update_durable(*smbd_object->smbd_volume,
							smbd_open->open_state);
				}

				return smbd_open;
			}
		}
		x_smbd_ref_dec(smbd_open);
	}
	return nullptr;
}

static inline x_smbd_sharemode_t *get_sharemode(
		x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream)
{
	if (!smbd_stream) {
		return &smbd_object->sharemode;
	} else {
		return &smbd_stream->sharemode;
	}
}

static inline const x_smbd_sharemode_t *get_sharemode(
		const x_smbd_object_t *smbd_object,
		const x_smbd_stream_t *smbd_stream)
{
	if (!smbd_stream) {
		return &smbd_object->sharemode;
	} else {
		return &smbd_stream->sharemode;
	}
}

static void sharemode_modified(x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream);

static void fill_out_info(x_smb2_create_close_info_t &info,
		const x_smbd_object_meta_t &object_meta,
		const x_smbd_stream_meta_t &stream_meta)
{
	info.out_create_ts = object_meta.creation;
	info.out_last_access_ts = object_meta.last_access;
	info.out_last_write_ts = object_meta.last_write;
	info.out_change_ts = object_meta.change;
	info.out_file_attributes = object_meta.file_attributes;
	info.out_allocation_size = stream_meta.allocation_size;
	info.out_end_of_file = stream_meta.end_of_file;
}

static NTSTATUS smbd_object_remove(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open)
{
	if (!smbd_open->object_link.is_valid()) {
		X_ASSERT(false);
		return NT_STATUS_OK;
	}

	auto sharemode = x_smbd_open_get_sharemode(smbd_open);
	sharemode->open_list.remove(smbd_open);
	if (--smbd_object->num_active_open == 0 && smbd_object->parent_object) {
		x_smbd_object_update_num_child(smbd_object->parent_object, -1);
	}

	if (smbd_open->open_state.initial_delete_on_close) {
		x_smbd_open_op_set_delete_on_close(smbd_open, true);
	}

	if (smbd_open->locks.size()) {
		x_smbd_lock_retry(sharemode);
	}

	if (!sharemode->open_list.empty()) {
		return NT_STATUS_OK;
	}

	if (smbd_object->sharemode.meta.delete_on_close &&
			smbd_object->num_active_open == 0) {
		uint32_t notify_filter = x_smbd_object_is_dir(smbd_object) ?
			FILE_NOTIFY_CHANGE_DIR_NAME : FILE_NOTIFY_CHANGE_FILE_NAME;

		NTSTATUS status = x_smbd_object_delete(smbd_object, nullptr,
				smbd_open);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		smbd_object->type = x_smbd_object_t::type_not_exist;
		auto &ads_list = smbd_object->ads_list;
		for (x_smbd_stream_t *smbd_stream = ads_list.get_front();
				smbd_stream;
				smbd_stream = ads_list.next(smbd_stream)) {
			smbd_stream->exists = false;
		}
		x_smbd_schedule_notify(
				NOTIFY_ACTION_REMOVED, notify_filter,
				smbd_open->open_state.parent_lease_key,
				smbd_open->open_state.client_guid,
				smbd_object->parent_object, nullptr,
				smbd_object->path_base, {});
	} else if (smbd_open->smbd_stream &&
			sharemode->meta.delete_on_close) {
		NTSTATUS status = x_smbd_object_delete(smbd_object,
				smbd_open->smbd_stream,
				smbd_open);

		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		smbd_open->smbd_stream->exists = false;
		// TODO should it also notify object MODIFIED
		x_smbd_schedule_notify(
				NOTIFY_ACTION_REMOVED_STREAM,
				FILE_NOTIFY_CHANGE_STREAM_NAME,
				smbd_open->open_state.parent_lease_key,
				smbd_open->open_state.client_guid,
				smbd_object->parent_object, nullptr,
				smbd_object->path_base + u':' + smbd_open->smbd_stream->name,
				{});
	}

	return NT_STATUS_OK;
}

/* caller hold smbd_object->mutex */
static void smbd_close_open_intl(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_close_t> &state,
		x_smbd_lease_t *&smbd_lease,
		x_tp_ddlist_t<requ_async_traits> &pending_requ_list)
{
	if (smbd_open->open_state.dhmode != x_smbd_dhmode_t::NONE) {
		int ret = x_smbd_volume_remove_durable(
				*smbd_open->smbd_object->smbd_volume,
				smbd_open->open_state.id_persistent);
		X_LOG_DBG("remove_durable for %p 0x%lx, ret = %d",
				smbd_open, smbd_open->open_state.id_persistent, ret);
	}

	clear_replay_cache(smbd_open->open_state);

	if (smbd_open->oplock_break_sent != x_smbd_open_t::OPLOCK_BREAK_NOT_SENT) {
		if (x_smbd_del_timer(&smbd_open->oplock_break_timer)) {
			x_smbd_ref_dec(smbd_open);
		}
		smbd_open->oplock_break_sent = x_smbd_open_t::OPLOCK_BREAK_NOT_SENT;
	}

       	smbd_lease = smbd_open->smbd_lease;
	smbd_open->smbd_lease = nullptr;

	if (smbd_open->smbd_qdir) {
		x_smbd_qdir_close(smbd_open->smbd_qdir);
		smbd_open->smbd_qdir = nullptr;
	}

	/* Windows server send NT_STATUS_NOTIFY_CLEANUP
	   when tree disconect.
	   while samba not send.
	   for simplicity we do not either for now
	 */
	if (smbd_open->notify_filter & X_FILE_NOTIFY_CHANGE_WATCH_TREE) {
		/* TODO make it atomic */
		X_ASSERT(smbd_object->smbd_volume->watch_tree_cnt > 0);
		--smbd_object->smbd_volume->watch_tree_cnt;
	}
	pending_requ_list = std::move(smbd_open->pending_requ_list);

	if (smbd_open->update_write_time) {
		x_smbd_schedule_notify(
				NOTIFY_ACTION_MODIFIED,
				FILE_NOTIFY_CHANGE_LAST_WRITE,
				smbd_open->open_state.parent_lease_key,
				smbd_open->open_state.client_guid,
				smbd_object->parent_object, nullptr,
				smbd_object->path_base, {});
		smbd_open->update_write_time = false;
	}

	smbd_object_remove(smbd_object, smbd_open);

	// TODO if last_write_time updated
	if (smbd_requ && (state->in_flags & X_SMB2_CLOSE_FLAGS_FULL_INFORMATION)) {
		state->out_flags = X_SMB2_CLOSE_FLAGS_FULL_INFORMATION;
		/* TODO stream may be freed */
		auto &stream_meta = x_smbd_open_get_sharemode(smbd_open)->meta;
		fill_out_info(state->out_info, smbd_object->meta,
					stream_meta);
	}
}

static bool smbd_open_close_disconnected_if(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		std::vector<x_smbd_lease_t *> &smbd_leases,
		x_tp_ddlist_t<requ_async_traits> &pending_requ_list)
{
	x_smbd_lease_t *smbd_lease = nullptr;
	x_tp_ddlist_t<requ_async_traits> tmp_requ_list;
	std::unique_ptr<x_smb2_state_close_t> state;

	if (smbd_open->state != SMBD_OPEN_S_DISCONNECTED) {
		return false;
	}

	if (!x_smbd_del_timer(&smbd_open->durable_timer)) {
		return false;
	}
	smbd_open->state = SMBD_OPEN_S_DONE;
	smbd_close_open_intl(smbd_object, smbd_open, nullptr, state,
			smbd_lease, tmp_requ_list);

	x_smbd_ref_dec(smbd_open); // durable timer ref

	g_smbd_open_table->remove(smbd_open->id_volatile);

	if (smbd_lease) {
		smbd_leases.push_back(smbd_lease);
	}

	pending_requ_list.concat(tmp_requ_list);
	return true;
}

bool x_smbd_open_match_get_lease(const x_smbd_open_t *smbd_open,
		x_smb2_lease_t &lease)
{
	return x_smbd_lease_match_get(smbd_open->smbd_lease,
			x_smbd_conn_curr_client_guid(),
			lease);
}

static void smbd_open_post_close(x_smbd_open_t *smbd_open,
		x_smbd_object_t *smbd_object,
		x_smbd_lease_t *smbd_lease,
		x_tp_ddlist_t<requ_async_traits> &pending_requ_list)
{
	g_smbd_open_table->remove(smbd_open->id_volatile);
	x_smbd_ref_dec(smbd_open);

	x_smbd_requ_t *pending_requ;
	while ((pending_requ = pending_requ_list.get_front()) != nullptr) {
		pending_requ_list.remove(pending_requ);
		x_smbd_conn_post_cancel(x_smbd_chan_get_conn(pending_requ->smbd_chan),
				pending_requ, pending_requ->status);
	}

	if (smbd_lease) {
		x_smbd_lease_close(smbd_lease);
	}
}

// caller hold the object mutex
static void smbd_open_close(
		x_smbd_open_t *smbd_open,
		x_smbd_object_t *smbd_object,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_close_t> &state,
		x_smbd_lease_t * &smbd_lease,
		x_tp_ddlist_t<requ_async_traits> &pending_requ_list)
{
	smbd_open->state = SMBD_OPEN_S_DONE;

	if (smbd_object->type != x_smbd_object_t::type_pipe) {
		smbd_close_open_intl(smbd_object, smbd_open, smbd_requ, state,
				smbd_lease, pending_requ_list);
		sharemode_modified(smbd_object, smbd_open->smbd_stream);
	}
}

static long smbd_open_durable_timeout(x_timer_job_t *timer)
{
	x_smbd_set_notify_schedulable(true);

	x_smbd_open_t *smbd_open = X_CONTAINER_OF(timer,
			x_smbd_open_t, durable_timer);
	X_LOG_DBG("durable_timeout %lx,%lx", smbd_open->open_state.id_persistent,
			smbd_open->id_volatile);
	auto smbd_object = smbd_open->smbd_object;

	std::unique_ptr<x_smb2_state_close_t> state;
	x_smbd_lease_t *smbd_lease = nullptr;
	x_tp_ddlist_t<requ_async_traits> pending_requ_list;

	bool closed = false;
	{
		auto lock = smbd_object_lock(smbd_object);
		if (smbd_open->state == SMBD_OPEN_S_DISCONNECTED) {
			smbd_open_close(smbd_open, smbd_object, nullptr, state,
					smbd_lease, pending_requ_list);
			closed = true;
		}
	}

	if (closed) {
		smbd_open_post_close(smbd_open, smbd_object,
				smbd_lease, pending_requ_list);
	}

	x_smbd_ref_dec(smbd_open); // ref by timer

	x_smbd_flush_notifies();
	return -1;
}

static bool smbd_open_set_durable(x_smbd_open_t *smbd_open)
{
	X_LOG_DBG("set_durable %lx,%lx", smbd_open->open_state.id_persistent,
			smbd_open->id_volatile);
	auto smbd_object = smbd_open->smbd_object;
	X_ASSERT(smbd_object);
	smbd_open->state = SMBD_OPEN_S_DISCONNECTED;

	/* TODO save durable info to volume so it can restore open
	 * when new smbd take over
	 */
	x_smbd_add_timer(&smbd_open->durable_timer,
			smbd_open->open_state.durable_timeout_msec * 1000000ul);

	int ret = x_smbd_volume_disconnect_durable(
			*smbd_object->smbd_volume,
			smbd_open->open_state.id_persistent);
	X_LOG_DBG("set_durable_expired for %p 0x%lx, ret = %d",
			smbd_open, smbd_open->open_state.id_persistent, ret);

	return true;
}

NTSTATUS x_smbd_open_op_close(
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_close_t> &state)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	x_smbd_tcon_t *smbd_tcon = nullptr;

	x_smbd_lease_t *smbd_lease = nullptr;
	x_tp_ddlist_t<requ_async_traits> pending_requ_list;

	{
		auto lock = smbd_object_lock(smbd_object);
		if (smbd_open->state != SMBD_OPEN_S_ACTIVE) {
			return NT_STATUS_FILE_CLOSED;
		}

		/* it could happen when client tdis on other channel */
		if (!x_smbd_tcon_unlink_open(smbd_open->smbd_tcon, &smbd_open->tcon_link)) {
			return NT_STATUS_FILE_CLOSED;
		}
		smbd_tcon = smbd_open->smbd_tcon;
		smbd_open->smbd_tcon = nullptr;
		smbd_open_close(smbd_open, smbd_object, smbd_requ, state,
				smbd_lease, pending_requ_list);
	}

	X_ASSERT(smbd_tcon);
	x_smbd_ref_dec(smbd_tcon);

	smbd_open_post_close(smbd_open, smbd_object, smbd_lease,
			pending_requ_list);
	x_smbd_ref_dec(smbd_open); // ref by smbd_tcon open_list

	return NT_STATUS_OK;
}

void x_smbd_open_unlinked(x_dlink_t *link,
		bool shutdown)
{
	x_smbd_open_t *smbd_open = X_CONTAINER_OF(link, x_smbd_open_t, tcon_link);
	auto smbd_object = smbd_open->smbd_object;
	std::unique_ptr<x_smb2_state_close_t> state;
	x_smbd_tcon_t *smbd_tcon = nullptr;

	x_smbd_lease_t *smbd_lease = nullptr;
	x_tp_ddlist_t<requ_async_traits> pending_requ_list;

	bool closed = true;
	{
		auto lock = smbd_object_lock(smbd_object);
		if (smbd_open->state != SMBD_OPEN_S_ACTIVE) {
			return;
		}
		smbd_tcon = smbd_open->smbd_tcon;
		smbd_open->smbd_tcon = nullptr;
		if (shutdown && smbd_open->open_state.dhmode != x_smbd_dhmode_t::NONE &&
				smbd_open_set_durable(smbd_open)) {
			closed = false;
		} else {
			smbd_open_close(smbd_open, smbd_object, nullptr, state,
					smbd_lease, pending_requ_list);
			closed = true;
		}
	}

	X_ASSERT(smbd_tcon);
	x_smbd_ref_dec(smbd_tcon);

	if (closed) {
		smbd_open_post_close(smbd_open, smbd_object, smbd_lease,
				pending_requ_list);
		/* dec ref only closed, otherwise the ref is used by timer */
		x_smbd_ref_dec(smbd_open); // ref by smbd_tcon open_list
	}
}

static bool is_stat_open(uint32_t access_mask)
{
	const uint32_t stat_open_bits =
		(idl::SEC_STD_SYNCHRONIZE|
		 idl::SEC_FILE_READ_ATTRIBUTE|
		 idl::SEC_FILE_WRITE_ATTRIBUTE);

	return (((access_mask &  stat_open_bits) != 0) &&
			((access_mask & ~stat_open_bits) == 0));
}

static bool is_lease_stat_open(uint32_t access_mask)
{
	const uint32_t stat_open_bits =
		(idl::SEC_STD_SYNCHRONIZE|
		 idl::SEC_FILE_READ_ATTRIBUTE|
		 idl::SEC_FILE_WRITE_ATTRIBUTE|
		 idl::SEC_STD_READ_CONTROL);

	return (((access_mask &  stat_open_bits) != 0) &&
			((access_mask & ~stat_open_bits) == 0));
}

struct defer_open_evt_t
{
	static void func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user)
	{
		defer_open_evt_t *evt = X_CONTAINER_OF(fdevt_user,
				defer_open_evt_t, base);
		x_smbd_requ_t *smbd_requ = evt->smbd_requ;
		X_LOG_DBG("defer_open_evt=%p, requ=%p, smbd_conn=%p",
				evt, smbd_requ, smbd_conn);

		auto state = smbd_requ->release_state<x_smb2_state_create_t>();
		if (x_smbd_requ_async_remove(smbd_requ) && smbd_conn) {
			NTSTATUS status = x_smbd_open_op_create(smbd_requ, state);
			if (!NT_STATUS_EQUAL(status, NT_STATUS_PENDING)) {
				smbd_requ->save_requ_state(state);
				smbd_requ->async_done_fn(smbd_conn, smbd_requ, status);
			}
		} else {
			if (state->replay_reserved) {
				x_smbd_replay_cache_clear(state->in_client_guid,
						state->in_create_guid);
			}
		}

		delete evt;
	}

	explicit defer_open_evt_t(x_smbd_requ_t *smbd_requ)
		: base(func), smbd_requ(smbd_requ)
	{
	}

	~defer_open_evt_t()
	{
		x_smbd_ref_dec(smbd_requ);
	}

	x_fdevt_user_t base;
	x_smbd_requ_t * const smbd_requ;
};

struct defer_rename_evt_t
{
	static void func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user)
	{
		defer_rename_evt_t *evt = X_CONTAINER_OF(fdevt_user,
				defer_rename_evt_t, base);
		x_smbd_requ_t *smbd_requ = evt->smbd_requ;
		X_LOG_DBG("defer_rename_evt=%p, requ=%p, smbd_conn=%p",
				evt, smbd_requ, smbd_conn);

		auto state = smbd_requ->release_state<x_smb2_state_rename_t>();
		if (x_smbd_requ_async_remove(smbd_requ) && smbd_conn) {
			NTSTATUS status = x_smbd_open_rename(smbd_requ, state);
			if (!NT_STATUS_EQUAL(status, NT_STATUS_PENDING)) {
				smbd_requ->save_requ_state(state);
				smbd_requ->async_done_fn(smbd_conn, smbd_requ, status);
			}
		}

		delete evt;
	}

	explicit defer_rename_evt_t(x_smbd_requ_t *smbd_requ)
		: base(func), smbd_requ(smbd_requ)
	{
	}

	~defer_rename_evt_t()
	{
		x_smbd_ref_dec(smbd_requ);
	}

	x_fdevt_user_t base;
	x_smbd_requ_t * const smbd_requ;
};

static void sharemode_modified(x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream)
{
	x_smbd_sharemode_t *sharemode = get_sharemode(
			smbd_object, smbd_stream);
	/* smbd_object is locked */
	while (x_smbd_requ_t *smbd_requ = sharemode->defer_rename_list.get_front()) {
		sharemode->defer_rename_list.remove(smbd_requ);
		defer_rename_evt_t *evt = new defer_rename_evt_t(smbd_requ);
		X_SMBD_CHAN_POST_USER(smbd_requ->smbd_chan, evt);
	}
	while (x_smbd_requ_t *smbd_requ = sharemode->defer_open_list.get_front()) {
		sharemode->defer_open_list.remove(smbd_requ);
		defer_open_evt_t *evt = new defer_open_evt_t(smbd_requ);
		X_SMBD_CHAN_POST_USER(smbd_requ->smbd_chan, evt);
	}
}

static long oplock_break_timeout(x_timer_job_t *timer)
{
	/* we already have a ref on smbd_chan when adding timer */
	x_smbd_open_t *smbd_open = X_CONTAINER_OF(timer,
			x_smbd_open_t, oplock_break_timer);
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	bool modified = true;
	{
		auto lock = smbd_object_lock(smbd_object);
		if (smbd_open->oplock_break_sent == x_smbd_open_t::OPLOCK_BREAK_TO_NONE_SENT) {
			smbd_open->oplock_break_sent = x_smbd_open_t::OPLOCK_BREAK_NOT_SENT;
			smbd_open->open_state.oplock_level = X_SMB2_OPLOCK_LEVEL_NONE;
		} else if (smbd_open->oplock_break_sent == x_smbd_open_t::OPLOCK_BREAK_TO_LEVEL_II_SENT) {
			smbd_open->oplock_break_sent = x_smbd_open_t::OPLOCK_BREAK_NOT_SENT;
			smbd_open->open_state.oplock_level = X_SMB2_OPLOCK_LEVEL_II;
		} else {
			modified = false;
		}
		if (modified) {
			sharemode_modified(smbd_object, smbd_open->smbd_stream);
		}
	}
	x_smbd_ref_dec(smbd_open);
	return -1;
}

struct send_lease_break_evt_t
{
	static void func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user)
	{
		send_lease_break_evt_t *evt = X_CONTAINER_OF(fdevt_user,
				send_lease_break_evt_t, base);
		X_LOG_DBG("send_lease_break_evt=%p curr_state=%d new_state=%d "
				"new_epoch=%u flags=0x%x",
				evt, evt->curr_state, evt->new_state, evt->new_epoch,
				evt->flags);

		if (smbd_conn) {
			x_smb2_send_lease_break(smbd_conn,
					evt->smbd_sess,
					&evt->lease_key,
					evt->curr_state,
					evt->new_state,
					evt->new_epoch,
					evt->flags);
		}
		delete evt;
	}

	send_lease_break_evt_t(x_smbd_sess_t *smbd_sess,
			const x_smb2_lease_key_t &lease_key,
			uint8_t curr_state,
			uint8_t new_state,
			uint16_t new_epoch,
			uint32_t flags)
		: base(func), smbd_sess(smbd_sess)
		, lease_key(lease_key)
		, curr_state(curr_state)
		, new_state(new_state)
		, new_epoch(new_epoch)
		, flags(flags)
	{
	}

	~send_lease_break_evt_t()
	{
		x_smbd_ref_dec(smbd_sess);
	}

	x_fdevt_user_t base;
	x_smbd_sess_t * const smbd_sess;
	const x_smb2_lease_key_t lease_key;
	const uint8_t curr_state, new_state;
	const uint16_t new_epoch;
	const uint32_t flags;
};

void x_smbd_open_break_lease(x_smbd_open_t *smbd_open,
		const x_smb2_lease_key_t *ignore_lease_key,
		const x_smb2_uuid_t *client_guid,
		uint8_t break_to)
{
	x_smb2_lease_key_t lease_key;
	uint8_t curr_state;
	uint16_t new_epoch;
	uint32_t flags;

	bool send_break = x_smbd_lease_require_break(smbd_open->smbd_lease,
			ignore_lease_key,
			client_guid,
			lease_key, break_to, curr_state,
			new_epoch, flags);
	if (!send_break) {
		return;
	}

	if (smbd_open->smbd_tcon) {
		x_smbd_sess_t *smbd_sess = x_smbd_tcon_get_sess(smbd_open->smbd_tcon);
		X_SMBD_SESS_POST_USER(smbd_sess, new send_lease_break_evt_t(
					smbd_sess, lease_key, curr_state, break_to,
					new_epoch, flags));
		/* if posted fails, the connection is in shutdown,
		 * and it eventually close the open and wakeup the
		 * defer opens
		 */
	}
}

static bool check_ads_share_access(x_smbd_object_t *smbd_object,
		uint32_t granted)
{
	x_smbd_stream_t *smbd_stream;
	for (smbd_stream = smbd_object->ads_list.get_front();
			smbd_stream;
			smbd_stream = smbd_object->ads_list.next(smbd_stream)) {
		x_smbd_open_t *other_open;
		auto &sharemode = smbd_stream->sharemode;
		for (other_open = sharemode.open_list.get_front();
				other_open;
				other_open = sharemode.open_list.next(other_open)) {
			if (!(other_open->open_state.share_access & X_SMB2_FILE_SHARE_DELETE)) {
				X_LOG_NOTICE("ads %s of %s share-access %d violate access 0x%x",
						x_str_todebug(smbd_stream->name).c_str(),
						x_str_todebug(smbd_object->path_base).c_str(),
						other_open->open_state.share_access,
						granted);

				return false;
			}
		}
	}
	return true;
}

static bool share_conflict(const x_smbd_open_t *smbd_open,
		uint32_t access_mask, uint32_t share_access)
{
	if ((smbd_open->open_state.access_mask & (idl::SEC_FILE_WRITE_DATA|
				idl::SEC_FILE_APPEND_DATA|
				idl::SEC_FILE_READ_DATA|
				idl::SEC_FILE_EXECUTE|
				idl::SEC_STD_DELETE)) == 0) {
		return false;
	}

#define CHECK_MASK(num, am, right, sa, share) \
	if (((am) & (right)) && !((sa) & (share))) { \
		X_DBG("share_conflict: check %d conflict am = 0x%x, right = 0x%x, \
				sa = 0x%x, share = 0x%x\n", (num), (unsigned int)(am), (unsigned int)(right), (unsigned int)(sa), \
				(unsigned int)(share) ); \
		return true; \
	}

	CHECK_MASK(1, smbd_open->open_state.access_mask, idl::SEC_FILE_WRITE_DATA | idl::SEC_FILE_APPEND_DATA,
			share_access, X_SMB2_FILE_SHARE_WRITE);
	CHECK_MASK(2, access_mask, idl::SEC_FILE_WRITE_DATA | idl::SEC_FILE_APPEND_DATA,
			smbd_open->open_state.share_access, X_SMB2_FILE_SHARE_WRITE);

	CHECK_MASK(3, smbd_open->open_state.access_mask, idl::SEC_FILE_READ_DATA | idl::SEC_FILE_EXECUTE,
			share_access, X_SMB2_FILE_SHARE_READ);
	CHECK_MASK(4, access_mask, idl::SEC_FILE_READ_DATA | idl::SEC_FILE_EXECUTE,
			smbd_open->open_state.share_access, X_SMB2_FILE_SHARE_READ);

	CHECK_MASK(5, smbd_open->open_state.access_mask, idl::SEC_STD_DELETE,
			share_access, X_SMB2_FILE_SHARE_DELETE);
	CHECK_MASK(6, access_mask, idl::SEC_STD_DELETE,
			smbd_open->open_state.share_access, X_SMB2_FILE_SHARE_DELETE);

	return false;
}

/* caller locked smbd_object */
static bool open_mode_check(x_smbd_object_t *smbd_object,
		x_smbd_sharemode_t *sharemode,
		uint32_t access_mask, uint32_t share_access,
		uint32_t &num_disconnected,
		std::vector<x_smbd_open_t *> &smbd_opens,
		std::vector<x_smbd_lease_t *> &smbd_leases,
		x_tp_ddlist_t<requ_async_traits> &pending_requ_list)
{
	if (is_stat_open(access_mask)) {
		/* Stat open that doesn't trigger oplock breaks or share mode
		 * checks... ! JRA. */
		return false;
	}

	if ((access_mask & (idl::SEC_FILE_WRITE_DATA|
					idl::SEC_FILE_APPEND_DATA|
					idl::SEC_FILE_READ_DATA|
					idl::SEC_FILE_EXECUTE|
					idl::SEC_STD_DELETE)) == 0) {
		X_DBG("share_conflict: No conflict due to "
				"access_mask = 0x%x\n",
				(unsigned int)access_mask );
		return false;
	}

	auto &open_list = sharemode->open_list;
	x_smbd_open_t *curr_open, *next_open;
	for (curr_open = open_list.get_front(); curr_open;
			curr_open = next_open) {
		next_open = open_list.next(curr_open);
		if (share_conflict(curr_open, access_mask, share_access)) {
			if (smbd_open_close_disconnected_if(smbd_object, curr_open,
						smbd_leases, pending_requ_list)) {
				++num_disconnected;
				smbd_opens.push_back(curr_open);
				continue;
			}
			return true;
		}
	}
	return false;
}

static void smbd_create_cancel(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	auto state = smbd_requ->get_requ_state<x_smb2_state_create_t>();
	x_smbd_sharemode_t *sharemode = get_sharemode(state->smbd_object,
			state->smbd_stream);

	{
		auto lock = smbd_object_lock(state->smbd_object);
		sharemode->defer_open_list.remove(smbd_requ);
	}
	x_smbd_conn_post_cancel(smbd_conn, smbd_requ, NT_STATUS_CANCELLED);
}

static void defer_open(x_smbd_sharemode_t *sharemode,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state)
{
	smbd_requ->save_requ_state(state);
	/* TODO does it need a timer? can break timer always wake up it? */
	x_smbd_ref_inc(smbd_requ);
	sharemode->defer_open_list.push_back(smbd_requ);
	X_LOG_DBG("smbd_requ %p interim_state %d", smbd_requ,
			smbd_requ->interim_state);
	x_smbd_requ_async_insert(smbd_requ, smbd_create_cancel, 0);
}

static inline uint8_t get_lease_type(const x_smbd_open_t *smbd_open)
{
	if (smbd_open->open_state.oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE) {
		return x_smbd_lease_get_state(smbd_open->smbd_lease);
	} else if (smbd_open->open_state.oplock_level == X_SMB2_OPLOCK_LEVEL_II) {
		return X_SMB2_LEASE_READ;
	} else if (smbd_open->open_state.oplock_level == X_SMB2_OPLOCK_LEVEL_EXCLUSIVE) {
		return X_SMB2_LEASE_READ | X_SMB2_LEASE_WRITE;
	} else if (smbd_open->open_state.oplock_level == X_SMB2_OPLOCK_LEVEL_BATCH) {
		return X_SMB2_LEASE_READ | X_SMB2_LEASE_WRITE | X_SMB2_LEASE_HANDLE;
	} else {
		return 0;
	}
}

static NTSTATUS grant_oplock(x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream,
		x_smbd_sharemode_t *sharemode,
		x_smb2_state_create_t &state,
		uint8_t &out_oplock_level)
{
	uint8_t granted = X_SMB2_LEASE_NONE;
	uint8_t requested = X_SMB2_LEASE_NONE;
	uint8_t oplock_level = state.in_oplock_level;

	x_smb2_lease_t *lease = nullptr;
	if (oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE) {
		lease = &state.lease;
		requested = x_convert<uint8_t>(lease->state);
	}

	if (smbd_object->type == x_smbd_object_t::type_dir &&
			!smbd_stream) {
		if (lease) {
			granted = lease->state & (X_SMB2_LEASE_READ|X_SMB2_LEASE_HANDLE);
			/* TODO workaround directory leasing upgrade issue,
			 * x_smbd_lease_grant check requested == granted 
			 */
			requested = granted;
			if (!(granted & X_SMB2_LEASE_READ)) {
				granted = X_SMB2_LEASE_NONE;
			}
		} else {
			oplock_level = X_SMB2_OPLOCK_LEVEL_NONE;
			granted = X_SMB2_LEASE_NONE;
		}
	} else {
		if (lease) {
			granted = lease->state & (X_SMB2_LEASE_READ|X_SMB2_LEASE_HANDLE|X_SMB2_LEASE_WRITE);
			if (!(granted & X_SMB2_LEASE_READ)) {
				granted = X_SMB2_LEASE_NONE;
			}
		} else if (oplock_level == X_SMB2_OPLOCK_LEVEL_II) {
			granted = X_SMB2_LEASE_READ;
		} else if (oplock_level == X_SMB2_OPLOCK_LEVEL_EXCLUSIVE) {
			granted = X_SMB2_LEASE_READ|X_SMB2_LEASE_WRITE;
		} else if (oplock_level == X_SMB2_OPLOCK_LEVEL_BATCH) {
			granted = X_SMB2_LEASE_READ|X_SMB2_LEASE_HANDLE|X_SMB2_LEASE_WRITE;
		} else {
			oplock_level = X_SMB2_OPLOCK_LEVEL_NONE;
			granted = X_SMB2_LEASE_NONE;
		}
	}

	bool self_is_stat_open = is_stat_open(state.in_desired_access);
	bool got_handle_lease = false;
	bool got_oplock = false;

	auto &open_list = sharemode->open_list;
	x_smbd_open_t *curr_open;
	for (curr_open = open_list.get_front(); curr_open; curr_open = open_list.next(curr_open)) {
		/* TODO mutex curr_open? */
		uint32_t e_lease_type = get_lease_type(curr_open);
		/* Stat opens should be ignored when granting leases
		 * especially the ones without any leases.
		 */
		if (is_stat_open(curr_open->open_state.access_mask) && e_lease_type == 0) {
			continue;
		}
		if (!(state.smbd_lease && curr_open->smbd_lease == state.smbd_lease)) {
			if (e_lease_type & X_SMB2_LEASE_WRITE) {
				granted = X_SMB2_LEASE_NONE;
				break;
			} else if (!self_is_stat_open || e_lease_type != 0
					|| oplock_level != X_SMB2_OPLOCK_LEVEL_LEASE) {
				/* Windows server allow WRITE_LEASE if new open
				 * is stat open and no current one has no lease.
				 */
				granted &= uint8_t(~X_SMB2_LEASE_WRITE);
			}
		}

		if (e_lease_type & X_SMB2_LEASE_HANDLE) {
			got_handle_lease = true;
		}

		if (curr_open->open_state.oplock_level != X_SMB2_OPLOCK_LEVEL_LEASE
				&& curr_open->open_state.oplock_level != X_SMB2_OPLOCK_LEVEL_NONE) {
			got_oplock = true;
		}
	}

	if ((granted & (X_SMB2_LEASE_READ|X_SMB2_LEASE_WRITE)) == X_SMB2_LEASE_READ) {
#if 0
		bool allow_level2 =
			lp_level2_oplocks(SNUM(fsp->conn));

		if (!allow_level2) {
			granted = SMB2_LEASE_NONE;
		}
#endif
	}

	if (oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE) {
		if (got_oplock) {
			granted &= uint8_t(~X_SMB2_LEASE_HANDLE);
		}
		out_oplock_level = X_SMB2_OPLOCK_LEVEL_LEASE;
		bool new_lease = false;
		if (!x_smbd_lease_grant(state.smbd_lease,
					state.lease,
					granted, requested,
					smbd_object,
					smbd_stream,
					new_lease)) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		if (new_lease) {
			/* it hold the ref of object, so it is ok the incref after lease
			 * TODO eventually it should incref inside x_smbd_lease_grant
			 */
			x_smbd_object_lease_granted(smbd_object, smbd_stream);
		}
	} else {
		if (got_handle_lease) {
			granted = X_SMB2_LEASE_NONE;
		}
		switch (granted) {
		case X_SMB2_LEASE_READ|X_SMB2_LEASE_WRITE|X_SMB2_LEASE_HANDLE:
			out_oplock_level = X_SMB2_OPLOCK_LEVEL_BATCH;
			break;
		case X_SMB2_LEASE_READ|X_SMB2_LEASE_WRITE:
			out_oplock_level = X_SMB2_OPLOCK_LEVEL_EXCLUSIVE;
			break;
		case X_SMB2_LEASE_READ|X_SMB2_LEASE_HANDLE:
		case X_SMB2_LEASE_READ:
			out_oplock_level = X_SMB2_OPLOCK_LEVEL_II;
			break;
		default:
			out_oplock_level = X_SMB2_OPLOCK_LEVEL_NONE;
			break;
		}
	}
	return NT_STATUS_OK;
}

struct send_oplock_break_evt_t
{
	static void func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user)
	{
		send_oplock_break_evt_t *evt = X_CONTAINER_OF(fdevt_user,
				send_oplock_break_evt_t, base);
		X_LOG_DBG("evt=%p", evt);

		if (smbd_conn) {
			x_smb2_send_oplock_break(smbd_conn,
					evt->smbd_sess,
					evt->open_persistent_id,
					evt->open_volatile_id,
					evt->oplock_level);
		}
		delete evt;
	}

	send_oplock_break_evt_t(x_smbd_sess_t *smbd_sess,
			uint64_t open_persistent_id,
			uint64_t open_volatile_id,
			uint8_t oplock_level)
		: base(func), smbd_sess(smbd_sess)
		, open_persistent_id(open_persistent_id)
		, open_volatile_id(open_volatile_id)
		, oplock_level(oplock_level)
	{
	}

	~send_oplock_break_evt_t()
	{
		x_smbd_ref_dec(smbd_sess);
	}

	x_fdevt_user_t base;
	x_smbd_sess_t * const smbd_sess;
	uint64_t const open_persistent_id, open_volatile_id;
	uint8_t const oplock_level;
};

void x_smbd_open_break_oplock(x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		uint8_t break_to)
{
	/* already hold smbd_object mutex */
	X_ASSERT(break_to == X_SMB2_LEASE_READ || break_to == X_SMB2_OPLOCK_LEVEL_NONE);
	if (smbd_open->oplock_break_sent != x_smbd_open_t::OPLOCK_BREAK_NOT_SENT) {
		X_LOG_DBG("smbd_open->oplock_break_sent = %d",
				smbd_open->oplock_break_sent);
		return;
	}

	uint8_t oplock_level = break_to == X_SMB2_LEASE_READ ?
		X_SMB2_OPLOCK_LEVEL_II : X_SMB2_OPLOCK_LEVEL_NONE;
	auto [ persistent_id, volatile_id ] = x_smbd_open_get_id(smbd_open); 
	if (smbd_open->smbd_tcon) {
		x_smbd_sess_t *smbd_sess = x_smbd_tcon_get_sess(smbd_open->smbd_tcon);
		X_SMBD_SESS_POST_USER(smbd_sess, new send_oplock_break_evt_t(
					smbd_sess, persistent_id, volatile_id,
					oplock_level));
		/* if posted fails, the connection is in shutdown,
		 * and it eventually close the open and wakeup the
		 * defer opens
		 */
		if (smbd_open->open_state.oplock_level == X_SMB2_OPLOCK_LEVEL_II && break_to == X_SMB2_OPLOCK_LEVEL_NONE) {
			smbd_open->open_state.oplock_level = oplock_level;
			sharemode_modified(smbd_object, smbd_open->smbd_stream);
			return;
		}
		smbd_open->oplock_break_sent = (break_to == X_SMB2_LEASE_READ ?
				x_smbd_open_t::OPLOCK_BREAK_TO_LEVEL_II_SENT :
				x_smbd_open_t::OPLOCK_BREAK_TO_NONE_SENT);
	}
	x_smbd_ref_inc(smbd_open);
	x_smbd_add_timer(&smbd_open->oplock_break_timer, x_smbd_timer_id_t::BREAK);
}

static bool delay_for_oplock(x_smbd_object_t *smbd_object,
		x_smbd_sharemode_t *sharemode,
		x_smbd_lease_t *smbd_lease,
		x_smb2_create_disposition_t create_disposition,
		uint32_t desired_access,
		bool have_sharing_violation,
		uint32_t open_attempt,
		uint32_t &num_disconnected,
		std::vector<x_smbd_open_t *> &smbd_opens,
		std::vector<x_smbd_lease_t *> &smbd_leases,
		x_tp_ddlist_t<requ_async_traits> &pending_requ_list)
{
	if (is_stat_open(desired_access)) {
		return false;
	}

	bool will_overwrite;

	switch (create_disposition) {
	case x_smb2_create_disposition_t::SUPERSEDE:
	case x_smb2_create_disposition_t::OVERWRITE:
	case x_smb2_create_disposition_t::OVERWRITE_IF:
		will_overwrite = true;
		break;
	default:
		will_overwrite = false;
		break;
	}

	uint32_t break_count = 0;
	bool delay = false;
	auto &open_list = sharemode->open_list;
	x_smbd_open_t *curr_open, *next_open;
	for (curr_open = open_list.get_front(); curr_open; curr_open = next_open) {
		next_open = open_list.next(curr_open);

		/* TODO mutex curr_open ? */
		uint8_t e_lease_type = get_lease_type(curr_open);
		uint8_t break_to;
		uint8_t delay_mask = 0;
		if (curr_open->open_state.oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE) {
			if (smbd_lease && curr_open->smbd_lease == smbd_lease) {
				continue;
			}

			if (is_lease_stat_open(desired_access)) {
				continue;
			}
		}

		if (have_sharing_violation) {
			delay_mask = X_SMB2_LEASE_HANDLE;
		} else {
			delay_mask = X_SMB2_LEASE_WRITE;
		}

		break_to = x_convert<uint8_t>(e_lease_type & ~delay_mask);

		if (will_overwrite) {
			break_to = x_convert<uint8_t>(break_to &
					~(X_SMB2_LEASE_HANDLE|X_SMB2_LEASE_READ));
		}

		if ((e_lease_type & ~break_to) == 0) {
			if (curr_open->smbd_lease && x_smbd_lease_is_breaking(curr_open->smbd_lease)) {
				delay = true;
			}
			continue;
		}

		if (smbd_open_close_disconnected_if(smbd_object, curr_open,
					smbd_leases, pending_requ_list)) {
			++num_disconnected;
			smbd_opens.push_back(curr_open);
			continue;
		}

		if (will_overwrite) {
			/*
			 * If we break anyway break to NONE directly.
			 * Otherwise vfs_set_filelen() will trigger the
			 * break.
			 */
			break_to = x_convert<uint8_t>(break_to & ~(X_SMB2_LEASE_READ|X_SMB2_LEASE_WRITE));
		}

		if (curr_open->open_state.oplock_level != X_SMB2_OPLOCK_LEVEL_LEASE) {
			/*
			 * Oplocks only support breaking to R or NONE.
			 */
			break_to = x_convert<uint8_t>(break_to & ~(X_SMB2_LEASE_HANDLE|X_SMB2_LEASE_WRITE));
		}

		++break_count;
		if (curr_open->smbd_lease) {
			x_smbd_open_break_lease(curr_open, nullptr, nullptr, break_to);
		} else {
			x_smbd_open_break_oplock(smbd_object, curr_open, break_to);
		}
		if (e_lease_type & delay_mask) {
			delay = true;
		}
		if (curr_open->open_state.oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE
				&& x_smbd_lease_is_breaking(curr_open->smbd_lease)
				&& open_attempt != 0) {
			delay = true;
		}
	}
	return delay;
}

static inline NTSTATUS x_smbd_object_access_check(x_smbd_object_t *smbd_object,
		uint32_t &granted_access,
		uint32_t &maximal_access,
		x_smbd_tcon_t *smbd_tcon,
		const x_smbd_user_t &smbd_user,
		uint32_t desired_access,
		bool overwrite)
{
	return smbd_object->smbd_volume->ops->access_check(smbd_object,
			granted_access,
			maximal_access,
			smbd_tcon,
			smbd_user,
			desired_access,
			overwrite);
}

static NTSTATUS smbd_open_create(
		x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state,
		x_smb2_create_action_t &create_action,
		uint8_t &out_oplock_level,
		bool overwrite,
		uint32_t &num_disconnected,
		std::vector<x_smbd_open_t *> &smbd_opens,
		std::vector<x_smbd_lease_t *> &smbd_leases,
		x_tp_ddlist_t<requ_async_traits> &pending_requ_list)
{
	if (smbd_object->type == x_smbd_object_t::type_file && overwrite) {
		// open_match_attributes
#define MIS_MATCH(attr) (((smbd_object->meta.file_attributes & attr) != 0) && ((state->in_file_attributes & attr) == 0))
		if (MIS_MATCH(X_SMB2_FILE_ATTRIBUTE_SYSTEM) ||
				MIS_MATCH(X_SMB2_FILE_ATTRIBUTE_HIDDEN)) {
			RETURN_OP_STATUS(smbd_requ, NT_STATUS_ACCESS_DENIED);
		}
	}

	NTSTATUS status;
	auto smbd_user = x_smbd_sess_get_user(smbd_requ->smbd_sess);
	uint32_t granted_access, maximal_access = 0;
	if (smbd_object->exists()) {
		status = x_smbd_object_access_check(smbd_object,
				granted_access,
				maximal_access,
				smbd_requ->smbd_tcon,
				*smbd_user,
				state->in_desired_access,
				overwrite);

		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		/* TODO seems windows do not check this for folder */
		if (granted_access & idl::SEC_STD_DELETE) {
			if (!check_ads_share_access(smbd_object, granted_access)) {
				return NT_STATUS_SHARING_VIOLATION;
			}
		}
	}

	x_smbd_sharemode_t *sharemode = get_sharemode(
			smbd_object, smbd_stream);

	bool conflict = open_mode_check(smbd_object,
			sharemode,
			granted_access, state->in_share_access,
			num_disconnected,
			smbd_opens, smbd_leases,
			pending_requ_list);
	if (delay_for_oplock(smbd_object,
				sharemode,
				state->smbd_lease,
				state->in_create_disposition,
				overwrite ? granted_access | idl::SEC_FILE_WRITE_DATA : granted_access,
				conflict, state->open_attempt,
				num_disconnected,
				smbd_opens, smbd_leases,
				pending_requ_list)) {
		++state->open_attempt;
		defer_open(sharemode,
				smbd_requ, state);
		return NT_STATUS_PENDING;
	}

	if (conflict) {
		return NT_STATUS_SHARING_VIOLATION;
	}

	if (!smbd_object->exists() || (smbd_stream && !smbd_stream->exists)) {
		if (!smbd_object->exists()) {
			uint32_t access_mask;
			if (state->in_desired_access & idl::SEC_FLAG_MAXIMUM_ALLOWED) {
				access_mask = idl::SEC_RIGHTS_FILE_ALL;
			} else {
				access_mask = state->in_desired_access;
			}

			if (state->in_create_options & X_SMB2_CREATE_OPTION_DELETE_ON_CLOSE) {
				status = x_smbd_can_set_delete_on_close(
						smbd_object, nullptr,
						state->in_file_attributes,
						access_mask);
				if (!NT_STATUS_IS_OK(status)) {
					return status;
				}
			}
		}
		status = x_smbd_create_object(smbd_object,
				smbd_stream,
				*smbd_user, *state,
				state->in_file_attributes,
				state->in_allocation_size);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		create_action = x_smb2_create_action_t::WAS_CREATED;
	} else {
		create_action = overwrite ? x_smb2_create_action_t::WAS_OVERWRITTEN :
			x_smb2_create_action_t::WAS_OPENED;

		state->granted_access = granted_access;
		state->out_maximal_access = maximal_access;
	}

       	status = grant_oplock(smbd_object,
			smbd_stream,
			sharemode,
			*state, out_oplock_level);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return status;
}

static NTSTATUS smbd_open_create_intl(x_smbd_open_t **psmbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state,
		std::vector<x_smbd_open_t *> &smbd_opens,
		std::vector<x_smbd_lease_t *> &smbd_leases,
		x_tp_ddlist_t<requ_async_traits> &pending_requ_list)
{
	x_smbd_object_t *smbd_object = state->smbd_object;
	x_smbd_stream_t *smbd_stream = state->smbd_stream;
	X_ASSERT(smbd_object);

	/* check lease first */
	if (state->smbd_lease && !x_smbd_lease_match(state->smbd_lease,
				smbd_object, smbd_stream)) {
		X_TRACE_REPORT(X_LOG_LEVEL_OP, "failed match lease");
		return NT_STATUS_INVALID_PARAMETER;
	}

	uint32_t num_disconnected = 0;
	auto in_disposition = state->in_create_disposition;
	auto lock = smbd_object_lock(smbd_object);

	if (in_disposition == x_smb2_create_disposition_t::CREATE) {
		if (!smbd_object->exists()) {
			if (state->end_with_sep) {
				return NT_STATUS_OBJECT_NAME_INVALID;
			}
		} else {
			if (!smbd_stream || smbd_stream->exists) {
				return NT_STATUS_OBJECT_NAME_COLLISION;
			}
		}

	} else if (in_disposition == x_smb2_create_disposition_t::OPEN) {
		if (state->in_timestamp != 0) {
			X_TODO; /* TODO snapshot */
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}
		if (!smbd_object->exists()) {
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;

		} else if (x_smbd_object_is_dir(smbd_object)) {
			if (state->is_dollar_data) {
				return NT_STATUS_FILE_IS_A_DIRECTORY;
			}
		} else {
			if (state->end_with_sep) {
				return NT_STATUS_OBJECT_NAME_INVALID;
			}
		}

		if (smbd_stream && !smbd_stream->exists) {
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}

	} else if (in_disposition == x_smb2_create_disposition_t::OPEN_IF) {
		if (state->in_timestamp != 0) {
			/* TODO snapshot */
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		} else if (!smbd_object->exists()) {
			if (state->end_with_sep) {
				return NT_STATUS_OBJECT_NAME_INVALID;
			}

		} else if (x_smbd_object_is_dir(smbd_object)) {
			if (state->is_dollar_data) {
				return NT_STATUS_FILE_IS_A_DIRECTORY;
			}
		}

	} else if (in_disposition == x_smb2_create_disposition_t::OVERWRITE) {
		if (!smbd_object->exists()) {
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;

		} else if (x_smbd_object_is_dir(smbd_object)) {
			if (!smbd_stream) {
				if (state->is_dollar_data) {
					return NT_STATUS_FILE_IS_A_DIRECTORY;
				} else {
					return NT_STATUS_INVALID_PARAMETER;
				}
			}
		}
	
	} else if (in_disposition == x_smb2_create_disposition_t::OVERWRITE_IF ||
			in_disposition == x_smb2_create_disposition_t::SUPERSEDE) {
		/* TODO
		 * Currently we're using FILE_SUPERSEDE as the same as
		 * FILE_OVERWRITE_IF but they really are
		 * different. FILE_SUPERSEDE deletes an existing file
		 * (requiring delete access) then recreates it.
		 */
		if (state->in_timestamp != 0) {
			/* TODO */
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		} else if (!smbd_object->exists()) {
			if (state->end_with_sep) {
				return NT_STATUS_OBJECT_NAME_INVALID;
			}

		} else if (x_smbd_object_is_dir(smbd_object)) {
			if (state->in_ads_name.size() == 0) {
				if (state->is_dollar_data) {
					return NT_STATUS_FILE_IS_A_DIRECTORY;
				} else {
					return NT_STATUS_INVALID_PARAMETER;
				}
			}
		}

	} else {
		return NT_STATUS_INVALID_PARAMETER;
	}

	NTSTATUS status;
	bool overwrite = false;
	x_smb2_create_action_t create_action = x_smb2_create_action_t::WAS_OPENED;
	uint8_t oplock_level = X_SMB2_OPLOCK_LEVEL_NONE;
	if (state->smbd_share->get_type() == X_SMB2_SHARE_TYPE_DISK) {
		if (smbd_object->exists()) {
			if (smbd_object->sharemode.meta.delete_on_close) {
				return NT_STATUS_DELETE_PENDING;
			}

			if (smbd_object->type == x_smbd_object_t::type_dir) {
				if (state->in_create_options & X_SMB2_CREATE_OPTION_NON_DIRECTORY_FILE) {
					return NT_STATUS_FILE_IS_A_DIRECTORY;
				}
			} else {
				if (state->in_create_options & X_SMB2_CREATE_OPTION_DIRECTORY_FILE) {
					return NT_STATUS_NOT_A_DIRECTORY;
				}
			}


			if ((smbd_object->meta.file_attributes & X_SMB2_FILE_ATTRIBUTE_READONLY) &&
					(state->in_desired_access & (idl::SEC_FILE_WRITE_DATA | idl::SEC_FILE_APPEND_DATA))) {
				X_LOG_NOTICE("deny access 0x%x to '%s' due to readonly 0x%x",
						state->in_desired_access,
						x_str_todebug(x_smbd_object_get_path(smbd_object)).c_str(),
						smbd_object->meta.file_attributes);
				return NT_STATUS_ACCESS_DENIED;
			}

			if (smbd_object->meta.file_attributes & X_SMB2_FILE_ATTRIBUTE_REPARSE_POINT) {
				X_LOG_DBG("object '%s' is reparse_point",
						x_str_todebug(x_smbd_object_get_path(smbd_object)).c_str());
				return NT_STATUS_PATH_NOT_COVERED;
			}
		}

		overwrite = in_disposition == x_smb2_create_disposition_t::OVERWRITE
			|| in_disposition == x_smb2_create_disposition_t::OVERWRITE_IF
			|| in_disposition == x_smb2_create_disposition_t::SUPERSEDE;
		status = smbd_open_create(
				smbd_object,
				smbd_stream,
				smbd_requ,
				state,
				create_action,
				oplock_level,
				overwrite,
				num_disconnected,
				smbd_opens,
				smbd_leases,
				pending_requ_list);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		if (state->in_contexts & X_SMB2_CONTEXT_FLAG_MXAC) {
			state->out_contexts |= X_SMB2_CONTEXT_FLAG_MXAC;
		}
	}

	if (create_action == x_smb2_create_action_t::WAS_CREATED) {
		overwrite = false;
	}

	if (state->in_create_options & X_SMB2_CREATE_OPTION_DELETE_ON_CLOSE) {
		status = x_smbd_can_set_delete_on_close(smbd_object,
				smbd_stream,
				smbd_object->meta.file_attributes,
				state->granted_access);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	/* TODO should we check the open limit before create the open */
	status = smbd_object->smbd_volume->ops->create_open(psmbd_open,
			smbd_requ, *state->smbd_share, state,
			overwrite,
			create_action,
			oplock_level);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* TODO we support MXAC and QFID for now,
	 * without QFID Windows 10 client query
	 * couple getinfo x_smb2_info_level_t::FILE_NETWORK_OPEN_INFORMATION
	 */
	if (state->in_contexts & X_SMB2_CONTEXT_FLAG_QFID) {
		x_put_le64(state->out_qfid_info, smbd_object->meta.inode);
		x_put_le64(state->out_qfid_info + 8, smbd_object->meta.fsid);
		memset(state->out_qfid_info + 16, 0, 16);
		state->out_contexts |= X_SMB2_CONTEXT_FLAG_QFID;
	}

	(*psmbd_open)->open_state.initial_delete_on_close =
		(state->in_create_options & X_SMB2_CREATE_OPTION_DELETE_ON_CLOSE) != 0;

	if (num_disconnected) {
		sharemode_modified(smbd_object, smbd_stream);
	}
	return NT_STATUS_OK;
}

static NTSTATUS smbd_open_op_create(x_smbd_open_t **psmbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state)
{
	std::vector<x_smbd_open_t *> smbd_opens;
	std::vector<x_smbd_lease_t *> smbd_leases;
	x_tp_ddlist_t<requ_async_traits> pending_requ_list;
	NTSTATUS status = smbd_open_create_intl(psmbd_open, smbd_requ,
			state, smbd_opens,
			smbd_leases, pending_requ_list);
	x_smbd_requ_t *requ_notify;
	while ((requ_notify = pending_requ_list.get_front()) != nullptr) {
		pending_requ_list.remove(requ_notify);
		x_smbd_conn_post_cancel(x_smbd_chan_get_conn(requ_notify->smbd_chan),
				requ_notify, NT_STATUS_NOTIFY_CLEANUP);
	}

	for (auto smbd_lease: smbd_leases) {
		x_smbd_lease_close(smbd_lease);
	}

	for (auto smbd_open: smbd_opens) {
		x_smbd_ref_dec(smbd_open);
	}

	return status;
}

void x_smbd_break_lease(x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream)
{
	auto lock = smbd_object_lock(smbd_object);
	sharemode_modified(smbd_object, smbd_stream);
}

NTSTATUS x_smbd_break_oplock(
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		x_smb2_state_oplock_break_t &state)
{
	uint8_t out_oplock_level;
	bool modified = false;
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	auto lock = smbd_object_lock(smbd_object);

	if (smbd_open->oplock_break_sent == x_smbd_open_t::OPLOCK_BREAK_NOT_SENT) {
		return NT_STATUS_INVALID_OPLOCK_PROTOCOL;
	} else if (x_smbd_del_timer(&smbd_open->oplock_break_timer)) {
		x_smbd_ref_dec(smbd_open);
	}

	if (smbd_open->oplock_break_sent == x_smbd_open_t::OPLOCK_BREAK_TO_NONE_SENT
			|| state.in_oplock_level == X_SMB2_OPLOCK_LEVEL_NONE) {
		out_oplock_level = X_SMB2_OPLOCK_LEVEL_NONE;
	} else {
		out_oplock_level = X_SMB2_OPLOCK_LEVEL_II;
	}
	smbd_open->oplock_break_sent = x_smbd_open_t::OPLOCK_BREAK_NOT_SENT;
	if (smbd_open->open_state.oplock_level != out_oplock_level) {
		modified = true;
		smbd_open->open_state.oplock_level = out_oplock_level;
	}

	state.out_oplock_level = out_oplock_level;
	if (modified) {
		// TODO downgrade_file_oplock
		sharemode_modified(smbd_object, smbd_open->smbd_stream);
	}

	return NT_STATUS_OK;
}

static bool lease_type_is_exclusive(const x_smbd_lease_t *smbd_lease,
		uint8_t oplock_level)
{
	if (smbd_lease) {
		uint8_t state = x_smbd_lease_get_state(smbd_lease);
		return (state & (X_SMB2_LEASE_READ | X_SMB2_LEASE_WRITE)) == 
			(X_SMB2_LEASE_READ | X_SMB2_LEASE_WRITE);
	} else {
		return oplock_level == X_SMB2_OPLOCK_LEVEL_EXCLUSIVE ||
			oplock_level == X_SMB2_OPLOCK_LEVEL_BATCH;
	}
}

void x_smbd_break_others_to_none(x_smbd_object_t *smbd_object,
		x_smbd_sharemode_t *sharemode,
		const x_smbd_lease_t *smbd_lease,
		uint8_t oplock_level)
{
	if (lease_type_is_exclusive(smbd_lease, oplock_level)) {
		return;
	}

	/* break other to none */
	auto &open_list = sharemode->open_list;
	for (x_smbd_open_t *other_open = open_list.get_front(); other_open;
			other_open = open_list.next(other_open)) {
		if (smbd_lease && other_open->smbd_lease == smbd_lease) {
			continue;
		}
		if (other_open->smbd_lease) {
			x_smbd_open_break_lease(other_open, nullptr, nullptr, X_SMB2_LEASE_NONE);
		} else {
			/* This can break the open's self oplock II, but 
			 * Windows behave same
			 */
			auto other_oplock_level = other_open->open_state.oplock_level;
			X_ASSERT(other_oplock_level != X_SMB2_OPLOCK_LEVEL_BATCH);
			X_ASSERT(other_oplock_level != X_SMB2_OPLOCK_LEVEL_EXCLUSIVE);
			if (other_oplock_level == X_SMB2_OPLOCK_LEVEL_II) {
				x_smbd_open_break_oplock(smbd_object,
						other_open, X_SMB2_LEASE_NONE);
			}
		}
	}
}

static bool oplock_valid_for_durable(const x_smbd_open_t *smbd_open)
{
	if (smbd_open->open_state.oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE) {
		return x_smbd_lease_get_state(smbd_open->smbd_lease) & X_SMB2_LEASE_HANDLE;
	} else {
		return smbd_open->open_state.oplock_level == X_SMB2_OPLOCK_LEVEL_BATCH;
	}
}

void x_smbd_save_durable(x_smbd_open_t *smbd_open,
		x_smbd_tcon_t *smbd_tcon,
		const x_smb2_state_create_t &state)
{
	/* we do not support durable handle for ADS */
	if (smbd_open->smbd_stream ||
			smbd_open->smbd_object->type != x_smbd_object_t::type_file ||
			!oplock_valid_for_durable(smbd_open)) {
		return;
	}

	x_smbd_dhmode_t mode = x_smbd_dhmode_t::NONE;
	uint32_t durable_timeout_msec = 0;
	if (state.in_contexts & X_SMB2_CONTEXT_FLAG_DH2Q) {
		if ((state.in_dh_flags & X_SMB2_DHANDLE_FLAG_PERSISTENT) &&
				x_smbd_tcon_get_continuously_available(smbd_tcon)) {
			mode = x_smbd_dhmode_t::PERSISTENT;
			durable_timeout_msec = state.in_dh_timeout;
		} else if (x_smbd_tcon_get_durable_handle(smbd_tcon)) {
			mode = x_smbd_dhmode_t::DURABLE;
			durable_timeout_msec = state.in_dh_timeout;
		}

	} else if (state.in_contexts & X_SMB2_CONTEXT_FLAG_DHNQ) {
		if (x_smbd_tcon_get_durable_handle(smbd_tcon)) {
			mode = x_smbd_dhmode_t::DURABLE;
		}
	}

	if (mode == x_smbd_dhmode_t::NONE) {
		return;
	}

	auto &smbd_volume = *smbd_open->smbd_object->smbd_volume;
	if (smbd_open->open_state.id_persistent == X_SMBD_OPEN_ID_NON_DURABLE) {
		int ret = x_smbd_volume_allocate_persistent(
				smbd_volume,
				&smbd_open->open_state.id_persistent);
		if (ret < 0) {
			X_LOG_WARN("x_smbd_volume_allocate_persisten for %p, 0x%lx failed, ret = %d",
					smbd_open,
					smbd_open->id_volatile, ret);
		}
	}

	smbd_open->open_state.dhmode = mode;

	if (durable_timeout_msec == 0) {
		durable_timeout_msec = X_SMBD_DURABLE_TIMEOUT_MAX * 1000u;
	} else {
		durable_timeout_msec = std::min(
				durable_timeout_msec,
				X_SMBD_DURABLE_TIMEOUT_MAX * 1000u);
	}
	smbd_open->open_state.durable_timeout_msec = durable_timeout_msec;
	X_LOG_DBG("smbd_save_durable for %p 0x%lx 0x%lx",
			smbd_open, smbd_open->open_state.id_persistent,
			smbd_open->id_volatile);

	/* TODO lease */

	x_smbd_volume_save_durable(smbd_volume,
			smbd_open->id_volatile,
			smbd_open->open_state,
			smbd_open->smbd_object->file_handle);
}

NTSTATUS x_smbd_open_op_create(x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state)
{
	X_TRACE_LOC;
	if (!x_smbd_open_has_space()) {
		X_LOG_WARN("too many opens, cannot allocate new");
		return NT_STATUS_INSUFFICIENT_RESOURCES;
	}

	NTSTATUS status;
	x_smbd_tcon_t *smbd_tcon = smbd_requ->smbd_tcon;

	if (!state->smbd_object) {
		std::shared_ptr<x_smbd_volume_t> smbd_volume;
		std::u16string path;
		long path_priv_data{};
		long open_priv_data{};

		status = x_smbd_tcon_resolve_path(smbd_requ->smbd_tcon,
				state->in_path,
				smbd_requ->in_smb2_hdr.flags & X_SMB2_HDR_FLAG_DFS,
				state->smbd_share, smbd_volume, path,
				path_priv_data, open_priv_data);
		if (!NT_STATUS_IS_OK(status)) {
			X_LOG_WARN("resolve_path failed");
			return status;
		}

		X_LOG_DBG("resolve_path(%s) to %s, %ld, %ld",
				x_str_todebug(state->in_path).c_str(),
				x_str_todebug(path).c_str(),
				path_priv_data, open_priv_data);

		x_smbd_object_t *smbd_object = nullptr;
		x_smbd_stream_t *smbd_stream = nullptr;
		status = x_smbd_open_object(&smbd_object,
				smbd_volume, path,
				path_priv_data, true);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		if (!state->in_ads_name.empty()) {
			status = smbd_volume->ops->open_stream(smbd_object,
				&smbd_stream,
				state->in_ads_name);
			if (!NT_STATUS_IS_OK(status)) {
				x_smbd_release_object(smbd_object);
				return status;
			}
		}

		state->smbd_object = smbd_object;
		state->smbd_stream = smbd_stream;

		state->open_priv_data = open_priv_data;
	}

	x_smbd_open_t *smbd_open = nullptr;
	/* TODO should we check the open limit before create the open */
	status = smbd_open_op_create(
			&smbd_open, smbd_requ,
			state);

	if (!NT_STATUS_IS_OK(status)) {
		X_ASSERT(!smbd_open);
		return status;
	}

	X_ASSERT(smbd_open);

	x_smbd_lease_t *smbd_lease;
	x_tp_ddlist_t<requ_async_traits> pending_requ_list;

	/* if client access the open from other channel now, it does not have
	 * link into smbd_tcon, probably we should call x_smbd_open_store in the last
	 */
	bool linked = false;
	{
		auto lock = smbd_object_lock(state->smbd_object);
		if (smbd_open->state == SMBD_OPEN_S_INIT &&
				x_smbd_tcon_link_open(smbd_tcon, &smbd_open->tcon_link)) {
			smbd_open->state = SMBD_OPEN_S_ACTIVE;
			smbd_open->smbd_tcon = smbd_tcon;
			linked = true;
		} else {
			std::unique_ptr<x_smb2_state_close_t> close_state;
			smbd_open_close(smbd_open, state->smbd_object, nullptr, close_state,
					smbd_lease, pending_requ_list);
		}
	}

	if (linked) {
		x_smbd_ref_inc(smbd_tcon); // ref by open
		x_smbd_ref_inc(smbd_open); // ref tcon link
		smbd_requ->smbd_open = x_smbd_ref_inc(smbd_open);
	} else {
		if (smbd_lease) {
			x_smbd_lease_close(smbd_lease);
		}
		status = NT_STATUS_NETWORK_NAME_DELETED;
	}

	return status;
}

static NTSTATUS smbd_open_reconnect(x_smbd_open_t *smbd_open,
		x_smbd_tcon_t *smbd_tcon,
		x_smb2_state_create_t &state)
{
	auto smbd_object = smbd_open->smbd_object;
	auto &open_state = smbd_open->open_state;
	auto smbd_user = x_smbd_tcon_get_user(smbd_tcon);

	auto lock = smbd_object_lock(smbd_object);
	if (smbd_open->state != SMBD_OPEN_S_DISCONNECTED) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}
	X_ASSERT(!smbd_open->smbd_tcon);

	if ((state.in_contexts & X_SMB2_CONTEXT_FLAG_DH2C) &&
			!(open_state.create_guid == state.in_create_guid)) {
		X_LOG_NOTICE("create_guid not match");
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}
	if (smbd_open->smbd_lease) {
		if (!x_smbd_lease_match_get(smbd_open->smbd_lease,
					x_smbd_conn_curr_client_guid(),
					state.lease)) {
			X_LOG_NOTICE("lease not match");
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}
		if (state.in_ads_name.size()) {
			X_LOG_NOTICE("we do not support reconnect ADS");
			return NT_STATUS_INVALID_PARAMETER;
		}
		/* TODO dfs path and case */
		if (state.in_path != x_smbd_object_get_path(smbd_open->smbd_object)) {
			X_LOG_NOTICE("path not match");
			return NT_STATUS_INVALID_PARAMETER;
		}
	}
	if (!smbd_user->match(open_state.owner)) {
		X_LOG_NOTICE("user sid not match");
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}
	if (!x_smbd_del_timer(&smbd_open->durable_timer)) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	/* if client access the open from other channel now, it does not have
	 * link into smbd_tcon, probably we should call x_smbd_open_store in the last
	 */
	if (!x_smbd_tcon_link_open(smbd_tcon, &smbd_open->tcon_link)) {
		return NT_STATUS_NETWORK_NAME_DELETED;
	}

	smbd_open->smbd_tcon = smbd_tcon;
	smbd_open->state = SMBD_OPEN_S_ACTIVE;
	open_state.create_action = x_smb2_create_action_t::WAS_OPENED;

	return NT_STATUS_OK;
}

NTSTATUS x_smbd_open_op_reconnect(x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state)
{
	uint64_t id_persistent = state->in_dh_id_persistent;
	std::shared_ptr<x_smbd_volume_t> smbd_volume;
	x_smbd_durable_t *durable = x_smbd_share_lookup_durable(
			smbd_volume, x_smbd_tcon_get_share(smbd_requ->smbd_tcon),
			id_persistent);
	if (!durable) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_OBJECT_NAME_NOT_FOUND);
	}

	auto smbd_tcon = smbd_requ->smbd_tcon;
	uint64_t id_volatile = durable->id_volatile;

	auto [found, smbd_open] = g_smbd_open_table->lookup(id_volatile);
	if (!found) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_OBJECT_NAME_NOT_FOUND);
	}

	NTSTATUS status = smbd_open_reconnect(smbd_open, smbd_tcon, *state);
	if (!NT_STATUS_IS_OK(status)) {
		x_smbd_ref_dec(smbd_open);
		return status;
	}

	x_smbd_ref_inc(smbd_tcon); // ref by smbd_open
	smbd_requ->smbd_open = smbd_open; // TODO ref count

	return status;
}

NTSTATUS x_smbd_open_restore(
		std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		x_smbd_durable_t &smbd_durable,
		uint64_t timeout_msec)
{
	if (!x_smbd_open_has_space()) {
		X_LOG_WARN("too many opens, cannot allocate new");
		return NT_STATUS_INSUFFICIENT_RESOURCES;
	}

	auto &open_state = smbd_durable.open_state;
	x_smbd_open_t *smbd_open{};
	NTSTATUS status;
	if (open_state.create_guid.is_valid()) {
		NTSTATUS status = x_smbd_replay_cache_lookup(&smbd_open,
				open_state.client_guid,
				open_state.create_guid,
				false);
		if (!NT_STATUS_EQUAL(status, NT_STATUS_FWP_RESERVED)) {
			X_LOG_WARN("open is already in replay_cache");
			return NT_STATUS_FILE_NOT_AVAILABLE;
		}

		X_ASSERT(!smbd_open);
	}

	status = x_smbd_open_durable(smbd_open, smbd_volume,
			smbd_durable);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (open_state.replay_cached && open_state.create_guid.is_valid()) {
		/* TODO atomic */
		x_smbd_replay_cache_set(open_state.client_guid,
				open_state.create_guid,
				smbd_open);
	}

	x_smbd_ref_inc(smbd_open); // durable timer
	{
		auto lock = smbd_object_lock(smbd_open->smbd_object);
		X_ASSERT(smbd_open->state == SMBD_OPEN_S_INIT);
		X_ASSERT(!smbd_open->smbd_tcon);
		smbd_open->state = SMBD_OPEN_S_DISCONNECTED;
		x_smbd_add_timer(&smbd_open->durable_timer,
				timeout_msec * 1000000ul);
	}

	smbd_durable.id_volatile = smbd_open->id_volatile;
	return NT_STATUS_OK;
}

static std::string x_smbd_open_get_path(const x_smbd_open_t *smbd_open)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	std::u16string object_path = x_smbd_object_get_path(smbd_object);
	if (!smbd_open->smbd_stream) {
		return x_str_todebug(object_path);
	} else {
		return x_str_todebug(object_path + u":" + smbd_open->smbd_stream->name);
	}
}

x_smbd_open_t::x_smbd_open_t(x_smbd_object_t *so,
		x_smbd_stream_t *strm,
		x_smbd_tcon_t *st,
		const x_smbd_open_state_t &open_state)
	: tick_create(tick_now), smbd_object(so), smbd_stream(strm)
	, durable_timer(smbd_open_durable_timeout)
	, state(SMBD_OPEN_S_INIT)
	, oplock_break_timer(oplock_break_timeout)
	, open_state(open_state)
{
	X_SMBD_COUNTER_INC_CREATE(open, 1);
	memset(lock_sequence_array, 0xff, LOCK_SEQUENCE_MAX);
}

x_smbd_open_t::~x_smbd_open_t()
{
	x_smbd_ref_dec_if(smbd_tcon);
	x_smbd_release_object_and_stream(smbd_object, smbd_stream);
	X_SMBD_COUNTER_INC_DELETE(open, 1);
}

struct x_smbd_open_list_t : x_smbd_ctrl_handler_t
{
	x_smbd_open_list_t() : iter(g_smbd_open_table->iter_start()) {
	}
	bool output(std::string &data) override;
	smbd_open_table_t::iter_t iter;
};

bool x_smbd_open_list_t::output(std::string &data)
{
	std::ostringstream os;

	bool ret = g_smbd_open_table->iter_entry(iter, [&os](const x_smbd_open_t *smbd_open) {
			os << idl::x_hex_t<uint64_t>(smbd_open->open_state.id_persistent) << ','
			<< idl::x_hex_t<uint64_t>(smbd_open->id_volatile) << ' '
			<< idl::x_hex_t<uint32_t>(smbd_open->open_state.access_mask) << ' '
			<< idl::x_hex_t<uint32_t>(smbd_open->open_state.share_access) << ' '
			<< x_smbd_dhmode_to_name(smbd_open->open_state.dhmode)
			<< (smbd_open->open_state.replay_cached ? 'R' : '-') << ' '
			<< idl::x_hex_t<uint32_t>(smbd_open->notify_filter) << ' '
			<< idl::x_hex_t<uint32_t>(x_smbd_tcon_get_id(smbd_open->smbd_tcon)) << " '"
			<< x_smbd_open_get_path(smbd_open) << "'" << std::endl;
			return true;
			});
	if (ret) {
		data = os.str(); // TODO avoid copying
		return true;
	} else {
		return false;
	}
}

x_smbd_ctrl_handler_t *x_smbd_open_list_create()
{
	return new x_smbd_open_list_t;
}

static std::u16string get_path(const x_smbd_open_t *smbd_open)
{
	auto smbd_object = smbd_open->smbd_object;
	std::u16string ret =  u"C:\\"
		+ smbd_object->smbd_volume->name_l16
		+ u"\\" + x_smbd_object_get_path(smbd_object);
	if (smbd_open->smbd_stream) {
		ret += u":" + smbd_open->smbd_stream->name;
	}
	return ret;
}

static inline void smbd_open_to_open_info(std::vector<idl::srvsvc_NetFileInfo2> &array,
		const x_smbd_open_t *smbd_open, const x_tick_t now)
{
	array.push_back(idl::srvsvc_NetFileInfo2{
			x_convert_assert<uint32_t>(smbd_open->id_volatile),
			});
}

static inline void smbd_open_to_open_info(std::vector<idl::srvsvc_NetFileInfo3> &array,
		const x_smbd_open_t *smbd_open, const x_tick_t now)
{
	std::shared_ptr<x_smbd_user_t> smbd_user;
	const auto smbd_object = smbd_open->smbd_object;
	size_t lock_count;
	auto &open_state = smbd_open->open_state;
	{
		auto lock = smbd_object_lock(smbd_object);
		if (smbd_open->smbd_tcon) {
			smbd_user = x_smbd_tcon_get_user(smbd_open->smbd_tcon);
		}
		lock_count = smbd_open->locks.size();
	}

	std::shared_ptr<std::u16string> user_name;
	if (smbd_user) {
		user_name = smbd_user->account_name;
	} else {
		user_name = std::make_shared<std::u16string>(
				x_str_convert_assert<std::u16string>(
					x_tostr(open_state.owner)));
	}

	array.push_back(idl::srvsvc_NetFileInfo3{
			x_convert_assert<uint32_t>(smbd_open->id_volatile),
			open_state.access_mask & (idl::SEC_FILE_READ_DATA | idl::SEC_FILE_WRITE_DATA),
			x_convert<uint32_t>(lock_count),
			std::make_shared<std::u16string>(get_path(smbd_open)),
			std::move(user_name)
			});
}

template <typename T>
static WERROR smbd_open_enum(std::vector<T> &array)
{
	smbd_open_table_t::iter_t iter = g_smbd_open_table->iter_start();
	auto now = tick_now;
	g_smbd_open_table->iterate(iter, [now, &array](x_smbd_open_t *smbd_open) {
			smbd_open_to_open_info(array, smbd_open, now);
			return true;
		});
	return WERR_OK;
}

WERROR x_smbd_net_enum(idl::srvsvc_NetFileEnum &arg,
		std::vector<idl::srvsvc_NetFileInfo2> &array)
{
	return smbd_open_enum(array);
}

WERROR x_smbd_net_enum(idl::srvsvc_NetFileEnum &arg,
		std::vector<idl::srvsvc_NetFileInfo3> &array)
{
	return smbd_open_enum(array);
}

static void smbd_net_file_close(x_smbd_open_t *smbd_open)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	x_smbd_tcon_t *smbd_tcon = nullptr;

	x_smbd_lease_t *smbd_lease = nullptr;
	x_tp_ddlist_t<requ_async_traits> pending_requ_list;
	std::unique_ptr<x_smb2_state_close_t> state;

	{
		auto lock = smbd_object_lock(smbd_object);
		if (smbd_open->state == SMBD_OPEN_S_ACTIVE) {
			/* it could happen when client tdis on other channel */
			if (!x_smbd_tcon_unlink_open(smbd_open->smbd_tcon, &smbd_open->tcon_link)) {
				X_LOG_NOTICE("failed to unlink open %p", smbd_open);
				return;
			}
			smbd_tcon = smbd_open->smbd_tcon;
			smbd_open->smbd_tcon = nullptr;
		} else if (smbd_open->state != SMBD_OPEN_S_DISCONNECTED) {
			return;
		}
		smbd_open_close(smbd_open, smbd_object, nullptr, state,
				smbd_lease, pending_requ_list);
	}

	smbd_open_post_close(smbd_open, smbd_object, smbd_lease,
			pending_requ_list);
	if (smbd_tcon) {
		x_smbd_ref_dec(smbd_tcon);
		x_smbd_ref_dec(smbd_open); // ref by smbd_tcon open_list
	}
}

void x_smbd_net_file_close(uint32_t fid)
{
	auto [found, smbd_open] = g_smbd_open_table->lookup(fid);
	if (!found) {
		X_LOG_NOTICE("cannot find open by fid 0x%x", fid);
		return;
	}
	smbd_net_file_close(smbd_open);
	x_smbd_ref_dec(smbd_open);
}


/* open with conflict
 *  client 1 open with file DELETE_ON_CLOSE and durable and close connection
 * client 2 have permission to create the file
 *  1, disposition=CREATE, 0xc0000035
 *  2, disposition=OPEN,   0xc0000043, and the file get deleted
 *  3, disposition=OPEN_IF, 0xc0000043, and the file get deleted

 * client 2 does not have permission to create the file
 *  1, disposition=CREATE, 0xc0000035
 *  2, disposition=OPEN,   0xc0000034, and the file get deleted
 *  3, disposition=OPEN_IF, 0xc0000043, and the file get deleted
 *
 * open without conflict
 *  1, disposition=CREATE, 0xc0000035
 *  1, disposition=OPEN, OK, the durable handle is kept
 *  1, disposition=OPEN_IF, OK, the durable handle is kept
 */
