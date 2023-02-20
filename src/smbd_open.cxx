
#include "smbd.hxx"
#include "smbd_ctrl.hxx"
#include "smbd_stats.hxx"
#include "smbd_open.hxx"
#include "include/idtable.hxx"
#include "smbd_access.hxx"

struct smbd_open_deleter
{
	void operator()(x_smbd_open_t *smbd_open) const {
		x_smbd_open_op_destroy(smbd_open);
	}
};

using smbd_open_table_t = x_idtable_t<x_smbd_open_t, x_idtable_64_traits_t, smbd_open_deleter>;
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

int x_smbd_open_table_init(uint32_t count)
{
	g_smbd_open_table = new smbd_open_table_t(count + g_smbd_open_extra);
	return 0;
}

bool x_smbd_open_store(x_smbd_open_t *smbd_open)
{
	return g_smbd_open_table->store(smbd_open, smbd_open->id_volatile);
}

x_smbd_open_t *x_smbd_open_lookup(uint64_t id_presistent, uint64_t id_volatile,
		const x_smbd_tcon_t *smbd_tcon)
{
	auto [found, smbd_open] = g_smbd_open_table->lookup(id_volatile);
	if (found) {
		if (smbd_open->smbd_tcon == smbd_tcon || !smbd_tcon) {
			return smbd_open;
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

static inline bool smbd_open_set_state(x_smbd_open_t *smbd_open,
		uint32_t curr_state, uint32_t new_state)
{
	uint32_t old_state = curr_state;
	if (!std::atomic_compare_exchange_strong_explicit(&smbd_open->state,
				&old_state, new_state,
				std::memory_order_release,
				std::memory_order_relaxed)) {
		X_LOG_NOTICE("smbd_open_set_state %p, %d->%d unexpected %d", 
				smbd_open, curr_state, new_state, old_state);
		return false;
	}
	X_LOG_DBG("smbd_open_set_state %p %d->%d", smbd_open, curr_state,
			new_state);
	return true;
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

static bool have_active_open(x_smbd_object_t *smbd_object)
{
	if (!smbd_object->sharemode.open_list.empty()) {
		return true;
	}
	
	for (x_smbd_stream_t *smbd_stream = smbd_object->ads_list.get_front();
			smbd_stream;
			smbd_stream = smbd_object->ads_list.next(smbd_stream)) {
		if (!smbd_stream->sharemode.open_list.empty()) {
			return true;
		}
	}
	return false;
}

static NTSTATUS smbd_object_remove(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		std::vector<x_smb2_change_t> &changes)
{
	if (!smbd_open->object_link.is_valid()) {
		X_ASSERT(false);
		return NT_STATUS_OK;
	}

	x_smbd_stream_t *smbd_stream = smbd_open->smbd_stream;
	auto sharemode = get_sharemode(smbd_object, smbd_stream);
	sharemode->open_list.remove(smbd_open);

	if (smbd_open->locks.size()) {
		x_smbd_lock_retry(sharemode);
	}

	if (!sharemode->open_list.empty()) {
		return NT_STATUS_OK;
	}

	// auto orig_changes_size = changes.size();
	if (smbd_object->stream_meta.delete_on_close &&
			!have_active_open(smbd_object)) {
		uint32_t notify_filter = x_smbd_object_is_dir(smbd_object) ?
			FILE_NOTIFY_CHANGE_DIR_NAME : FILE_NOTIFY_CHANGE_FILE_NAME;

		NTSTATUS status = x_smbd_object_delete(smbd_object, nullptr,
				smbd_open, changes);
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
		changes.push_back(x_smb2_change_t{NOTIFY_ACTION_REMOVED, notify_filter,
				smbd_open->open_state.parent_lease_key,
				smbd_object->path, {}});
	} else if (smbd_open->smbd_stream &&
			smbd_open->smbd_stream->meta.delete_on_close) {
		NTSTATUS status = x_smbd_object_delete(smbd_object,
				smbd_stream,
				smbd_open,
				changes);

		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		smbd_stream->exists = false;
		// TODO should it also notify object MODIFIED
		changes.push_back(x_smb2_change_t{NOTIFY_ACTION_REMOVED_STREAM,
				FILE_NOTIFY_CHANGE_STREAM_NAME,
				smbd_open->open_state.parent_lease_key,
				smbd_object->path + u':' + smbd_stream->name,
				{}});
	}

	return NT_STATUS_OK;
}

static NTSTATUS smbd_object_close(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_close_t> &state,
		std::vector<x_smb2_change_t> &changes)
{
	x_smbd_lease_t *smbd_lease;

	std::unique_lock<std::mutex> lock(smbd_object->mutex);
	/* TODO move to smbd_open */
	if (smbd_open->oplock_break_sent != x_smbd_open_t::OPLOCK_BREAK_NOT_SENT) {
		if (x_smbd_cancel_timer(x_smbd_timer_t::BREAK, &smbd_open->oplock_break_timer)) {
			x_smbd_ref_dec(smbd_open);
		}
		smbd_open->oplock_break_sent = x_smbd_open_t::OPLOCK_BREAK_NOT_SENT;
	}

       	smbd_lease = smbd_open->smbd_lease;
	smbd_open->smbd_lease = nullptr;

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
	x_smbd_requ_t *requ_notify;
	while ((requ_notify = smbd_open->notify_requ_list.get_front()) != nullptr) {
		smbd_open->notify_requ_list.remove(requ_notify);
		lock.unlock();
		x_smbd_conn_post_cancel(x_smbd_chan_get_conn(requ_notify->smbd_chan),
				requ_notify, NT_STATUS_NOTIFY_CLEANUP);
		lock.lock();
	}

	if (smbd_open->update_write_time) {
		changes.push_back(x_smb2_change_t{NOTIFY_ACTION_MODIFIED,
				FILE_NOTIFY_CHANGE_LAST_WRITE,
				smbd_open->open_state.parent_lease_key,
				smbd_object->path, {}});
		smbd_open->update_write_time = false;
	}

	smbd_object_remove(smbd_object, smbd_open, changes);

	sharemode_modified(smbd_object, smbd_open->smbd_stream);

	// TODO if last_write_time updated
	if (smbd_requ && (state->in_flags & X_SMB2_CLOSE_FLAGS_FULL_INFORMATION)) {
		state->out_flags = X_SMB2_CLOSE_FLAGS_FULL_INFORMATION;
		/* TODO stream may be freed */
		auto stream_meta = smbd_open->smbd_stream ?
			&smbd_open->smbd_stream->meta : &smbd_object->stream_meta;
		fill_out_info(state->out_info, smbd_object->meta,
					*stream_meta);
	}
	lock.unlock();

	if (smbd_lease) {
		x_smbd_lease_close(smbd_lease);
	}

	return NT_STATUS_OK;
}

static NTSTATUS smbd_open_check(x_smbd_open_t *smbd_open, x_smbd_tcon_t *smbd_tcon,
		x_smb2_state_create_t &state)
{
	auto &open_state = smbd_open->open_state;
	if (smbd_open->smbd_tcon) {
		X_LOG_NOTICE("open is active");
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
		if (state.in_path != smbd_open->smbd_object->path) {
			X_LOG_NOTICE("path not match");
			return NT_STATUS_INVALID_PARAMETER;
		}
	}
	if (!x_smbd_tcon_get_user(smbd_tcon)->match(open_state.owner)) {
		X_LOG_NOTICE("user sid not match");
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}
	if (!smbd_open_set_state(smbd_open, x_smbd_open_t::S_INACTIVE,
				x_smbd_open_t::S_ACTIVE)) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}
	if (!x_smbd_cancel_timer(x_smbd_timer_t::DURABLE, &smbd_open->durable_timer)) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	return NT_STATUS_OK;
}

x_smbd_open_t *x_smbd_open_reopen(NTSTATUS &status,
		uint64_t id_presistent, uint64_t id_volatile,
		x_smbd_tcon_t *smbd_tcon,
		x_smb2_state_create_t &state)
{
	auto [found, smbd_open] = g_smbd_open_table->lookup(id_volatile);
	if (found) {
		auto lock = std::lock_guard(smbd_open->smbd_object->mutex);
		status = smbd_open_check(smbd_open, smbd_tcon, state);
		if (NT_STATUS_IS_OK(status)) {
			smbd_open->smbd_tcon = x_smbd_ref_inc(smbd_tcon);
			return smbd_open;
		}
		x_smbd_ref_dec(smbd_open);
	} else {
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}
	return nullptr;
}

static void smbd_open_durable_timeout(x_timerq_entry_t *timerq_entry)
{
	x_smbd_open_t *smbd_open = X_CONTAINER_OF(timerq_entry,
			x_smbd_open_t, durable_timer);
	X_LOG_DBG("durable_timeout %lx,%lx", smbd_open->id_persistent,
			smbd_open->id_volatile);
	if (smbd_open_set_state(smbd_open, x_smbd_open_t::S_INACTIVE, 
				x_smbd_open_t::S_DONE)) {
		g_smbd_open_table->remove(smbd_open->id_volatile);
		x_smbd_ref_dec(smbd_open);

		x_smbd_object_t *smbd_object = smbd_open->smbd_object;
		auto smbd_volume = smbd_object->smbd_volume;
		std::vector<x_smb2_change_t> changes;
		std::unique_ptr<x_smb2_state_close_t> state;
		smbd_object_close(smbd_object, smbd_open,
				nullptr, state, changes);
		/* TODO changes */
	}
	x_smbd_ref_dec(smbd_open); // ref by timer
}

static NTSTATUS smbd_open_set_durable(x_smbd_open_t *smbd_open)
{
	X_LOG_DBG("set_durable %lx,%lx", smbd_open->id_persistent,
			smbd_open->id_volatile);
	X_ASSERT(smbd_open->smbd_object);
	x_smbd_tcon_t *smbd_tcon;
	{
		/* TODO save durable info to volume so it can restore open
		 * when new smbd take over
		 */
		auto lock = std::lock_guard(smbd_open->smbd_object->mutex);
		X_ASSERT(smbd_open->smbd_tcon);
		smbd_open_set_state(smbd_open, x_smbd_open_t::S_ACTIVE,
				x_smbd_open_t::S_INACTIVE);
		smbd_tcon = smbd_open->smbd_tcon;
		smbd_open->smbd_tcon = nullptr;
		smbd_open->durable_timer.func = smbd_open_durable_timeout;
		smbd_open->durable_expire_tick = x_tick_add(tick_now,
				smbd_open->open_state.durable_timeout_msec * 1000000u);
		x_smbd_add_timer(x_smbd_timer_t::DURABLE, &smbd_open->durable_timer);
	}

	uint32_t durable_sec = (smbd_open->open_state.durable_timeout_msec + 999) / 1000;
	int ret = x_smbd_volume_set_durable_timeout(
			*smbd_open->smbd_object->smbd_volume,
			smbd_open->id_persistent,
			durable_sec);
	X_LOG_DBG("set_durable_expired for %p 0x%lx, ret = %d",
			smbd_open, smbd_open->id_persistent, ret);

	x_smbd_ref_dec(smbd_tcon);
	return NT_STATUS_OK;
}

NTSTATUS x_smbd_open_restore(
		std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		x_smbd_durable_t &smbd_durable)
{
	if (!x_smbd_open_has_space()) {
		X_LOG_WARN("too many opens, cannot allocate new");
		return NT_STATUS_INSUFFICIENT_RESOURCES;
	}

	x_smbd_open_t *smbd_open{};
	NTSTATUS status = x_smbd_open_durable(smbd_open, smbd_volume,
			smbd_durable);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	{
		auto lock = std::lock_guard(smbd_open->smbd_object->mutex);
		X_ASSERT(smbd_open->state == x_smbd_open_t::S_ACTIVE);
		X_ASSERT(!smbd_open->smbd_tcon);
		smbd_open->state = x_smbd_open_t::S_INACTIVE;
		smbd_open->durable_timer.func = smbd_open_durable_timeout;
		smbd_open->durable_expire_tick = x_tick_add(tick_now,
				smbd_open->open_state.durable_timeout_msec * 1000000u);
		x_smbd_add_timer(x_smbd_timer_t::DURABLE, &smbd_open->durable_timer);
	}

	smbd_durable.id_volatile = smbd_open->id_volatile;
	return NT_STATUS_OK;
}

NTSTATUS x_smbd_open_close(x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_close_t> &state,
		std::vector<x_smb2_change_t> &changes,
		bool shutdown)
{
	/* TODO atomic change and set */
	if (smbd_open->state == x_smbd_open_t::S_DONE) {
		return NT_STATUS_FILE_CLOSED;
	}

	NTSTATUS status;
	if (shutdown && smbd_open->dh_mode != x_smbd_open_t::DH_NONE) {
		status = smbd_open_set_durable(smbd_open);
		if (NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	smbd_open->state = x_smbd_open_t::S_DONE;

	if (smbd_open->dh_mode != x_smbd_open_t::DH_NONE) {
		int ret = x_smbd_volume_set_durable_timeout(
				*smbd_open->smbd_object->smbd_volume,
				smbd_open->id_persistent,
				0); // 0 mean expired immediately
		X_LOG_DBG("remove_durable for %p 0x%lx, ret = %d",
				smbd_open, smbd_open->id_persistent, ret);
	}

	g_smbd_open_table->remove(smbd_open->id_volatile);
	x_smbd_ref_dec(smbd_open);

	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	status = smbd_object_close(smbd_object, smbd_open,
			smbd_requ, state, changes);

	x_smbd_ref_dec(smbd_open); // ref by smbd_tcon open_list
	return status;
}


NTSTATUS x_smbd_open_op_close(
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_close_t> &state)
{
	if (!x_smbd_tcon_unlink_open(smbd_open->smbd_tcon, &smbd_open->tcon_link)) {
		return NT_STATUS_FILE_CLOSED;
	}

	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	auto smbd_volume = smbd_object->smbd_volume;
	std::vector<x_smb2_change_t> changes;
	auto status = x_smbd_open_close(smbd_open, smbd_requ, state, changes, false);
	x_smbd_notify_change(smbd_volume, changes);

	return status;
}

void x_smbd_open_unlinked(x_dlink_t *link, x_smbd_tcon_t *smbd_tcon,
		std::vector<x_smb2_change_t> &changes,
		bool shutdown)
{
	x_smbd_open_t *smbd_open = X_CONTAINER_OF(link, x_smbd_open_t, tcon_link);
	std::unique_ptr<x_smb2_state_close_t> state;
	x_smbd_open_close(smbd_open, nullptr, state, changes, shutdown);
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
		X_LOG_DBG("evt=%p, requ=%p, smbd_conn=%p", evt, smbd_requ, smbd_conn);

		auto state = smbd_requ->release_state<x_smb2_state_create_t>();
		if (x_smbd_requ_async_remove(smbd_requ) && smbd_conn) {
			NTSTATUS status = x_smbd_tcon_op_create(smbd_requ, state);
			if (!NT_STATUS_EQUAL(status, NT_STATUS_PENDING)) {
				smbd_requ->save_state(state);
				smbd_requ->async_done_fn(smbd_conn, smbd_requ, status);
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
		X_LOG_DBG("evt=%p, requ=%p, smbd_conn=%p", evt, smbd_requ, smbd_conn);

		auto state = smbd_requ->release_state<x_smb2_state_rename_t>();
		if (x_smbd_requ_async_remove(smbd_requ) && smbd_conn) {
			NTSTATUS status = x_smbd_open_op_rename(smbd_requ, state);
			if (!NT_STATUS_EQUAL(status, NT_STATUS_PENDING)) {
				smbd_requ->save_state(state);
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

static void oplock_break_timeout(x_timerq_entry_t *timerq_entry)
{
	/* we already have a ref on smbd_chan when adding timer */
	x_smbd_open_t *smbd_open = X_CONTAINER_OF(timerq_entry,
			x_smbd_open_t, oplock_break_timer);
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	bool modified = true;
	auto lock = std::lock_guard(smbd_object->mutex);
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
	x_smbd_ref_dec(smbd_open);
}

struct send_lease_break_evt_t
{
	static void func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user)
	{
		send_lease_break_evt_t *evt = X_CONTAINER_OF(fdevt_user,
				send_lease_break_evt_t, base);
		X_LOG_DBG("evt=%p", evt);

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
		uint8_t break_to)
{
	x_smb2_lease_key_t lease_key;
	uint8_t curr_state;
	uint16_t new_epoch;
	uint32_t flags;

	bool send_break = x_smbd_lease_require_break(smbd_open->smbd_lease,
			ignore_lease_key,
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
						x_convert_utf16_to_utf8_safe(smbd_stream->name).c_str(),
						x_convert_utf16_to_utf8_safe(smbd_object->path).c_str(),
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
		std::vector<x_smb2_change_t> &changes)
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
#if 0
		DEBUG(10,("share_conflict: No conflict due to "
					"access_mask = 0x%x\n",
					(unsigned int)access_mask ));
#endif
		return false;
	}

	auto &open_list = sharemode->open_list;
	x_smbd_open_t *curr_open, *next_open;
	for (curr_open = open_list.get_front(); curr_open;
			curr_open = next_open) {
		next_open = open_list.next(curr_open);
		if (curr_open->is_disconnected()) {
			/* TODO for persistent handle?? */
			continue;
		}

		if (share_conflict(curr_open, access_mask, share_access)) {
#if 0
			TODO
			if (posixfs_open->base.is_disconnected()) {
				/* TODO for persistent handle?? */
				posixfs_object_remove(posixfs_object, posixfs_open,
						changes);
				continue;
			}
#endif
			return true;
		}
	}
	return false;
}

static void smbd_create_cancel(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	auto state = smbd_requ->get_state<x_smb2_state_create_t>();
	x_smbd_sharemode_t *sharemode = get_sharemode(state->smbd_object,
			state->smbd_stream);

	{
		auto lock = std::lock_guard(state->smbd_object->mutex);
		sharemode->defer_open_list.remove(smbd_requ);
	}
	x_smbd_conn_post_cancel(smbd_conn, smbd_requ, NT_STATUS_CANCELLED);
}

static void defer_open(x_smbd_sharemode_t *sharemode,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state)
{
	smbd_requ->save_state(state);
	/* TODO does it need a timer? can break timer always wake up it? */
	x_smbd_ref_inc(smbd_requ);
	sharemode->defer_open_list.push_back(smbd_requ);
	x_smbd_requ_async_insert(smbd_requ, smbd_create_cancel);
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
		x_smb2_state_create_t &state)
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
		state.out_oplock_level = X_SMB2_OPLOCK_LEVEL_LEASE;
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
			state.out_oplock_level = X_SMB2_OPLOCK_LEVEL_BATCH;
			break;
		case X_SMB2_LEASE_READ|X_SMB2_LEASE_WRITE:
			state.out_oplock_level = X_SMB2_OPLOCK_LEVEL_EXCLUSIVE;
			break;
		case X_SMB2_LEASE_READ|X_SMB2_LEASE_HANDLE:
		case X_SMB2_LEASE_READ:
			state.out_oplock_level = X_SMB2_OPLOCK_LEVEL_II;
			break;
		default:
			state.out_oplock_level = X_SMB2_OPLOCK_LEVEL_NONE;
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
	x_smbd_add_timer(x_smbd_timer_t::BREAK, &smbd_open->oplock_break_timer);
}

static bool delay_for_oplock(x_smbd_object_t *smbd_object,
		x_smbd_sharemode_t *sharemode,
		x_smbd_lease_t *smbd_lease,
		x_smb2_create_disposition_t create_disposition,
		uint32_t desired_access,
		bool have_sharing_violation,
		uint32_t open_attempt,
		std::vector<x_smb2_change_t> &changes)
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
#if 0
		if (curr_open->is_disconnected()) {
			posixfs_object_remove(posixfs_object, curr_open, changes);
			continue;
		}
#endif
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
			x_smbd_open_break_lease(curr_open, nullptr, break_to);
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

static NTSTATUS smbd_open_create_exist(
		x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state,
		bool overwrite,
		std::vector<x_smb2_change_t> &changes)
{
	if (smbd_object->type == x_smbd_object_t::type_file && overwrite) {
		// open_match_attributes
#define MIS_MATCH(attr) (((smbd_object->meta.file_attributes & attr) != 0) && ((state->in_file_attributes & attr) == 0))
		if (MIS_MATCH(X_SMB2_FILE_ATTRIBUTE_SYSTEM) ||
				MIS_MATCH(X_SMB2_FILE_ATTRIBUTE_HIDDEN)) {
			RETURN_OP_STATUS(smbd_requ, NT_STATUS_ACCESS_DENIED);
		}
	}

	auto smbd_user = x_smbd_sess_get_user(smbd_requ->smbd_sess);
	uint32_t granted_access, maximal_access;
	NTSTATUS status = x_smbd_object_access_check(smbd_object,
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

	state->granted_access = granted_access;
	state->out_maximal_access = maximal_access;

	x_smbd_sharemode_t *sharemode = get_sharemode(
			smbd_object, smbd_stream);

	bool conflict = open_mode_check(smbd_object,
			sharemode,
			granted_access, state->in_share_access,
			changes);
	if (delay_for_oplock(smbd_object,
				sharemode,
				state->smbd_lease,
				state->in_create_disposition,
				overwrite ? granted_access | idl::SEC_FILE_WRITE_DATA : granted_access,
				conflict, state->open_attempt,
				changes)) {
		++state->open_attempt;
		defer_open(sharemode,
				smbd_requ, state);
		return NT_STATUS_PENDING;
	}

	if (conflict) {
		return NT_STATUS_SHARING_VIOLATION;
	}

       	status = grant_oplock(smbd_object,
			smbd_stream,
			sharemode,
			*state);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return status;
}

static NTSTATUS smbd_open_create_new(
		x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream,
		x_smbd_requ_t *smbd_requ,
		x_smb2_state_create_t &state,
		std::vector<x_smb2_change_t> &changes)
{
	auto smbd_user = x_smbd_sess_get_user(smbd_requ->smbd_sess);
	NTSTATUS status = x_smbd_create_object(smbd_object,
			smbd_stream,
			*smbd_user, state,
			state.in_file_attributes,
			state.in_allocation_size,
			changes);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	x_smbd_sharemode_t *sharemode = get_sharemode(smbd_object,
			smbd_stream);
       	status = grant_oplock(smbd_object, smbd_stream, sharemode,
			state);
	X_ASSERT(NT_STATUS_IS_OK(status));
	return status;
}


NTSTATUS x_smbd_open_create(x_smbd_open_t **psmbd_open,
		x_smbd_requ_t *smbd_requ,
		x_smbd_share_t &smbd_share,
		std::unique_ptr<x_smb2_state_create_t> &state,
		std::vector<x_smb2_change_t> &changes)
{
	x_smbd_object_t *smbd_object = state->smbd_object;
	x_smbd_stream_t *smbd_stream = state->smbd_stream;
	X_ASSERT(smbd_object);

	/* check lease first */
	if (state->smbd_lease && !x_smbd_lease_match(state->smbd_lease,
				smbd_object, smbd_stream)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	auto in_disposition = state->in_create_disposition;
	auto lock = std::lock_guard(smbd_object->mutex);

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

	/* TODO check can_delete_on_close for existing object and stream */
	if (!smbd_object->exists()) {
		uint32_t access_mask;
		if (state->in_desired_access & idl::SEC_FLAG_MAXIMUM_ALLOWED) {
			access_mask = idl::SEC_RIGHTS_FILE_ALL;
		} else {
			access_mask = state->in_desired_access;
		}

		NTSTATUS status;
		if (state->in_create_options & X_SMB2_CREATE_OPTION_DELETE_ON_CLOSE) {
			status = x_smbd_can_set_delete_on_close(
					smbd_object, nullptr,
					state->in_file_attributes,
					access_mask);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
		}
	} else {
		if (smbd_object->stream_meta.delete_on_close) {
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
					x_convert_utf16_to_utf8_safe(smbd_object->path).c_str(),
					smbd_object->meta.file_attributes);
			return NT_STATUS_ACCESS_DENIED;
		}

		if (smbd_object->meta.file_attributes & X_SMB2_FILE_ATTRIBUTE_REPARSE_POINT) {
			X_LOG_DBG("object '%s' is reparse_point",
					x_convert_utf16_to_utf8_safe(smbd_object->path).c_str());
			return NT_STATUS_PATH_NOT_COVERED;
		}
	}

	NTSTATUS status;
	x_smb2_create_action_t create_action = x_smb2_create_action_t::WAS_OPENED;
	bool overwrite = false;
	if (smbd_share.get_type() == X_SMB2_SHARE_TYPE_DISK) {
		if (!smbd_object->exists() || (smbd_stream && !smbd_stream->exists)) {
			status = smbd_open_create_new(
					smbd_object,
					smbd_stream,
					smbd_requ,
					*state,
					changes);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
			create_action = x_smb2_create_action_t::WAS_CREATED;

		} else {
			overwrite = in_disposition == x_smb2_create_disposition_t::OVERWRITE
				|| in_disposition == x_smb2_create_disposition_t::OVERWRITE_IF
				|| in_disposition == x_smb2_create_disposition_t::SUPERSEDE;
			status = smbd_open_create_exist(
					smbd_object,
					smbd_stream,
					smbd_requ,
					state,
					overwrite,
					changes);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}

			create_action = overwrite ? x_smb2_create_action_t::WAS_OVERWRITTEN :
				x_smb2_create_action_t::WAS_OPENED;
		}

		if (state->in_contexts & X_SMB2_CONTEXT_FLAG_MXAC) {
			state->out_contexts |= X_SMB2_CONTEXT_FLAG_MXAC;
		}
	}

	/* TODO should we check the open limit before create the open */
	status = smbd_object->smbd_volume->ops->create_open(psmbd_open,
			smbd_requ, smbd_share, state,
			overwrite,
			create_action != x_smb2_create_action_t::WAS_CREATED,
			changes);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	state->out_create_flags = 0;
	state->out_create_action = create_action;
	return NT_STATUS_OK;
}

void x_smbd_break_lease(x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream)
{
	std::unique_lock<std::mutex> lock(smbd_object->mutex);
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
	auto lock = std::lock_guard(smbd_object->mutex);

	if (smbd_open->oplock_break_sent == x_smbd_open_t::OPLOCK_BREAK_NOT_SENT) {
		return NT_STATUS_INVALID_OPLOCK_PROTOCOL;
	} else if (x_smbd_cancel_timer(x_smbd_timer_t::BREAK, &smbd_open->oplock_break_timer)) {
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
			x_smbd_open_break_lease(other_open, nullptr, X_SMB2_LEASE_NONE);
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


static std::string x_smbd_open_get_path(const x_smbd_open_t *smbd_open)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	if (!smbd_open->smbd_stream) {
		return x_convert_utf16_to_utf8_safe(smbd_object->path);
	} else {
		return x_convert_utf16_to_utf8_safe(smbd_object->path + u":" + smbd_open->smbd_stream->name);
	}
}

x_smbd_open_t::x_smbd_open_t(x_smbd_object_t *so,
		x_smbd_stream_t *strm,
		x_smbd_tcon_t *st,
		const x_smbd_open_state_t &open_state)
	: tick_create(tick_now), smbd_object(so), smbd_stream(strm)
	, smbd_tcon(st ? x_smbd_ref_inc(st) : nullptr), open_state(open_state)
{
	X_SMBD_COUNTER_INC(open_create, 1);
	oplock_break_timer.func = oplock_break_timeout;
}

x_smbd_open_t::~x_smbd_open_t()
{
	x_smbd_ref_dec_if(smbd_tcon);
	x_smbd_object_release(smbd_object, nullptr);
	X_SMBD_COUNTER_INC(open_delete, 1);
}

struct x_smbd_open_list_t : x_smbd_ctrl_handler_t
{
	x_smbd_open_list_t() : iter(g_smbd_open_table->iter_start()) {
	}
	bool output(std::string &data) override;
	smbd_open_table_t::iter_t iter;
};

static const char dh_mode_name[] = "-DP";
bool x_smbd_open_list_t::output(std::string &data)
{
	std::ostringstream os;

	bool ret = g_smbd_open_table->iter_entry(iter, [&os](const x_smbd_open_t *smbd_open) {
			os << idl::x_hex_t<uint64_t>(smbd_open->id_persistent) << ','
			<< idl::x_hex_t<uint64_t>(smbd_open->id_volatile) << ' '
			<< idl::x_hex_t<uint32_t>(smbd_open->open_state.access_mask) << ' '
			<< idl::x_hex_t<uint32_t>(smbd_open->open_state.share_access) << ' '
			<< dh_mode_name[int(smbd_open->dh_mode)] << ' '
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
