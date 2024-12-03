
#include "smbd.hxx"
#include "smbd_ctrl.hxx"
#include "nxfsd_stats.hxx"
#include "smbd_open.hxx"
#include "smbd_replay.hxx"
#include "include/idtable.hxx"
#include "include/nttime.hxx"
#include "smbd_access.hxx"
#include "smbd_ntacl.hxx"
#include "smbd_dcerpc_srvsvc.hxx"
#include "nxfsd_sched.hxx"

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
x_smbd_open_t *x_ref_inc(x_smbd_open_t *smbd_open)
{
	g_smbd_open_table->incref(smbd_open->id_volatile);
	return smbd_open;
}

template <>
void x_ref_dec(x_smbd_open_t *smbd_open)
{
	g_smbd_open_table->decref(smbd_open->id_volatile);
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
	if (open_state.flags & x_smbd_open_state_t::F_REPLAY_CACHED) {
		x_smbd_replay_cache_clear(open_state.client_guid,
				open_state.create_guid);
		open_state.flags &= ~(x_smbd_open_state_t::F_REPLAY_CACHED);
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
			auto lock = smbd_object->lock();
			if (smbd_open->id_persistent == id_persistent &&
					smbd_open->state == SMBD_OPEN_S_ACTIVE &&
					(smbd_open->smbd_tcon == smbd_tcon ||
					 !smbd_tcon)) {
				if (clear_replay_cache(smbd_open->open_state) &&
						smbd_open->open_state.dhmode !=
						x_smbd_dhmode_t::NONE) {
					/* update durable */
					x_smbd_volume_update_durable_flags(
							*smbd_object->smbd_volume,
							smbd_open->id_persistent,
							smbd_open->open_state);
				}

				return smbd_open;
			}
		}
		x_ref_dec(smbd_open);
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

static void fill_out_info(x_smb2_create_close_info_t &info,
		const x_smbd_object_meta_t &object_meta,
		const x_smbd_stream_meta_t &stream_meta)
{
	info.out_create_ts = x_timespec_to_nttime_val(object_meta.creation);
	info.out_last_access_ts = x_timespec_to_nttime_val(object_meta.last_access);
	info.out_last_write_ts = x_timespec_to_nttime_val(object_meta.last_write);
	info.out_change_ts = x_timespec_to_nttime_val(object_meta.change);
	info.out_file_attributes = object_meta.file_attributes;
	info.out_allocation_size = stream_meta.allocation_size;
	info.out_end_of_file = stream_meta.end_of_file;
}

void x_smbd_open_release(x_smbd_open_t *smbd_open)
{
	g_smbd_open_table->remove(smbd_open->id_volatile);
	x_ref_dec(smbd_open);
	x_ref_dec(smbd_open);
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
	--smbd_object->num_active_open;
	if (smbd_open->open_state.flags & x_smbd_open_state_t::F_INITIAL_DELETE_ON_CLOSE) {
		x_smbd_requ_state_disposition_t state;
		state.delete_pending = true;
		x_smbd_object_set_delete_pending_intl(smbd_object, smbd_open,
				nullptr, state);
	}

	if (smbd_open->open_state.locks.size()) {
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

struct smbd_wakeup_oplock_pending_list_evt_t
{
	static void func(void *ctx_conn, x_fdevt_user_t *fdevt_user)
	{
		X_ASSERT(!ctx_conn);
		smbd_wakeup_oplock_pending_list_evt_t *evt = X_CONTAINER_OF(fdevt_user,
				smbd_wakeup_oplock_pending_list_evt_t, base);
		x_smbd_wakeup_requ_list(evt->oplock_pending_list);
		delete evt;
	}

	explicit smbd_wakeup_oplock_pending_list_evt_t(x_nxfsd_requ_id_list_t &oplock_pending_list)
		: base(func), oplock_pending_list(std::move(oplock_pending_list))
	{
	}

	x_fdevt_user_t base;
	x_nxfsd_requ_id_list_t oplock_pending_list;
};

static void smbd_schedule_wakeup_oplock_pending_list(x_nxfsd_requ_id_list_t &oplock_pending_list)
{
	smbd_wakeup_oplock_pending_list_evt_t *evt =
		new smbd_wakeup_oplock_pending_list_evt_t(oplock_pending_list);
	x_nxfsd_schedule(&evt->base);
}

/* caller hold smbd_object->mutex */
static void smbd_close_open_intl(
		x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		x_smb2_create_close_info_t *info)
{
	if (smbd_open->open_state.dhmode != x_smbd_dhmode_t::NONE) {
		int ret = x_smbd_volume_remove_durable(
				*smbd_open->smbd_object->smbd_volume,
				smbd_open->id_persistent);
		X_LOG(SMB, DBG, "remove_durable for %p 0x%lx, ret = %d",
				smbd_open, smbd_open->id_persistent, ret);
	}

	clear_replay_cache(smbd_open->open_state);

	if (smbd_open->oplock_break_sent != x_smbd_open_t::OPLOCK_BREAK_NOT_SENT) {
		if (x_nxfsd_del_timer(&smbd_open->oplock_break_timer)) {
			x_ref_dec(smbd_open);
		}
		smbd_open->oplock_break_sent = x_smbd_open_t::OPLOCK_BREAK_NOT_SENT;
	}

	if (smbd_open->smbd_lease) {
		x_smbd_schedule_release_lease(smbd_open->smbd_lease);
		smbd_open->smbd_lease = nullptr;
	}

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
	x_smbd_schedule_clean_pending_requ_list(smbd_open->pending_requ_list);
	smbd_schedule_wakeup_oplock_pending_list(smbd_open->oplock_pending_list);

	if (smbd_open->update_write_time_on_close) {
		x_smbd_object_update_mtime(smbd_object);
		if (smbd_open->smbd_stream) {
			x_smbd_schedule_notify(
					NOTIFY_ACTION_MODIFIED_STREAM,
					FILE_NOTIFY_CHANGE_STREAM_SIZE | FILE_NOTIFY_CHANGE_STREAM_WRITE,
					smbd_open->open_state.parent_lease_key,
					smbd_open->open_state.client_guid,
					smbd_object->parent_object, nullptr,
					smbd_object->path_base + u":" + smbd_open->smbd_stream->name, {});
		} else {
			x_smbd_schedule_notify(
					NOTIFY_ACTION_MODIFIED,
					FILE_NOTIFY_CHANGE_LAST_WRITE,
					smbd_open->open_state.parent_lease_key,
					smbd_open->open_state.client_guid,
					smbd_object->parent_object, nullptr,
					smbd_object->path_base, {});
		}
		smbd_open->update_write_time_on_close = false;
	}

	smbd_object_remove(smbd_object, smbd_open);

	// TODO if last_write_time updated
	if (info) {
		/* TODO stream may be freed */
		auto &stream_meta = x_smbd_open_get_sharemode(smbd_open)->meta;
		fill_out_info(*info, smbd_object->meta, stream_meta);
	}
}

// caller hold the object mutex
static void smbd_open_close(
		x_smbd_open_t *smbd_open,
		x_smbd_object_t *smbd_object,
		x_smb2_create_close_info_t *info)
{
	smbd_open->state = SMBD_OPEN_S_DONE;

	if (smbd_object->type != x_smbd_object_t::type_pipe) {
		smbd_close_open_intl(smbd_object, smbd_open, info);
	}
}

struct x_smbd_open_release_evt_t
{
	static void func(void *ctx_conn, x_fdevt_user_t *fdevt_user)
	{
		X_ASSERT(!ctx_conn);
		x_smbd_open_release_evt_t *evt = X_CONTAINER_OF(fdevt_user,
				x_smbd_open_release_evt_t, base);
		x_smbd_open_release(evt->smbd_open);
		delete evt;
	}

	explicit x_smbd_open_release_evt_t(x_smbd_open_t *smbd_open)
		: base(func), smbd_open(smbd_open)
	{
	}

	x_fdevt_user_t base;
	x_smbd_open_t * const smbd_open;
};

static bool smbd_open_close_disconnected(
		x_smbd_open_t *smbd_open)
{
	if (smbd_open->state != SMBD_OPEN_S_DISCONNECTED) {
		return false;
	}

	if (!x_nxfsd_del_timer(&smbd_open->durable_timer)) {
		return false;
	}
	smbd_open_close(smbd_open, smbd_open->smbd_object, nullptr);

	x_smbd_open_release_evt_t *evt = new x_smbd_open_release_evt_t(smbd_open);
	x_nxfsd_schedule(&evt->base);
	return true;
}

static bool smbd_open_close_non_requ(x_smbd_open_t *smbd_open,
		x_smbd_tcon_t **p_smbd_tcon)
{
	if (smbd_open->state == SMBD_OPEN_S_ACTIVE) {
		/* it could happen when client tdis on other channel */
		if (!x_smbd_tcon_unlink_open(smbd_open->smbd_tcon, &smbd_open->tcon_link)) {
			X_LOG(SMB, NOTICE, "failed to unlink open %p", smbd_open);
			return false;
		}
		*p_smbd_tcon = smbd_open->smbd_tcon;
		smbd_open->smbd_tcon = nullptr;
	} else if (smbd_open->state != SMBD_OPEN_S_DISCONNECTED) {
		return false;
	}
	smbd_open_close(smbd_open, smbd_open->smbd_object, nullptr);
	return true;
}

static long smbd_open_durable_timeout(x_timer_job_t *timer)
{
	x_nxfsd_scheduler_t smbd_scheduler;

	x_smbd_open_t *smbd_open = X_CONTAINER_OF(timer,
			x_smbd_open_t, durable_timer);
	X_LOG(SMB, DBG, "durable_timeout %lx,%lx", smbd_open->id_persistent,
			smbd_open->id_volatile);
	auto smbd_object = smbd_open->smbd_object;

	bool closed = false;
	{
		auto lock = smbd_object->lock();
		if (smbd_open->state == SMBD_OPEN_S_DISCONNECTED) {
			smbd_open_close(smbd_open, smbd_object, nullptr);
			closed = true;
		}
	}

	X_LOG(SMB, DBG, "open=%lx,%lx closed=%d", smbd_open->id_persistent,
			smbd_open->id_volatile, closed);
	if (closed) {
		x_smbd_open_release(smbd_open);
	}

	return -1;
}

static bool smbd_open_set_durable(x_smbd_open_t *smbd_open)
{
	X_LOG(SMB, DBG, "set_durable %lx,%lx", smbd_open->id_persistent,
			smbd_open->id_volatile);
	auto smbd_object = smbd_open->smbd_object;
	X_ASSERT(smbd_object);
	smbd_open->state = SMBD_OPEN_S_DISCONNECTED;

	/* TODO save durable info to volume so it can restore open
	 * when new smbd take over
	 */
	x_nxfsd_add_timer(&smbd_open->durable_timer,
			smbd_open->open_state.durable_timeout_msec * 1000000ul);

	int ret = x_smbd_volume_disconnect_durable(
			*smbd_object->smbd_volume,
			smbd_open->id_persistent);
	X_LOG(SMB, DBG, "set_durable_expired for %p 0x%lx, ret = %d",
			smbd_open, smbd_open->id_persistent, ret);

	return true;
}

NTSTATUS x_smbd_open_op_close(
		x_smbd_open_t *smbd_open,
		x_smb2_create_close_info_t *info)
{
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	x_smbd_tcon_t *smbd_tcon = nullptr;

	{
		auto lock = smbd_object->lock();
		if (smbd_open->state != SMBD_OPEN_S_ACTIVE) {
			return NT_STATUS_FILE_CLOSED;
		}

		if (smbd_open->smbd_tcon) {
			/* it could happen when client tdis on other channel */
			if (!x_smbd_tcon_unlink_open(smbd_open->smbd_tcon,
						&smbd_open->tcon_link)) {
				return NT_STATUS_FILE_CLOSED;
			}
			smbd_tcon = smbd_open->smbd_tcon;
			smbd_open->smbd_tcon = nullptr;
		}
		smbd_open_close(smbd_open, smbd_object, info);
	}

	x_ref_dec_if(smbd_tcon);

	x_smbd_open_release(smbd_open);

	return NT_STATUS_OK;
}

void x_smbd_open_unlinked(x_dlink_t *link,
		bool shutdown)
{
	x_smbd_open_t *smbd_open = X_CONTAINER_OF(link, x_smbd_open_t, tcon_link);
	auto smbd_object = smbd_open->smbd_object;
	x_smbd_tcon_t *smbd_tcon = nullptr;

	bool closed = true;
	{
		auto lock = smbd_object->lock();
		if (smbd_open->state != SMBD_OPEN_S_ACTIVE) {
			return;
		}
		smbd_tcon = smbd_open->smbd_tcon;
		smbd_open->smbd_tcon = nullptr;
		if (shutdown && smbd_open->open_state.dhmode != x_smbd_dhmode_t::NONE &&
				smbd_open_set_durable(smbd_open)) {
			closed = false;
		} else {
			smbd_open_close(smbd_open, smbd_object, nullptr);
			closed = true;
		}
	}

	x_ref_dec_if(smbd_tcon);

	if (closed) {
		x_smbd_open_release(smbd_open);
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

void x_smbd_wakeup_requ_list(const x_nxfsd_requ_id_list_t &requ_list)
{
	for (auto requ_id : requ_list) {
		x_nxfsd_requ_t *nxfsd_requ = x_nxfsd_requ_lookup(requ_id);
		if (!nxfsd_requ) {
			X_LOG(SMB, DBG, "requ_id 0x%lx not exist", requ_id);
			X_NXFSD_COUNTER_INC(smbd_wakeup_stale, 1);
			continue;
		}

		int32_t count = nxfsd_requ->async_pending.fetch_sub(1,
				std::memory_order_relaxed);
		X_NXFSD_REQU_LOG(DBG, nxfsd_requ, " count=%d", count);
		X_ASSERT(count > 0);
		if (count == 1) {
			x_nxfsd_requ_resume(nxfsd_requ);
		} else {
			x_ref_dec(nxfsd_requ);
		}
	}
}

static long oplock_break_timeout(x_timer_job_t *timer)
{
	/* we already have a ref on smbd_chan when adding timer */
	x_smbd_open_t *smbd_open = X_CONTAINER_OF(timer,
			x_smbd_open_t, oplock_break_timer);
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	x_nxfsd_requ_id_list_t oplock_pending_list;
	{
		auto lock = smbd_object->lock();
		if (smbd_open->oplock_break_sent == x_smbd_open_t::OPLOCK_BREAK_TO_NONE_SENT) {
			smbd_open->oplock_break_sent = x_smbd_open_t::OPLOCK_BREAK_NOT_SENT;
			smbd_open->open_state.oplock_level = X_SMB2_OPLOCK_LEVEL_NONE;
		} else if (smbd_open->oplock_break_sent == x_smbd_open_t::OPLOCK_BREAK_TO_LEVEL_II_SENT) {
			smbd_open->oplock_break_sent = x_smbd_open_t::OPLOCK_BREAK_NOT_SENT;
			smbd_open->open_state.oplock_level = X_SMB2_OPLOCK_LEVEL_II;
		}
		std::swap(oplock_pending_list, smbd_open->oplock_pending_list);
	}
	x_ref_dec(smbd_open);
	x_smbd_wakeup_requ_list(oplock_pending_list);
	return -1;
}

struct send_lease_break_evt_t
{
	static void func(void *ctx_conn, x_fdevt_user_t *fdevt_user)
	{
		x_smbd_conn_t *smbd_conn = (x_smbd_conn_t *)ctx_conn;
		send_lease_break_evt_t *evt = X_CONTAINER_OF(fdevt_user,
				send_lease_break_evt_t, base);
		X_LOG(SMB, DBG, "send_lease_break_evt=%p curr_state=%d new_state=%d "
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
		x_ref_dec(smbd_sess);
	}

	x_fdevt_user_t base;
	x_smbd_sess_t * const smbd_sess;
	const x_smb2_lease_key_t lease_key;
	const uint8_t curr_state, new_state;
	const uint16_t new_epoch;
	const uint32_t flags;
};

bool x_smbd_open_match_get_lease(const x_smbd_open_t *smbd_open,
	       	const x_smb2_uuid_t &client_guid,
		x_smb2_lease_t &lease)
{
	return x_smbd_lease_match_get(smbd_open->smbd_lease,
			client_guid, lease);
}

/* smbd_object is locked */
bool x_smbd_open_break_lease(x_smbd_open_t *smbd_open,
		const x_smb2_lease_key_t *ignore_lease_key,
		const x_smb2_uuid_t *client_guid,
		uint8_t break_mask,
		uint8_t delay_mask,
		x_nxfsd_requ_t *nxfsd_requ,
		bool block_breaking)
{
	x_smb2_lease_key_t lease_key;
	uint8_t curr_state, new_state;
	uint16_t new_epoch;
	uint32_t flags;

	uint32_t break_action = x_smbd_lease_require_break(smbd_open->smbd_lease,
			ignore_lease_key,
			client_guid,
			lease_key, break_mask, delay_mask,
			curr_state, new_state,
			new_epoch, flags, nxfsd_requ,
			block_breaking);
	if (break_action & X_SMBD_BREAK_ACTION_SEND) {
		/* schedule lease break or close disconnected open */
		if (smbd_open->smbd_tcon) {
			x_smbd_sess_t *smbd_sess = x_smbd_tcon_get_sess(smbd_open->smbd_tcon);
			X_SMBD_SESS_POST_USER(smbd_sess, new send_lease_break_evt_t(
						smbd_sess, lease_key, curr_state, new_state,
						new_epoch, flags));
		} else {
			smbd_open_close_disconnected(smbd_open);
		}
	}

	return break_action & X_SMBD_BREAK_ACTION_BLOCKED;
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
				X_LOG(SMB, NOTICE, "ads %s of %s share-access %d violate access 0x%x",
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

/* caller locked smbd_object */
static bool check_app_instance(x_smbd_object_t *smbd_object,
		x_smbd_sharemode_t *sharemode,
		const x_smbd_requ_state_create_t &state)
{
	X_LOG(SMB, DBG, "contexts=0x%x app_instance_id=%s app_instance_version=%lu.%lu",
			state.in_context.bits,
			x_tostr(state.in_context.app_instance_id).c_str(),
			state.in_context.app_instance_version_high,
			state.in_context.app_instance_version_low);

	if ((state.in_context.bits & X_SMB2_CONTEXT_FLAG_APP_INSTANCE_ID) == 0) {
		return true;
	}

	auto &open_list = sharemode->open_list;
	x_smbd_open_t *curr_open, *next_open;
	for (curr_open = open_list.get_front(); curr_open;
			curr_open = next_open) {
		next_open = open_list.next(curr_open);
		auto &open_state = curr_open->open_state;
		if ((open_state.flags & x_smbd_open_state_t::F_APP_INSTANCE_ID) == 0 ||
				!(open_state.app_instance_id == state.in_context.app_instance_id)) {
			continue;
		}
		if (open_state.client_guid == state.client_guid) {
			continue;
		}
		if ((open_state.app_instance_version_high != 0 ||
					open_state.app_instance_version_low != 0) &&
				(open_state.app_instance_version_high >
				 state.in_context.app_instance_version_high ||
				 (open_state.app_instance_version_high ==
				  state.in_context.app_instance_version_high &&
				  open_state.app_instance_version_low >=
				  state.in_context.app_instance_version_low))) {
			return false;
		}
		x_smbd_tcon_t *smbd_tcon;
		if (smbd_open_close_non_requ(curr_open, &smbd_tcon)) {
			if (smbd_tcon) {
				x_ref_dec(smbd_tcon);
			}
			x_smbd_open_release(curr_open);
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
		uint32_t access_mask, uint32_t share_access)
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
			if (!smbd_open_close_disconnected(curr_open)) {
				return true;
			}
		}
	}
	return false;
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

static NTSTATUS grant_oplock(x_smbd_requ_t *smbd_requ,
		x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream,
		x_smbd_sharemode_t *sharemode,
		x_smbd_requ_state_create_t &state,
		uint8_t &out_oplock_level)
{
	uint8_t granted = X_SMB2_LEASE_NONE;
	uint8_t requested = X_SMB2_LEASE_NONE;
	uint8_t oplock_level = state.in_oplock_level;

	x_smb2_lease_t *lease = nullptr;
	if (oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE) {
		lease = &state.in_context.lease;
		requested = x_convert<uint8_t>(lease->state);
	}

	if (smbd_object->type == x_smbd_object_t::type_dir &&
			!smbd_stream) {
		if (lease && (state.server_capabilities & X_SMB2_CAP_DIRECTORY_LEASING)) {
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
					state.in_context.lease,
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
	static void func(void *ctx_conn, x_fdevt_user_t *fdevt_user)
	{
		x_smbd_conn_t *smbd_conn = (x_smbd_conn_t *)ctx_conn;
		send_oplock_break_evt_t *evt = X_CONTAINER_OF(fdevt_user,
				send_oplock_break_evt_t, base);
		X_LOG(SMB, DBG, "evt=%p", evt);

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
		x_ref_dec(smbd_sess);
	}

	x_fdevt_user_t base;
	x_smbd_sess_t * const smbd_sess;
	uint64_t const open_persistent_id, open_volatile_id;
	uint8_t const oplock_level;
};

static void smbd_open_add_oplock_pending(x_smbd_open_t *smbd_open,
		x_nxfsd_requ_t *nxfsd_requ)
{
	int32_t count = nxfsd_requ->async_pending.fetch_add(1, std::memory_order_relaxed);
	X_ASSERT(count >= 0);
	X_LOG(SMB, DBG, "add requ 0x%lx %p pending %d", nxfsd_requ->id, nxfsd_requ,
			count + 1);
	smbd_open->oplock_pending_list.push_back(nxfsd_requ->id);
}

bool x_smbd_open_break_oplock(x_smbd_object_t *smbd_object,
		x_smbd_open_t *smbd_open,
		uint8_t break_mask,
		x_nxfsd_requ_t *nxfsd_requ)
{
	uint8_t e_lease_type = get_lease_type(smbd_open);
	if (!(break_mask & e_lease_type)) {
		return false;
	}

	/*
	 * Oplocks only support breaking to R or NONE.
	 */
	break_mask |= X_SMB2_LEASE_HANDLE|X_SMB2_LEASE_WRITE;
	uint8_t break_to = e_lease_type & x_convert<uint8_t>(~break_mask);
	/* already hold smbd_object mutex */
	X_ASSERT(break_to == X_SMB2_LEASE_READ || break_to == X_SMB2_OPLOCK_LEVEL_NONE);
	if (smbd_open->oplock_break_sent != x_smbd_open_t::OPLOCK_BREAK_NOT_SENT) {
		X_LOG(SMB, DBG, "smbd_open->oplock_break_sent = %d",
				smbd_open->oplock_break_sent);
		if (nxfsd_requ) {
			smbd_open_add_oplock_pending(smbd_open, nxfsd_requ);
		}
		return true;
	}

	if (nxfsd_requ) {
		smbd_open_add_oplock_pending(smbd_open, nxfsd_requ);
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
			// sharemode_modified(smbd_object, smbd_open->smbd_stream);
			return false; // TODO;
		}
		smbd_open->oplock_break_sent = (break_to == X_SMB2_LEASE_READ ?
				x_smbd_open_t::OPLOCK_BREAK_TO_LEVEL_II_SENT :
				x_smbd_open_t::OPLOCK_BREAK_TO_NONE_SENT);
		x_ref_inc(smbd_open);
		x_smbd_add_timer(&smbd_open->oplock_break_timer, x_smbd_timer_id_t::BREAK);
	} else {
		smbd_open_close_disconnected(smbd_open);
	}
	return true;
}

static bool delay_for_oplock(x_smbd_object_t *smbd_object,
		x_smbd_sharemode_t *sharemode,
		x_nxfsd_requ_t *nxfsd_requ,
		x_smbd_lease_t *smbd_lease,
		x_smb2_create_disposition_t create_disposition,
		uint32_t desired_access,
		bool have_sharing_violation,
		uint32_t open_attempt)
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

		if (curr_open->smbd_lease) {
			if (curr_open->smbd_lease == smbd_lease) {
				continue;
			}

			if (is_lease_stat_open(desired_access)) {
				continue;
			}
		}

		uint8_t delay_mask = 0;
		if (have_sharing_violation) {
			delay_mask = X_SMB2_LEASE_HANDLE;
		} else {
			delay_mask = X_SMB2_LEASE_WRITE;
		}

		uint8_t break_mask = delay_mask;

		if (will_overwrite) {
			/* windows server seem not break HANDLE or READ */
			break_mask |= X_SMB2_LEASE_HANDLE|X_SMB2_LEASE_READ;
		}

		if (will_overwrite) {
			/*
			 * If we break anyway break to NONE directly.
			 * Otherwise vfs_set_filelen() will trigger the
			 * break.
			 */
			break_mask |= X_SMB2_LEASE_READ|X_SMB2_LEASE_WRITE;
		}

		++break_count;
		if (curr_open->smbd_lease) {
			if (x_smbd_open_break_lease(curr_open, nullptr, nullptr,
						break_mask, delay_mask, nxfsd_requ,
						open_attempt != 0)) {
				delay = true;
			}
		} else {
			if (x_smbd_open_break_oplock(smbd_object, curr_open,
						break_mask, nxfsd_requ)) {
				delay = true;
			}
		}
	}
	return delay;
}

static bool can_delete_file_in_directory(
		x_smbd_object_t *smbd_object,
		const x_smbd_tcon_t *smbd_tcon,
		const x_smbd_user_t &smbd_user)
{
#if 0
	char *dname = NULL;
	struct smb_filename *smb_fname_parent;
	bool ret;

	if (!CAN_WRITE(conn)) {
		return False;
	}

	if (!lp_acl_check_permissions(SNUM(conn))) {
		/* This option means don't check. */
		return true;
	}

	/* Get the parent directory permission mask and owners. */
	if (!parent_dirname(ctx, smb_fname->base_name, &dname, NULL)) {
		return False;
	}

	smb_fname_parent = synthetic_smb_fname(ctx,
				dname,
				NULL,
				NULL,
				smb_fname->flags);
	if (smb_fname_parent == NULL) {
		ret = false;
		goto out;
	}

	if(SMB_VFS_STAT(conn, smb_fname_parent) != 0) {
		ret = false;
		goto out;
	}

	/* fast paths first */

	if (!S_ISDIR(smb_fname_parent->st.st_ex_mode)) {
		ret = false;
		goto out;
	}
	if (get_current_uid(conn) == (uid_t)0) {
		/* I'm sorry sir, I didn't know you were root... */
		ret = true;
		goto out;
	}

#ifdef S_ISVTX
	/* sticky bit means delete only by owner of file or by root or
	 * by owner of directory. */
	if (smb_fname_parent->st.st_ex_mode & S_ISVTX) {
		if (!VALID_STAT(smb_fname->st)) {
			/* If the file doesn't already exist then
			 * yes we'll be able to delete it. */
			ret = true;
			goto out;
		}

		/*
		 * Patch from SATOH Fumiyasu <fumiyas@miraclelinux.com>
		 * for bug #3348. Don't assume owning sticky bit
		 * directory means write access allowed.
		 * Fail to delete if we're not the owner of the file,
		 * or the owner of the directory as we have no possible
		 * chance of deleting. Otherwise, go on and check the ACL.
		 */
		if ((get_current_uid(conn) !=
			smb_fname_parent->st.st_ex_uid) &&
		    (get_current_uid(conn) != smb_fname->st.st_ex_uid)) {
			DEBUG(10,("can_delete_file_in_directory: not "
				  "owner of file %s or directory %s",
				  smb_fname_str_dbg(smb_fname),
				  smb_fname_str_dbg(smb_fname_parent)));
			ret = false;
			goto out;
		}
	}
#endif
#endif
	/* now for ACL checks */
	std::shared_ptr<idl::security_descriptor> psd = smbd_object->parent_object->psd;

	uint32_t rejected_mask = 0;
	NTSTATUS status = se_file_access_check(*psd, smbd_user, false,
			idl::SEC_DIR_DELETE_CHILD, &rejected_mask);
	return NT_STATUS_IS_OK(status);
	/*
	 * There's two ways to get the permission to delete a file: First by
	 * having the DELETE bit on the file itself and second if that does
	 * not help, by the DELETE_CHILD bit on the containing directory.
	 *
	 * Here we only check the directory permissions, we will
	 * check the file DELETE permission separately.
	 */
}

static uint32_t smbd_object_access_check(
		x_smbd_object_t *smbd_object,
		uint32_t &granted_access,
		uint32_t &maximal_access,
		x_smbd_tcon_t *smbd_tcon,
		const x_smbd_user_t &smbd_user,
		const idl::security_descriptor &sd,
		const uint32_t in_desired_access,
		bool overwrite)
{
	uint32_t share_access = x_smbd_tcon_get_share_access(smbd_tcon);
	uint32_t out_maximal_access = se_calculate_maximal_access(sd, smbd_user);
	out_maximal_access &= share_access;

	if (overwrite && (out_maximal_access & idl::SEC_FILE_WRITE_DATA) == 0) {
		return idl::SEC_FILE_WRITE_DATA;
	}

	// No access check needed for attribute opens.
	if ((in_desired_access & ~(idl::SEC_FILE_READ_ATTRIBUTE | idl::SEC_STD_SYNCHRONIZE)) == 0) {
		granted_access = in_desired_access;
		maximal_access = out_maximal_access;
		return 0;
	}

	uint32_t desired_access = in_desired_access & ~idl::SEC_FLAG_MAXIMUM_ALLOWED;

	uint32_t granted = out_maximal_access;
	if (in_desired_access & idl::SEC_FLAG_MAXIMUM_ALLOWED) {
		if (smbd_object->meta.file_attributes & X_SMB2_FILE_ATTRIBUTE_READONLY) {
			granted &= ~(idl::SEC_FILE_WRITE_DATA | idl::SEC_FILE_APPEND_DATA);
		}
		granted |= idl::SEC_FILE_READ_ATTRIBUTE;
		if (!(granted & idl::SEC_STD_DELETE)) {
			if (can_delete_file_in_directory(smbd_object,
						smbd_tcon, smbd_user)) {
				granted |= idl::SEC_STD_DELETE;
			}
		}
	} else {
		granted = (desired_access & out_maximal_access);
	}

	uint32_t rejected_mask = desired_access & ~granted;
	if ((rejected_mask & idl::SEC_STD_DELETE) && !(in_desired_access
				& idl::SEC_FLAG_MAXIMUM_ALLOWED)) {
		if (can_delete_file_in_directory(smbd_object,
					smbd_tcon, smbd_user)) {
			granted |= idl::SEC_STD_DELETE;
			rejected_mask &= ~idl::SEC_STD_DELETE;
		}
	}
	granted_access = granted;
	maximal_access = out_maximal_access;
	return rejected_mask;
}

static inline NTSTATUS x_smbd_object_access_check(x_smbd_object_t *smbd_object,
		uint32_t &granted_access,
		uint32_t &maximal_access,
		x_smbd_tcon_t *smbd_tcon,
		const x_smbd_user_t &smbd_user,
		uint32_t desired_access,
		bool overwrite)
{
	std::shared_ptr<idl::security_descriptor> psd = smbd_object->psd;

	uint32_t rejected_mask = smbd_object_access_check(smbd_object, 
			granted_access, maximal_access,
			smbd_tcon, smbd_user,
			*psd,
			desired_access, overwrite);

	if (rejected_mask & idl::SEC_FLAG_SYSTEM_SECURITY) {
		if (smbd_user.priviledge_mask & idl::SEC_PRIV_SECURITY_BIT) {
			granted_access |= idl::SEC_FLAG_SYSTEM_SECURITY;
			rejected_mask &= ~idl::SEC_FLAG_SYSTEM_SECURITY;
		} else {
			return NT_STATUS_PRIVILEGE_NOT_HELD;
		}
	}

        if (rejected_mask & idl::SEC_STD_WRITE_OWNER) {
		if (smbd_user.priviledge_mask & idl::SEC_PRIV_TAKE_OWNERSHIP_BIT) {
			granted_access |= idl::SEC_STD_WRITE_OWNER;
			rejected_mask &= ~idl::SEC_STD_WRITE_OWNER;
		}
        }

	if (rejected_mask != 0) {
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_OK;
}

NTSTATUS x_smbd_open_create(
		x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream,
		x_smbd_requ_t *smbd_requ,
		x_smbd_requ_state_create_t &state,
		x_smb2_create_action_t &create_action,
		uint8_t &out_oplock_level,
		bool overwrite)
{
	if (smbd_object->type == x_smbd_object_t::type_file && overwrite) {
		// open_match_attributes
#define MIS_MATCH(attr) (((smbd_object->meta.file_attributes & attr) != 0) && ((state.in_file_attributes & attr) == 0))
		if (MIS_MATCH(X_SMB2_FILE_ATTRIBUTE_SYSTEM) ||
				MIS_MATCH(X_SMB2_FILE_ATTRIBUTE_HIDDEN)) {
			X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_ACCESS_DENIED);
		}
	}

	NTSTATUS status;
	auto smbd_user = smbd_requ->base.smbd_user;
	uint32_t granted_access, maximal_access = 0;
	if (smbd_object->exists()) {
		status = x_smbd_object_access_check(smbd_object,
				granted_access,
				maximal_access,
				smbd_requ->smbd_tcon,
				*smbd_user,
				state.in_desired_access,
				overwrite);

		if (!NT_STATUS_IS_OK(status)) {
			X_SMBD_REQU_RETURN_STATUS(smbd_requ, status);
		}

		/* TODO seems windows do not check this for folder */
		if (granted_access & idl::SEC_STD_DELETE) {
			if (!check_ads_share_access(smbd_object, granted_access)) {
				X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_SHARING_VIOLATION);
			}
		}
	}

	x_smbd_sharemode_t *sharemode = get_sharemode(
			smbd_object, smbd_stream);

	if (!check_app_instance(smbd_object, sharemode, state)) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_FILE_FORCED_CLOSED);
	}

	bool conflict = open_mode_check(smbd_object,
			sharemode,
			granted_access, state.in_share_access);
	if (delay_for_oplock(smbd_object,
				sharemode,
				&smbd_requ->base,
				state.smbd_lease,
				state.in_create_disposition,
				overwrite ? granted_access | idl::SEC_FILE_WRITE_DATA : granted_access,
				conflict, state.open_attempt)) {
		++state.open_attempt;
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_PENDING);
	}

	if (conflict) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_SHARING_VIOLATION);
	}

	if (!smbd_object->exists() || (smbd_stream && !smbd_stream->exists)) {
		if (!smbd_object->exists()) {
			uint32_t access_mask;
			if (state.in_desired_access & idl::SEC_FLAG_MAXIMUM_ALLOWED) {
				access_mask = idl::SEC_RIGHTS_FILE_ALL;
			} else {
				access_mask = state.in_desired_access;
			}

			if (state.in_create_options & X_SMB2_CREATE_OPTION_DELETE_ON_CLOSE) {
				status = x_smbd_can_set_delete_on_close(
						smbd_object, nullptr,
						state.in_file_attributes,
						access_mask);
				if (!NT_STATUS_IS_OK(status)) {
					X_SMBD_REQU_RETURN_STATUS(smbd_requ, status);
				}
			}
		}
		status = x_smbd_create_object(smbd_object,
				smbd_stream,
				*smbd_user, state,
				state.in_file_attributes,
				state.in_context.allocation_size);
		if (!NT_STATUS_IS_OK(status)) {
			X_SMBD_REQU_RETURN_STATUS(smbd_requ, status);
		}
		create_action = x_smb2_create_action_t::WAS_CREATED;
	} else {
		create_action = overwrite ? x_smb2_create_action_t::WAS_OVERWRITTEN :
			x_smb2_create_action_t::WAS_OPENED;

		state.granted_access = granted_access;
		state.out_maximal_access = maximal_access;
	}

       	status = grant_oplock(smbd_requ, smbd_object,
			smbd_stream,
			sharemode,
			state, out_oplock_level);
	if (!NT_STATUS_IS_OK(status)) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, status);
	}

	return status;
}

NTSTATUS x_smbd_break_oplock(
		x_smbd_open_t *smbd_open,
		uint8_t in_oplock_level,
		uint8_t &out_oplock_level)
{
	uint8_t tmp_oplock_level;
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	x_nxfsd_requ_id_list_t oplock_pending_list;

	{
	auto lock = smbd_object->lock();

	if (smbd_open->oplock_break_sent == x_smbd_open_t::OPLOCK_BREAK_NOT_SENT) {
		return NT_STATUS_INVALID_OPLOCK_PROTOCOL;
	} else if (x_nxfsd_del_timer(&smbd_open->oplock_break_timer)) {
		x_ref_dec(smbd_open);
	}

	if (smbd_open->oplock_break_sent == x_smbd_open_t::OPLOCK_BREAK_TO_NONE_SENT
			|| in_oplock_level == X_SMB2_OPLOCK_LEVEL_NONE) {
		tmp_oplock_level = X_SMB2_OPLOCK_LEVEL_NONE;
	} else {
		tmp_oplock_level = X_SMB2_OPLOCK_LEVEL_II;
	}
	smbd_open->oplock_break_sent = x_smbd_open_t::OPLOCK_BREAK_NOT_SENT;
	if (smbd_open->open_state.oplock_level != tmp_oplock_level) {
		smbd_open->open_state.oplock_level = tmp_oplock_level;
	}

	out_oplock_level = tmp_oplock_level;
	std::swap(oplock_pending_list, smbd_open->oplock_pending_list);
	}
	x_smbd_wakeup_requ_list(oplock_pending_list);

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
			x_smbd_open_break_lease(other_open, nullptr, nullptr,
					X_SMB2_LEASE_ALL, 0, nullptr, false);
		} else {
			/* This can break the open's self oplock II, but 
			 * Windows behave same
			 */
			auto other_oplock_level = other_open->open_state.oplock_level;
			X_ASSERT(other_oplock_level != X_SMB2_OPLOCK_LEVEL_BATCH);
			X_ASSERT(other_oplock_level != X_SMB2_OPLOCK_LEVEL_EXCLUSIVE);
			if (other_oplock_level == X_SMB2_OPLOCK_LEVEL_II) {
				x_smbd_open_break_oplock(smbd_object, other_open,
						X_SMB2_LEASE_ALL, nullptr);
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
		const x_smbd_requ_state_create_t &state)
{
	/* we do not support durable handle for ADS */
	if (smbd_open->smbd_stream ||
			smbd_open->smbd_object->type != x_smbd_object_t::type_file ||
			!oplock_valid_for_durable(smbd_open)) {
		return;
	}

	x_smbd_dhmode_t mode = x_smbd_dhmode_t::NONE;
	uint32_t durable_timeout_msec = 0;
	if (state.in_context.bits & X_SMB2_CONTEXT_FLAG_DH2Q) {
		if ((state.in_context.dh_flags & X_SMB2_DHANDLE_FLAG_PERSISTENT) &&
				x_smbd_tcon_get_continuously_available(smbd_tcon)) {
			mode = x_smbd_dhmode_t::PERSISTENT;
			durable_timeout_msec = state.in_context.dh_timeout;
		} else if (x_smbd_tcon_get_durable_handle(smbd_tcon)) {
			mode = x_smbd_dhmode_t::DURABLE;
			durable_timeout_msec = state.in_context.dh_timeout;
		}

	} else if (state.in_context.bits & X_SMB2_CONTEXT_FLAG_DHNQ) {
		if (x_smbd_tcon_get_durable_handle(smbd_tcon)) {
			mode = x_smbd_dhmode_t::DURABLE;
		}
	}

	if (mode == x_smbd_dhmode_t::NONE) {
		return;
	}

	auto &smbd_volume = *smbd_open->smbd_object->smbd_volume;
	if (smbd_open->id_persistent == X_SMBD_OPEN_ID_NON_DURABLE) {
		int ret = x_smbd_volume_allocate_persistent(
				smbd_volume,
				&smbd_open->id_persistent,
				smbd_open->id_volatile);
		if (ret < 0) {
			X_LOG(SMB, WARN, "x_smbd_volume_allocate_persisten for %p, 0x%lx failed, ret = %d",
					smbd_open,
					smbd_open->id_volatile, ret);
			return;
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
	X_LOG(SMB, DBG, "smbd_save_durable for %p 0x%lx 0x%lx",
			smbd_open, smbd_open->id_persistent,
			smbd_open->id_volatile);

	x_smbd_lease_data_t lease_data =
		(smbd_open->open_state.oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE) ?
		x_smbd_lease_get_data(smbd_open->smbd_lease) : x_smbd_lease_data_t{};

	x_smbd_volume_save_durable(smbd_volume,
			smbd_open->id_persistent,
			smbd_open->id_volatile,
			smbd_open->open_state,
			lease_data,
			smbd_open->smbd_object->file_handle);
}

NTSTATUS x_smbd_open_op_create(x_smbd_requ_t *smbd_requ,
		x_smbd_requ_state_create_t &state)
{
	X_TRACE_LOC;
	if (!x_smbd_open_has_space()) {
		X_LOG(SMB, WARN, "too many opens, cannot allocate new");
		X_NXFSD_COUNTER_INC(smbd_toomany_open, 1);
		return NT_STATUS_INSUFFICIENT_RESOURCES;
	}

	NTSTATUS status;
	x_smbd_tcon_t *smbd_tcon = smbd_requ->smbd_tcon;

	if (!state.smbd_object) {
		long path_priv_data{};
		long open_priv_data{};

		state.smbd_share = x_smbd_tcon_get_share(smbd_requ->smbd_tcon);
#if 0
		status = x_smbd_tcon_resolve_path(smbd_requ->smbd_tcon,
				state.in_path,
				smbd_requ->in_smb2_hdr.flags & X_SMB2_HDR_FLAG_DFS,
				state.smbd_share, path,
				path_priv_data, open_priv_data);
		if (!NT_STATUS_IS_OK(status)) {
			X_LOG(SMB, WARN, "resolve_path failed");
			return status;
		}

		X_LOG(SMB, DBG, "resolve_path(%s) to %s, %ld, %ld",
				x_str_todebug(state.in_path).c_str(),
				x_str_todebug(path).c_str(),
				path_priv_data, open_priv_data);
#endif
		x_smbd_object_t *smbd_object = nullptr;
		status = x_smbd_open_object(&smbd_object,
				state.smbd_share, state.in_path,
				path_priv_data, true);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		state.smbd_object = smbd_object;
		state.open_priv_data = open_priv_data;
	}

	x_smbd_open_t *smbd_open = nullptr;
	/* TODO should we check the open limit before create the open */
	status = state.smbd_object->smbd_volume->ops->create_open(&smbd_open,
			smbd_requ, state);

	if (!NT_STATUS_IS_OK(status)) {
		X_ASSERT(!smbd_open);
		return status;
	}

	X_ASSERT(smbd_open);

	/* if client access the open from other channel now, it does not have
	 * link into smbd_tcon, probably we should call x_smbd_open_store in the last
	 */
	bool linked = false;
	{
		auto lock = state.smbd_object->lock();
		if (smbd_open->state == SMBD_OPEN_S_INIT &&
				x_smbd_tcon_link_open(smbd_tcon, &smbd_open->tcon_link)) {
			smbd_open->state = SMBD_OPEN_S_ACTIVE;
			smbd_open->smbd_tcon = smbd_tcon;
			linked = true;
		} else {
			smbd_open_close(smbd_open, state.smbd_object, nullptr);
		}
	}

	if (linked) {
		x_ref_inc(smbd_tcon); // ref by open
		x_ref_inc(smbd_open); // ref tcon link
		smbd_requ->base.smbd_open = x_ref_inc(smbd_open);
	} else {
		status = NT_STATUS_NETWORK_NAME_DELETED;
	}

	return status;
}

static NTSTATUS smbd_open_reconnect(x_smbd_open_t *smbd_open,
		x_smbd_tcon_t *smbd_tcon,
		x_smbd_requ_t *smbd_requ,
		x_smbd_requ_state_create_t &state)
{
	auto smbd_object = smbd_open->smbd_object;
	auto &open_state = smbd_open->open_state;
	auto smbd_user = smbd_requ->base.smbd_user;

	auto lock = smbd_object->lock();
	if (smbd_open->state != SMBD_OPEN_S_DISCONNECTED) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}
	X_ASSERT(!smbd_open->smbd_tcon);

	if ((state.in_context.bits & X_SMB2_CONTEXT_FLAG_DH2C) &&
			!(open_state.create_guid == state.in_context.create_guid)) {
		X_LOG(SMB, NOTICE, "create_guid %s!=%s",
				x_tostr(open_state.create_guid).c_str(),
				x_tostr(state.in_context.create_guid).c_str());
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}
	if (smbd_open->smbd_lease) {
		if (!x_smbd_lease_match_get(smbd_open->smbd_lease,
					state.client_guid,
					state.in_context.lease)) {
			X_LOG(SMB, NOTICE, "lease not match");
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}
		if (state.in_ads_name.size()) {
			X_LOG(SMB, NOTICE, "we do not support reconnect ADS");
			return NT_STATUS_INVALID_PARAMETER;
		}
		/* TODO dfs path and case */
		if (state.in_path != x_smbd_object_get_path(smbd_open->smbd_object)) {
			X_LOG(SMB, NOTICE, "path not match");
			return NT_STATUS_INVALID_PARAMETER;
		}
	}
	if (!smbd_user->match(open_state.owner)) {
		X_LOG(SMB, NOTICE, "user sid not match, STATUS_ACCESS_DENIED");
		return NT_STATUS_ACCESS_DENIED;
	}
	if (!x_nxfsd_del_timer(&smbd_open->durable_timer)) {
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
		std::unique_ptr<x_smbd_requ_state_create_t> &state)
{
	uint64_t id_persistent = state->in_context.dh_id_persistent;
	std::shared_ptr<x_smbd_volume_t> smbd_volume;
	uint64_t id_volatile = x_smbd_share_lookup_durable(
			smbd_volume, x_smbd_tcon_get_share(smbd_requ->smbd_tcon),
			id_persistent);
	if (id_volatile == 0) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_OBJECT_NAME_NOT_FOUND);
	}

	auto smbd_tcon = smbd_requ->smbd_tcon;

	auto [found, smbd_open] = g_smbd_open_table->lookup(id_volatile);
	if (!found) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_OBJECT_NAME_NOT_FOUND);
	}

	NTSTATUS status = smbd_open_reconnect(smbd_open, smbd_tcon, smbd_requ, *state);
	if (!NT_STATUS_IS_OK(status)) {
		x_ref_dec(smbd_open);
		return status;
	}

	x_ref_inc(smbd_tcon); // ref by smbd_open
	smbd_requ->base.smbd_open = smbd_open; // TODO ref count

	return status;
}

NTSTATUS x_smbd_open_restore(
		std::shared_ptr<x_smbd_share_t> &smbd_share,
		std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		x_smbd_durable_t &smbd_durable,
		uint64_t timeout_msec)
{
	if (!x_smbd_open_has_space()) {
		X_LOG(SMB, WARN, "too many opens, cannot allocate new");
		X_NXFSD_COUNTER_INC(smbd_toomany_open, 1);
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
			X_LOG(SMB, WARN, "open is already in replay_cache");
			return NT_STATUS_FILE_NOT_AVAILABLE;
		}

		X_ASSERT(!smbd_open);
	}

	status = x_smbd_open_durable(smbd_open, smbd_share, smbd_volume,
			smbd_durable);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if ((open_state.flags & x_smbd_open_state_t::F_REPLAY_CACHED) &&
			open_state.create_guid.is_valid()) {
		/* TODO atomic */
		x_smbd_replay_cache_set(open_state.client_guid,
				open_state.create_guid,
				smbd_open);
	}

	x_ref_inc(smbd_open); // durable timer
	{
		auto lock = smbd_open->smbd_object->lock();
		X_ASSERT(smbd_open->state == SMBD_OPEN_S_INIT);
		X_ASSERT(!smbd_open->smbd_tcon);
		smbd_open->state = SMBD_OPEN_S_DISCONNECTED;
		x_nxfsd_add_timer(&smbd_open->durable_timer,
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
	X_NXFSD_COUNTER_INC_CREATE(smbd_open, 1);
	memset(lock_sequence_array, 0xff, LOCK_SEQUENCE_MAX);
}

x_smbd_open_t::~x_smbd_open_t()
{
	x_ref_dec_if(smbd_tcon);
	x_smbd_release_object_and_stream(smbd_object, smbd_stream);
	X_NXFSD_COUNTER_INC_DELETE(smbd_open, 1);
}

uint32_t x_smbd_open_encode_output_contexts(const x_smbd_open_t *smbd_open,
		const x_nxfsd_requ_state_open_t &state,
		uint8_t *out_ptr)
{
	const auto &open_state = smbd_open->open_state;
	return x_smb2_create_resp_context_encode(out_ptr,
			open_state.oplock_level == X_SMB2_OPLOCK_LEVEL_LEASE ?
				&state.in_context.lease : nullptr,
			state.out_contexts & X_SMB2_CONTEXT_FLAG_MXAC ?
				&state.out_maximal_access : nullptr,
			state.out_contexts & X_SMB2_CONTEXT_FLAG_QFID ?
				state.out_qfid_info : nullptr,
			state.out_contexts & (X_SMB2_CONTEXT_FLAG_DH2Q | X_SMB2_CONTEXT_FLAG_DHNQ),
			open_state.dhmode == x_smbd_dhmode_t::PERSISTENT ?
				X_SMB2_DHANDLE_FLAG_PERSISTENT : 0,
			open_state.durable_timeout_msec);
}


struct x_smbd_open_list_t : x_ctrl_handler_t
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
			os << idl::x_hex_t<uint64_t>(smbd_open->id_persistent) << ','
			<< idl::x_hex_t<uint64_t>(smbd_open->id_volatile) << ' '
			<< idl::x_hex_t<uint32_t>(smbd_open->open_state.access_mask) << ' '
			<< idl::x_hex_t<uint32_t>(smbd_open->open_state.share_access) << ' '
			<< idl::x_hex_t<uint8_t>(smbd_open->open_state.oplock_level) << ' '
			<< x_smbd_dhmode_to_name(smbd_open->open_state.dhmode)
			<< ((smbd_open->open_state.flags & x_smbd_open_state_t::F_REPLAY_CACHED) ? 'R' : '-') << ' '
			<< idl::x_hex_t<uint32_t>(smbd_open->notify_filter) << ' '
			<< idl::x_hex_t<uint32_t>(smbd_open->smbd_tcon ? x_smbd_tcon_get_id(smbd_open->smbd_tcon) : 0) << " '"
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

x_ctrl_handler_t *x_smbd_open_list_create()
{
	return new x_smbd_open_list_t;
}

static std::u16string get_path(const x_smbd_open_t *smbd_open)
{
	auto smbd_object = smbd_open->smbd_object;
	std::u16string ret =  u"C:\\"
		+ smbd_object->smbd_volume->owner_share->name_16
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
		auto lock = smbd_object->lock();
		if (smbd_open->smbd_tcon) {
			smbd_user = x_smbd_tcon_get_user(smbd_open->smbd_tcon);
		}
		lock_count = smbd_open->open_state.locks.size();
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
	bool closed;

	{
		auto lock = smbd_object->lock();
		closed = smbd_open_close_non_requ(smbd_open, &smbd_tcon);
	}

	if (closed) {
		if (smbd_tcon) {
			x_ref_dec(smbd_tcon);
		}
		x_smbd_open_release(smbd_open);
	}
}

void x_smbd_net_file_close(uint32_t fid)
{
	auto [found, smbd_open] = g_smbd_open_table->lookup(fid);
	if (!found) {
		X_LOG(SMB, NOTICE, "cannot find open by fid 0x%x", fid);
		return;
	}
	smbd_net_file_close(smbd_open);
	x_ref_dec(smbd_open);
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
