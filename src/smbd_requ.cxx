
#include "smbd.hxx"
#include "smbd_stats.hxx"
#include "smbd_ctrl.hxx"
#include "smbd_open.hxx"
#include "smbd_replay.hxx"
#include "nxfsd_sched.hxx"
#include "include/idtable.hxx"

using smbd_requ_table_t = x_idtable_t<x_smbd_requ_t, x_idtable_64_traits_t>;
static smbd_requ_table_t *g_smbd_requ_table;

x_smbd_requ_state_create_t::x_smbd_requ_state_create_t(const x_smb2_uuid_t &client_guid)
	: in_client_guid(client_guid)
{
}

x_smbd_requ_state_create_t::~x_smbd_requ_state_create_t()
{
	if (replay_reserved) {
		x_smbd_replay_cache_clear(in_client_guid, in_context.create_guid);
	}
	if (smbd_object) {
		x_smbd_release_object_and_stream(smbd_object, smbd_stream);
	}
	if (smbd_lease) {
		x_smbd_lease_release(smbd_lease);
	}
}

static long interim_timeout_func(x_timer_job_t *timer)
{
	/* we already have a ref on smbd_chan when adding timer */
	x_smbd_requ_t *smbd_requ = X_CONTAINER_OF(timer,
			x_smbd_requ_t, interim_timer);
	x_smbd_conn_post_interim(smbd_requ);
	return -1;
}

x_smbd_requ_t::x_smbd_requ_t(x_buf_t *in_buf, uint32_t in_msgsize,
		bool encrypted)
	: interim_timer(interim_timeout_func), in_buf(in_buf)
	, compound_id(X_SMBD_COUNTER_INC_CREATE(requ, 1) + 1)
	, in_msgsize(in_msgsize)
	, encrypted(encrypted)
{
}

x_smbd_requ_t::~x_smbd_requ_t()
{
	X_SMBD_REQU_LOG(DBG, this, " freed");
	x_buf_release(in_buf);

	while (out_buf_head) {
		auto next = out_buf_head->next;
		delete out_buf_head;
		out_buf_head = next;
	}

	x_ref_dec_if(smbd_open);
	x_ref_dec_if(smbd_tcon);
	x_ref_dec_if(smbd_chan);
	x_ref_dec_if(smbd_sess);
	X_SMBD_COUNTER_INC_DELETE(requ, 1);
}

template <>
x_smbd_requ_t *x_ref_inc(x_smbd_requ_t *smbd_requ)
{
	g_smbd_requ_table->incref(smbd_requ->id);
	return smbd_requ;
}

template <>
void x_ref_dec(x_smbd_requ_t *smbd_requ)
{
	g_smbd_requ_table->decref(smbd_requ->id);
}

x_smbd_requ_t *x_smbd_requ_create(x_buf_t *in_buf, uint32_t in_msgsize,
		bool encrypted)
{
	auto smbd_requ = new x_smbd_requ_t(in_buf, in_msgsize, encrypted);
	if (!g_smbd_requ_table->store(smbd_requ, smbd_requ->id)) {
		delete smbd_requ;
		return nullptr;
	}
	X_SMBD_REQU_LOG(DBG, smbd_requ, " created");
	return smbd_requ;
}

uint64_t x_smbd_requ_get_async_id(const x_smbd_requ_t *smbd_requ)
{
	X_ASSERT(smbd_requ->interim_state == x_smbd_requ_t::INTERIM_S_SENT);
	return smbd_requ->id;
}

x_smbd_requ_t *x_smbd_requ_lookup(uint64_t id)
{
	auto [found, smbd_requ] = g_smbd_requ_table->lookup(id);
	if (!found) {
		return nullptr;
	}
	return smbd_requ;
}

x_smbd_requ_t *x_smbd_requ_async_lookup(uint64_t id, const x_smbd_conn_t *smbd_conn, bool remove)
{
	/* skip client_guid checking, since session bind is signed,
	 * the check does not improve security
	 */
	auto [found, smbd_requ] = g_smbd_requ_table->lookup(id);
	if (!found) {
		return nullptr;
	}

	if (x_smbd_chan_get_conn(smbd_requ->smbd_chan) != smbd_conn || !smbd_requ->cancel_fn) {
		x_ref_dec(smbd_requ);
		return nullptr;
	}

	if (remove) {
		x_ref_dec(smbd_requ);
	}
	return smbd_requ;
}

void x_smbd_requ_async_done(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
		NTSTATUS status)
{
	if (!x_smbd_requ_async_remove(smbd_requ)) {
		/* it must be cancelled by x_smbd_conn_cancel */
	}
	auto state = smbd_requ->release_state();
	state->async_done(smbd_conn, smbd_requ, status);
}

void x_smbd_requ_done(x_smbd_requ_t *smbd_requ)
{
	X_SMBD_REQU_LOG(DBG, smbd_requ, "");
	smbd_requ->id = g_smbd_requ_table->remove(smbd_requ->id);
	smbd_requ->done = true;
}

int x_smbd_requ_pool_init(uint32_t count)
{
	g_smbd_requ_table = new smbd_requ_table_t(count);
	return 0;
}

NTSTATUS x_smbd_requ_init_open(x_smbd_requ_t *smbd_requ,
		uint64_t id_persistent, uint64_t id_volatile,
		bool modify_call)
{
	if (!smbd_requ->smbd_open && !x_smb2_file_id_is_nul(id_persistent,
				id_volatile)) {
		smbd_requ->smbd_open = x_smbd_open_lookup(
				id_persistent,
				id_volatile,
				smbd_requ->smbd_tcon);
	}

	if (smbd_requ->smbd_open) {
		return x_smbd_conn_dispatch_update_counts(smbd_requ,
				modify_call);
	}

	if (smbd_requ->is_compound_related() && !NT_STATUS_IS_OK(smbd_requ->status)) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, smbd_requ->status);
	} else {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_FILE_CLOSED);
	}
}

struct x_smbd_requ_list_t : x_ctrl_handler_t
{
	x_smbd_requ_list_t() : iter(g_smbd_requ_table->iter_start()) {
	}
	bool output(std::string &data) override;
	smbd_requ_table_t::iter_t iter;
};

bool x_smbd_requ_list_t::output(std::string &data)
{
	std::ostringstream os;

	bool ret = g_smbd_requ_table->iter_entry(iter, [&os](const x_smbd_requ_t *smbd_requ) {
			/* TODO list channels */
			os << idl::x_hex_t<uint64_t>(smbd_requ->id) << ' '
			<< idl::x_hex_t<uint64_t>(smbd_requ->in_smb2_hdr.mid);
			os << std::endl;
			return true;
		});
	if (ret) {
		data = os.str(); // TODO avoid copying
		return true;
	} else {
		return false;
	}
}

x_ctrl_handler_t *x_smbd_requ_list_create()
{
	return new x_smbd_requ_list_t;
}


struct x_smbd_open_release_evt_t
{
	static void func(void *arg, x_fdevt_user_t *fdevt_user)
	{
		X_ASSERT(!arg);
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

void x_smbd_schedule_release_open(x_smbd_open_t *smbd_open)
{
	x_smbd_open_release_evt_t *evt = new x_smbd_open_release_evt_t(smbd_open);
	x_nxfsd_schedule(&evt->base);
}

struct x_smbd_lease_release_evt_t
{
	static void func(void *arg, x_fdevt_user_t *fdevt_user)
	{
		X_ASSERT(!arg);
		x_smbd_lease_release_evt_t *evt = X_CONTAINER_OF(fdevt_user,
				x_smbd_lease_release_evt_t, base);
		x_smbd_lease_close(evt->smbd_lease);
		delete evt;
	}

	explicit x_smbd_lease_release_evt_t(x_smbd_lease_t *smbd_lease)
		: base(func), smbd_lease(smbd_lease)
	{
	}

	x_fdevt_user_t base;
	x_smbd_lease_t * const smbd_lease;
};

void x_smbd_schedule_release_lease(x_smbd_lease_t *smbd_lease)
{
	x_smbd_lease_release_evt_t *evt = new x_smbd_lease_release_evt_t(smbd_lease);
	x_nxfsd_schedule(&evt->base);
}

struct x_smbd_wakeup_oplock_pending_list_evt_t
{
	static void func(void *arg, x_fdevt_user_t *fdevt_user)
	{
		X_ASSERT(!arg);
		x_smbd_wakeup_oplock_pending_list_evt_t *evt = X_CONTAINER_OF(fdevt_user,
				x_smbd_wakeup_oplock_pending_list_evt_t, base);
		x_smbd_wakeup_requ_list(evt->oplock_pending_list);
		delete evt;
	}

	explicit x_smbd_wakeup_oplock_pending_list_evt_t(x_smbd_requ_id_list_t &oplock_pending_list)
		: base(func), oplock_pending_list(std::move(oplock_pending_list))
	{
	}

	x_fdevt_user_t base;
	x_smbd_requ_id_list_t oplock_pending_list;
};

void x_smbd_schedule_wakeup_oplock_pending_list(x_smbd_requ_id_list_t &oplock_pending_list)
{
	x_smbd_wakeup_oplock_pending_list_evt_t *evt =
		new x_smbd_wakeup_oplock_pending_list_evt_t(oplock_pending_list);
	x_nxfsd_schedule(&evt->base);
}

struct x_smbd_clean_pending_requ_list_evt_t
{
	static void func(void *arg, x_fdevt_user_t *fdevt_user)
	{
		X_ASSERT(!arg);
		x_smbd_clean_pending_requ_list_evt_t *evt = X_CONTAINER_OF(fdevt_user,
				x_smbd_clean_pending_requ_list_evt_t, base);
		x_smbd_requ_t *smbd_requ;
		while ((smbd_requ = evt->pending_requ_list.get_front()) != nullptr) {
			evt->pending_requ_list.remove(smbd_requ);
			x_smbd_conn_post_cancel(x_smbd_chan_get_conn(smbd_requ->smbd_chan),
					smbd_requ, smbd_requ->status);
		}

		delete evt;
	}

	explicit x_smbd_clean_pending_requ_list_evt_t(x_tp_ddlist_t<requ_async_traits> &pending_requ_list)
		: base(func), pending_requ_list(std::move(pending_requ_list))
	{
	}

	x_fdevt_user_t base;
	x_tp_ddlist_t<requ_async_traits> pending_requ_list;
};

void x_smbd_schedule_clean_pending_requ_list(x_tp_ddlist_t<requ_async_traits> &pending_requ_list)
{
	x_smbd_clean_pending_requ_list_evt_t *evt =
		new x_smbd_clean_pending_requ_list_evt_t(pending_requ_list);
	x_nxfsd_schedule(&evt->base);
}

struct x_smbd_notify_evt_t
{
	static void func(void *arg, x_fdevt_user_t *fdevt_user)
	{
		X_ASSERT(!arg);
		x_smbd_notify_evt_t *evt = X_CONTAINER_OF(fdevt_user,
				x_smbd_notify_evt_t, base);
		x_smbd_notify_change(evt->smbd_object,
				evt->action,
				evt->filter,
				evt->ignore_lease_key,
				evt->client_guid,
				evt->path_base,
				evt->new_path_base);
		delete evt;
	}

	explicit x_smbd_notify_evt_t(x_smbd_object_t *parent_object,
			uint32_t action, uint32_t filter,
			const x_smb2_lease_key_t &ignore_lease_key,
			const x_smb2_uuid_t &client_guid,
			const std::u16string &path_base,
			const std::u16string &new_path_base)
		: base(func), smbd_object(parent_object)
		, action(action), filter(filter)
		, ignore_lease_key(ignore_lease_key)
		, client_guid(client_guid)
		, path_base(path_base)
		, new_path_base(new_path_base)
	{
		smbd_object->incref();
	}

	~x_smbd_notify_evt_t()
	{
		x_smbd_release_object(smbd_object);
	}

	x_fdevt_user_t base;
	x_smbd_object_t * const smbd_object;
	const uint32_t action;
	const uint32_t filter;
	const x_smb2_lease_key_t ignore_lease_key;
	const x_smb2_uuid_t client_guid;
	std::u16string path_base;
	std::u16string new_path_base;
};

static void x_smbd_schedule_notify_evt(x_smbd_object_t *parent_object,
		uint32_t action, uint32_t filter,
		const x_smb2_lease_key_t &ignore_lease_key,
		const x_smb2_uuid_t &client_guid,
		const std::u16string &path_base,
		const std::u16string &new_path_base)
{
	x_smbd_notify_evt_t *evt = new x_smbd_notify_evt_t(parent_object,
			action, filter, ignore_lease_key, client_guid,
			path_base, new_path_base);
	x_nxfsd_schedule(&evt->base);
}

void x_smbd_schedule_notify(
		uint32_t notify_action,
		uint32_t notify_filter,
		const x_smb2_lease_key_t &ignore_lease_key,
		const x_smb2_uuid_t &client_guid,
		x_smbd_object_t *parent_object,
		x_smbd_object_t *new_parent_object,
		const std::u16string &path_base,
		const std::u16string &new_path_base)
{
	if (!parent_object) {
		return;
	}

	if (new_parent_object) {
		X_ASSERT(notify_action == NOTIFY_ACTION_OLD_NAME);

		if (new_parent_object == parent_object) {
			x_smbd_schedule_notify_evt(parent_object,
					notify_action,
					notify_filter,
					ignore_lease_key,
					client_guid,
					path_base, new_path_base);
		} else {
			x_smbd_schedule_notify_evt(parent_object,
					NOTIFY_ACTION_REMOVED,
					notify_filter,
					ignore_lease_key,
					client_guid,
					path_base, u"");
			x_smbd_schedule_notify_evt(new_parent_object,
					NOTIFY_ACTION_ADDED,
					notify_filter,
					{},
					{},
					new_path_base, u"");
		}
	} else {
		X_ASSERT(new_path_base.empty());
		X_ASSERT(notify_action != NOTIFY_ACTION_OLD_NAME);
		x_smbd_schedule_notify_evt(parent_object,
				notify_action,
				notify_filter,
				ignore_lease_key,
				client_guid,
				path_base, new_path_base);
	}
}
