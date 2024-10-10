
#include "smbd.hxx"
#include "smbd_stats.hxx"
#include "smbd_ctrl.hxx"
#include "smbd_open.hxx"
#include "smbd_replay.hxx"
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

struct x_smbd_notify_t
{
	x_smbd_object_t *smbd_object;
	uint32_t action;
	uint32_t filter;
	x_smb2_lease_key_t ignore_lease_key;
	x_smb2_uuid_t client_guid;
	std::u16string path_base;
	std::u16string new_path_base;
};

struct x_smbd_defer_t
{
	uint32_t seqno = 0, last_seqno = 0;
	bool is_schedulable = false;
	std::vector<x_smbd_open_t *> smbd_opens;
	std::vector<x_smbd_lease_t *> smbd_leases;
	x_tp_ddlist_t<requ_async_traits> pending_requ_list;
	x_smbd_requ_id_list_t oplock_pending_list;
	std::vector<x_smbd_notify_t> smbd_notifies;
};

static thread_local x_smbd_defer_t g_smbd_defer;

static void x_smbd_set_schedulable(bool f)
{
	X_ASSERT(g_smbd_defer.is_schedulable != f);
	g_smbd_defer.is_schedulable = f;
}

x_smbd_scheduler_t::x_smbd_scheduler_t()
{
	x_smbd_set_schedulable(true);
}

static void smbd_defer_exec()
{
	x_tp_ddlist_t<requ_async_traits> pending_requ_list =
		std::move(g_smbd_defer.pending_requ_list);
	x_smbd_requ_t *smbd_requ;
	while ((smbd_requ = pending_requ_list.get_front()) != nullptr) {
		pending_requ_list.remove(smbd_requ);
		x_smbd_conn_post_cancel(x_smbd_chan_get_conn(smbd_requ->smbd_chan),
				smbd_requ, smbd_requ->status);
	}

	std::vector<x_smbd_lease_t *> smbd_leases = std::move(g_smbd_defer.smbd_leases);
	for (auto smbd_lease: smbd_leases) {
		x_smbd_lease_close(smbd_lease);
	}

	std::vector<x_smbd_open_t *> smbd_opens = std::move(g_smbd_defer.smbd_opens);
	for (auto smbd_open: smbd_opens) {
		x_smbd_open_release(smbd_open);
	}

	std::vector<x_smbd_notify_t> smbd_notifies = std::move(g_smbd_defer.smbd_notifies);
	for (auto &notify: smbd_notifies) {
		x_smbd_notify_change(notify.smbd_object,
				notify.action,
				notify.filter,
				notify.ignore_lease_key,
				notify.client_guid,
				notify.path_base,
				notify.new_path_base);
		x_smbd_release_object(notify.smbd_object);
	}

	x_smbd_requ_id_list_t oplock_pending_list = std::move(g_smbd_defer.oplock_pending_list);
	x_smbd_wakeup_requ_list(oplock_pending_list);
}

void x_smbd_schedule_release_open(x_smbd_open_t *smbd_open)
{
	X_ASSERT(g_smbd_defer.is_schedulable);
	g_smbd_defer.smbd_opens.push_back(smbd_open);
	++g_smbd_defer.seqno;
}

void x_smbd_schedule_release_lease(x_smbd_lease_t *smbd_lease)
{
	X_ASSERT(g_smbd_defer.is_schedulable);
	g_smbd_defer.smbd_leases.push_back(smbd_lease);
	++g_smbd_defer.seqno;
}

void x_smbd_schedule_wakeup_oplock_pending_list(x_smbd_requ_id_list_t &oplock_pending_list)
{
	X_ASSERT(g_smbd_defer.is_schedulable);
	if (!oplock_pending_list.empty()) {
		if (g_smbd_defer.oplock_pending_list.empty()) {
			std::swap(g_smbd_defer.oplock_pending_list, oplock_pending_list);
		} else {
			std::move(oplock_pending_list.begin(),
					oplock_pending_list.end(),
					std::back_inserter(g_smbd_defer.oplock_pending_list));
			oplock_pending_list.clear(); // TODO needed after std::move?
		}
		++g_smbd_defer.seqno;
	}
}

void x_smbd_schedule_clean_pending_requ_list(x_tp_ddlist_t<requ_async_traits> &pending_requ_list)
{
	X_ASSERT(g_smbd_defer.is_schedulable);
	if (!pending_requ_list.empty()) {
		g_smbd_defer.pending_requ_list.concat(pending_requ_list);
		++g_smbd_defer.seqno;
	}
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
	X_ASSERT(g_smbd_defer.is_schedulable);
	if (!parent_object) {
		return;
	}

	if (new_parent_object) {
		X_ASSERT(notify_action == NOTIFY_ACTION_OLD_NAME);

		if (new_parent_object == parent_object) {
			parent_object->incref();
			g_smbd_defer.smbd_notifies.push_back(x_smbd_notify_t{parent_object,
					notify_action,
					notify_filter,
					ignore_lease_key,
					client_guid,
					path_base, new_path_base});
		} else {
			parent_object->incref();
			new_parent_object->incref();
			g_smbd_defer.smbd_notifies.push_back(x_smbd_notify_t{parent_object,
					NOTIFY_ACTION_REMOVED,
					notify_filter,
					ignore_lease_key,
					client_guid,
					path_base, u""});
			g_smbd_defer.smbd_notifies.push_back(x_smbd_notify_t{new_parent_object,
					NOTIFY_ACTION_ADDED,
					notify_filter,
					{},
					{},
					new_path_base, u""});
		}
	} else {
		X_ASSERT(new_path_base.empty());
		X_ASSERT(notify_action != NOTIFY_ACTION_OLD_NAME);
		parent_object->incref();
		g_smbd_defer.smbd_notifies.push_back(x_smbd_notify_t{parent_object,
				notify_action,
				notify_filter,
				ignore_lease_key,
				client_guid,
				path_base, new_path_base});
	}
	++g_smbd_defer.seqno;
}

x_smbd_scheduler_t::~x_smbd_scheduler_t()
{
	while (g_smbd_defer.seqno != g_smbd_defer.last_seqno) {
		g_smbd_defer.last_seqno = g_smbd_defer.seqno;
		smbd_defer_exec();
	}
	x_smbd_set_schedulable(false);
}

