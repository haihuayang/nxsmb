
#include "nxfsd.hxx"
#include "nxfsd_stats.hxx"
#include "smbd_ctrl.hxx"
#include "smbd_replay.hxx"
#include "smbd_open.hxx"
#include "include/idtable.hxx"

	enum {
		S_INIT,
		S_PROCESSING,
		S_CANCELLED,
		S_DONE,
	};

struct nxfsd_requ_deleter_t {
	void operator()(x_nxfsd_requ_t *nxfsd_requ) {
		delete nxfsd_requ;
	}
};

using nxfsd_requ_table_t = x_idtable_t<x_nxfsd_requ_t, x_idtable_64_traits_t,
      nxfsd_requ_deleter_t>;
static nxfsd_requ_table_t *g_nxfsd_requ_table;

static long interim_timeout_func(x_timer_job_t *timer)
{
	/* we already have a ref on smbd_chan when adding timer */
	x_nxfsd_requ_t *nxfsd_requ = X_CONTAINER_OF(timer,
			x_nxfsd_requ_t, interim_timer);
	x_nxfsd_requ_post_interim(nxfsd_requ);
	return -1;
}

x_nxfsd_requ_t::x_nxfsd_requ_t(
		x_nxfsd_conn_t *nxfsd_conn,
		x_in_buf_t &in_buf, uint32_t in_msgsize)
	: interim_timer(interim_timeout_func)
	, nxfsd_conn(x_ref_inc(nxfsd_conn))
	, start(x_tick_now())
	, async_state(S_INIT)
	, requ_in_buf(std::move(in_buf)), in_msgsize(in_msgsize)
{
}

x_nxfsd_requ_t::~x_nxfsd_requ_t()
{
	x_ref_dec_if(smbd_open);
	x_ref_dec(nxfsd_conn);
}

void x_nxfsd_requ_t::incref()
{
	g_nxfsd_requ_table->incref(id);
}

void x_nxfsd_requ_t::decref()
{
	g_nxfsd_requ_table->decref(id);
}

void x_nxfsd_requ_t::cancel(void *ctx_conn, int reason)
{
	uint32_t old_val = S_INIT;
	if (!std::atomic_compare_exchange_strong(&async_state,
				&old_val, S_CANCELLED)) {
		return;
	}
	NTSTATUS status = cancelled(ctx_conn, reason);
	async_done(ctx_conn, status);
}

bool x_nxfsd_requ_t::set_processing()
{
	uint32_t old_val = S_INIT;
	return std::atomic_compare_exchange_strong(&async_state,
			&old_val, S_PROCESSING);
}

void x_nxfsd_requ_t::set_open(x_smbd_open_t *open)
{
	X_ASSERT(!smbd_open);
	smbd_open = x_ref_inc(open);
}

bool x_nxfsd_requ_store(x_nxfsd_requ_t *nxfsd_requ)
{
	return g_nxfsd_requ_table->store(nxfsd_requ, nxfsd_requ->id);
}

void x_nxfsd_requ_remove(x_nxfsd_requ_t *nxfsd_requ)
{
	X_NXFSD_REQU_LOG(DBG, nxfsd_requ, "");
	nxfsd_requ->async_state.store(S_DONE, std::memory_order_relaxed);
	nxfsd_requ->id = g_nxfsd_requ_table->remove(nxfsd_requ->id);
}

x_nxfsd_requ_t *x_nxfsd_requ_async_lookup(uint64_t id,
		const x_nxfsd_conn_t *nxfsd_conn, bool remove)
{
	/* skip client_guid checking, since session bind is signed,
	 * the check does not improve security
	 */
	auto [found, nxfsd_requ] = g_nxfsd_requ_table->lookup(id);
	if (!found) {
		return nullptr;
	}

	if (nxfsd_requ->nxfsd_conn != nxfsd_conn) {
		nxfsd_requ->decref();
		return nullptr;
	}

	if (remove) {
		nxfsd_requ->decref();
	}
	return nxfsd_requ;
}

static void x_nxfsd_requ_async_done(void *ctx_conn, x_nxfsd_requ_t *nxfsd_requ,
		NTSTATUS status)
{
	nxfsd_requ->async_done(ctx_conn, status);
}

x_nxfsd_requ_t *x_nxfsd_requ_lookup(uint64_t id)
{
	auto [found, nxfsd_requ] = g_nxfsd_requ_table->lookup(id);
	if (!found) {
		return nullptr;
	}
	return nxfsd_requ;
}

uint64_t x_nxfsd_requ_get_async_id(const x_nxfsd_requ_t *nxfsd_requ)
{
	X_ASSERT(nxfsd_requ->interim_state == x_nxfsd_requ_t::INTERIM_S_SENT);
	return nxfsd_requ->id;
}

static void x_nxfsd_requ_resume(void *ctx_conn, x_nxfsd_requ_t *nxfsd_requ)
{
	NTSTATUS status = NT_STATUS_CANCELLED;
	/* TODO review the state transition of requ */
	if (nxfsd_requ->async_state.load(std::memory_order_relaxed) != S_INIT) {
		return;
	}
	if (ctx_conn) {
		status = nxfsd_requ->process(ctx_conn);
	}
	X_NXFSD_REQU_LOG(DBG, nxfsd_requ, " ctx_conn=%p status=%s",
			ctx_conn, x_ntstatus_str(status));
	if (status != NT_STATUS_PENDING) {
		x_nxfsd_requ_async_done(ctx_conn, nxfsd_requ, status);
	}
}

struct requ_resume_evt_t
{
	static void func(void *ctx_conn, x_fdevt_user_t *fdevt_user)
	{
		requ_resume_evt_t *evt = X_CONTAINER_OF(fdevt_user,
				requ_resume_evt_t, base);
		x_nxfsd_requ_t *nxfsd_requ = evt->nxfsd_requ;
		x_nxfsd_requ_resume(ctx_conn, nxfsd_requ);
		delete evt;
	}

	explicit requ_resume_evt_t(x_nxfsd_requ_t *nxfsd_requ)
		: base(func), nxfsd_requ(nxfsd_requ)
	{
	}

	~requ_resume_evt_t()
	{
		nxfsd_requ->decref();
	}

	x_fdevt_user_t base;
	x_nxfsd_requ_t * const nxfsd_requ;
};

void x_nxfsd_requ_post_resume(x_nxfsd_requ_t *nxfsd_requ)
{
	X_NXFSD_REQU_POST_USER(nxfsd_requ, new requ_resume_evt_t(nxfsd_requ));
}

struct requ_done_evt_t
{
	static void func(void *ctx_conn, x_fdevt_user_t *fdevt_user)
	{
		requ_done_evt_t *evt = X_CONTAINER_OF(fdevt_user,
				requ_done_evt_t, base);
		x_nxfsd_requ_t *nxfsd_requ = evt->nxfsd_requ;
		X_NXFSD_REQU_LOG(DBG, nxfsd_requ, " ctx_conn=%p", ctx_conn);

		x_nxfsd_requ_async_done(ctx_conn, nxfsd_requ, evt->status);

		delete evt;
	}

	explicit requ_done_evt_t(x_nxfsd_requ_t *nxfsd_requ, NTSTATUS status)
		: base(func), nxfsd_requ(nxfsd_requ), status(status)
	{
	}

	~requ_done_evt_t()
	{
		if (nxfsd_requ) {
			nxfsd_requ->decref();
		}
	}

	x_fdevt_user_t base;
	x_nxfsd_requ_t * nxfsd_requ;
	NTSTATUS const status;
};

void x_nxfsd_requ_post_done(x_nxfsd_requ_t *nxfsd_requ, NTSTATUS status)
{
	X_NXFSD_REQU_POST_USER(nxfsd_requ, new requ_done_evt_t(nxfsd_requ, status));
}

struct x_nxfsd_requ_list_t : x_ctrl_handler_t
{
	x_nxfsd_requ_list_t() : iter(g_nxfsd_requ_table->iter_start()) {
	}
	bool output(std::string &data) override;
	nxfsd_requ_table_t::iter_t iter;
};

bool x_nxfsd_requ_list_t::output(std::string &data)
{
	std::ostringstream os;

	bool ret = g_nxfsd_requ_table->iter_entry(iter, [&os](const x_nxfsd_requ_t *nxfsd_requ) {
			os << idl::x_hex_t<uint64_t>(nxfsd_requ->id) << ' '
			<< (*nxfsd_requ) << std::endl;
			return true;
		});
	if (ret) {
		data = os.str(); // TODO avoid copying
		return true;
	} else {
		return false;
	}
}

x_ctrl_handler_t *x_nxfsd_requ_list_create()
{
	return new x_nxfsd_requ_list_t;
}

int x_nxfsd_requ_pool_init(uint32_t count)
{
	g_nxfsd_requ_table = new nxfsd_requ_table_t(count);
	return 0;
}

x_nxfsd_requ_state_open_t::x_nxfsd_requ_state_open_t(const x_smb2_uuid_t &client_guid,
		uint32_t server_capabilities)
	: client_guid(client_guid), server_capabilities(server_capabilities)
{
}

x_nxfsd_requ_state_open_t::~x_nxfsd_requ_state_open_t()
{
	if (replay_reserved) {
		x_smbd_replay_cache_clear(client_guid, in_context.create_guid);
	}
	if (smbd_object) {
		x_smbd_release_object_and_stream(smbd_object, smbd_stream);
	}
	if (smbd_lease) {
		x_smbd_lease_release(smbd_lease);
	}
}


