
#include "smbd.hxx"
#include "smbd_stats.hxx"
#include "smbd_ctrl.hxx"
#include "smbd_open.hxx"
#include "include/idtable.hxx"

using smbd_requ_table_t = x_idtable_t<x_smbd_requ_t, x_idtable_64_traits_t>;
static smbd_requ_table_t *g_smbd_requ_table;

x_smbd_requ_state_create_t::x_smbd_requ_state_create_t(const x_smb2_uuid_t &client_guid)
	: in_client_guid(client_guid), in_create_guid{0, 0}
{
}

x_smbd_requ_state_create_t::~x_smbd_requ_state_create_t()
{
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
	X_LOG_DBG("create %p", this);
}

x_smbd_requ_t::~x_smbd_requ_t()
{
	X_LOG_DBG("free %p", this);
	x_buf_release(in_buf);

	while (out_buf_head) {
		auto next = out_buf_head->next;
		delete out_buf_head;
		out_buf_head = next;
	}

	x_smbd_ref_dec_if(smbd_open);
	x_smbd_ref_dec_if(smbd_tcon);
	x_smbd_ref_dec_if(smbd_chan);
	x_smbd_ref_dec_if(smbd_sess);
	X_SMBD_COUNTER_INC_DELETE(requ, 1);
}

template <>
x_smbd_requ_t *x_smbd_ref_inc(x_smbd_requ_t *smbd_requ)
{
	g_smbd_requ_table->incref(smbd_requ->id);
	return smbd_requ;
}

template <>
void x_smbd_ref_dec(x_smbd_requ_t *smbd_requ)
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
	X_LOG_DBG(X_SMBD_REQU_DBG_FMT, X_SMBD_REQU_DBG_ARG(smbd_requ));
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
		x_smbd_ref_dec(smbd_requ);
		return nullptr;
	}

	if (remove) {
		x_smbd_ref_dec(smbd_requ);
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
	X_LOG_DBG(X_SMBD_REQU_DBG_FMT, X_SMBD_REQU_DBG_ARG(smbd_requ));
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
		RETURN_OP_STATUS(smbd_requ, smbd_requ->status);
	} else {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_FILE_CLOSED);
	}
}

struct x_smbd_requ_list_t : x_smbd_ctrl_handler_t
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

x_smbd_ctrl_handler_t *x_smbd_requ_list_create()
{
	return new x_smbd_requ_list_t;
}

