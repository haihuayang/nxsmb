
#include "smbd.hxx"
#include "smbd_stats.hxx"
#include "smbd_ctrl.hxx"
#include "include/idtable.hxx"

using smbd_requ_table_t = x_idtable_t<x_smbd_requ_t, x_idtable_64_traits_t>;
static smbd_requ_table_t *g_smbd_requ_table;

x_smbd_requ_t::x_smbd_requ_t(x_buf_t *in_buf, uint32_t in_msgsize)
	: in_buf(in_buf), in_msgsize(in_msgsize)
{
	X_LOG_DBG("create %p", this);
	X_SMBD_COUNTER_INC(requ_create, 1);
}

x_smbd_requ_t::~x_smbd_requ_t()
{
	X_LOG_DBG("free %p", this);
	X_ASSERT(!requ_state);
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
	X_SMBD_COUNTER_INC(requ_delete, 1);
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

x_smbd_requ_t *x_smbd_requ_create(x_buf_t *in_buf, uint32_t in_msgsize)
{
	auto smbd_requ = new x_smbd_requ_t(in_buf, in_msgsize);
	if (!g_smbd_requ_table->store(smbd_requ, smbd_requ->id)) {
		delete smbd_requ;
		return nullptr;
	}
	X_LOG_DBG("0x%lx %p", smbd_requ->id, smbd_requ);
	return smbd_requ;
}

uint64_t x_smbd_requ_get_async_id(const x_smbd_requ_t *smbd_requ)
{
	if (!smbd_requ->async) {
		return 0;
	}
	return smbd_requ->id;
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

	if (x_smbd_chan_get_conn(smbd_requ->smbd_chan) != smbd_conn) {
		x_smbd_ref_dec(smbd_requ);
		return nullptr;
	}

	if (remove) {
		x_smbd_ref_dec(smbd_requ);
	}
	return smbd_requ;
}

/* must be in context of smbd_conn */
void x_smbd_requ_async_insert(x_smbd_requ_t *smbd_requ,
		void (*cancel_fn)(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ))
{
	X_ASSERT(!smbd_requ->cancel_fn);
	smbd_requ->cancel_fn = cancel_fn;
	smbd_requ->async = true;
	x_smbd_ref_inc(smbd_requ);
}

/* must be in context of smbd_conn */
bool x_smbd_requ_async_remove(x_smbd_requ_t *smbd_requ)
{
	X_ASSERT(smbd_requ->async);
	if (!smbd_requ->cancel_fn) {
		return false;
	}
	smbd_requ->cancel_fn = nullptr;
	x_smbd_ref_dec(smbd_requ);
	return true;
}

void x_smbd_requ_async_done(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
		NTSTATUS status, bool terminated)
{
	if (!x_smbd_requ_async_remove(smbd_requ)) {
		/* it must be cancelled by x_smbd_conn_cancel */
		X_ASSERT(NT_STATUS_EQUAL(status, NT_STATUS_CANCELLED));
	}
	smbd_requ->async_done_fn(smbd_conn, smbd_requ, status, terminated);
}

void x_smbd_requ_done(x_smbd_requ_t *smbd_requ)
{
	smbd_requ->id = g_smbd_requ_table->remove(smbd_requ->id);
}

int x_smbd_requ_pool_init(uint32_t count)
{
	g_smbd_requ_table = new smbd_requ_table_t(count);
	return 0;
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
			<< idl::x_hex_t<uint64_t>(smbd_requ->in_mid);
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

