
#include "smbd.hxx"
#include "smbd_ctrl.hxx"
#include "include/idtable.hxx"

static x_idtable_t<x_smbd_tcon_t, x_idtable_32_traits_t> *g_smbd_tcon_table;

struct x_smbd_tcon_ops_t;
struct x_smbd_tcon_t
{ 
	x_smbd_tcon_t(x_smbd_sess_t *smbd_sess,
			const std::shared_ptr<x_smbd_share_t> &share,
			const x_smbd_tcon_ops_t *ops,
			uint32_t share_access)
       		: ops(ops), share_access(share_access)
		, smbd_sess(smbd_sess), smbd_share(share) {
	}

	x_smbd_share_type_t get_share_type() const {
		return smbd_share->type;
	}

	x_dqlink_t hash_link;
	x_dlink_t sess_link;
	const x_smbd_tcon_ops_t * const ops;
	uint32_t tid;
	const uint32_t share_access;
	x_smbd_sess_t * const smbd_sess;
	std::shared_ptr<x_smbd_share_t> smbd_share;
	x_tp_ddlist_t<open_tcon_traits> open_list;
};
X_DECLARE_MEMBER_TRAITS(tcon_sess_traits, x_smbd_tcon_t, sess_link)

template <>
x_smbd_tcon_t *x_smbd_ref_inc(x_smbd_tcon_t *smbd_tcon)
{
	g_smbd_tcon_table->incref(smbd_tcon->tid);
	return smbd_tcon;
}

template <>
void x_smbd_ref_dec(x_smbd_tcon_t *smbd_tcon)
{
	g_smbd_tcon_table->decref(smbd_tcon->tid);
}

x_smbd_tcon_t *x_smbd_tcon_create(x_smbd_sess_t *smbd_sess, 
		const std::shared_ptr<x_smbd_share_t> &smbshare,
		uint32_t share_access)
{
	const x_smbd_tcon_ops_t *ops = (smbshare->type == TYPE_IPC) ?
		x_smbd_ipc_get_tcon_ops() : x_smbd_posixfs_get_tcon_ops();
	x_smbd_tcon_t *smbd_tcon = new x_smbd_tcon_t(smbd_sess, smbshare, ops, share_access);
	if (!g_smbd_tcon_table->store(smbd_tcon, smbd_tcon->tid)) {
		delete smbd_tcon;
		return nullptr;
	}
	x_smbd_ref_inc(smbd_tcon);
	x_smbd_sess_link_tcon(smbd_sess, &smbd_tcon->sess_link);
	return smbd_tcon;
}

uint32_t x_smbd_tcon_get_id(const x_smbd_tcon_t *smbd_tcon)
{
	return smbd_tcon->tid;
}

bool x_smbd_tcon_access_check(const x_smbd_tcon_t *smbd_tcon, uint32_t desired_access)
{
	return (desired_access & ~smbd_tcon->share_access) == 0;
}

bool x_smbd_tcon_match(const x_smbd_tcon_t *smbd_tcon, const x_smbd_sess_t *smbd_sess, uint32_t tid)
{
	return smbd_tcon->smbd_sess == smbd_sess && smbd_tcon->tid == tid;
}

std::shared_ptr<x_smbd_share_t> x_smbd_tcon_get_share(const x_smbd_tcon_t *smbd_tcon)
{
	return smbd_tcon->smbd_share;
}

x_smbd_tcon_t *x_smbd_tcon_find(uint32_t id, const x_smbd_sess_t *smbd_sess)
{
	auto ret = g_smbd_tcon_table->lookup(id);
	if (!ret.first) {
		return nullptr;
	}
	if (ret.second->smbd_sess == smbd_sess) {
		return ret.second;
	} else {
		g_smbd_tcon_table->decref(id);
	}
	return nullptr;
}

NTSTATUS x_smbd_tcon_op_create(x_smbd_tcon_t *smbd_tcon,
		x_smbd_open_t **psmbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state)
{
       	x_smbd_open_t *smbd_open = nullptr;
	NTSTATUS status = smbd_tcon->ops->create(smbd_tcon, psmbd_open, smbd_requ, state);
	if (smbd_open) {
		X_ASSERT(!smbd_requ->smbd_open);
		smbd_requ->smbd_open = smbd_open;
		x_smbd_open_insert_local(smbd_open);
		X_ASSERT(smbd_open->smbd_tcon); // initialized in side op_create
		smbd_requ->smbd_tcon->open_list.push_back(smbd_open);
		x_smbd_ref_inc(smbd_open);
	}
	return status;
}


int x_smbd_tcon_table_init(uint32_t count)
{
	g_smbd_tcon_table = new x_idtable_t<x_smbd_tcon_t, x_idtable_32_traits_t>(count);
	return 0;
}

void x_smbd_tcon_remove_open(x_smbd_tcon_t *smbd_tcon, x_smbd_open_t *smbd_open)
{
	smbd_tcon->open_list.remove(smbd_open);
}

struct x_smbd_tcon_list_t : x_smbd_ctrl_handler_t
{
	x_smbd_tcon_list_t() : iter(g_smbd_tcon_table->iter_start()) {
	}
	bool output(std::string &data) override;
	x_idtable_t<x_smbd_tcon_t, x_idtable_32_traits_t>::iter_t iter;
};

bool x_smbd_tcon_list_t::output(std::string &data)
{
	std::ostringstream os;

	bool ret = g_smbd_tcon_table->iter_entry(iter, [&os](const x_smbd_tcon_t *smbd_tcon) {
			std::shared_ptr<x_smbd_share_t> smbshare = smbd_tcon->smbd_share;
			os << idl::x_hex_t<uint32_t>(smbd_tcon->tid) << ' ' << idl::x_hex_t<uint32_t>(smbd_tcon->share_access) << ' ' << smbshare->name << std::endl;
			return true;
		});
	if (ret) {
		data = os.str(); // TODO avoid copying
		return true;
	} else {
		return false;
	}
}

x_smbd_ctrl_handler_t *x_smbd_tcon_list_create()
{
	return new x_smbd_tcon_list_t;
}

