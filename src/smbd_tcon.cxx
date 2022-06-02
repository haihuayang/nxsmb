
#include "smbd.hxx"
#include "smbd_ctrl.hxx"
#include "smbd_stats.hxx"
#include "smbd_open.hxx"
#include "include/idtable.hxx"
#include "smbd_share.hxx"

using smbd_tcon_table_t = x_idtable_t<x_smbd_tcon_t, x_idtable_32_traits_t>;
static smbd_tcon_table_t *g_smbd_tcon_table;

struct x_smbd_tcon_t
{ 
	x_smbd_tcon_t(x_smbd_sess_t *smbd_sess,
			const std::shared_ptr<x_smbd_share_t> &share,
			uint32_t share_access)
       		: share_access(share_access)
		, smbd_sess(x_smbd_ref_inc(smbd_sess)), smbd_share(share) {
		X_SMBD_COUNTER_INC(tcon_create, 1);
	}
	~x_smbd_tcon_t() {
		x_smbd_ref_dec(smbd_sess);
		X_SMBD_COUNTER_INC(tcon_delete, 1);
	}

	x_dlink_t sess_link; // protected by smbd_sess' mutex
	enum {
		S_ACTIVE,
		S_DONE,
	} state = S_ACTIVE;
	uint32_t tid;
	const uint32_t share_access;
	x_smbd_sess_t * const smbd_sess;
	std::shared_ptr<x_smbd_share_t> smbd_share;
	std::mutex mutex;
	x_ddlist_t open_list;
};

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
	x_smbd_tcon_t *smbd_tcon = new x_smbd_tcon_t(smbd_sess, smbshare, share_access);
	if (!g_smbd_tcon_table->store(smbd_tcon, smbd_tcon->tid)) {
		delete smbd_tcon;
		return nullptr;
	}
	if (!x_smbd_sess_link_tcon(smbd_sess, &smbd_tcon->sess_link)) {
		g_smbd_tcon_table->remove(smbd_tcon->tid);
		x_smbd_ref_dec(smbd_tcon);
		return nullptr;
	}
	x_smbd_ref_inc(smbd_tcon); // ref by smbd_sess list

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

x_smbd_sess_t *x_smbd_tcon_get_sess(const x_smbd_tcon_t *smbd_tcon)
{
	return x_smbd_ref_inc(smbd_tcon->smbd_sess);
}

std::shared_ptr<x_smbd_share_t> x_smbd_tcon_get_share(const x_smbd_tcon_t *smbd_tcon)
{
	return smbd_tcon->smbd_share;
}

x_smbd_tcon_t *x_smbd_tcon_lookup(uint32_t id, const x_smbd_sess_t *smbd_sess)
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
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state)
{
	X_ASSERT(!smbd_requ->smbd_open);
	if (!x_smbd_open_has_space()) {
		return NT_STATUS_INSUFFICIENT_RESOURCES;
	}

       	x_smbd_open_t *smbd_open = nullptr;
	/* TODO should we check the open limit before create the open */
	NTSTATUS status = smbd_tcon->smbd_share->create_open(&smbd_open, smbd_requ, state);
	if (smbd_open) {
		X_ASSERT(NT_STATUS_IS_OK(status));
		/* if client access the open from other channel now, it does not have
		 * link into smbd_tcon, probably we should call x_smbd_open_store in the last
		 */
		{
			std::lock_guard<std::mutex> lock(smbd_tcon->mutex);
			if (smbd_tcon->state != x_smbd_tcon_t::S_ACTIVE) {
				x_smbd_open_op_destroy(smbd_open);
				return NT_STATUS_NETWORK_NAME_DELETED;
			}
			smbd_tcon->open_list.push_back(&smbd_open->tcon_link);
		}
		if (!x_smbd_open_store(smbd_open)) {
			X_LOG_WARN("has no space for open although we create it");
			{
				std::lock_guard<std::mutex> lock(smbd_tcon->mutex);
				smbd_tcon->open_list.remove(&smbd_open->tcon_link);
			}
			x_smbd_open_op_destroy(smbd_open);
			return NT_STATUS_INSUFFICIENT_RESOURCES;
		}
		x_smbd_ref_inc(smbd_open); // ref by smbd_tcon open_list
		smbd_requ->smbd_open = x_smbd_ref_inc(smbd_open);
	}
	return status;
}

static bool smbd_tcon_terminate(x_smbd_tcon_t *smbd_tcon)
{
	std::unique_lock<std::mutex> lock(smbd_tcon->mutex);
	if (smbd_tcon->state == x_smbd_tcon_t::S_DONE) {
		/* this can happen if client logoff on one channel and
		 * tdis on another
		 */
		return false;
	}
	smbd_tcon->state = x_smbd_tcon_t::S_DONE;
	lock.unlock();

	g_smbd_tcon_table->remove(smbd_tcon->tid);
	x_smbd_ref_dec(smbd_tcon);

	x_dlink_t *link;
	lock.lock();
	while ((link = smbd_tcon->open_list.get_front()) != nullptr) {
		smbd_tcon->open_list.remove(link);
		lock.unlock();
		x_smbd_open_unlinked(link, smbd_tcon);
		lock.lock();
	}
	x_smbd_ref_dec(smbd_tcon); // ref by smbd_sess tcon_list
	return true;
}

void x_smbd_tcon_unlinked(x_dlink_t *link, x_smbd_sess_t *smbd_sess)
{
	x_smbd_tcon_t *smbd_tcon = X_CONTAINER_OF(link, x_smbd_tcon_t, sess_link);
	smbd_tcon_terminate(smbd_tcon);
}

bool x_smbd_tcon_disconnect(x_smbd_tcon_t *smbd_tcon)
{
	if (x_smbd_sess_unlink_tcon(smbd_tcon->smbd_sess, &smbd_tcon->sess_link)) {
		return smbd_tcon_terminate(smbd_tcon);
	}
	return false;
}

bool x_smbd_tcon_unlink_open(x_smbd_tcon_t *smbd_tcon, x_dlink_t *link)
{
	std::lock_guard<std::mutex> lock(smbd_tcon->mutex);
	if (link->is_valid()) {
		smbd_tcon->open_list.remove(link);
		return true;
	}
	return false;
}

int x_smbd_tcon_table_init(uint32_t count)
{
	g_smbd_tcon_table = new smbd_tcon_table_t(count);
	return 0;
}

struct x_smbd_tcon_list_t : x_smbd_ctrl_handler_t
{
	x_smbd_tcon_list_t() : iter(g_smbd_tcon_table->iter_start()) {
	}
	bool output(std::string &data) override;
	smbd_tcon_table_t::iter_t iter;
};

bool x_smbd_tcon_list_t::output(std::string &data)
{
	std::ostringstream os;

	bool ret = g_smbd_tcon_table->iter_entry(iter, [&os](const x_smbd_tcon_t *smbd_tcon) {
			std::shared_ptr<x_smbd_share_t> smbshare = smbd_tcon->smbd_share;
			os << idl::x_hex_t<uint32_t>(smbd_tcon->tid) << ' '
			<< idl::x_hex_t<uint32_t>(smbd_tcon->share_access) << ' '
			<< smbshare->name << std::endl;
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

