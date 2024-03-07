
#include "smbd.hxx"
#include "smbd_ctrl.hxx"
#include "smbd_stats.hxx"
#include "smbd_open.hxx"
#include "include/idtable.hxx"
#include "smbd_share.hxx"
#include "smbd_replay.hxx"
#include "smbd_conf.hxx"
#include "smbd_dcerpc_srvsvc.hxx"

using smbd_tcon_table_t = x_idtable_t<x_smbd_tcon_t, x_idtable_32_traits_t>;
static smbd_tcon_table_t *g_smbd_tcon_table;

struct x_smbd_tcon_t
{ 
	x_smbd_tcon_t(x_smbd_sess_t *smbd_sess,
			const std::shared_ptr<x_smbd_share_t> &share,
			std::shared_ptr<x_smbd_volume_t> &&volume,
			uint32_t share_access)
		: tick_create(tick_now), share_access(share_access)
		, encrypted(share->smb_encrypt == x_smbd_feature_option_t::required)
		, smbd_sess(x_ref_inc(smbd_sess)), smbd_share(share)
		, smbd_volume(volume)
       	{
		X_SMBD_COUNTER_INC_CREATE(tcon, 1);
	}
	~x_smbd_tcon_t()
	{
		x_ref_dec(smbd_sess);
		X_SMBD_COUNTER_INC_DELETE(tcon, 1);
	}

	x_dlink_t sess_link; // protected by smbd_sess' mutex
	const x_tick_t tick_create;
	const uint32_t share_access;
	const bool encrypted;
	enum {
		S_ACTIVE,
		S_DONE,
	} state = S_ACTIVE;
	uint32_t tid;
	std::atomic<uint32_t> num_open = 0;
	x_smbd_sess_t * const smbd_sess;
	const std::shared_ptr<x_smbd_share_t> smbd_share;
	const std::shared_ptr<x_smbd_volume_t> smbd_volume;
	std::mutex mutex;
	x_ddlist_t open_list;
};

template <>
x_smbd_tcon_t *x_ref_inc(x_smbd_tcon_t *smbd_tcon)
{
	g_smbd_tcon_table->incref(smbd_tcon->tid);
	return smbd_tcon;
}

template <>
void x_ref_dec(x_smbd_tcon_t *smbd_tcon)
{
	g_smbd_tcon_table->decref(smbd_tcon->tid);
}

x_smbd_tcon_t *x_smbd_tcon_create(x_smbd_sess_t *smbd_sess, 
		const std::shared_ptr<x_smbd_share_t> &smbshare,
		std::shared_ptr<x_smbd_volume_t> &&volume,
		uint32_t share_access)
{
	x_smbd_tcon_t *smbd_tcon = new x_smbd_tcon_t(smbd_sess, smbshare,
			std::move(volume), share_access);
	if (!g_smbd_tcon_table->store(smbd_tcon, smbd_tcon->tid)) {
		delete smbd_tcon;
		return nullptr;
	}
	if (!x_smbd_sess_link_tcon(smbd_sess, &smbd_tcon->sess_link)) {
		g_smbd_tcon_table->remove(smbd_tcon->tid);
		x_ref_dec(smbd_tcon);
		return nullptr;
	}
	x_ref_inc(smbd_tcon); // ref by smbd_sess list

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

std::shared_ptr<x_smbd_user_t> x_smbd_tcon_get_user(const x_smbd_tcon_t *smbd_tcon)
{
	return x_smbd_sess_get_user(smbd_tcon->smbd_sess);
}

uint32_t x_smbd_tcon_get_share_access(const x_smbd_tcon_t *smbd_tcon)
{
	return smbd_tcon->share_access;
}

bool x_smbd_tcon_get_read_only(const x_smbd_tcon_t *smbd_tcon)
{
	return smbd_tcon->smbd_share->is_read_only();
}

bool x_smbd_tcon_get_durable_handle(const x_smbd_tcon_t *smbd_tcon)
{
	return smbd_tcon->smbd_share->support_durable_handle();
}

bool x_smbd_tcon_get_continuously_available(const x_smbd_tcon_t *smbd_tcon)
{
	return smbd_tcon->smbd_share->is_continuously_available();
}

bool x_smbd_tcon_get_abe(const x_smbd_tcon_t *smbd_tcon)
{
	return smbd_tcon->smbd_share->abe_enabled();
}

bool x_smbd_tcon_encrypted(const x_smbd_tcon_t *smbd_tcon)
{
	return smbd_tcon->encrypted;
}

bool x_smbd_tcon_match(const x_smbd_tcon_t *smbd_tcon, const x_smbd_sess_t *smbd_sess, uint32_t tid)
{
	return smbd_tcon->smbd_sess == smbd_sess && smbd_tcon->tid == tid;
}

x_smbd_sess_t *x_smbd_tcon_get_sess(const x_smbd_tcon_t *smbd_tcon)
{
	return x_ref_inc(smbd_tcon->smbd_sess);
}

bool x_smbd_tcon_same_sess(const x_smbd_tcon_t *smbd_tcon1, const x_smbd_tcon_t *smbd_tcon2)
{
	return smbd_tcon1->smbd_sess == smbd_tcon2->smbd_sess;
}

std::shared_ptr<x_smbd_share_t> x_smbd_tcon_get_share(const x_smbd_tcon_t *smbd_tcon)
{
	return smbd_tcon->smbd_share;
}

x_smbd_tcon_t *x_smbd_tcon_lookup(uint32_t id, const x_smbd_sess_t *smbd_sess)
{
	auto [found, smbd_tcon] = g_smbd_tcon_table->lookup(id);
	if (!found) {
		return nullptr;
	}
	if (smbd_tcon->smbd_sess == smbd_sess) {
		return smbd_tcon;
	} else {
		g_smbd_tcon_table->decref(id);
		return nullptr;
	}
}

NTSTATUS x_smbd_tcon_resolve_path(x_smbd_tcon_t *smbd_tcon,
		const std::u16string &in_path,
		bool dfs,
		std::shared_ptr<x_smbd_share_t> &smbd_share,
		std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		std::u16string &path,
		long &path_priv_data,
		long &open_priv_data)
{
	NTSTATUS status = smbd_tcon->smbd_share->resolve_path(
			smbd_volume, path, path_priv_data, open_priv_data,
			dfs,
			in_path.data(),
			in_path.data() + in_path.length(),
			smbd_tcon->smbd_volume);
	if (NT_STATUS_IS_OK(status)) {
		smbd_share = smbd_tcon->smbd_share;
	}
	return status;
}

static inline void smbd_tcon_unlink_open(x_smbd_tcon_t *smbd_tcon, x_dlink_t *link)
{
	smbd_tcon->open_list.remove(link);
	smbd_tcon->num_open.fetch_sub(1, std::memory_order_relaxed);
	x_smbd_sess_update_num_open(smbd_tcon->smbd_sess, -1);
}

static bool smbd_tcon_terminate(x_smbd_tcon_t *smbd_tcon, bool shutdown)
{
	auto lock = std::unique_lock(smbd_tcon->mutex);
	if (smbd_tcon->state == x_smbd_tcon_t::S_DONE) {
		/* this can happen if client logoff on one channel and
		 * tdis on another
		 */
		return false;
	}
	smbd_tcon->state = x_smbd_tcon_t::S_DONE;
	lock.unlock();

	g_smbd_tcon_table->remove(smbd_tcon->tid);
	x_ref_dec(smbd_tcon);

	x_dlink_t *link;
	lock.lock();
	while ((link = smbd_tcon->open_list.get_front()) != nullptr) {
		smbd_tcon_unlink_open(smbd_tcon, link);
		lock.unlock();
		x_smbd_open_unlinked(link, shutdown);
		lock.lock();
	}
	lock.unlock();

	x_ref_dec(smbd_tcon); // ref by smbd_sess tcon_list
	return true;
}

void x_smbd_tcon_unlinked(x_dlink_t *link, x_smbd_sess_t *smbd_sess, bool shutdown)
{
	x_smbd_tcon_t *smbd_tcon = X_CONTAINER_OF(link, x_smbd_tcon_t, sess_link);
	smbd_tcon_terminate(smbd_tcon, shutdown);
}

bool x_smbd_tcon_disconnect(x_smbd_tcon_t *smbd_tcon)
{
	if (x_smbd_sess_unlink_tcon(smbd_tcon->smbd_sess, &smbd_tcon->sess_link)) {
		return smbd_tcon_terminate(smbd_tcon, false);
	}
	return false;
}

bool x_smbd_tcon_link_open(x_smbd_tcon_t *smbd_tcon, x_dlink_t *link)
{
	std::lock_guard<std::mutex> lock(smbd_tcon->mutex);
	if (smbd_tcon->state == x_smbd_tcon_t::S_ACTIVE) {
		smbd_tcon->open_list.push_back(link);
		smbd_tcon->num_open.fetch_add(1, std::memory_order_relaxed);
		x_smbd_sess_update_num_open(smbd_tcon->smbd_sess, 1);
		return true;
	} else {
		return false;
	}
}

bool x_smbd_tcon_unlink_open(x_smbd_tcon_t *smbd_tcon, x_dlink_t *link)
{
	std::lock_guard<std::mutex> lock(smbd_tcon->mutex);
	if (link->is_valid()) {
		smbd_tcon_unlink_open(smbd_tcon, link);
		return true;
	}
	return false;
}

int x_smbd_tcon_table_init(uint32_t count)
{
	g_smbd_tcon_table = new smbd_tcon_table_t(count);
	return 0;
}

std::u16string x_smbd_tcon_get_volume_label(const x_smbd_tcon_t *smbd_tcon)
{
	if (smbd_tcon->smbd_volume) {
		return smbd_tcon->smbd_volume->name_l16;
	} else {
		return smbd_tcon->smbd_share->name_16;
	}
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

static inline void smbd_tcon_to_tcon_info(std::vector<idl::srvsvc_NetConnInfo0> &array,
		const x_smbd_tcon_t *smbd_tcon, const x_tick_t now,
		std::shared_ptr<std::u16string> &share_name)
{
	array.push_back(idl::srvsvc_NetConnInfo0{
			smbd_tcon->tid,
			});
}

static inline void smbd_tcon_to_tcon_info(std::vector<idl::srvsvc_NetConnInfo1> &array,
		const x_smbd_tcon_t *smbd_tcon, const x_tick_t now,
		std::shared_ptr<std::u16string> &share_name)
{
	const auto smbd_user = x_smbd_tcon_get_user(smbd_tcon);
	array.push_back(idl::srvsvc_NetConnInfo1{
			smbd_tcon->tid,
			0x3, // conn_type
			smbd_tcon->num_open.load(std::memory_order_relaxed),
			1, // TODO num_users
			x_convert<uint32_t>((now - smbd_tcon->tick_create) / X_NSEC_PER_SEC),
			smbd_user->account_name,
			share_name,
			});
}

template <typename T>
static WERROR smbd_tcon_enum(idl::srvsvc_NetConnEnum &arg, std::vector<T> &array)
{
	const x_smbd_conf_t &smbd_conf = x_smbd_conf_get_curr();

	std::shared_ptr<x_smbd_share_t> smbd_share;
	if (arg.path) {
		smbd_share = x_smbd_find_share(smbd_conf, *arg.path);
		if (!smbd_share) {
			X_LOG(SMB, WARN, "fail to find share '%s'",
					x_str_todebug(*arg.path).c_str());
			return WERR_INVALID_NAME;
		}
	}

	smbd_tcon_table_t::iter_t iter = g_smbd_tcon_table->iter_start();
	auto now = tick_now;
	g_smbd_tcon_table->iterate(iter, [now, &array, &smbd_share, &arg](x_smbd_tcon_t *smbd_tcon) {
			if (smbd_tcon->state == x_smbd_tcon_t::S_ACTIVE &&
					smbd_share == smbd_tcon->smbd_share) {
				smbd_tcon_to_tcon_info(array, smbd_tcon, now, arg.path);
			}
			return true;
		});
	return WERR_OK;
}

WERROR x_smbd_net_enum(idl::srvsvc_NetConnEnum &arg,
		std::vector<idl::srvsvc_NetConnInfo0> &array)
{
	return smbd_tcon_enum(arg, array);
}

WERROR x_smbd_net_enum(idl::srvsvc_NetConnEnum &arg,
		std::vector<idl::srvsvc_NetConnInfo1> &array)
{
	return smbd_tcon_enum(arg, array);
}

