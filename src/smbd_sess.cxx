
#include "smbd.hxx"
#include "include/idtable.hxx"
#include "smbd_ctrl.hxx"
#include "smbd_stats.hxx"

using smbd_sess_table_t = x_idtable_t<x_smbd_sess_t, x_idtable_64_traits_t>;
static smbd_sess_table_t *g_smbd_sess_table;

struct x_smbd_sess_t
{
	enum { MAX_CHAN_COUNT = 32, };
	x_smbd_sess_t() {
		X_SMBD_COUNTER_INC(sess_create, 1);
	}
	~x_smbd_sess_t() {
		X_SMBD_COUNTER_INC(sess_delete, 1);
	}
	// uint64_t id;
	std::mutex mutex;
	std::shared_ptr<x_smbd_user_t> smbd_user;
	uint64_t id;
	enum {
		S_INIT,
		S_ACTIVE,
		S_DONE,
	} state = S_INIT;
	// uint16_t security_mode = 0;
	bool signing_required = false;
	bool key_is_valid = false;
	uint8_t chan_count = 0;
	x_ddlist_t chan_list;
	x_ddlist_t tcon_list;

	x_smbd_key_set_t keys;
};

template <>
x_smbd_sess_t *x_smbd_ref_inc(x_smbd_sess_t *smbd_sess)
{
	g_smbd_sess_table->incref(smbd_sess->id);
	return smbd_sess;
}

template <>
void x_smbd_ref_dec(x_smbd_sess_t *smbd_sess)
{
	g_smbd_sess_table->decref(smbd_sess->id);
}

x_smbd_sess_t *x_smbd_sess_create(uint64_t &id)
{
	x_smbd_sess_t *smbd_sess = new x_smbd_sess_t;
	if (!g_smbd_sess_table->store(smbd_sess, smbd_sess->id)) {
		delete smbd_sess;
		return nullptr;
	}
	X_LOG_DBG("0x%lx %p", id, smbd_sess);
	return smbd_sess;
}

x_smbd_sess_t *x_smbd_sess_lookup(uint64_t id, const x_smb2_uuid_t &client_guid)
{
	/* skip client_guid checking, since session bind is signed,
	 * the check does not improve security
	 */
	auto ret = g_smbd_sess_table->lookup(id);
	if (!ret.first) {
		return nullptr;
	}
	return ret.second;
}

uint64_t x_smbd_sess_get_id(const x_smbd_sess_t *smbd_sess)
{
	return smbd_sess->id;
}

bool x_smbd_sess_is_signing_required(const x_smbd_sess_t *smbd_sess)
{
	return smbd_sess->signing_required;
}

std::shared_ptr<x_smbd_user_t> x_smbd_sess_get_user(const x_smbd_sess_t *smbd_sess)
{
	return smbd_sess->smbd_user;
}

const x_smb2_key_t *x_smbd_sess_get_signing_key(const x_smbd_sess_t *smbd_sess)
{
	// TODO memory order
	if (smbd_sess->key_is_valid) {
		return &smbd_sess->keys.signing_key;
	}
	return nullptr;
}

bool x_smbd_sess_link_chan(x_smbd_sess_t *smbd_sess, x_dlink_t *link)
{
	std::lock_guard<std::mutex> lock(smbd_sess->mutex);
	if (smbd_sess->state == x_smbd_sess_t::S_DONE) {
		return false;
	}
	if (smbd_sess->chan_count >= x_smbd_sess_t::MAX_CHAN_COUNT) {
		return false;
	}
	
	smbd_sess->chan_list.push_back(link);
	++smbd_sess->chan_count;
	return true;
}

template <class L>
static void smbd_sess_terminate(x_smbd_sess_t *smbd_sess, L &lock)
{
	x_dlink_t *link;
	smbd_sess->smbd_user = nullptr;

	while ((link = smbd_sess->chan_list.get_front()) != nullptr) {
		smbd_sess->chan_list.remove(link);
		--smbd_sess->chan_count;
		lock.unlock();
		x_smbd_chan_logoff(link, smbd_sess);
		lock.lock();
	}

	X_ASSERT(smbd_sess->chan_count == 0);

	while ((link = smbd_sess->tcon_list.get_front()) != nullptr) {
		smbd_sess->tcon_list.remove(link);
		lock.unlock();
		x_smbd_tcon_unlinked(link, smbd_sess);
		lock.lock();
	}
}

bool x_smbd_sess_unlink_chan(x_smbd_sess_t *smbd_sess, x_dlink_t *link)
{
	std::unique_lock<std::mutex> lock(smbd_sess->mutex);
	if (!link->is_valid()) {
		return false;
	}
	smbd_sess->chan_list.remove(link);
	if (--smbd_sess->chan_count == 0) {
		if (smbd_sess->state != x_smbd_sess_t::S_DONE) {
			smbd_sess->state = x_smbd_sess_t::S_DONE;
			smbd_sess_terminate(smbd_sess, lock);
		}
	}
	return true;
}

#if 0
	uint32_t chan_count;
	{
		std::lock_guard<std::mutex> lock(smbd_sess->mutex);
		if (smbd_sess->state == x_smbd_sess_t::S_DONE) {
			X_ASSERT(smbd_sess->chan_count == 0);
			return;
		}
		uint32_t i;
		for (i = 0; i < smbd_sess->chans.size(); ++i) {
			if (smbd_sess->chans[i] == smbd_chan) {
				X_SMBD_REF_DEC(smbd_sess->chans[i]);
				--smbd_sess->chan_count;
				break;
			}
		}
		X_ASSERT(i != smbd_sess->chans.size());
		chan_count = smbd_sess->chan_count;
	}
	if (chan_count == 0) {
		smbd_sess_terminate(smbd_sess);
	}
}

void x_smbd_sess_remove_chan(x_smbd_sess_t *smbd_sess, x_smbd_chan_t *smbd_chan)
{
	uint32_t chan_count;
	{
		std::lock_guard<std::mutex> lock(smbd_sess->mutex);
		if (smbd_sess->state == x_smbd_sess_t::S_DONE) {
			X_ASSERT(smbd_sess->chan_count == 0);
			return;
		}
		uint32_t i;
		for (i = 0; i < smbd_sess->chans.size(); ++i) {
			if (smbd_sess->chans[i] == smbd_chan) {
				X_SMBD_REF_DEC(smbd_sess->chans[i]);
				--smbd_sess->chan_count;
				break;
			}
		}
		X_ASSERT(i != smbd_sess->chans.size());
		chan_count = smbd_sess->chan_count;
	}
	if (chan_count == 0) {
		smbd_sess_terminate(smbd_sess);
	}
}
#endif
x_smbd_chan_t *x_smbd_sess_lookup_chan(x_smbd_sess_t *smbd_sess, x_smbd_conn_t *smbd_conn)
{
	x_dlink_t *link;
	std::lock_guard<std::mutex> lock(smbd_sess->mutex);
	for (link = smbd_sess->chan_list.get_front(); link; link = link->get_next()) {
		x_smbd_chan_t *smbd_chan = x_smbd_chan_match(link, smbd_conn);
		if (smbd_chan) {
			return smbd_chan;
		}
	}
	return nullptr;
}

x_smbd_chan_t *x_smbd_sess_get_active_chan(x_smbd_sess_t *smbd_sess)
{
	x_dlink_t *link;
	std::lock_guard<std::mutex> lock(smbd_sess->mutex);
	for (link = smbd_sess->chan_list.get_front(); link; link = link->get_next()) {
		x_smbd_chan_t *smbd_chan = x_smbd_chan_get_active(link);
		if (smbd_chan) {
			return smbd_chan;
		}
	}
	return nullptr;
}

bool x_smbd_sess_link_tcon(x_smbd_sess_t *smbd_sess, x_dlink_t *link)
{
	std::lock_guard<std::mutex> lock(smbd_sess->mutex);
	if (smbd_sess->state != x_smbd_sess_t::S_ACTIVE) {
		return false;
	}
	smbd_sess->tcon_list.push_back(link);
	return true;
}

/* called by smb2_tdis */
bool x_smbd_sess_unlink_tcon(x_smbd_sess_t *smbd_sess, x_dlink_t *link)
{
	std::lock_guard<std::mutex> lock(smbd_sess->mutex);
	if (link->is_valid()) {
		smbd_sess->tcon_list.remove(link);
		return true;
	}
	return false;
}

NTSTATUS x_smbd_sess_auth_succeeded(x_smbd_sess_t *smbd_sess,
		std::shared_ptr<x_smbd_user_t> &smbd_user,
		const x_smbd_key_set_t &keys)
{
	std::lock_guard<std::mutex> lock(smbd_sess->mutex);
	if (smbd_sess->state == x_smbd_sess_t::S_ACTIVE) {
		// TODO check smbd_user is matched?
	} else {
		smbd_sess->smbd_user = smbd_user;
		smbd_sess->keys = keys;
		smbd_sess->state = x_smbd_sess_t::S_ACTIVE;
		smbd_sess->key_is_valid = true;
	}
	return NT_STATUS_OK;
}

NTSTATUS x_smbd_sess_logoff(x_smbd_sess_t *smbd_sess)
{
	std::unique_lock<std::mutex> lock(smbd_sess->mutex);
	if (smbd_sess->state != x_smbd_sess_t::S_ACTIVE) {
		return NT_STATUS_USER_SESSION_DELETED;
	}
	smbd_sess->state = x_smbd_sess_t::S_DONE;

	smbd_sess_terminate(smbd_sess, lock);
	return NT_STATUS_OK;
}

int x_smbd_sess_table_init(uint32_t count)
{
	g_smbd_sess_table = new smbd_sess_table_t(count);
	return 0;
}

struct x_smbd_sess_list_t : x_smbd_ctrl_handler_t
{
	x_smbd_sess_list_t() : iter(g_smbd_sess_table->iter_start()) {
	}
	bool output(std::string &data) override;
	smbd_sess_table_t::iter_t iter;
};

bool x_smbd_sess_list_t::output(std::string &data)
{
	std::ostringstream os;

	bool ret = g_smbd_sess_table->iter_entry(iter, [&os](const x_smbd_sess_t *smbd_sess) {
			std::shared_ptr<x_smbd_user_t> smbd_user = smbd_sess->smbd_user;
			/* TODO list channels */
			os << idl::x_hex_t<uint64_t>(smbd_sess->id);
			if (smbd_user) {
				os << ' ' << smbd_user->domain_sid << ' ' << smbd_user->uid << ' ' << smbd_user->gid;
			} else {
				os << " - -";
			}
			return true;
		});
	if (ret) {
		data = os.str(); // TODO avoid copying
		return true;
	} else {
		return false;
	}
}

x_smbd_ctrl_handler_t *x_smbd_sess_list_create()
{
	return new x_smbd_sess_list_t;
}

