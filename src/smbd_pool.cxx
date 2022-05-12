
#include "smbd.hxx"
#include "smbd_object.hxx"
#include "smbd_ctrl.hxx"
#include "smbd_pool.hxx"
#include "include/librpc/security.hxx"


X_DECLARE_MEMBER_TRAITS(smbd_open_hash_traits, x_smbd_open_t, hash_link)
using smbd_open_pool_t = smbd_pool_t<smbd_open_hash_traits>;

void x_smbd_open_init(x_smbd_open_t *smbd_open, x_smbd_object_t *smbd_object, x_smbd_tcon_t *smbd_tcon, uint32_t share_access, uint32_t access_mask)
{
	smbd_open->smbd_object = smbd_object;
	smbd_open->smbd_tcon = smbd_tcon;
	smbd_open->share_access = share_access;
	smbd_open->access_mask = access_mask;
}

/* open ref to object, and link into object's open list
   object does not ref to open
 */
template <>
x_smbd_open_t *x_smbd_ref_inc(x_smbd_open_t *smbd_open)
{
	X_ASSERT(smbd_open->refcnt++ > 0);
	return smbd_open;
}

template <>
void x_smbd_ref_dec(x_smbd_open_t *smbd_open)
{
	if (unlikely(--smbd_open->refcnt == 0)) {
		X_TODO; // ops->destroy(this);
	}
}

static inline x_smbd_open_t *smbd_open_find_by_id(smbd_open_pool_t &pool, uint64_t id)
{
	return pool.hashtable.find(id, [id](const x_smbd_open_t &s) { return s.id == id; });
}

static x_smbd_open_t *smbd_open_find_intl(smbd_open_pool_t &pool, uint64_t id)
{
	std::unique_lock<std::mutex> lock(pool.mutex);
	x_smbd_open_t *smbd_open = smbd_open_find_by_id(pool, id);
	if (smbd_open) {
		return x_smbd_ref_inc(smbd_open);
	}
	return nullptr;
}

static uint64_t g_open_id = 0x1234;
static void smbd_open_insert_intl(smbd_open_pool_t &pool, x_smbd_open_t *smbd_open)
{
	x_smbd_ref_inc(smbd_open); /* for hash */

	std::lock_guard<std::mutex> lock(pool.mutex);
	for (;;) {
		/* TODO to reduce hash conflict */
		smbd_open->id = g_open_id++;
		if (smbd_open->id == 0) {
			continue;
		}
		x_smbd_ptr_t<x_smbd_open_t> exist{smbd_open_find_by_id(pool, smbd_open->id)};
		if (!exist) {
			break;
		}
	}
	pool.hashtable.insert(smbd_open, smbd_open->id);
}

#if 0
X_DECLARE_MEMBER_TRAITS(smbd_tcon_hash_traits, x_smbd_tcon_t, hash_link)
using smbd_tcon_pool_t = smbd_pool_t<smbd_tcon_hash_traits>;

static inline x_smbd_tcon_t *smbd_tcon_find_by_id(smbd_tcon_pool_t &pool, uint32_t tid)
{
	return pool.hashtable.find(tid, [tid](const x_smbd_tcon_t &s) { return s.tid == tid; });
}

static x_smbd_tcon_t *smbd_tcon_find_intl(smbd_tcon_pool_t &pool, uint32_t id,
		const x_smbd_sess_t *smbd_sess)
{
	std::unique_lock<std::mutex> lock(pool.mutex);
	x_smbd_tcon_t *smbd_tcon = smbd_tcon_find_by_id(pool, id);
	if (smbd_tcon && smbd_tcon->smbd_sess == smbd_sess) {
		return x_smbd_ref_inc(smbd_tcon);
	}
	return nullptr;
}

static uint64_t g_tcon_id = 0x1234;
static x_smbd_tcon_t *smbd_tcon_insert_intl(smbd_tcon_pool_t &pool, x_smbd_tcon_t *smbd_tcon)
{
#if 0
	if (pool.count++ > pool.capacity) {
		--pool.count;
		return nullptr;
	}
	x_smbd_tcon_t *smbd_tcon = new x_smbd_tcon_t(smbd_conn);
	smbd_tcon->incref(); /* for hash */
	// smbd_tcon->incref(); /* for dcircle */
#endif
	std::unique_lock<std::mutex> lock(pool.mutex);
	for (;;) {
		/* TODO to reduce hash conflict */
		smbd_tcon->tid = g_tcon_id++;
		x_smbd_ptr_t<x_smbd_tcon_t> exist{smbd_tcon_find_by_id(pool, smbd_tcon->tid)};
		if (!exist) {
			break;
		}
	}
	pool.hashtable.insert(smbd_tcon, smbd_tcon->tid);
	
	return smbd_tcon;
}

x_smbd_sess_t::x_smbd_sess_t(x_smbd_conn_t *smbd_conn)
	: smbd_conn{smbd_conn}, refcnt{1}
{
	smbd_conn->incref();
}

x_smbd_sess_t::~x_smbd_sess_t()
{
	if (auth) {
		x_auth_destroy(auth);
	}
	if (smbd_conn) {
		smbd_conn->decref();
	}
}


X_DECLARE_MEMBER_TRAITS(smbd_sess_hash_traits, x_smbd_sess_t, hash_link)
using smbd_sess_pool_t = smbd_pool_t<smbd_sess_hash_traits>;

static inline x_smbd_sess_t *smbd_sess_find_by_id(smbd_sess_pool_t &pool, uint64_t id)
{
	return pool.hashtable.find(id, [id](const x_smbd_sess_t &s) { return s.id == id; });
}

static x_smbd_sess_t *smbd_sess_find_intl(smbd_sess_pool_t &pool, uint64_t id,
		const x_smbd_conn_t *smbd_conn)
{
	std::unique_lock<std::mutex> lock(pool.mutex);
	x_smbd_sess_t *smbd_sess = smbd_sess_find_by_id(pool, id);
	if (smbd_sess && smbd_sess->smbd_conn == smbd_conn) {
		smbd_sess->incref();
		return smbd_sess;
	}
	return nullptr;
}

static uint64_t g_sess_id = 0x1234;
static x_smbd_sess_t *smbd_sess_create_intl(smbd_sess_pool_t &pool, x_smbd_conn_t *smbd_conn)
{
	if (pool.count++ > pool.capacity) {
		--pool.count;
		return nullptr;
	}
	x_smbd_sess_t *smbd_sess = new x_smbd_sess_t(smbd_conn);
	smbd_sess->incref(); /* for hash */
	// smbd_sess->incref(); /* for dcircle */

	std::unique_lock<std::mutex> lock(pool.mutex);
	for (;;) {
		/* TODO to reduce hash conflict */
		smbd_sess->id = g_sess_id++;
		x_auto_ref_t<x_smbd_sess_t> exist{smbd_sess_find_by_id(pool, smbd_sess->id)};
		if (!exist) {
			break;
		}
	}
	pool.hashtable.insert(smbd_sess, smbd_sess->id);
	
	return smbd_sess;
}
#endif

X_DECLARE_MEMBER_TRAITS(smbd_requ_hash_traits, x_smbd_requ_t, hash_link)
using smbd_requ_pool_t = smbd_pool_t<smbd_requ_hash_traits>;

static inline x_smbd_requ_t *smbd_requ_find_by_id(smbd_requ_pool_t &pool, uint64_t id)
{
	return pool.hashtable.find(id, [id](const x_smbd_requ_t &s) { return s.async_id == id; });
}

static x_smbd_requ_t *smbd_requ_find_intl(smbd_requ_pool_t &pool, uint64_t id,
		const x_smbd_conn_t *smbd_conn)
{
	std::unique_lock<std::mutex> lock(pool.mutex);
	x_smbd_requ_t *smbd_requ = smbd_requ_find_by_id(pool, id);
	if (smbd_requ) {
		if (x_smbd_chan_get_conn(smbd_requ->smbd_chan) == smbd_conn) {
			return x_smbd_ref_inc(smbd_requ);
		}
	}
	return nullptr;
}

static uint64_t g_async_id_id = 0x0;
static void smbd_requ_insert_intl(smbd_requ_pool_t &pool, x_smbd_requ_t *smbd_requ)
{
	std::unique_lock<std::mutex> lock(pool.mutex);
	for (;;) {
		/* TODO to reduce hash conflict */
		smbd_requ->async_id = g_async_id_id++;
		if (smbd_requ->async_id == 0) {
			continue;
		}
		x_smbd_ptr_t<x_smbd_requ_t> exist{smbd_requ_find_by_id(pool, smbd_requ->async_id)};
		if (!exist) {
			break;
		}
	}
	pool.hashtable.insert(smbd_requ, smbd_requ->async_id);
}




static smbd_open_pool_t g_smbd_open_pool;
static smbd_requ_pool_t g_smbd_requ_pool;


int x_smbd_open_pool_init(uint32_t count)
{
	pool_init(g_smbd_open_pool, count);
	return 0;
}

void x_smbd_open_release(x_smbd_open_t *smbd_open)
{
	pool_release(g_smbd_open_pool, smbd_open);
}


#if 0
static smbd_tcon_pool_t g_smbd_tcon_pool;
int x_smbd_tcon_pool_init(uint32_t count)
{
	pool_init(g_smbd_tcon_pool, count);
	return 0;
}

x_smbd_tcon_t *x_smbd_tcon_find(uint32_t id, const x_smbd_sess_t *smbd_sess)
{
	return smbd_tcon_find_intl(g_smbd_tcon_pool, id, smbd_sess);
}

void x_smbd_tcon_insert(x_smbd_tcon_t *smbd_tcon)
{
	smbd_tcon_insert_intl(g_smbd_tcon_pool, smbd_tcon);
}

static void x_smbd_tcon_release(x_smbd_tcon_t *smbd_tcon)
{
	pool_release(g_smbd_tcon_pool, smbd_tcon);
}

x_smbd_sess_t *x_smbd_sess_find(uint64_t id, const x_smbd_conn_t *smbd_conn)
{
	return smbd_sess_find_intl(g_smbd_sess_pool, id, smbd_conn);
}

x_smbd_sess_t *x_smbd_sess_create(x_smbd_conn_t *smbd_conn)
{
	return smbd_sess_create_intl(g_smbd_sess_pool, smbd_conn);
}

static void x_smbd_sess_release(x_smbd_sess_t *smbd_sess)
{
	pool_release(g_smbd_sess_pool, smbd_sess);
}

int x_smbd_sess_pool_init(uint32_t count)
{
	pool_init(g_smbd_sess_pool, count);
	return 0;
}
#endif

int x_smbd_requ_pool_init(uint32_t count)
{
	pool_init(g_smbd_requ_pool, count);
	return 0;
}

x_smbd_requ_t *x_smbd_requ_find(uint64_t id, const x_smbd_conn_t *smbd_conn)
{
	return smbd_requ_find_intl(g_smbd_requ_pool, id, smbd_conn);
}

void x_smbd_requ_insert(x_smbd_requ_t *smbd_requ)
{
	x_smbd_ref_inc(smbd_requ);
	smbd_requ_insert_intl(g_smbd_requ_pool, smbd_requ);
}

void x_smbd_requ_remove(x_smbd_requ_t *smbd_requ)
{
	pool_release(g_smbd_requ_pool, smbd_requ);
}


/* TODO should also match persistent id??? */
x_smbd_open_t *x_smbd_open_find(uint64_t id_presistent, uint64_t id_volatile,
		const x_smbd_tcon_t *smbd_tcon)
{
	x_smbd_open_t *smbd_open = smbd_open_find_intl(g_smbd_open_pool, id_volatile);
	if (smbd_open) {
		if (smbd_open->smbd_tcon == smbd_tcon) {
			return smbd_open;
		} else {
			x_smbd_ref_dec(smbd_open);
		}
	}
	return nullptr;
}

x_smbd_open_t *x_smbd_open_find(uint64_t id_presistent, uint64_t id_volatile,
		uint32_t tid, const x_smbd_sess_t *smbd_sess)
{
	x_smbd_open_t *smbd_open = smbd_open_find_intl(g_smbd_open_pool, id_volatile);
	if (smbd_open) {
		if (x_smbd_tcon_match(smbd_open->smbd_tcon, smbd_sess, tid)) {
			return smbd_open;
		} else {
			x_smbd_ref_dec(smbd_open);
		}
	}
	return nullptr;
}

void x_smbd_open_insert_local(x_smbd_open_t *smbd_open)
{
	return smbd_open_insert_intl(g_smbd_open_pool, smbd_open);
}

#if 0
void x_smbd_tcon_terminate(x_smbd_tcon_t *smbd_tcon)
{
	x_smbd_tcon_release(smbd_tcon);
#if 0
	TODO
	std::unique_ptr<x_smb2_state_close_t> close_state;
	x_smbd_open_t *smbd_open;
	while ((smbd_open = smbd_tcon->open_list.get_front()) != nullptr) {
		smbd_tcon->open_list.remove(smbd_open);
		x_smbd_object_op_close(smbd_open->smbd_object,
				smbd_tcon->smbd_sess->smbd_conn,
				smbd_open, nullptr, close_state);
		smbd_open->decref();
	}
#endif
}

void x_smbd_sess_terminate(x_smbd_sess_t *smbd_sess)
{
	x_smbd_tcon_t *smbd_tcon;
	while ((smbd_tcon = smbd_sess->tcon_list.get_front()) != nullptr) {
		smbd_sess->tcon_list.remove(smbd_tcon);
		x_smbd_tcon_terminate(smbd_tcon);
		smbd_tcon->decref();
	}

	x_smbd_sess_release(smbd_sess);
}

NTSTATUS x_smbd_open_close(x_smbd_conn_t *smbd_conn,
		x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_close_t> &state)
{
	/* TODO call x_smbd_open_close */
	NTSTATUS status = smbd_open->ops->close(smbd_conn, smbd_open,
			smbd_requ, state);
	if (!NT_STATUS_IS_OK(status)) {
		RETURN_OP_STATUS(smbd_requ, status);
	}

	x_smbd_open_release(smbd_open);
	return NT_STATUS_OK;
}

struct x_smbd_list_session_t : x_smbd_ctrl_handler_t
{
	x_smbd_list_session_t() : sess_iter(g_smbd_sess_pool) { }

	bool output(std::string &data) override;
	pool_iterator_t<smbd_sess_hash_traits> sess_iter;
};

bool x_smbd_list_session_t::output(std::string &data)
{
	std::ostringstream os;
	size_t count = sess_iter.get_next([&os](const x_smbd_sess_t &smbd_sess) {
		x_smbd_conn_t *smbd_conn = smbd_sess.smbd_conn;
		std::shared_ptr<x_smbd_user_t> smbd_user = smbd_sess.smbd_user;
		os << idl::x_hex_t<uint64_t>(smbd_sess.id) << ' '
			<< idl::x_hex_t<uint64_t>(smbd_conn->ep_id) << ' '
			<< smbd_conn->saddr.tostring() << ' '
			<< idl::x_hex_t<uint16_t>(smbd_conn->dialect);
		if (smbd_user) {
			os << ' ' << smbd_user->domain_sid << ' ' << smbd_user->uid << ' ' << smbd_user->gid;
		} else {
			os << " - -";
		}
	       	os << std::endl;
		return false;
	}, 0);
	if (count) {
		data = os.str(); // TODO avoid copying
		return true;
	} else {
		return false;
	}
}

x_smbd_ctrl_handler_t *x_smbd_list_session_create()
{
	return new x_smbd_list_session_t;
}

struct x_smbd_list_tcon_t : x_smbd_ctrl_handler_t
{
	x_smbd_list_tcon_t() : tcon_iter(g_smbd_tcon_pool) { }

	bool output(std::string &data) override;
	pool_iterator_t<smbd_tcon_hash_traits> tcon_iter;
};

bool x_smbd_list_tcon_t::output(std::string &data)
{
	std::ostringstream os;
	size_t count = tcon_iter.get_next([&os](const x_smbd_tcon_t &smbd_tcon) {
		std::shared_ptr<x_smbd_share_t> smbshare = smbd_tcon.smbd_share;
		os << idl::x_hex_t<uint32_t>(smbd_tcon.tid) << ' ' << idl::x_hex_t<uint32_t>(smbd_tcon.share_access) << ' ' << smbshare->name << std::endl;
		return false;
	}, 0);
	if (count) {
		data = os.str(); // TODO avoid copying
		return true;
	} else {
		return false;
	}
}

x_smbd_ctrl_handler_t *x_smbd_list_tcon_create()
{
	return new x_smbd_list_tcon_t;
}
#endif

struct x_smbd_list_open_t : x_smbd_ctrl_handler_t
{
	x_smbd_list_open_t() : open_iter(g_smbd_open_pool) { }

	bool output(std::string &data) override;
	pool_iterator_t<smbd_open_hash_traits> open_iter;
};

bool x_smbd_list_open_t::output(std::string &data)
{
	std::ostringstream os;
	size_t count = open_iter.get_next([&os](x_smbd_open_t &smbd_open) {
		os << idl::x_hex_t<uint64_t>(smbd_open.id) << ' '
			<< idl::x_hex_t<uint32_t>(smbd_open.access_mask) << ' '
			<< idl::x_hex_t<uint32_t>(smbd_open.share_access) << ' '
			<< idl::x_hex_t<uint32_t>(x_smbd_tcon_get_id(smbd_open.smbd_tcon)) << " '"
			<< x_smbd_object_op_get_path(smbd_open.smbd_object) << "'" << std::endl;
		return false;
	}, 0);
	if (count) {
		data = os.str(); // TODO avoid copying
		return true;
	} else {
		return false;
	}
}

x_smbd_ctrl_handler_t *x_smbd_list_open_create()
{
	return new x_smbd_list_open_t;
}



#if 0
template <typename HashTraits, typename Func>
static void foreach(x_hashtable_t<HashTraits> &pool, Func &&func)
{
	std::unique_lock<std::mutex> lock(pool.mutex);
	for (auto &bucket: pool.buckets) {
		for (x_dqlink_t *link = bucket.get_front(); link; link = link->get_next()) {
			item_type *item = HashTraits::container(link);
			if (!func(*item)) {
				return;
			}
		}
	}
}
#endif
