
#include "smbd_open.hxx"
#include "include/hashtable.hxx"

X_DECLARE_MEMBER_TRAITS(smbd_open_hash_traits, x_smbd_open_t, hash_link)
struct smbd_open_pool_t
{
	x_hashtable_t<smbd_open_hash_traits> hashtable;
	std::atomic<uint32_t> count;
	uint32_t capacity;
	std::mutex mutex;
};

void x_smbd_open_t::decref()
{
	if (unlikely(--refcnt == 0)) {
		ops->destroy(this);
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
		smbd_open->incref();
		return smbd_open;
	}
	return nullptr;
}

static uint64_t g_open_id = 0x1234;
static void smbd_open_insert_intl(smbd_open_pool_t &pool, x_smbd_open_t *smbd_open)
{
	smbd_open->incref(); /* for hash */

	std::lock_guard<std::mutex> lock(pool.mutex);
	for (;;) {
		/* TODO to reduce hash conflict */
		smbd_open->id = g_open_id++;
		if (smbd_open->id == 0) {
			continue;
		}
		x_auto_ref_t<x_smbd_open_t> exist{smbd_open_find_by_id(pool, smbd_open->id)};
		if (!exist) {
			break;
		}
	}
	pool.hashtable.insert(smbd_open, smbd_open->id);
}

X_DECLARE_MEMBER_TRAITS(smbd_tcon_hash_traits, x_smbd_tcon_t, hash_link)
struct smbd_tcon_pool_t
{
	x_hashtable_t<smbd_tcon_hash_traits> hashtable;
	std::atomic<uint32_t> count;
	uint32_t capacity;
	std::mutex mutex;
};

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
		smbd_tcon->incref();
		return smbd_tcon;
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
		x_auto_ref_t<x_smbd_tcon_t> exist{smbd_tcon_find_by_id(pool, smbd_tcon->tid)};
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
struct smbd_sess_pool_t
{
	x_hashtable_t<smbd_sess_hash_traits> hashtable;
	std::atomic<uint32_t> count;
	uint32_t capacity;
	std::mutex mutex;
};


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


X_DECLARE_MEMBER_TRAITS(smbd_requ_hash_traits, x_smbd_requ_t, hash_link)
struct smbd_requ_pool_t
{
	x_hashtable_t<smbd_requ_hash_traits> hashtable;
	std::atomic<uint32_t> count;
	uint32_t capacity;
	std::mutex mutex;
};



template <typename P>
static inline void pool_init(P &pool, uint32_t count)
{
	size_t bucket_size = x_next_2_power(count);
	pool.hashtable.init(bucket_size);
	pool.capacity = count;
}

template <typename P, typename E>
static inline void pool_release(P &pool, E *elem)
{
	{
		std::lock_guard<std::mutex> lock(pool.mutex);
		pool.hashtable.remove(elem);
	}
	--pool.count;
	elem->decref();
}



static smbd_open_pool_t g_smbd_open_pool;
static smbd_tcon_pool_t g_smbd_tcon_pool;
static smbd_sess_pool_t g_smbd_sess_pool;
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

void x_smbd_tcon_release(x_smbd_tcon_t *smbd_tcon)
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

void x_smbd_sess_release(x_smbd_sess_t *smbd_sess)
{
	pool_release(g_smbd_sess_pool, smbd_sess);
}

int x_smbd_sess_pool_init(uint32_t count)
{
	pool_init(g_smbd_sess_pool, count);
	return 0;
}


int x_smbd_requ_pool_init(uint32_t count)
{
	pool_init(g_smbd_requ_pool, count);
	return 0;
}


#if 0
x_smbd_sess_t *x_smbd_sess_find(x_smbd_conn_t *smbd_conn, NTSTATUS &status,
		uint64_t sess_id)
{
	x_smbd_sess_t *smbd_sess = smbd_sess_find_intl(smbd_sess_pool, sess_id);
	if (smbd_sess) {
		if (smbd_sess_match(smbd_conn)) {
			return smbd_sess;
		}
		x_smbd_sess_release(smbd_sess);
	}
	status = NT_STATUS_USER_SESSION_DELETED;
	return nullptr;
}

static x_smbd_sess_t *smbd_sess_find_intl(smbd_sess_pool_t &pool, uint64_t id)
{
	std::unique_lock<std::mutex> lock(pool.mutex);
	x_smbd_sess_t *smbd_sess = smbd_sess_find_by_id(pool, id);
	if (smbd_sess) {
		smbd_sess->incref();
		return smbd_sess;
	}
	return nullptr;
}

x_smbd_tcon_t *x_smbd_tcon_find(x_smbd_conn_t *smbd_conn, NTSTATUS &status,
		uint32_t tcon_id, uint64_t sess_id)
{
	x_smbd_tcon_t *smbd_tcon = smbd_tcon_find_intl(smbd_tcon_pool, open_id);
	if (smbd_tcon) {
		if (smbd_tcon_match(smbd_conn, sess_id)) {
			return smbd_tcon;
		}
		x_smbd_tcon_release(smbd_tcon);
	}

	x_smbd_sess_t *smbd_sess = x_smbd_sess_find(smbd_conn, status, sess_id);
	if (smbd_sess) {
		x_smbd_sess_release(smbd_sess);
		status = NT_STATUS_NETWORK_NAME_DELETED;
	}
	return nullptr;
}

int x_smbd_pool_init(uint32_t max_sess,
		uint32_t max_tcon,
		uint32_t max_open)
{
	x_smbd_sess_pool_init(g_smbd_sess_pool, max_sess);
	x_smbd_tcon_pool_init(g_smbd_tcon_pool, max_tcon);
	x_smbd_open_pool_init(g_smbd_open_pool, max_open);
}
static void x_smbd_tcon_pool_init(smbd_tcon_pool_t &pool, uint32_t count)
{
	size_t bucket_size = x_next_2_power(count);
	pool.hashtable.init(bucket_size);
	pool.capacity = count;
}

static void x_smbd_sess_pool_init(smbd_sess_pool_t &pool, uint32_t count)
{
	size_t bucket_size = x_next_2_power(count);
	pool.hashtable.init(bucket_size);
	pool.capacity = count;
}

#endif

/* TODO should also match persistent id??? */
x_smbd_open_t *x_smbd_open_find(uint64_t id_presistent, uint64_t id_volatile,
		const x_smbd_tcon_t *smbd_tcon)
{
	x_smbd_open_t *smbd_open = smbd_open_find_intl(g_smbd_open_pool, id_volatile);
	if (smbd_open) {
		if (smbd_open->smbd_tcon == smbd_tcon) {
			return smbd_open;
		} else {
			smbd_open->decref();
		}
	}
	return nullptr;
}

x_smbd_open_t *x_smbd_open_find(uint64_t id_presistent, uint64_t id_volatile,
		uint32_t tid, const x_smbd_sess_t *smbd_sess)
{
	x_smbd_open_t *smbd_open = smbd_open_find_intl(g_smbd_open_pool, id_volatile);
	if (smbd_open) {
		if (smbd_open->smbd_tcon->tid == tid && smbd_open->smbd_tcon->smbd_sess == smbd_sess) {
			return smbd_open;
		} else {
			smbd_open->decref();
		}
	}
	return nullptr;
}

void x_smbd_open_insert_local(x_smbd_open_t *smbd_open)
{
	return smbd_open_insert_intl(g_smbd_open_pool, smbd_open);
}

