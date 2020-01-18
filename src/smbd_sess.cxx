
#include "smbd.hxx"
#include "include/hashtable.hxx"

x_smbd_sess_t::x_smbd_sess_t(x_smbd_conn_t *smbd_conn)
	: smbd_conn{smbd_conn}, refcnt{1}
{
	smbd_conn->incref();
}

#if 0
enum {
	TIMER_INTERVAL = 3000,
};
#endif
struct smbd_sess_pool_t
{
#if 0
	x_timer_t timer; // check expire
	x_tp_dcircle_t<smbd_sess_dcircle_traits> active_list;
	x_tp_dcircle_t<smbd_sess_dcircle_traits> timeout_list;
#endif
	x_hashtable_t<smbd_sess_hash_traits> hashtable;
	std::atomic<uint32_t> count;
	uint32_t capacity;
	std::mutex mutex;
};

static inline int __smbd_sess_pool_init(smbd_sess_pool_t &pool, x_evtmgmt_t *ep, uint32_t count)
{
	uint32_t bucket_size = 1;
	while (bucket_size <= count) {
		bucket_size <<= 1;
	}
	pool.hashtable.init(bucket_size);
	pool.capacity = count;

	return 0;
}

static inline x_smbd_sess_t *smbd_sess_find_by_id(smbd_sess_pool_t &pool, uint64_t id)
{
	return pool.hashtable.find(id, [id](const x_smbd_sess_t &s) { return s.id == id; });
}

static x_smbd_sess_t *__smbd_sess_find(smbd_sess_pool_t &pool, uint64_t id,
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
static x_smbd_sess_t *__smbd_sess_create(smbd_sess_pool_t &pool, x_smbd_conn_t *smbd_conn)
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

static void __smbd_sess_release(smbd_sess_pool_t &pool, x_smbd_sess_t *smbd_sess)
{
	{
		std::lock_guard<std::mutex> lock(pool.mutex);
		pool.hashtable.remove(smbd_sess);
	}
	--pool.count;
	smbd_sess->decref();
}

static smbd_sess_pool_t smbd_sess_pool;

int x_smbd_sess_pool_init(x_evtmgmt_t *ep, uint32_t count)
{
	return __smbd_sess_pool_init(smbd_sess_pool, ep, count);
}

x_smbd_sess_t *x_smbd_sess_create(x_smbd_conn_t *smbd_conn)
{
	return __smbd_sess_create(smbd_sess_pool, smbd_conn);
}

x_smbd_sess_t *x_smbd_sess_find(uint64_t id, const x_smbd_conn_t *smbd_conn)
{
	return __smbd_sess_find(smbd_sess_pool, id, smbd_conn);
}

void x_smbd_sess_release(x_smbd_sess_t *smbd_sess)
{
	return __smbd_sess_release(smbd_sess_pool, smbd_sess);
}

