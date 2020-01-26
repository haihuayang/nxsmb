
#include "smbd.hxx"
#include "include/hashtable.hxx"

struct smbd_open_pool_t
{
#if 0
	x_timer_t timer; // check expire
	x_tp_dcircle_t<smbd_open_dcircle_traits> active_list;
	x_tp_dcircle_t<smbd_open_dcircle_traits> timeout_list;
#endif
	x_hashtable_t<smbd_open_hash_traits> hashtable;
	std::atomic<uint32_t> count;
	uint32_t capacity;
	std::mutex mutex;
};

static inline int __smbd_open_pool_init(smbd_open_pool_t &pool, x_evtmgmt_t *ep, uint32_t count)
{
	uint32_t bucket_size = 1;
	while (bucket_size <= count) {
		bucket_size <<= 1;
	}
	pool.hashtable.init(bucket_size);
	pool.capacity = count;

	return 0;
}

static inline x_smbd_open_t *smbd_open_find_by_id(smbd_open_pool_t &pool, uint64_t id)
{
	return pool.hashtable.find(id, [id](const x_smbd_open_t &s) { return s.id == id; });
}

static x_smbd_open_t *__smbd_open_find(smbd_open_pool_t &pool, uint64_t id,
		const x_smbd_tcon_t *smbd_tcon)
{
	std::unique_lock<std::mutex> lock(pool.mutex);
	x_smbd_open_t *smbd_open = smbd_open_find_by_id(pool, id);
	if (smbd_open && smbd_open->smbd_tcon.get() == smbd_tcon) {
		smbd_open->incref();
		return smbd_open;
	}
	return nullptr;
}

static uint64_t g_open_id = 0x1234;
static void __smbd_open_insert(smbd_open_pool_t &pool, x_smbd_open_t *smbd_open)
{
#if 0
	if (pool.count++ > pool.capacity) {
		--pool.count;
		return nullptr;
	}
	x_smbd_open_t *smbd_open = new x_smbd_open_t;
	smbd_open->smbd_tcon.reset(smbd_tcon);
	
	return smbd_open;
#endif
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

static void __smbd_open_release(smbd_open_pool_t &pool, x_smbd_open_t *smbd_open)
{
	{
		std::lock_guard<std::mutex> lock(pool.mutex);
		pool.hashtable.remove(smbd_open);
	}
//	--pool.count;
	smbd_open->decref();
}

static smbd_open_pool_t smbd_open_pool;

int x_smbd_open_pool_init(x_evtmgmt_t *ep, uint32_t count)
{
	return __smbd_open_pool_init(smbd_open_pool, ep, count);
}

void x_smbd_open_insert_local(x_smbd_open_t *smbd_open)
{
	return __smbd_open_insert(smbd_open_pool, smbd_open);
}

/* TODO should also match persistent id??? */
x_smbd_open_t *x_smbd_open_find(uint64_t id, const x_smbd_tcon_t *smbd_tcon)
{
	return __smbd_open_find(smbd_open_pool, id, smbd_tcon);
}

void x_smbd_open_release(x_smbd_open_t *smbd_open)
{
	return __smbd_open_release(smbd_open_pool, smbd_open);
}

