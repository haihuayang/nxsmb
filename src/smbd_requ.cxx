
#include "smbd.hxx"
#include "smbd_pool.hxx"

static std::atomic<uint32_t> g_smbd_requ_count = 0;

x_smbd_requ_t::x_smbd_requ_t(x_buf_t *in_buf)
	: in_buf(in_buf)
{
	++g_smbd_requ_count;
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
	/* TODO free them
	x_smbd_object_t *smbd_object{};
	*/
	--g_smbd_requ_count;
}

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

static uint64_t g_async_id = 0x0;
static void smbd_requ_insert_intl(smbd_requ_pool_t &pool, x_smbd_requ_t *smbd_requ)
{
	std::unique_lock<std::mutex> lock(pool.mutex);
	for (;;) {
		/* TODO to reduce hash conflict */
		smbd_requ->async_id = g_async_id++;
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



static smbd_requ_pool_t g_smbd_requ_pool;


int x_smbd_requ_pool_init(uint32_t count)
{
	pool_init(g_smbd_requ_pool, count);
	return 0;
}

x_smbd_requ_t *x_smbd_requ_lookup(uint64_t id, const x_smbd_conn_t *smbd_conn)
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

