
#include <mutex>
#include "include/hashtable.hxx"
#include "smbd.hxx"

x_smbdsess_t::x_smbdsess_t(x_smbdconn_t *smbdconn)
	: smbdconn{smbdconn}, refcnt{1}
{
	smbdconn->incref();
}

#if 0
enum {
	TIMER_INTERVAL = 3000,
};
#endif
struct smbdsess_pool_t
{
#if 0
	x_timer_t timer; // check expire
	x_tp_dcircle_t<smbdsess_dcircle_traits> active_list;
	x_tp_dcircle_t<smbdsess_dcircle_traits> timeout_list;
#endif
	x_hashtable_t<smbdsess_hash_traits> hashtable;
	std::atomic<uint32_t> count;
	uint32_t capacity;
	std::mutex mutex;
};

static inline int __smbdsess_pool_init(smbdsess_pool_t &pool, x_evtmgmt_t *ep, uint32_t count)
{
	uint32_t bucket_size = 1;
	while (bucket_size <= count) {
		bucket_size <<= 1;
	}
	pool.hashtable.init(bucket_size);
	pool.capacity = count;

	return 0;
}

static inline x_smbdsess_t *smbdsess_find_by_id(smbdsess_pool_t &pool, uint64_t id)
{
	return pool.hashtable.find(id, [id](const x_smbdsess_t &s) { return s.id == id; });
}

static x_smbdsess_t *__smbdsess_find(smbdsess_pool_t &pool, uint64_t id,
		const x_smbdconn_t *smbdconn)
{
	std::unique_lock<std::mutex> lock(pool.mutex);
	x_smbdsess_t *smbdsess = smbdsess_find_by_id(pool, id);
	if (smbdsess && smbdsess->smbdconn == smbdconn) {
		smbdsess->incref();
		return smbdsess;
	}
	return nullptr;
}

static uint64_t g_sess_id = 0x1234;
static x_smbdsess_t *__smbdsess_create(smbdsess_pool_t &pool, x_smbdconn_t *smbdconn)
{
	if (pool.count++ > pool.capacity) {
		--pool.count;
		return nullptr;
	}
	x_smbdsess_t *smbdsess = new x_smbdsess_t(smbdconn);
	smbdsess->incref(); /* for hash */
	// smbdsess->incref(); /* for dcircle */
	std::unique_lock<std::mutex> lock(pool.mutex);
	for (;;) {
		/* TODO to reduce hash conflict */
		smbdsess->id = g_sess_id++;
		x_smbdsess_t *exist = smbdsess_find_by_id(pool, smbdsess->id);
		if (!exist) {
			break;
		}
	}
	pool.hashtable.insert(smbdsess, smbdsess->id);
	
	return smbdsess;
}

static void __smbdsess_release(smbdsess_pool_t &pool, x_smbdsess_t *smbdsess)
{
	{
		std::lock_guard<std::mutex> lock(pool.mutex);
		pool.hashtable.remove(smbdsess);
	}
	--pool.count;
	smbdsess->decref();
}

static smbdsess_pool_t smbdsess_pool;

int x_smbdsess_pool_init(x_evtmgmt_t *ep, uint32_t count)
{
	return __smbdsess_pool_init(smbdsess_pool, ep, count);
}

x_smbdsess_t *x_smbdsess_create(x_smbdconn_t *smbdconn)
{
	return __smbdsess_create(smbdsess_pool, smbdconn);
}

x_smbdsess_t *x_smbdsess_find(uint64_t id, const x_smbdconn_t *smbdconn)
{
	return __smbdsess_find(smbdsess_pool, id, smbdconn);
}

void x_smbdsess_release(x_smbdsess_t *smbdsess)
{
	return __smbdsess_release(smbdsess_pool, smbdsess);
}

#if 0
void x_smbdsess_stop(x_smbdsess_t *smbdsess);
void x_smbdsess_stop(x_smbdsess_t *sess)
{
	{
		std::unique_lock<std::mutex> lock(smbdsess_pool.mutex);
		smbdsess_pool.hashtable.remove(sess);
	}
	atomic_exchange state to S_SHUTDONW;
	if (orig_state == S_WAITINPUT) {
		remove from timeout list;
		sess->decref();
	}
	sess->decref();
	sess->decref();
}

static x_smbdsess_t *x_smbdconn_lookup_session(const x_smbdconn_t *smbdconn,
		uint64_t session_id)
{
	for (auto &sess: smbdconn->sessions) {
		if (sess->id == session_id) {
			sess->incref();
			return sess;
		}
	}
	return nullptr;
}

static x_smbdsess_ptr_t x_smbdconn_create_session(x_smbdconn_t *smbdconn)
{
	x_smbdsess_t sess = new x_smbdsess_t();
	sess->id = g_sess_id++;
	sess->auth = x_smbd_create_auth(smbdconn->smbsrv);
	smbdconn->sessions.push_back(sess);
	return sess;
}

NTSTATUS x_smbdconn_auth_update(x_smbdconn_t *smbdconn, uint64_t in_session_id,
		x_msg_t *msg, const uint8_t *inbuf, size_t inlen,
		std::vector<uint8_t> &outbuf)
{
	x_smbdsess_t *smbdsess;
	if (in_session_id == 0) {
		smbdsess = x_smbdsess_create(smbdconn);
	} else {
		smbdsess = x_smbdsess_find(in_session_id, smbdconn);
		if (smbdsess == nullptr) {
			return NT_STATUS_USER_SESSION_DELETED;
		}

		if (!smbdsess_set_state(smbdsess, x_smbdsess_t::SF_WAITINPUT, x_smbdsess_t::SF_PROCESSING)) {
			/* it is removing due to expired */
			return NT_STATUS_NETWORK_SESSION_EXPIRED;
		}

		smbdsess_pool.timeout_list.remove(smbdsess);
		smbdsess->decref();
	}

	smbdsess->msg = msg;
	NTSTATUS status = smbdsess->auth->update(inbuf, inlen, outbuf, smbdsess);
	if (NT_STATUS_IS_OK(status)) {
		smbdsess->msg = nullptr;
		X_ASSERT(smbdsess_set_state(smbdsess, x_smbdsess_t::SF_PROCESSING, x_smbdsess_t::SF_ACTIVE));
	} else if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		smbdsess->msg = nullptr;
		X_ASSERT(smbdsess_set_state(smbdsess, x_smbdsess_t::SF_PROCESSING, x_smbdsess_t::SF_WAITINPUT));
		smbdsess->timeout = x_tick_add(tick_now, 2 * 60 * 1000);
		smbdsess_pool.timeout_list.push_back(smbdsess);
		smbdsess->incref();
	} else if (NT_STATUS_EQUAL(status, X_NT_STATUS_INTERNAL_BLOCKED)) {
		X_ASSERT(smbdsess_set_state(smbdsess, x_smbdsess_t::SF_PROCESSING, x_smbdsess_t::SF_BLOCKED));
	} else {
		smbdsess->msg = nullptr;
		X_ASSERT(smbdsess_set_state(smbdsess, x_smbdsess_t::SF_PROCESSING, x_smbdsess_t::SF_FAILED));
	}
	smbdsess->decref();
	return status;
}

#endif

