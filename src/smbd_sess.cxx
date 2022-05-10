
#include "smbd.hxx"
#include "include/atomic.hxx"
#include "smbd_ctrl.hxx"

template <class T>
struct x_pool_t
{
	struct entry_t
	{
		x_genref_t genref;
		union alignas(std::max(alignof(T), alignof(entry_t *)) {
			entry_t *next;
			char data[sizeof(T)];
		};

		T *get_obj() noexcept {
			return static_cast<T *>((void *)&data);
		}
	};

	const uint32_t count;
	std::atomic<uint32_t> alloc_count{};
	std::atomic<entry_t *>freelist = nullptr;
	entry_t *data = nullptr;
	
	x_pool_t(size_t count) : count(count) {
		X_ASSERT(count < 0x80000000u);
		entry_t *ptr = data = new entry_t[count];
		entry_t *head = nullptr;
		for (size_t i = count; i--; ) {
			entry_t *obj = ptr + i;
			obj->next = head;
			head = obj;
		}
		freelist = head;
	}

	uint64_t to_id(uint32_t index, uint64_t gen) const noexcept {
		X_ASSERT(index < count);
		/* +1 so the id will not equal 0 */
		return gen | (index + 1);
	}

	T *find(uint64_t id) const noexcept {
		uint32_t index = id;
		if (index == 0) {
			return nullptr;
		}
		if (index > count) {
			return nullptr;
		}
		--index;
		entry_t *entry = data + index;
		if (!entry->genref.try_get(id & 0xffffffff00000000ul)) {
			return nullptr;
		}
		return entry->get_obj();
	}

	T *try_incref(uint64_t &id, uint32_t index) noexcept {
		entry_t *entry = data + index;
		if (!entry->genref.try_get()) {
			return nullptr;
		}
	}

	void get(T *obj) noexcept {
		entry_t *entry = X_CONTAINER_OF(obj, entry_t, data);
		entry->genref.incref();
	}

	void put(T *obj) noexcept {
		entry_t *entry = X_CONTAINER_OF(obj, entry_t, data);
		if (entry->genref.decref()) {
			X_LOG_DBG("free %p", obj);
			obj->~T();

			entry_t *oval = freelist.load(std::memory_order_relaxed);
			for (;;) {
				entry->next = oval;
				if (std::atomic_compare_exchange_weak_explicit(
							&freelist,
							&oval,
							entry,
							std::memory_order_release,
							std::memory_order_relaxed)) {
					break;
				}
			}
			--alloc_count;
		}
	}

	template <typename... Args>
	T *allocate(uint64_t &id, Args&&... args) {
		entry_t *oval = freelist.load(std::memory_order_relaxed);
		for (;;) {
			if (!oval) {
				return nullptr;
			}
			entry_t *nval = oval->next;
			if (std::atomic_compare_exchange_weak_explicit(
						&freelist,
						&oval,
						nval,
						std::memory_order_release,
						std::memory_order_relaxed)) {
				++alloc_count;
				uint64_t gen = oval->genref.init(1);
				T *obj = oval->get_obj();
				// we assume constructor not raise exception
				new (obj) T{std::forward<Args>(args)...};
				size_t index = oval - data;
				id = to_id(index, gen);
				return obj;
			}
		}
	}

	uint64_t get_id(const T *obj) noexcept {
		const entry_t *entry = X_CONTAINER_OF(obj, entry_t, data);
		size_t index = entry - data;
		return to_id(index, entry->genref.get_gen());
	}
};

struct x_smbd_sess_t
{
	~x_smbd_sess_t() {} // TODO

	// uint64_t id;
	std::mutex mutex;
	std::shared_ptr<x_smbd_user_t> smbd_user;
	std::atomic<int> refcnt;
	enum {
		S_INIT,
		S_ACTIVE,
		S_TERMINATED,
	} state = S_INIT;
	// uint16_t security_mode = 0;
	bool signing_required = false;
	bool key_is_valid = false;
	uint8_t chan_count = 0;
	std::array<x_smbd_chan_t *, 32> chans = { nullptr, };

	x_smbd_key_set_t keys;

	x_ddlist_t tcon_list;
};

using x_smbd_sess_pool_t = x_pool_t<x_smbd_sess_t>;

static x_smbd_sess_pool_t *g_smbd_sess_pool;

int x_smbd_sess_pool_init(uint32_t count)
{
	g_smbd_sess_pool = new x_smbd_sess_pool_t(count);
	return 0;
}

x_smbd_sess_t *x_smbd_sess_create(uint64_t &id)
{
	x_smbd_sess_t *smbd_sess = g_smbd_sess_pool->allocate(id);
	X_LOG_DBG("0x%lx %p", id, smbd_sess);
	return smbd_sess;
}

x_smbd_sess_t *x_smbd_sess_find(uint64_t id, const x_smb2_uuid_t &client_guid)
{
	/* skip client_guid checking, since session bind is signed,
	 * the check does not improve security
	 */
	return g_smbd_sess_pool->find(id);
}

template <>
x_smbd_sess_t *x_smbd_ref_inc(x_smbd_sess_t *smbd_sess)
{
	g_smbd_sess_pool->get(smbd_sess);
	return smbd_sess;
}

template <>
void x_smbd_ref_dec(x_smbd_sess_t *smbd_sess)
{
	g_smbd_sess_pool->put(smbd_sess);
}

uint64_t x_smbd_sess_get_id(const x_smbd_sess_t *smbd_sess)
{
	return g_smbd_sess_pool->get_id(smbd_sess);
}

bool x_smbd_sess_is_signing_required(const x_smbd_sess_t *smbd_sess)
{
	return smbd_sess->signing_required;
}

std::shared_ptr<x_smbd_user_t> x_smbd_sess_get_user(const x_smbd_sess_t *smbd_sess)
{
	return smbd_sess->smbd_user;
}

const x_smb2_key_t *x_smbd_sess_get_signing_key(x_smbd_sess_t *smbd_sess)
{
	// TODO memory order
	if (smbd_sess->key_is_valid) {
		return &smbd_sess->keys.signing_key;
	}
	return nullptr;
}

bool x_smbd_sess_add_chan(x_smbd_sess_t *smbd_sess, x_smbd_chan_t *smbd_chan)
{
	std::lock_guard<std::mutex> lock(smbd_sess->mutex);
	if (smbd_sess->chan_count >= smbd_sess->chans.size()) {
		return false;
	}
	for (uint32_t i = 0; i < smbd_sess->chans.size(); ++i) {
		if (!smbd_sess->chans[i]) {
			smbd_sess->chans[i] = x_smbd_ref_inc(smbd_chan);
			++smbd_sess->chan_count;
			return true;
		}
	}
	X_ASSERT(false);
	return false;
}
	
void x_smbd_sess_remove_chan(x_smbd_sess_t *smbd_sess, x_smbd_chan_t *smbd_chan)
{
	std::lock_guard<std::mutex> lock(smbd_sess->mutex);
	for (uint32_t i = 0; i < smbd_sess->chans.size(); ++i) {
		if (smbd_sess->chans[i] == smbd_chan) {
			X_SMBD_REF_DEC(smbd_sess->chans[i]);
			--smbd_sess->chan_count;
			return;
		}
	}
	X_ASSERT(false);
}

x_smbd_chan_t *x_smbd_sess_find_chan(x_smbd_sess_t *smbd_sess, x_smbd_conn_t *smbd_conn)
{
	std::lock_guard<std::mutex> lock(smbd_sess->mutex);
	for (auto smbd_chan: smbd_sess->chans) {
		if (smbd_chan && x_smbd_chan_get_conn(smbd_chan) == smbd_conn) {
			return x_smbd_ref_inc(smbd_chan);
		}
	}
	return nullptr;
}

x_smbd_chan_t *x_smbd_sess_get_active_chan(x_smbd_sess_t *smbd_sess)
{
	std::lock_guard<std::mutex> lock(smbd_sess->mutex);
	for (auto smbd_chan: smbd_sess->chans) {
		if (smbd_chan && x_smbd_chan_is_active(smbd_chan)) {
			return x_smbd_ref_inc(smbd_chan);
		}
	}
	return nullptr;
}

void x_smbd_sess_link_tcon(x_smbd_sess_t *smbd_sess, x_dlink_t *link)
{
	smbd_sess->tcon_list.push_back(link);
}

void x_smbd_sess_unlink_tcon(x_smbd_sess_t *smbd_sess, x_dlink_t *link)
{
	smbd_sess->tcon_list.remove(link);
}

#if 0
x_smbd_sess_t::~x_smbd_sess_t()
{
	if (auth) {
		x_auth_destroy(auth);
	}
	if (smbd_conn) {
		smbd_conn->decref();
	}
	--count;
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
	std::mutex mutex; // TODO granuarly
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

x_smbd_sess_t *x_smbd_sess_create(x_smbd_conn_t *smbd_conn)
{
	return __smbd_sess_create(smbd_sess_pool, smbd_conn);
}

void x_smbd_sess_release(x_smbd_sess_t *smbd_sess)
{
	return __smbd_sess_release(smbd_sess_pool, smbd_sess);
}
#endif

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
	std::array<x_smbd_chan_t *, 32> smbd_chans{};
	uint8_t smbd_chan_count = 0;
	{
		std::lock_guard<std::mutex> lock(smbd_sess->mutex);
		smbd_sess->state = x_smbd_sess_t::S_TERMINATED;
		smbd_sess->smbd_user = nullptr;
		std::swap(smbd_chans, smbd_sess->chans);
		std::swap(smbd_chan_count, smbd_sess->chan_count);
	}
	for (auto smbd_chan: smbd_chans) {
		if (!smbd_chan) {
			continue;
		}
		x_smbd_chan_logoff(smbd_chan);
		x_smbd_ref_dec(smbd_sess);
		--smbd_chan_count;
	}
	X_ASSERT(smbd_chan_count == 0);
	// TODO free all tcon
	return NT_STATUS_OK;
}

x_smbd_ctrl_handler_t *x_smbd_list_session_create()
{
	X_TODO;
	return nullptr; // new x_smbd_list_session_t;
}

