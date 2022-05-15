
#include "smbd.hxx"
#include "smbd_ctrl.hxx"
#include "smbd_stats.hxx"
#include "smbd_open.hxx"
#include "include/idtable.hxx"

struct smbd_open_deleter
{
	void operator()(x_smbd_open_t *smbd_open) const {
		x_smbd_open_op_destroy(smbd_open);
	}
};

using smbd_open_table_t = x_idtable_t<x_smbd_open_t, x_idtable_64_traits_t, smbd_open_deleter>;
static smbd_open_table_t *g_smbd_open_table;

/* allocate extra count of open, so it unlikely exceed the hard limit when multiple thread
 * create the open in the same time, because each of them call x_smbd_open_has_space
 * before create it
 */
static constexpr uint32_t g_smbd_open_extra = 32;
bool x_smbd_open_has_space()
{
	return g_smbd_open_table->alloc_count + g_smbd_open_extra < g_smbd_open_table->count;
}

x_smbd_open_t::x_smbd_open_t(x_smbd_object_t *so, x_smbd_tcon_t *st,
		uint32_t am, uint32_t sa)
	: smbd_object(so), smbd_tcon(x_smbd_ref_inc(st))
	, access_mask(am), share_access(sa)
{
	X_SMBD_COUNTER_INC(open_create, 1);
}

x_smbd_open_t::~x_smbd_open_t()
{
	x_smbd_ref_dec(smbd_tcon);
	X_SMBD_COUNTER_INC(open_delete, 1);
}

template <>
x_smbd_open_t *x_smbd_ref_inc(x_smbd_open_t *smbd_open)
{
	g_smbd_open_table->incref(smbd_open->id);
	return smbd_open;
}

template <>
void x_smbd_ref_dec(x_smbd_open_t *smbd_open)
{
	g_smbd_open_table->decref(smbd_open->id);
}

int x_smbd_open_table_init(uint32_t count)
{
	g_smbd_open_table = new smbd_open_table_t(count + g_smbd_open_extra);
	return 0;
}

bool x_smbd_open_store(x_smbd_open_t *smbd_open)
{
	return g_smbd_open_table->store(smbd_open, smbd_open->id);
}

x_smbd_open_t *x_smbd_open_lookup(uint64_t id_presistent, uint64_t id_volatile,
		const x_smbd_tcon_t *smbd_tcon)
{
	auto ret = g_smbd_open_table->lookup(id_volatile);
	if (ret.first) {
		x_smbd_open_t *smbd_open = ret.second;
		if (smbd_open->smbd_tcon == smbd_tcon) {
			return smbd_open;
		}
		x_smbd_ref_dec(smbd_open);
	}
	return nullptr;
}

static bool smbd_open_terminate(x_smbd_open_t *smbd_open)
{
	std::unique_lock<std::mutex> lock;
	if (smbd_open->state == x_smbd_open_t::S_DONE) {
		return false;
	}
	smbd_open->state = x_smbd_open_t::S_DONE;
	lock.unlock();

	g_smbd_open_table->remove(smbd_open->id);
	x_smbd_ref_dec(smbd_open);

	x_smbd_ref_dec(smbd_open); // ref by smbd_tcon open_list
	return true;
}

bool x_smbd_open_close(x_smbd_open_t *smbd_open)
{
	if (x_smbd_tcon_unlink_open(smbd_open->smbd_tcon, &smbd_open->tcon_link)) {
		return smbd_open_terminate(smbd_open);
	}
	return false;
}

void x_smbd_open_unlinked(x_dlink_t *link, x_smbd_tcon_t *smbd_tcon)
{
	x_smbd_open_t *smbd_open = X_CONTAINER_OF(link, x_smbd_open_t, tcon_link);
	smbd_open_terminate(smbd_open);
}

struct x_smbd_open_list_t : x_smbd_ctrl_handler_t
{
	x_smbd_open_list_t() : iter(g_smbd_open_table->iter_start()) {
	}
	bool output(std::string &data) override;
	smbd_open_table_t::iter_t iter;
};

bool x_smbd_open_list_t::output(std::string &data)
{
	std::ostringstream os;

	bool ret = g_smbd_open_table->iter_entry(iter, [&os](const x_smbd_open_t *smbd_open) {
			os << idl::x_hex_t<uint64_t>(smbd_open->id) << ' '
			<< idl::x_hex_t<uint32_t>(smbd_open->access_mask) << ' '
			<< idl::x_hex_t<uint32_t>(smbd_open->share_access) << ' '
			<< idl::x_hex_t<uint32_t>(x_smbd_tcon_get_id(smbd_open->smbd_tcon)) << " '"
			<< x_smbd_open_op_get_path(smbd_open) << "'" << std::endl;
			return true;
		});
	if (ret) {
		data = os.str(); // TODO avoid copying
		return true;
	} else {
		return false;
	}
}

x_smbd_ctrl_handler_t *x_smbd_open_list_create()
{
	return new x_smbd_open_list_t;
}
#if 0
X_DECLARE_MEMBER_TRAITS(smbd_open_hash_traits, x_smbd_open_t, hash_link)
struct smbd_open_pool_t
{
	x_hashtable_t<smbd_open_hash_traits> hashtable;
	std::atomic<uint32_t> count;
	uint32_t capacity;
	std::mutex mutex;
};

static inline int __smbd_open_pool_init(smbd_open_pool_t &pool, x_evtmgmt_t *ep, uint32_t count)
{
	size_t bucket_size = x_next_2_power(count);
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
#endif
