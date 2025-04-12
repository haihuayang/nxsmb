
#ifndef __smbd_pool__hxx__
#define __smbd_pool__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/hashtable.hxx"

template <typename HashTraits>
struct smbd_pool_t
{
	x_hashtable_t<HashTraits> hashtable;
	std::atomic<uint32_t> count;
	uint32_t capacity;
	std::mutex mutex;
};

template <typename P>
static inline void pool_init(P &pool, uint32_t count)
{
	uint32_t bucket_size = x_convert_assert<uint32_t>(x_next_2_power(count));
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
	x_smbd_ref_dec(elem);
}

template <typename HashTraits>
struct pool_iterator_t
{
	pool_iterator_t(smbd_pool_t<HashTraits> &pool) : ppool(&pool) { }
	smbd_pool_t<HashTraits> *const ppool;
	size_t next_bucket_idx = 0;

	template <typename Func>
	size_t get_next(Func &&func, size_t min_count);
};


template <typename HashTraits> template <typename Func>
size_t pool_iterator_t<HashTraits>::get_next(Func &&func, size_t min_count)
{
	if (min_count == 0) {
		min_count = 1;
	}

	size_t count = 0;
	auto lock = std::lock_guard(ppool->mutex);
	while (next_bucket_idx < ppool->hashtable.buckets.size()) {
		for (x_dqlink_t *link = ppool->hashtable.buckets[next_bucket_idx].get_front();
				link; link = link->get_next()) {
			auto item = HashTraits::container(link);
			if (func(*item)) {
				min_count = 0;
			}
			++count;
		}
		++next_bucket_idx;
		if (count >= min_count) {
			break;
		}
	}
	return count;
}



#endif /* __smbd_pool__hxx__ */

