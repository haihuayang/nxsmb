
#ifndef __smbd_hashtable__hxx__
#define __smbd_hashtable__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/utils.hxx"
#include "include/bits.hxx"
#include <vector>
#include <mutex>
#include <atomic>
#include "include/hashtable.hxx"

template <typename HashTraits>
struct x_smbd_hashtable_t
{
	void init(uint32_t count, uint32_t mutex_count) {
		uint32_t bucket_size = x_convert_assert<uint32_t>(x_next_2_power(count));
		hashtable.init(bucket_size);
		capacity = count;
		std::vector<std::mutex> tmp(mutex_count);
		std::swap(mutex, tmp);
	}

	x_hashtable_t<HashTraits> hashtable;
	std::atomic<uint32_t> count;
	uint32_t capacity;
	std::vector<std::mutex> mutex;
};


#endif /* __smbd_hashtable__hxx__ */

