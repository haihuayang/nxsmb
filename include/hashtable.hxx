
#ifndef __hashtable__hxx__
#define __hashtable__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include <vector>
#include "list.hxx"

template <typename HashTraits>
struct x_hashtable_t
{
	typedef typename HashTraits::container_type item_type;
	typedef x_sdqueue_t bucket_type;

	void init(uint32_t count) {
		buckets.resize(count);
	}

	void insert(item_type *item, size_t hash) {
		bucket_type &bucket = buckets[hash % buckets.size()];
		bucket.push_front(HashTraits::member(item));
	}

	void remove(item_type *item) {
		HashTraits::member(item)->remove();
	}

	template <typename EQ> item_type *find(size_t hash, const EQ &eq) const {
		const bucket_type &bucket = buckets[hash % buckets.size()];
		return find_in_bucket(bucket, eq);
	}

private:
	template <class EQ> item_type *find_in_bucket(const bucket_type &bucket,
			const EQ &eq) const
	{
		for (x_dqlink_t *link = bucket.get_front(); link; link = link->get_next()) {
			item_type *item = HashTraits::container(link);
			if (eq(*item))
				return item;
		}
		return NULL;
	}

	std::vector<x_sdqueue_t> buckets;
};

#endif /* __hashtable__hxx__ */

