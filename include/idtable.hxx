
#ifndef __idtable__hxx__
#define __idtable__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/xdefines.h"
#include <atomic>
#include <memory>

struct x_idtable_64_traits_t
{
	enum {
		index_max = 0x7fffffffu,
		index_null = 0xffffffffu,
		id_invalid = uint64_t(-1),
	};
	using id_type = uint64_t;
	static constexpr uint64_t entry_to_gen(uint64_t val) {
		return val & 0xfffffffful;
	}
	static constexpr uint64_t build_id(uint32_t gen, uint32_t index) {
		return uint64_t(index) << 32 | gen;
	}
	static constexpr uint32_t id_to_index(uint64_t id) {
		return id >> 32;
	}
	static constexpr uint32_t id_to_gen(uint64_t id) {
		return uint32_t(id);
	}
	static constexpr uint32_t inc_gen(uint32_t gen) {
		return gen + 1;
	}
};

struct x_idtable_32_traits_t
{
	enum {
		index_max = 0xfff8u,
		index_null = 0xffffu,
		id_invalid = uint32_t(-1),
	};
	using id_type = uint32_t;
	static constexpr uint32_t entry_to_gen(uint64_t val) {
		return val & 0xfffful;
	}
	static constexpr uint32_t build_id(uint16_t gen, uint16_t index) {
		return uint32_t(index) << 16 | gen;
	}
	static constexpr uint16_t id_to_index(uint32_t id) {
		return id >> 16;
	}
	static constexpr uint16_t id_to_gen(uint16_t id) {
		return uint16_t(id);
	}
	static constexpr uint16_t inc_gen(uint16_t gen) {
		return gen + 1;
	}
};

template <class T, class Traits, class Delete = std::default_delete<T>>
struct x_idtable_t
{
	using id_type = typename Traits::id_type;
	enum { refcnt_max = 0x10000000u, };

	struct entry_t
	{
		/*
		 * 1 bit allocated or not, 31 bits next (if free) or refcount (if allocated)
		 * and gen (32 bit for 64, 16 bit for 32)
		 */
		std::atomic<uint64_t> header;
		T *data{};
	};

	explicit x_idtable_t(uint32_t count) : count(count) {
		X_ASSERT(count < Traits::index_max);
		entries = new entry_t[count];
		X_ASSERT(entries);
		uint64_t head = uint64_t(Traits::index_null) << 32;
		for (uint64_t i = count; i--; ) {
			entry_t *entry = entries + i;
			entry->header = head;
			head = i << 32;
		}
		freelist = head;
	}

	~x_idtable_t() {
		delete[] entries;
	}

	entry_t *allocate() {
		uint64_t oval = freelist.load(std::memory_order_relaxed);
		for (;;) {
			uint64_t free_index = oval >> 32;
			if (free_index == Traits::index_null) {
				return nullptr;
			}
			X_ASSERT(free_index < count);
			entry_t *entry = entries + free_index;
			/* increase tag to solve ABA issue */
			uint32_t tag = uint32_t(oval) + 1;
			uint64_t nval = (entry->header & 0xffffffff00000000ul) | tag;

			if (std::atomic_compare_exchange_weak_explicit(
						&freelist,
						&oval,
						nval,
						std::memory_order_release,
						std::memory_order_relaxed)) {
				++alloc_count; // memory order release
				return entry;
			}
		}
	}

	void deallocate(entry_t *entry) {
		X_ASSERT(alloc_count > 0); // memory order acquire
		uint64_t oval = freelist.load(std::memory_order_relaxed);
		for (;;) {
			uint64_t free_index = oval >> 32;
			X_ASSERT(free_index < count ||
					free_index == Traits::index_null);

			/* we can use acq_rel order here */
			entry->header = (free_index << 32) | uint32_t(entry->header);
			/* increase tag to solve ABA issue */
			uint32_t tag = uint32_t(oval) + 1;
			free_index = entry - entries;
			uint64_t nval = (free_index << 32) | tag;
			if (std::atomic_compare_exchange_weak_explicit(
						&freelist,
						&oval,
						nval,
						std::memory_order_release,
						std::memory_order_relaxed)) {
				--alloc_count;
				break;
			}
		}
	}

	bool store(T *data, id_type &id) noexcept {
		entry_t *entry = allocate();
		if (!entry) {
			return false;
		}
		X_ASSERT(!entry->data);
		entry->data = data;
		id_type index = entry - entries;
		id_type entry_gen = Traits::entry_to_gen(entry->header);
		/* should set id first, otherwise there is a race, other thread
		 * may lookup the entry before the caller get the id
		 * idealy the id should be kept by the table, instead the object,
		 * then how to get id from the object?
		 */
		id = Traits::build_id(entry_gen, (index + 1));
		// TODO should be possible to use more loose memory order
		entry->header = (entry_gen | (0x80000001ul << 32));
		/* +1 to avoid id be 0 */
		return true;
	}

	entry_t *find_entry(id_type id) const noexcept {
		uint32_t index = Traits::id_to_index(id);
		if (index == 0) {
			return nullptr;
		}
		if (index > count) {
			return nullptr;
		}
		--index;
		return entries + index;
	}

	std::pair<bool, T*> lookup(id_type id) const noexcept {
		entry_t *entry = find_entry(id);
		if (!entry) {
			return std::make_pair(false, nullptr);
		}

		uint32_t gen = Traits::id_to_gen(id);
		uint64_t oval = entry->header.load(std::memory_order_relaxed);
		for (;;) {
			if (Traits::id_to_gen(oval) != gen) {
				return std::make_pair(false, nullptr);
			}

			uint32_t refcnt = oval >> 32;
			if (!(refcnt & 0x80000000u)) {
				return std::make_pair(false, nullptr);
			}
			refcnt &= 0x7fffffffu;
			if (refcnt == 0) {
				return std::make_pair(false, nullptr);
			}

			/* refcnt should not so high */
			X_ASSERT(refcnt < refcnt_max);

			/* increase the refcnt */
			uint64_t nval = (((refcnt + 1) | 0x80000000ul) << 32)| gen;
			if (std::atomic_compare_exchange_weak_explicit(
						&entry->header,
						&oval,
						nval,
						std::memory_order_release,
						std::memory_order_relaxed)) {
				break;
			}
		}
		return std::make_pair(true, entry->data);
	}

	void remove(id_type id) noexcept {
		entry_t *entry = find_entry(id);
		X_ASSERT(entry);

		uint32_t gen = Traits::id_to_gen(id);

		uint64_t oval = entry->header.load(std::memory_order_relaxed);
		for (;;) {
			X_ASSERT(Traits::id_to_gen(oval) == gen);
			uint32_t refcnt = oval >> 32;
			X_ASSERT(refcnt & 0x80000000u);
			refcnt &= 0x7fffffffu;
			X_ASSERT(refcnt > 0);
			X_ASSERT(refcnt < refcnt_max);

			/* increase the generation to mark it is removed, it does not free
			 * entry.
			 */
			uint64_t nval = (oval & 0xffffffff00000000ul) | Traits::inc_gen(gen);
			if (std::atomic_compare_exchange_weak_explicit(
						&entry->header,
						&oval,
						nval,
						std::memory_order_release,
						std::memory_order_relaxed)) {
				break;
			}
		}
	}

	void incref(id_type id) noexcept {
		entry_t *entry = find_entry(id);
		X_ASSERT(entry);
		/* we do not check gen because it entry could be removed */

		uint64_t oval = entry->header.load(std::memory_order_relaxed);
		for (;;) {
			uint32_t refcnt = oval >> 32;
			X_ASSERT(refcnt & 0x80000000u);
			refcnt &= 0x7fffffffu;
			X_ASSERT(refcnt > 0);
			X_ASSERT(refcnt < refcnt_max);

			/* increase the refcnt */
			uint64_t nval = (((refcnt + 1) | 0x80000000ul) << 32)| uint32_t(oval);
			if (std::atomic_compare_exchange_weak_explicit(
						&entry->header,
						&oval,
						nval,
						std::memory_order_release,
						std::memory_order_relaxed)) {
				return;
			}
		}
	}

	bool decref(id_type id) noexcept {
		entry_t *entry = find_entry(id);
		X_ASSERT(entry);
		/* we do not check gen because it entry could be removed */
		return __decref(entry);
	}

	entry_t *try_incref(uint32_t index) const noexcept {
		entry_t *entry = entries + index;
		uint64_t oval = entry->header.load(std::memory_order_relaxed);
		for (;;) {
			uint32_t refcnt = oval >> 32;
			if (!(refcnt & 0x80000000u)) {
				return nullptr;
			}
			refcnt &= 0x7fffffffu;
			X_ASSERT(refcnt < refcnt_max);
			if (refcnt == 0) {
				return nullptr;
			}

			/* increase the refcnt */
			uint64_t nval = (((refcnt + 1) | 0x80000000ul) << 32)| uint32_t(oval);
			if (std::atomic_compare_exchange_weak_explicit(
						&entry->header,
						&oval,
						nval,
						std::memory_order_release,
						std::memory_order_relaxed)) {
				return entry;
			}
		}
	}

	struct iter_t
	{
		uint32_t index;
	};

	iter_t iter_start() const noexcept {
		return iter_t{0};
	}

	void iter_end(iter_t &iter) const noexcept { }

	template <typename Func>
	bool iter_entry(iter_t &iter, Func &&func) {
		uint32_t index = iter.index;
		entry_t *entry = nullptr;
		for (; index < count; ++index) {
			entry = try_incref(index);
			if (entry) {
				break;
			}
		}

		if (!entry) {
			iter.index = index;
			return false;
		}

		iter.index = index + 1;
		bool ret = func(entry->data);
		__decref(entry);
		return ret;
	}

	bool __decref(entry_t *entry) noexcept {
		uint64_t oval = entry->header.load(std::memory_order_relaxed);
		for (;;) {
			uint32_t refcnt = oval >> 32;
			X_ASSERT(refcnt & 0x80000000u);
			refcnt &= 0x7fffffffu;
			X_ASSERT(refcnt > 0);
			X_ASSERT(refcnt < refcnt_max);

			/* decrease the refcnt */
			uint64_t nval = (((refcnt - 1) | 0x80000000ul) << 32)| uint32_t(oval);
			if (std::atomic_compare_exchange_weak_explicit(
						&entry->header,
						&oval,
						nval,
						std::memory_order_release,
						std::memory_order_relaxed)) {
				if (refcnt == 1) {
					deallocate(entry);
					T *data = std::exchange(entry->data, nullptr);
					Delete()(data);
					return true;
				}
				return false;
			}
		}
	}

	const uint32_t count;
	std::atomic<uint32_t> alloc_count{};
	/* high 32 bits index, low 32 bits tag (avoid ABA) */
	std::atomic<uint64_t> freelist;
	entry_t *entries = nullptr;

};


#endif /* __idtable__hxx__ */

