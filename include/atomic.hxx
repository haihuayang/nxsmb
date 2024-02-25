
#ifndef __genref__hxx__
#define __genref__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "xdefines.h"
#include "utils.hxx"
#include <assert.h>
#include <atomic>

struct x_genref_t
{
	/* high 32 bit is gen, low 32 bit is refcount */
	std::atomic<uint64_t> val{0};

	uint64_t init(uint32_t init_ref = 1) noexcept {
		uint64_t oval = val;
		assert((oval & 0xffffffffu) == 0);
		val += init_ref;
		return oval & 0xffffffff00000000ul;
	}

	uint64_t get_gen() const noexcept {
		uint64_t oval = val.load(std::memory_order_release);
		return (oval & 0xffffffff00000000ul);
	}

	bool try_get(uint64_t gen) noexcept {
		uint64_t oval = val.load(std::memory_order_relaxed);
		for (;;) {
			if ((oval & 0xffffffff00000000ul) != gen) {
				return false;
			}

			int32_t ref = int32_t(oval);
			assert(ref >= 0);

			if (ref == 0) {
				return false;
			}

			uint64_t nval = gen | (ref + 1);
			if (std::atomic_compare_exchange_weak_explicit(
						&val,
						&oval,
						nval,
						std::memory_order_release,
						std::memory_order_relaxed)) {
				break;
			}
		}
		return true;
	}

	bool try_incref(uint64_t &ret_gen) noexcept {
		uint64_t oval = val.load(std::memory_order_relaxed);
		for (;;) {
			int32_t ref = int32_t(oval);
			assert(ref >= 0);

			if (ref == 0) {
				return false;
			}
			uint64_t gen = oval & 0xffffffff00000000ul;
			uint64_t nval = gen | (ref + 1);
			if (std::atomic_compare_exchange_weak_explicit(
						&val,
						&oval,
						nval,
						std::memory_order_release,
						std::memory_order_relaxed)) {
				ret_gen = gen;
				break;
			}
		}
		return true;
	}

	bool incref() noexcept {
		uint64_t oval = val.load(std::memory_order_relaxed);
		for (;;) {
			int32_t ref = int32_t(oval);
			assert(ref > 0);

			if (std::atomic_compare_exchange_weak_explicit(
						&val,
						&oval,
						oval + 1,
						std::memory_order_release,
						std::memory_order_relaxed)) {
				break;
			}
		}
		return true;
	}

	void release() noexcept {
		X_ASSERT(int32_t(val) > 0);
		/* increase the generation */
		val += (1ul << 32);
	}

	bool decref() noexcept {
		uint64_t oval = val.load(std::memory_order_relaxed);
		uint64_t nval;
		for (;;) {
			int32_t ref = int32_t(oval);
			assert(ref > 0);
			nval = (oval & 0xffffffff00000000) | (uint32_t)(ref - 1);
			if (std::atomic_compare_exchange_weak_explicit(
						&val,
						&oval,
						nval,
						std::memory_order_release,
						std::memory_order_relaxed)) {
				return ref == 1;
			}
		}
	}
};

template <typename T>
inline bool x_atomic_check_set_flags(std::atomic<T> &obj,
		T expected_flags, T new_flag)
{
	auto old_flag = obj.load(std::memory_order_relaxed);
	for (;;) {
		if (x_unlikely((old_flag & expected_flags) == 0)) {
			return false;
		}

		X_ASSERT((old_flag & (~expected_flags)) == 0);
		if (std::atomic_compare_exchange_weak_explicit(
					&obj,
					&old_flag,
					new_flag,
					std::memory_order_release,
					std::memory_order_relaxed)) {
			return true;
		}
	}
}

template <typename T>
inline bool x_atomic_check_set_value(std::atomic<T> &obj,
		T expected_value, T new_value)
{
	auto old_value = obj.load(std::memory_order_relaxed);
	for (;;) {
		if (x_unlikely((old_value != expected_value) == 0)) {
			return false;
		}

		if (std::atomic_compare_exchange_weak_explicit(
					&obj,
					&old_value,
					new_value,
					std::memory_order_release,
					std::memory_order_relaxed)) {
			return true;
		}
	}
}

#endif /* __genref__hxx__ */

