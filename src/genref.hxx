
#ifndef __genref__hxx__
#define __genref__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/xdefines.h"

struct genref_t
{
	/* high 32 bit is gen, low 32 bit is refcount */
	std::atomic<uint64_t> val{0};

	uint64_t init(uint32_t init_ref = 1) {
		uint64_t oval = val;
		assert((oval & 0xffffffff) == 0);
		val += init_ref;
		return oval & 0xffffffff00000000;
	}

	bool try_get(uint64_t gen) {
		uint64_t oval = val.load(std::memory_order_relaxed);
		for (;;) {
			if ((oval & 0xffffffff00000000) != gen) {
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

	void release() {
		X_ASSERT(int32_t(val) > 0);
		val += (1ul << 32);
	}

	bool put() {
		uint64_t oval = val.load(std::memory_order_relaxed);
		uint64_t nval;
		for (;;) {
			int32_t ref = int32_t(oval);
			assert(ref > 0);
			nval = (oval & 0xffffffff00000000) | (ref - 1);
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

#endif /* __genref__hxx__ */

