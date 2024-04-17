
#ifndef __stats__hxx__
#define __stats__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/xdefines.h"
#include <stdint.h>
#include <vector>
#include <string>

enum {
	X_HISTOGRAM_BAND_NUMBER = 32,
};

#define X_STATS_ATOMIC_IF_SET(ptr, val, comp) do { \
	auto __oval = __atomic_load_n((ptr), __ATOMIC_RELAXED); \
	auto __val = (val); \
	while (__val comp __oval) { \
		if (__atomic_compare_exchange_n((ptr), &__oval, __val, true, \
					__ATOMIC_RELEASE, __ATOMIC_RELAXED)) { \
			break; \
		} \
	} \
} while (0)

struct x_histogram_t
{
	uint64_t min{uint64_t(-1)}, max{}, sum{};
	uint64_t bands[X_HISTOGRAM_BAND_NUMBER]{};

	void update(uint64_t val) {
		unsigned int band = 0;
		if (x_likely(val != 0)) {
			band = 64 - __builtin_clzl(val);
			if (x_unlikely(band >= X_HISTOGRAM_BAND_NUMBER)) {
				band = X_HISTOGRAM_BAND_NUMBER - 1;
			}
		}

		__atomic_fetch_add(&bands[band], 1, __ATOMIC_RELAXED);
		__atomic_fetch_add(&sum, val, __ATOMIC_RELAXED);
		X_STATS_ATOMIC_IF_SET(&min, val, <);
		X_STATS_ATOMIC_IF_SET(&max, val, >);
	}
};


struct x_stats_t
{
	uint64_t *counters;
	uint64_t *pair_counters;
	x_histogram_t *histograms;
};


extern thread_local x_stats_t local_stats;

#define X_STATS_COUNTER_INC(id, num) \
	__atomic_fetch_add(&local_stats.counters[id], (num), __ATOMIC_RELAXED)

#define X_STATS_COUNTER_INC_CREATE(id, num) \
	__atomic_fetch_add(&local_stats.pair_counters[(id) * 2], (num), __ATOMIC_RELAXED)

#define X_STATS_COUNTER_INC_DELETE(id, num) \
	__atomic_fetch_add(&local_stats.pair_counters[(id) * 2 + 1], (num), __ATOMIC_RELAXED)

#define X_STATS_HISTOGRAM_UPDATE(id, elapsed) do { \
	local_stats.histograms[id].update(elapsed); \
} while (0)

void x_stats_init(uint32_t num_thread, uint32_t num_counter,
		uint32_t num_pair_counter, uint32_t num_histogram);
int x_stats_register(uint32_t thread_id);
void x_stats_unregister(uint32_t thread_id);

struct x_stats_store_t
{
	void init();
	void merge(const x_stats_store_t &other);
	std::vector<uint64_t> counters;
	std::vector<uint64_t> pair_counters;
	std::vector<uint64_t> histogram_totals;
	std::vector<x_histogram_t> histograms;
};

void x_stats_collect(x_stats_store_t &store);
void x_stats_load(x_stats_store_t &store);

std::string x_stats_output(const x_stats_store_t &stats,
		const char *const counter_names[],
		const char *const pair_counter_names[],
		const char *const histogram_names[],
		uint32_t band_start, uint32_t band_group, uint32_t band_step);

#endif /* __stats__hxx__ */

