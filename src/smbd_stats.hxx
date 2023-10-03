
#ifndef __smbd_stats__hxx__
#define __smbd_stats__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/xdefines.h"
#include <atomic>

/* Declare counter id below, e.g., X_SMBD_COUNTER_DECL(name) */
#define X_SMBD_COUNTER_ENUM \
	X_SMBD_COUNTER_DECL(sess_bind) \

enum {
#undef X_SMBD_COUNTER_DECL
#define X_SMBD_COUNTER_DECL(x) X_SMBD_COUNTER_ID_ ## x,
	X_SMBD_COUNTER_ENUM
	X_SMBD_COUNTER_ID_MAX,
};

/* Declare pair counter id below, e.g., X_SMBD_PAIR_COUNTER_DECL(name) */
#define X_SMBD_PAIR_COUNTER_ENUM \
	X_SMBD_PAIR_COUNTER_DECL(conn) \
	X_SMBD_PAIR_COUNTER_DECL(sess) \
	X_SMBD_PAIR_COUNTER_DECL(chan) \
	X_SMBD_PAIR_COUNTER_DECL(tcon) \
	X_SMBD_PAIR_COUNTER_DECL(object) \
	X_SMBD_PAIR_COUNTER_DECL(stream) \
	X_SMBD_PAIR_COUNTER_DECL(lease) \
	X_SMBD_PAIR_COUNTER_DECL(ads) \
	X_SMBD_PAIR_COUNTER_DECL(open) \
	X_SMBD_PAIR_COUNTER_DECL(replay) \
	X_SMBD_PAIR_COUNTER_DECL(requ) \
	X_SMBD_PAIR_COUNTER_DECL(qdir) \
	X_SMBD_PAIR_COUNTER_DECL(auth_krb5) \
	X_SMBD_PAIR_COUNTER_DECL(auth_ntlmssp) \

enum {
#undef X_SMBD_PAIR_COUNTER_DECL
#define X_SMBD_PAIR_COUNTER_DECL(x) X_SMBD_PAIR_COUNTER_ID_ ## x,
	X_SMBD_PAIR_COUNTER_ENUM
	X_SMBD_PAIR_COUNTER_ID_MAX,
};

/* Declare histogram id below, e.g., X_SMBD_HISTOGRAM_DECL(name) */
#define X_SMBD_HISTOGRAM_ENUM \
	X_SMBD_HISTOGRAM_DECL(op_create_us) \
	X_SMBD_HISTOGRAM_DECL(op_close_us) \

enum {
#undef X_SMBD_HISTOGRAM_DECL
#define X_SMBD_HISTOGRAM_DECL(x) X_SMBD_HISTOGRAM_ID_ ## x,
	X_SMBD_HISTOGRAM_ENUM
	X_SMBD_HISTOGRAM_ID_MAX,
};

template <class T>
struct atomic_relaxed_t
{
	std::atomic<T> val;
	operator T() const {
		return val.load(std::memory_order_relaxed);
	}
	T operator+=(T v) {
		return val.fetch_add(v, std::memory_order_relaxed);
	}
	void operator=(T v) {
		return val.store(v, std::memory_order_relaxed);
	}
};

enum {
	X_SMBD_HISTOGRAM_BAND_NUMBER = 32,
};

template <template <typename> typename T>
struct x_smbd_histogram_t
{
	T<uint64_t> min{uint64_t(-1)}, max{}, sum{};
	T<uint64_t> bands[X_SMBD_HISTOGRAM_BAND_NUMBER]{};

	void update(uint64_t val) {
		unsigned int band = 0;
		if (x_likely(val != 0)) {
			band = 64 - __builtin_clzl(val);
			if (x_unlikely(band >= X_SMBD_HISTOGRAM_BAND_NUMBER)) {
				band = X_SMBD_HISTOGRAM_BAND_NUMBER - 1;
			}
		}

		bands[band] += 1;
		sum += val;
		if (min > val) {
			min = val;
		}
		if (max < val) {
			max = val;
		}
	}
};

template <template <typename> typename T>
struct x_smbd_stats_t
{
	T<uint64_t> counters[X_SMBD_COUNTER_ID_MAX]{};
	T<uint64_t> pair_counters[X_SMBD_PAIR_COUNTER_ID_MAX][2]{};
	x_smbd_histogram_t<T> histograms[X_SMBD_HISTOGRAM_ID_MAX];
};

extern thread_local x_smbd_stats_t<atomic_relaxed_t> *g_smbd_stats;

#define X_SMBD_COUNTER_INC(id, num) ( \
	g_smbd_stats->counters[X_SMBD_COUNTER_ID_ ## id] += (num) \
)

#define X_SMBD_COUNTER_INC_CREATE(id, num) ( \
	g_smbd_stats->pair_counters[X_SMBD_PAIR_COUNTER_ID_ ## id][0] += (num) \
)

#define X_SMBD_COUNTER_INC_DELETE(id, num) ( \
	g_smbd_stats->pair_counters[X_SMBD_PAIR_COUNTER_ID_ ## id][1] += (num) \
)

#define X_SMBD_HISTOGRAM_UPDATE(id, elapsed) do { \
	g_smbd_stats->histograms[X_SMBD_HISTOGRAM_ID_ ## id].update(elapsed); \
} while (0)

#define X_SMBD_HISTOGRAM_UPDATE_US(id, elapsed) do { \
	g_smbd_stats->histograms[X_SMBD_HISTOGRAM_ID_ ## id].update((elapsed) / 1000); \
} while (0)

int x_smbd_stats_init(uint32_t thread_id);


#endif /* __smbd_stats__hxx__ */

