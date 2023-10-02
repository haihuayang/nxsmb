
#ifndef __smbd_stats__hxx__
#define __smbd_stats__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/xdefines.h"
#include <atomic>

/* Declare counter id below, e.g., X_SMBD_COUNTER_DECL(name) */
#define X_SMBD_COUNTER_ENUM \
	X_SMBD_COUNTER_DECL(conn_create) \
	X_SMBD_COUNTER_DECL(conn_delete) \
	X_SMBD_COUNTER_DECL(sess_create) \
	X_SMBD_COUNTER_DECL(sess_delete) \
	X_SMBD_COUNTER_DECL(chan_create) \
	X_SMBD_COUNTER_DECL(chan_delete) \
	X_SMBD_COUNTER_DECL(tcon_create) \
	X_SMBD_COUNTER_DECL(tcon_delete) \
	X_SMBD_COUNTER_DECL(object_create) \
	X_SMBD_COUNTER_DECL(object_delete) \
	X_SMBD_COUNTER_DECL(stream_create) \
	X_SMBD_COUNTER_DECL(stream_delete) \
	X_SMBD_COUNTER_DECL(lease_create) \
	X_SMBD_COUNTER_DECL(lease_delete) \
	X_SMBD_COUNTER_DECL(ads_create) \
	X_SMBD_COUNTER_DECL(ads_delete) \
	X_SMBD_COUNTER_DECL(open_create) \
	X_SMBD_COUNTER_DECL(open_delete) \
	X_SMBD_COUNTER_DECL(replay_create) \
	X_SMBD_COUNTER_DECL(replay_delete) \
	X_SMBD_COUNTER_DECL(requ_create) \
	X_SMBD_COUNTER_DECL(requ_delete) \
	X_SMBD_COUNTER_DECL(qdir_create) \
	X_SMBD_COUNTER_DECL(qdir_delete) \
	X_SMBD_COUNTER_DECL(auth_krb5_create) \
	X_SMBD_COUNTER_DECL(auth_krb5_delete) \
	X_SMBD_COUNTER_DECL(auth_ntlmssp_create) \
	X_SMBD_COUNTER_DECL(auth_ntlmssp_delete) \
	X_SMBD_COUNTER_DECL(sess_bind) \

enum {
#undef X_SMBD_COUNTER_DECL
#define X_SMBD_COUNTER_DECL(x) X_SMBD_COUNTER_ID_ ## x,
	X_SMBD_COUNTER_ENUM
	X_SMBD_COUNTER_ID_MAX,
};

#define X_SMBD_HISTOGRAM_ENUM \
	X_SMBD_HISTOGRAM_DECL(op_create) \
	X_SMBD_HISTOGRAM_DECL(op_close) \

enum {
#undef X_SMBD_HISTOGRAM_DECL
#define X_SMBD_HISTOGRAM_DECL(x) X_SMBD_HISTOGRAM_ID_ ## x,
	X_SMBD_HISTOGRAM_ENUM
	X_SMBD_HISTOGRAM_ID_MAX,
};

struct x_smbd_histogram_t
{
	enum { BAND_NUMBER = 32, };
	std::atomic<uint64_t> min{uint64_t(-1)}, max, sum;
	std::atomic<uint64_t> bands[BAND_NUMBER];

	void update(uint64_t val) {
		unsigned int band = 0;
		if (x_likely(val != 0)) {
			band = 64 - __builtin_clzl(val);
			if (x_unlikely(band >= BAND_NUMBER)) {
				band = BAND_NUMBER - 1;
			}
		}

		bands[band].fetch_add(1, std::memory_order_relaxed);
		sum.fetch_add(val, std::memory_order_relaxed);
		if (min.load(std::memory_order_relaxed) > val) {
			min.store(val, std::memory_order_relaxed);
		}
		if (max.load(std::memory_order_relaxed) < val) {
			max.store(val, std::memory_order_relaxed);
		}
	}
};

struct x_smbd_stats_t
{
	std::atomic<uint64_t> counters[X_SMBD_COUNTER_ID_MAX];
	x_smbd_histogram_t histograms[X_SMBD_HISTOGRAM_ID_MAX];
};

extern thread_local x_smbd_stats_t *g_smbd_stats;

#define X_SMBD_COUNTER_INC(id, num) ( \
	g_smbd_stats->counters[X_SMBD_COUNTER_ID_ ## id].fetch_add(num, std::memory_order_relaxed) \
)

#define X_SMBD_HISTOGRAM_UPDATE(id, elapsed) do { \
	g_smbd_stats->histograms[X_SMBD_HISTOGRAM_ID_ ## id].update(elapsed); \
} while (0)

int x_smbd_stats_init(uint32_t thread_id);


#endif /* __smbd_stats__hxx__ */

