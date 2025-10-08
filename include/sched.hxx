
#ifndef __sched__hxx__
#define __sched__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "stats.hxx"

/* Declare counter id below, e.g., X_SCHED_COUNTER_DECL(name) */
#define X_SCHED_COUNTER_ENUM \
	X_SCHED_COUNTER_DECL(sched_queue) \
	X_SCHED_COUNTER_DECL(sched_wakeup) \
	X_SCHED_COUNTER_DECL(sched_nojob) \
	X_SCHED_COUNTER_DECL(sched_done) \
	X_SCHED_COUNTER_DECL(sched_already) \
	X_SCHED_COUNTER_DECL(sched_selfcont) \
	X_SCHED_COUNTER_DECL(sched_requeue) \

enum {
#undef X_SCHED_COUNTER_DECL
#define X_SCHED_COUNTER_DECL(x) X_SCHED_COUNTER_ID_ ## x,
	X_SCHED_COUNTER_ENUM
	X_SCHED_COUNTER_ID_MAX,
};

/* Declare pair counter id below, e.g., X_SCHED_PAIR_COUNTER_DECL(name) */
#define X_SCHED_PAIR_COUNTER_ENUM \
	X_SCHED_PAIR_COUNTER_DECL(user_evt) \

enum {
#undef X_SCHED_PAIR_COUNTER_DECL
#define X_SCHED_PAIR_COUNTER_DECL(x) X_SCHED_PAIR_COUNTER_ID_ ## x,
	X_SCHED_PAIR_COUNTER_ENUM
	X_SCHED_PAIR_COUNTER_ID_MAX,
};

/* Declare histogram id below, e.g., X_SCHED_HISTOGRAM_DECL(name) */
#define X_SCHED_HISTOGRAM_ENUM \
	X_SCHED_HISTOGRAM_DECL(sched_run) \

enum {
#undef X_SCHED_HISTOGRAM_DECL
#define X_SCHED_HISTOGRAM_DECL(x) X_SCHED_HISTOGRAM_ID_ ## x,
	X_SCHED_HISTOGRAM_ENUM
	X_SCHED_HISTOGRAM_ID_MAX,
};

extern x_stats_module_t x_sched_stats;

#define X_SCHED_COUNTER_INC(id, num) \
	X_STATS_COUNTER_INC(x_sched_stats.counter_base, X_SCHED_COUNTER_ID_##id, (num))

#define X_SCHED_COUNTER_INC_CREATE(id, num) \
	X_STATS_COUNTER_INC_CREATE(x_sched_stats.pair_counter_base, X_SCHED_PAIR_COUNTER_ID_##id, (num))

#define X_SCHED_COUNTER_INC_DELETE(id, num) \
	X_STATS_COUNTER_INC_DELETE(x_sched_stats.pair_counter_base, X_SCHED_PAIR_COUNTER_ID_##id, (num))

#define X_SCHED_HISTOGRAM_UPDATE_(id, elapsed) \
	X_STATS_HISTOGRAM_UPDATE(x_sched_stats.histogram_base, (id), (elapsed))

#define X_SCHED_HISTOGRAM_UPDATE(id, elapsed) \
	X_SCHED_HISTOGRAM_UPDATE_(X_SCHED_HISTOGRAM_ID_ ## id, elapsed)

void x_sched_stats_init();

#endif /* __sched__hxx__ */

