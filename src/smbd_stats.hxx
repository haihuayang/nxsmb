
#ifndef __smbd_stats__hxx__
#define __smbd_stats__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif


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

struct x_smbd_stats_t
{
	std::atomic<uint64_t> counters[X_SMBD_COUNTER_ID_MAX];
};

extern x_smbd_stats_t g_smbd_stats;

#define X_SMBD_COUNTER_INC(id, num) ( \
	g_smbd_stats.counters[X_SMBD_COUNTER_ID_ ## id].fetch_add(num, std::memory_order_relaxed) \
)

int x_smbd_stats_init();


#endif /* __smbd_stats__hxx__ */

