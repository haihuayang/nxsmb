
#ifndef __smbd_stats__hxx__
#define __smbd_stats__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/xdefines.h"
#include "stats.hxx"
#include <atomic>

/* Declare counter id below, e.g., X_NXFSD_COUNTER_DECL(name) */
#define X_NXFSD_COUNTER_ENUM \
	X_NXFSD_COUNTER_DECL(smbd_sess_bind) \
	X_NXFSD_COUNTER_DECL(smbd_reply_interim) \
	X_NXFSD_COUNTER_DECL(smbd_cancel_success) \
	X_NXFSD_COUNTER_DECL(smbd_cancel_toolate) \
	X_NXFSD_COUNTER_DECL(smbd_cancel_noent) \
	X_NXFSD_COUNTER_DECL(smbd_wakeup_stale) \
	X_NXFSD_COUNTER_DECL(smbd_toomany_open) \
	X_NXFSD_COUNTER_DECL(smbd_toomany_tcon) \
	X_NXFSD_COUNTER_DECL(smbd_toomany_sess) \
	X_NXFSD_COUNTER_DECL(smbd_stale_sess) \
	X_NXFSD_COUNTER_DECL(smbd_toomany_chan) \
	X_NXFSD_COUNTER_DECL(smbd_fail_alloc_chan) \
	X_NXFSD_COUNTER_DECL(smbd_fail_alloc_qdir) \

enum {
#undef X_NXFSD_COUNTER_DECL
#define X_NXFSD_COUNTER_DECL(x) X_NXFSD_COUNTER_ID_ ## x,
	X_NXFSD_COUNTER_ENUM
	X_NXFSD_COUNTER_ID_MAX,
};

/* Declare pair counter id below, e.g., X_NXFSD_PAIR_COUNTER_DECL(name) */
#define X_NXFSD_PAIR_COUNTER_ENUM \
	X_NXFSD_PAIR_COUNTER_DECL(user_evt) \
	X_NXFSD_PAIR_COUNTER_DECL(orphan_user_evt) \
	X_NXFSD_PAIR_COUNTER_DECL(smbd_conn) \
	X_NXFSD_PAIR_COUNTER_DECL(smbd_sess) \
	X_NXFSD_PAIR_COUNTER_DECL(smbd_chan) \
	X_NXFSD_PAIR_COUNTER_DECL(smbd_tcon) \
	X_NXFSD_PAIR_COUNTER_DECL(smbd_object) \
	X_NXFSD_PAIR_COUNTER_DECL(smbd_stream) \
	X_NXFSD_PAIR_COUNTER_DECL(smbd_lease) \
	X_NXFSD_PAIR_COUNTER_DECL(posixfs_ads) \
	X_NXFSD_PAIR_COUNTER_DECL(smbd_open) \
	X_NXFSD_PAIR_COUNTER_DECL(smbd_replay) \
	X_NXFSD_PAIR_COUNTER_DECL(smbd_requ) \
	X_NXFSD_PAIR_COUNTER_DECL(smbd_qdir) \
	X_NXFSD_PAIR_COUNTER_DECL(auth_krb5) \
	X_NXFSD_PAIR_COUNTER_DECL(auth_ntlmssp) \

enum {
#undef X_NXFSD_PAIR_COUNTER_DECL
#define X_NXFSD_PAIR_COUNTER_DECL(x) X_NXFSD_PAIR_COUNTER_ID_ ## x,
	X_NXFSD_PAIR_COUNTER_ENUM
	X_NXFSD_PAIR_COUNTER_ID_MAX,
};

/* Declare histogram id below, e.g., X_NXFSD_HISTOGRAM_DECL(name) */
#define X_NXFSD_HISTOGRAM_ENUM \
	X_NXFSD_HISTOGRAM_DECL(smbd_op_negprot) \
	X_NXFSD_HISTOGRAM_DECL(smbd_op_sesssetup) \
	X_NXFSD_HISTOGRAM_DECL(smbd_op_logoff) \
	X_NXFSD_HISTOGRAM_DECL(smbd_op_tcon) \
	X_NXFSD_HISTOGRAM_DECL(smbd_op_tdis) \
	X_NXFSD_HISTOGRAM_DECL(smbd_op_create) \
	X_NXFSD_HISTOGRAM_DECL(smbd_op_close) \
	X_NXFSD_HISTOGRAM_DECL(smbd_op_flush) \
	X_NXFSD_HISTOGRAM_DECL(smbd_op_read) \
	X_NXFSD_HISTOGRAM_DECL(smbd_op_write) \
	X_NXFSD_HISTOGRAM_DECL(smbd_op_lock) \
	X_NXFSD_HISTOGRAM_DECL(smbd_op_ioctl) \
	X_NXFSD_HISTOGRAM_DECL(smbd_op_cancel) \
	X_NXFSD_HISTOGRAM_DECL(smbd_op_keepalive) \
	X_NXFSD_HISTOGRAM_DECL(smbd_op_querydir) \
	X_NXFSD_HISTOGRAM_DECL(smbd_op_notify) \
	X_NXFSD_HISTOGRAM_DECL(smbd_op_getinfo) \
	X_NXFSD_HISTOGRAM_DECL(smbd_op_setinfo) \
	X_NXFSD_HISTOGRAM_DECL(smbd_op_break) \
	X_NXFSD_HISTOGRAM_DECL(noded_op_ping) \

enum {
#undef X_NXFSD_HISTOGRAM_DECL
#define X_NXFSD_HISTOGRAM_DECL(x) X_NXFSD_HISTOGRAM_ID_ ## x,
	X_NXFSD_HISTOGRAM_ENUM
	X_NXFSD_HISTOGRAM_ID_MAX,
};

#define X_NXFSD_COUNTER_INC(id, num) \
	X_STATS_COUNTER_INC(X_NXFSD_COUNTER_ID_##id, (num))

#define X_NXFSD_COUNTER_INC_CREATE(id, num) \
	X_STATS_COUNTER_INC_CREATE(X_NXFSD_PAIR_COUNTER_ID_##id, (num))

#define X_NXFSD_COUNTER_INC_DELETE(id, num) \
	X_STATS_COUNTER_INC_DELETE(X_NXFSD_PAIR_COUNTER_ID_##id, (num))

#define X_NXFSD_HISTOGRAM_UPDATE(id, elapsed) do { \
	local_stats.histograms[X_NXFSD_HISTOGRAM_ID_ ## id].update(elapsed); \
} while (0)

void x_nxfsd_stats_init();
int x_nxfsd_stats_register(uint32_t thread_id);
void x_nxfsd_stats_report();


#endif /* __smbd_stats__hxx__ */

