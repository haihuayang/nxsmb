
#ifndef __smbd_stats__hxx__
#define __smbd_stats__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/xdefines.h"
#include "stats.hxx"
#include <atomic>

/* Declare counter id below, e.g., X_SMBD_COUNTER_DECL(name) */
#define X_SMBD_COUNTER_ENUM \
	X_SMBD_COUNTER_DECL(sess_bind) \
	X_SMBD_COUNTER_DECL(reply_interim) \
	X_SMBD_COUNTER_DECL(cancel_success) \
	X_SMBD_COUNTER_DECL(cancel_too_late) \
	X_SMBD_COUNTER_DECL(cancel_not_exist) \
	X_SMBD_COUNTER_DECL(wakeup_stale_requ) \
	X_SMBD_COUNTER_DECL(toomany_open) \
	X_SMBD_COUNTER_DECL(toomany_tcon) \
	X_SMBD_COUNTER_DECL(toomany_sess) \
	X_SMBD_COUNTER_DECL(stale_sess) \
	X_SMBD_COUNTER_DECL(toomany_chan) \
	X_SMBD_COUNTER_DECL(fail_alloc_chan) \
	X_SMBD_COUNTER_DECL(fail_create_qdir) \

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
	X_SMBD_HISTOGRAM_DECL(op_negprot_us) \
	X_SMBD_HISTOGRAM_DECL(op_sesssetup_us) \
	X_SMBD_HISTOGRAM_DECL(op_logoff_us) \
	X_SMBD_HISTOGRAM_DECL(op_tcon_us) \
	X_SMBD_HISTOGRAM_DECL(op_tdis_us) \
	X_SMBD_HISTOGRAM_DECL(op_create_us) \
	X_SMBD_HISTOGRAM_DECL(op_close_us) \
	X_SMBD_HISTOGRAM_DECL(op_flush_us) \
	X_SMBD_HISTOGRAM_DECL(op_read_us) \
	X_SMBD_HISTOGRAM_DECL(op_write_us) \
	X_SMBD_HISTOGRAM_DECL(op_lock_us) \
	X_SMBD_HISTOGRAM_DECL(op_ioctl_us) \
	X_SMBD_HISTOGRAM_DECL(op_cancel_us) \
	X_SMBD_HISTOGRAM_DECL(op_keepalive_us) \
	X_SMBD_HISTOGRAM_DECL(op_querydir_us) \
	X_SMBD_HISTOGRAM_DECL(op_notify_us) \
	X_SMBD_HISTOGRAM_DECL(op_getinfo_us) \
	X_SMBD_HISTOGRAM_DECL(op_setinfo_us) \
	X_SMBD_HISTOGRAM_DECL(op_break_us) \

enum {
#undef X_SMBD_HISTOGRAM_DECL
#define X_SMBD_HISTOGRAM_DECL(x) X_SMBD_HISTOGRAM_ID_ ## x,
	X_SMBD_HISTOGRAM_ENUM
	X_SMBD_HISTOGRAM_ID_MAX,
};

#define X_SMBD_COUNTER_INC(id, num) \
	X_STATS_COUNTER_INC(X_SMBD_COUNTER_ID_##id, (num))

#define X_SMBD_COUNTER_INC_CREATE(id, num) \
	X_STATS_COUNTER_INC_CREATE(X_SMBD_PAIR_COUNTER_ID_##id, (num))

#define X_SMBD_COUNTER_INC_DELETE(id, num) \
	X_STATS_COUNTER_INC_DELETE(X_SMBD_PAIR_COUNTER_ID_##id, (num))

#define X_SMBD_HISTOGRAM_UPDATE(id, elapsed) do { \
	local_stats.histograms[X_SMBD_HISTOGRAM_ID_ ## id].update(elapsed); \
} while (0)

void x_smbd_stats_init();
int x_smbd_stats_register(uint32_t thread_id);
void x_smbd_stats_report();


#endif /* __smbd_stats__hxx__ */

