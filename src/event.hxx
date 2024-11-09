
#ifndef __event__hxx__
#define __event__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/evtmgmt.hxx"
#include "nxfsd_stats.hxx"

struct x_fdevt_user_t
{
	typedef void func_t(void *arg, x_fdevt_user_t *);
	x_fdevt_user_t(func_t f) : func(f) {
		X_NXFSD_COUNTER_INC_CREATE(user_evt, 1);
	}
	~x_fdevt_user_t() {
		X_NXFSD_COUNTER_INC_DELETE(user_evt, 1);
	}
	x_fdevt_user_t(const x_fdevt_user_t &) = delete;
	x_fdevt_user_t &operator=(const x_fdevt_user_t &) = delete;
	x_dlink_t link;
	func_t *const func;
};
X_DECLARE_MEMBER_TRAITS(fdevt_user_conn_traits, x_fdevt_user_t, link)

extern x_evtmgmt_t *g_evtmgmt;

static inline void x_nxfsd_add_timer(x_timer_job_t *entry, x_tick_diff_t expires)
{
	x_evtmgmt_add_timer(g_evtmgmt, entry, expires);
}

static inline bool x_nxfsd_del_timer(x_timer_job_t *entry)
{
	return x_evtmgmt_del_timer(g_evtmgmt, entry);
}


#endif /* __event__hxx__ */

