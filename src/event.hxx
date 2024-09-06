
#ifndef __event__hxx__
#define __event__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/evtmgmt.hxx"

struct x_fdevt_user_t
{
	typedef void func_t(void *arg, x_fdevt_user_t *);
	x_fdevt_user_t(func_t f) : func(f) {}
	x_fdevt_user_t(const x_fdevt_user_t &) = delete;
	x_fdevt_user_t &operator=(const x_fdevt_user_t &) = delete;
	x_dlink_t link;
	func_t *const func;
};
X_DECLARE_MEMBER_TRAITS(fdevt_user_conn_traits, x_fdevt_user_t, link)

extern x_evtmgmt_t *g_evtmgmt;

#endif /* __event__hxx__ */

