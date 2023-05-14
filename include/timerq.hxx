
#ifndef __timerq__hxx__
#define __timerq__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "xdefines.h"
#include "list.hxx"
#include "evtmgmt.hxx"
#include <mutex>

struct x_timerq_entry_t
{
	x_dlink_t link;
	enum {
		S_NONE,
		S_QUEUED,
		S_CANCELLED,
		S_FIRED,
	} state = S_NONE;
	x_tick_t queue_time;
	void (*func)(x_timerq_entry_t *entry);
};
X_DECLARE_MEMBER_TRAITS(timerq_link_traits, x_timerq_entry_t, link)

struct x_timerq_t
{
	x_timerq_t();
	x_timer_t timer;
	x_tick_diff_t timeout;
	std::mutex mutex;
	x_tp_ddlist_t<timerq_link_traits> entry_list;
};

void x_timerq_init(x_timerq_t &timerq, x_evtmgmt_t *evtmgmt, uint64_t timeout_ns);
void x_timerq_add(x_timerq_t &timerq, x_timerq_entry_t *entry);
bool x_timerq_cancel(x_timerq_t &timerq, x_timerq_entry_t *entry);
bool x_timerq_reset(x_timerq_t &timerq, x_timerq_entry_t *entry);

#endif /* __timerq__hxx__ */

