
#ifndef __evtmgmt__hxx__
#define __evtmgmt__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "threadpool.hxx"
#include <sys/epoll.h>

enum {
	FDEVT_IN = EPOLLIN,
	FDEVT_OUT = EPOLLOUT,
	FDEVT_ERR = EPOLLERR,
	FDEVT_USER = (1u << 30),
	FDEVT_SHUTDOWN = (1u << 31),
};

typedef uint64_t x_fdevents_t;

static inline x_fdevents_t x_fdevents_init(uint32_t posted, uint32_t enabled)
{
	return (uint64_t(posted) << 32) | enabled;
}

static inline uint32_t x_fdevents_processable(x_fdevents_t fdevents)
{
	return uint32_t((fdevents >> 32) & fdevents);
}

static inline x_fdevents_t x_fdevents_enable(x_fdevents_t fdevents, uint32_t events)
{
	return fdevents | uint64_t(events);
}

static inline x_fdevents_t x_fdevents_disable(x_fdevents_t fdevents, uint32_t events)
{
	return fdevents & ~uint64_t(events);
}

static inline x_fdevents_t x_fdevents_consume(x_fdevents_t fdevents, uint32_t events)
{
	return fdevents & ~(uint64_t(events) << 32);
}

static inline x_fdevents_t x_fdevents_post(x_fdevents_t fdevents, uint32_t events)
{
	return fdevents | (uint64_t(events) << 32);
}


struct x_epoll_upcall_t;
struct x_epoll_upcall_cbs_t
{
	bool (*cb_getevents)(x_epoll_upcall_t *upcall, x_fdevents_t &fdevents);
	void (*cb_unmonitored)(x_epoll_upcall_t *upcall);
};

struct x_epoll_upcall_t
{
	bool on_getevents(x_fdevents_t &fdevents) {
		return cbs->cb_getevents(this, fdevents);
	}
	void on_unmonitored() {
		cbs->cb_unmonitored(this);
	}
	const x_epoll_upcall_cbs_t *cbs;
};

struct x_timer_t;
struct x_timer_upcall_cbs_t
{
	/* return -1, stop the time */
	long (*cb_time)(x_timer_t *timer);
	void (*cb_unmonitored)(x_timer_t *timer);
};

extern x_job_t::retval_t x_timer_job_run(x_job_t *job, void *data);

struct x_timer_t
{
	long on_time() {
		return cbs->cb_time(this);
	}
	void on_unmonitored() {
		cbs->cb_unmonitored(this);
	}
	x_job_t job{x_timer_job_run};
	const x_timer_upcall_cbs_t *cbs;
	x_tick_t timeout;
};

struct x_evtmgmt_t;
x_evtmgmt_t *x_evtmgmt_create(x_threadpool_t *tpool, uint32_t max_fd);
void x_evtmgmt_dispatch(x_evtmgmt_t *ep);

uint64_t x_evtmgmt_monitor(x_evtmgmt_t *ep, unsigned int fd, uint32_t poll_events, x_epoll_upcall_t * upcall);
bool x_evtmgmt_enable_events(x_evtmgmt_t *ep, uint64_t id, uint32_t events);
bool x_evtmgmt_post_events(x_evtmgmt_t *ep, uint64_t id, uint32_t events);

void x_evtmgmt_add_timer(x_evtmgmt_t *ep, x_timer_t *timer, unsigned long ms);
/* TODO bool x_evtmgmt_cancel_timer(x_evtmgmt_t *ep, x_timer_t *timer); */

#endif /* __evtmgmt__hxx__ */

