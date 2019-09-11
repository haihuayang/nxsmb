
#ifndef __src__defines__hxx__
#define __src__defines__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/xdefines.h"
#include "byteorder.hxx"
#include "list.hxx"
#include <sys/epoll.h>
#include <atomic>

// TODO
#define EVENT_LOG(...) do { } while (0)

extern __thread char task_name[8];

struct threadpool_t;
threadpool_t *threadpool_create(unsigned int count);
void threadpool_destroy(threadpool_t *);

struct job_ops_t;
struct job_t
{
	enum retval_t {
		JOB_BLOCKED,
		JOB_CONTINUE,
		JOB_DONE,
	};

	enum state_t : uint16_t {
		STATE_NONE = 0,
		STATE_SCHEDULED = 1,
		STATE_RUNNING = 2,
		STATE_DONE,
	};

	dlink_t dlink;
	const job_ops_t *ops;
	// job_func_t func;
	std::atomic<uint32_t> state{STATE_NONE};
};

struct job_ops_t
{
	job_t::retval_t (*run)(job_t *job);
	void (*done)(job_t *job);
};

// typedef bool (*job_func_t)(job_t *job);

bool threadpool_schedule(threadpool_t *tpool, job_t *job);


enum {
	FDEVT_IN = EPOLLIN,
	FDEVT_OUT = EPOLLOUT,
	FDEVT_ERR = EPOLLERR,
	FDEVT_SHUTDOWN = (1u << 31),
};

typedef uint64_t x_fdevents_t;

static inline x_fdevents_t x_fdevents_init(uint32_t posted, uint32_t enabled)
{
	return (uint64_t(posted) << 32) | enabled;
}

static inline uint32_t x_fdevents_processable(x_fdevents_t fdevents)
{
	return (fdevents >> 32) & fdevents;
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


struct epoll_upcall_t;
struct epoll_upcall_cbs_t
{
	bool (*cb_getevents)(epoll_upcall_t *upcall, x_fdevents_t &fdevents);
	void (*cb_unmonitored)(epoll_upcall_t *upcall);
};

struct epoll_upcall_t
{
	bool on_getevents(x_fdevents_t &fdevents) {
		return cbs->cb_getevents(this, fdevents);
	}
	void on_unmonitored() {
		cbs->cb_unmonitored(this);
	}
	const epoll_upcall_cbs_t *cbs;
};

struct epollmgmt_t;
epollmgmt_t *epollmgmt_create(threadpool_t *tpoll);
void epollmgmt_dispatch(epollmgmt_t *ep);
uint64_t epollmgmt_monitor(epollmgmt_t *ep, unsigned int fd, uint32_t poll_events, epoll_upcall_t * upcall);
bool epollmgmt_enable_events(epollmgmt_t *ep, uint64_t id, uint32_t events);


using x_oid_t = const char *;
struct x_gensec_t;
struct x_gensec_context_t;
struct x_gensec_mech_t;

x_gensec_context_t *x_gensec_create_context();
x_gensec_t *x_gensec_create_by_oid(x_gensec_context_t *context, x_oid_t oid);
int x_gensec_register(x_gensec_context_t *context, const x_gensec_mech_t *mech);


#endif /* __src__defines__hxx__ */

