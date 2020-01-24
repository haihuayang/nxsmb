
#ifndef __threadpool__hxx__
#define __threadpool__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/xdefines.h"
#include "list.hxx"
#include "utils.hxx"
#include <atomic>
#include <string>

extern __thread char task_name[8];
extern __thread x_tick_t tick_now;

struct x_threadpool_t;
x_threadpool_t *x_threadpool_create(unsigned int count);
void x_threadpool_destroy(x_threadpool_t *);

struct x_job_ops_t;
struct x_job_t
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

	x_dlink_t dlink;
	const x_job_ops_t *ops;
	void *private_data;
	std::atomic<uint32_t> state{STATE_NONE};
};

struct x_job_ops_t
{
	x_job_t::retval_t (*run)(x_job_t *x_job);
	void (*done)(x_job_t *x_job);
};

bool x_threadpool_schedule(x_threadpool_t *tpool, x_job_t *x_job);



#endif /* __threadpool__hxx__ */

