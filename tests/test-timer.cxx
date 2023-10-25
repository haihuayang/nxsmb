
#include "include/evtmgmt.hxx"

struct test_timer_job_t
{
	x_timer_job_t timer_job;
	int count = 0;
};

static long test_timer_job_func(x_timer_job_t *timer_job)
{
	test_timer_job_t *test_timer_job = X_CONTAINER_OF(timer_job, test_timer_job_t, timer_job);
	X_LOG(UTILS, DBG, "%p %d", test_timer_job, test_timer_job->count);
	++test_timer_job->count;
	if (test_timer_job->count == 8) {
		return 0;
	} else if (test_timer_job->count > 8) {
		return -1;
	}
	return 100000000 * test_timer_job->count;
}

int main()
{
	x_threadpool_t *tpool = x_threadpool_create("test", 2, nullptr);
	x_evtmgmt_t *evtmgmt = x_evtmgmt_create(tpool, 1024, 500, 10);

	test_timer_job_t test_timer_job{test_timer_job_func};

	x_evtmgmt_add_timer(evtmgmt, &test_timer_job.timer_job, 100000000);
	
	for (;;) {
		x_evtmgmt_dispatch(evtmgmt);
	}

	return 0;
}

