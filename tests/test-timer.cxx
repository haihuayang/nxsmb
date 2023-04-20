
#include "include/evtmgmt.hxx"

struct test_timer_t
{
	x_timer_t timer;
};

static long test_timer_func(x_timer_t *timer)
{
	// test_timer_t *test_timer = X_CONTAINER_OF(timer, test_timer_t, timer);
	X_DBG("");
	return 1000;
}

static void test_timer_done(x_timer_t *timer)
{
	X_ASSERT(false);
}

static const x_timer_upcall_cbs_t test_timer_cbs = {
	test_timer_func,
	test_timer_done,
};

int main()
{
	x_threadpool_t *tpool = x_threadpool_create(2);
	x_evtmgmt_t *evtmgmt = x_evtmgmt_create(tpool, 0, 1024);

	test_timer_t test_timer;
	test_timer.timer.cbs = &test_timer_cbs;

	x_evtmgmt_add_timer(evtmgmt, &test_timer.timer, 1000000000);
	
	for (;;) {
		x_evtmgmt_dispatch(evtmgmt);
	}

	return 0;
}

