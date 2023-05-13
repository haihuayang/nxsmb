
#include "include/evtmgmt.hxx"

struct test_timer_t
{
	x_timer_t timer;
	int count = 0;
};

static long test_timer_func(x_timer_t *timer)
{
	test_timer_t *test_timer = X_CONTAINER_OF(timer, test_timer_t, timer);
	X_LOG_DBG("%p %d", test_timer, test_timer->count);
	++test_timer->count;
	if (test_timer->count == 5) {
		return 0;
	} else if (test_timer->count > 5) {
		return -1;
	}
	return 1000000000;
}

int main()
{
	x_threadpool_t *tpool = x_threadpool_create("test", 2);
	x_evtmgmt_t *evtmgmt = x_evtmgmt_create(tpool, 1024, 1);

	test_timer_t test_timer{test_timer_func};

	x_evtmgmt_add_timer(evtmgmt, &test_timer.timer, 1000000000);
	
	for (;;) {
		x_evtmgmt_dispatch(evtmgmt);
	}

	return 0;
}

