
#include "include/threadpool.hxx"
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>

__thread char task_name[8] = "";
__thread x_tick_t tick_now;

X_DECLARE_MEMBER_TRAITS(job_dlink_traits, x_job_t, dlink)

struct x_threadpool_t
{
	x_threadpool_t(unsigned int count) : threads{count} { }
	std::vector<std::thread> threads;
	std::mutex mutex;
	std::condition_variable cond;
	x_tp_ddlist_t<job_dlink_traits> queue;
};

static void __threadpool_schedule_job(x_threadpool_t *tp, x_job_t *job)
{
	X_ASSERT(job->state == x_job_t::STATE_SCHEDULED);
	{
		std::unique_lock<std::mutex> ul(tp->mutex);
		tp->queue.push_back(job);
		job->state = x_job_t::STATE_SCHEDULED;
	}
	tp->cond.notify_one();
}

static inline x_job_t *__threadpool_get(x_threadpool_t *tp)
{
	x_job_t *job;
	{
		std::unique_lock<std::mutex> ul(tp->mutex);
		while (tp->queue.empty()) {
			tp->cond.wait(ul);
		}

		job = tp->queue.get_front();
		tp->queue.remove(job);
	}
	X_ASSERT(job->state.exchange(x_job_t::STATE_RUNNING) == x_job_t::STATE_SCHEDULED);
	return job;
}

/* TODO exit gracely */
static void thread_func(x_threadpool_t *tpool, uint32_t no)
{
	snprintf(task_name, sizeof task_name, "T%03d", no);
	tick_now = x_tick_now();
	for (;;) {
		x_job_t *job = __threadpool_get(tpool);
		tick_now = x_tick_now();
		x_job_t::retval_t status = job->ops->run(job);
		X_DBG("%s run job %p %d", task_name, job, status);
		if (status == x_job_t::JOB_DONE) {
			job->state = x_job_t::STATE_DONE;
			job->ops->done(job);
			continue;
		}

		if (status == x_job_t::JOB_CONTINUE) {
			job->state = x_job_t::STATE_SCHEDULED;
			__threadpool_schedule_job(tpool, job);
			continue;
		}

		X_ASSERT(status == x_job_t::JOB_BLOCKED);

		uint32_t oval = job->state.load(std::memory_order_relaxed);
		uint32_t nval = x_job_t::STATE_SCHEDULED;
		for (;;) {
			if (oval & 0xffff0000) {
				nval = x_job_t::STATE_SCHEDULED;
			} else {
				nval = x_job_t::STATE_NONE;
			}
			if (std::atomic_compare_exchange_weak_explicit(
						&job->state,
						&oval,
						nval,
						std::memory_order_release,
						std::memory_order_relaxed)) {
				break;
			}
		}
		if (nval == x_job_t::STATE_SCHEDULED) {
			__threadpool_schedule_job(tpool, job);
		}
	}
}

x_threadpool_t *x_threadpool_create(unsigned int count)
{
	x_threadpool_t *tpool = new x_threadpool_t{count};
	for (uint32_t i = 0; i < count; ++i) {
		tpool->threads[i] = std::thread(thread_func, tpool, i);
	}
	return tpool;
}

void x_threadpool_destroy(x_threadpool_t *tpool)
{
	// TODO
	for (uint32_t i = 0; i < tpool->threads.size(); ++i) {
		tpool->threads[i].join();
	}
	delete tpool;
}

bool x_threadpool_schedule(x_threadpool_t *tpool, x_job_t *job)
{
	X_DBG("%s schedule %p", task_name, job);
	uint32_t oval = job->state.load(std::memory_order_relaxed);
	uint32_t nval;

	for (;;) {
		uint32_t state = oval & 0xffff;
		if (state == x_job_t::STATE_DONE) {
			X_ASSERT(oval == state);
			return false;
		} else if (state == x_job_t::STATE_RUNNING) {
			nval = state | 0x10000;
		} else if (state == x_job_t::STATE_NONE) {
			nval = x_job_t::STATE_SCHEDULED;
		} else {
			/* Already scheduled */
			return true;
		}

		if (std::atomic_compare_exchange_weak_explicit(
					&job->state,
					&oval,
					nval,
					std::memory_order_release,
					std::memory_order_relaxed)) {
			break;
		}
	}

	if (nval == x_job_t::STATE_SCHEDULED) {
		__threadpool_schedule_job(tpool, job);
	}
	return true;
}
