
#include "include/threadpool.hxx"
#include <pthread.h>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <stdarg.h>

__thread char task_name[16] = "NONAME";
__thread x_tick_t tick_now;

void x_thread_init(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(task_name, sizeof task_name, fmt, ap);
	va_end(ap);
}

X_DECLARE_MEMBER_TRAITS(job_dlink_traits, x_job_t, dlink)

struct x_threadpool_t
{
	x_threadpool_t(std::string &&name, unsigned int count)
		: name{name}, threads(count) { }
	const std::string name;
	void *private_data = nullptr;
	bool running = true;
	std::vector<pthread_t> threads;
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
			if (!tp->running) {
				return nullptr;
			}
			tp->cond.wait(ul);
		}

		job = tp->queue.get_front();
		tp->queue.remove(job);
	}
	X_ASSERT(job->state.exchange(x_job_t::STATE_RUNNING) == x_job_t::STATE_SCHEDULED);
	return job;
}

struct x_threadpool_arg_t
{
	x_threadpool_t * const tpool;
	uint32_t const no;
	void (*init_func)(uint32_t no);
};

static void *thread_func(void *arg)
{
	x_threadpool_arg_t *tparg = (x_threadpool_arg_t *)arg;
	x_threadpool_t *tpool = tparg->tpool;
	uint32_t no = tparg->no;
	void (*init_func)(uint32_t) = tparg->init_func;
	delete tparg;

	x_thread_init("%s-%03d", tpool->name.c_str(), no);
	if (init_func) {
		init_func(no);
	}

	tick_now = x_tick_now();
	X_LOG_NOTICE("started");
	for (;;) {
		x_job_t *job = __threadpool_get(tpool);
		if (!job) {
			break;
		}
		tick_now = x_tick_now();
		x_job_t::retval_t status = job->run(job, tpool->private_data);
		X_LOG_DBG("run job %p %d", job, status);
		if (status == x_job_t::JOB_DONE) {
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
	X_LOG_NOTICE("stopped");
	return nullptr;
}

x_threadpool_t *x_threadpool_create(std::string name, unsigned int count,
		void (*init_func)(uint32_t no))
{
	x_threadpool_t *tpool = new x_threadpool_t{std::move(name), count};
	for (uint32_t i = 0; i < count; ++i) {
		x_threadpool_arg_t *tparg = new x_threadpool_arg_t{tpool, i, init_func};
		int err = pthread_create(&tpool->threads[i], nullptr,
				thread_func, tparg);
		X_ASSERT(err == 0);
	}
	return tpool;
}

void x_threadpool_set_private_data(x_threadpool_t *tpool, void *data)
{
	X_ASSERT(!tpool->private_data);
	tpool->private_data = data;
}

void x_threadpool_destroy(x_threadpool_t *tpool)
{
	X_ASSERT(tpool->running);
	tpool->running = false;
	tpool->cond.notify_all();
	for (uint32_t i = 0; i < tpool->threads.size(); ++i) {
		X_ASSERT(pthread_join(tpool->threads[i], nullptr) == 0);
	}
	delete tpool;
}

bool x_threadpool_schedule(x_threadpool_t *tpool, x_job_t *job)
{
	X_LOG_DBG("schedule %p", job);
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
