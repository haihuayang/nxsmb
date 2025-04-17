
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

struct x_threadpool_t;
struct x_thread_t
{
	pthread_t pthread_id;
	std::condition_variable cond;
	x_thread_t *next = nullptr;
	x_job_t *job = nullptr;
};

struct x_threadpool_t
{
	x_threadpool_t(std::string &&name, unsigned int count)
		: name{name}, count(count) { }
	const std::string name;
	void *private_data = nullptr;
	bool running = true;
	const unsigned int count;
	std::mutex mutex;
	x_tp_ddlist_t<job_dlink_traits> queue;
	x_thread_t *free_thread_list = nullptr;
	x_thread_t threads[0];
};

static void __threadpool_schedule_job(x_threadpool_t *tp, x_job_t *job)
{
	X_ASSERT(job->state == x_job_t::STATE_SCHEDULED);
	auto lock = std::lock_guard(tp->mutex);
	if (tp->free_thread_list) {
		x_thread_t *thread = nullptr;
		thread = tp->free_thread_list;
		tp->free_thread_list = thread->next;
		thread->next = nullptr;
		thread->job = job;
		thread->cond.notify_one();
	} else {
		tp->queue.push_back(job);
	}
}

static inline void __threadpool_continue_job(x_threadpool_t *tpool, x_thread_t *thread_self, x_job_t *job)
{
	if (tpool->queue.empty()) {
		/* no pending job */
		X_LOG(EVENT, DBG, "continue job %p", job);
		thread_self->job = job;
	} else {
		/* no thread waiting */
		X_LOG(EVENT, DBG, "queue job %p", job);
		tpool->queue.push_back(job);
	}
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

	x_thread_t *thread_self = &tpool->threads[no];

	tick_now = x_tick_now();
	X_LOG(EVENT, NOTICE, "started");

	std::unique_lock<std::mutex> ul(tpool->mutex);
	for (;;) {
		x_job_t *job = std::exchange(thread_self->job, nullptr);
		if (!job) {
			if (tpool->queue.empty()) {
				if (!tpool->running) {
					ul.unlock();
					break;
				}
				X_ASSERT(!thread_self->next);
				thread_self->next = tpool->free_thread_list;
				tpool->free_thread_list = thread_self;
				thread_self->cond.wait(ul);
				continue;
			}
			job = tpool->queue.get_front();
			tpool->queue.remove(job);
		}
		ul.unlock();
		auto orig_job_state = job->state.exchange(x_job_t::STATE_RUNNING);
		X_ASSERT(orig_job_state == x_job_t::STATE_SCHEDULED);

		tick_now = x_tick_now();
		x_job_t::retval_t status = job->run(job, tpool->private_data);
		X_LOG(EVENT, DBG, "run job %p %d", job, status);
		if (status == x_job_t::JOB_DONE) {
			ul.lock();
			continue;
		}

		if (status == x_job_t::JOB_CONTINUE) {
			job->state = x_job_t::STATE_SCHEDULED;
			ul.lock();
			__threadpool_continue_job(tpool, thread_self, job);
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
			ul.lock();
			__threadpool_continue_job(tpool, thread_self, job);
		} else {
			ul.lock();
		}
	}
	X_LOG(EVENT, NOTICE, "stopped");
	return nullptr;
}

x_threadpool_t *x_threadpool_create(std::string name, unsigned int count,
		void (*init_func)(uint32_t no))
{
	void *ptr = malloc(sizeof(x_threadpool_t) + count * sizeof(x_thread_t));
	if (!ptr) {
		return nullptr;
	}
	x_threadpool_t *tpool = new (ptr) x_threadpool_t{std::move(name), count};
	auto lock = std::lock_guard(tpool->mutex);
	for (uint32_t i = 0; i < count; ++i) {
		x_thread_t *thread = new (&tpool->threads[i]) x_thread_t{};
		x_threadpool_arg_t *tparg = new x_threadpool_arg_t{tpool, i, init_func};
		int err = pthread_create(&thread->pthread_id, nullptr,
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
	for (uint32_t i = 0; i < tpool->count; ++i) {
		tpool->threads[i].cond.notify_one();
	}
	for (uint32_t i = 0; i < tpool->count; ++i) {
		X_ASSERT(pthread_join(tpool->threads[i].pthread_id, nullptr) == 0);
		tpool->threads[i].~x_thread_t();
	}
	tpool->~x_threadpool_t();
	free(tpool);
}

bool x_threadpool_schedule(x_threadpool_t *tpool, x_job_t *job)
{
	X_LOG(EVENT, DBG, "schedule %p", job);
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
