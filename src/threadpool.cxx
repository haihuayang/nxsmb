#include "defines.hxx"
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>

__thread char task_name[8] = "";

YAPL_DECLARE_MEMBER_TRAITS(job_dlink_traits, job_t, dlink)
struct threadpool_t
{
	threadpool_t(unsigned int count) : threads{count} { }
	std::vector<std::thread> threads;
	std::mutex mutex_;
	std::condition_variable cond_;
	tp_d2list_t<job_dlink_traits> queue;

	void schedule_job(job_t *job) {
		X_ASSERT(job->state == job_t::STATE_SCHEDULED);
		std::unique_lock<std::mutex> ul(mutex_);
		queue.push_back(job);
		job->state = job_t::STATE_SCHEDULED;
		ul.unlock();
		cond_.notify_one();
	}

	bool schedule(job_t *job) {
		uint32_t oval = job->state.load(std::memory_order_relaxed);
		uint32_t nval;

		for (;;) {
			uint32_t state = oval & 0xffff;
			if (state == job_t::STATE_DONE) {
				X_ASSERT(oval == state);
				return false;
			} else if (state == job_t::STATE_RUNNING) {
				nval = state | 0x10000;
			} else if (state == job_t::STATE_NONE) {
				nval = job_t::STATE_SCHEDULED;
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

		if (nval == job_t::STATE_SCHEDULED) {
			schedule_job(job);
		}
		return true;
	}

	job_t *get() {
		job_t *job;
		{
			std::unique_lock<std::mutex> ul(mutex_);
			while (queue.empty()) {
				cond_.wait(ul);
			}

			job = queue.get_front();
			queue.remove(job);
		}
		X_ASSERT(job->state.exchange(job_t::STATE_RUNNING) == job_t::STATE_SCHEDULED);
		return job;
	}
};


static void thread_func(threadpool_t *tpool, uint32_t no)
{
	snprintf(task_name, sizeof task_name, "T%03d", no);
	for (;;) {
		job_t *job = tpool->get();
		job_t::retval_t status = job->ops->run(job);
		X_DBG("%s run job %p %d", task_name, job, status);
		if (status == job_t::JOB_DONE) {
			job->state = job_t::STATE_DONE;
			job->ops->done(job);
			continue;
		}

		if (status == job_t::JOB_CONTINUE) {
			job->state = job_t::STATE_SCHEDULED;
			tpool->schedule_job(job);
			continue;
		}

		uint32_t oval = job->state.load(std::memory_order_relaxed);
		uint32_t nval = job_t::STATE_SCHEDULED;
		for (;;) {
			if (oval & 0xffff0000) {
				nval = job_t::STATE_SCHEDULED;
			} else {
				nval = job_t::STATE_NONE;
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
		if (nval == job_t::STATE_SCHEDULED) {
			tpool->schedule_job(job);
		}
	}
}

threadpool_t *threadpool_create(unsigned int count)
{
	threadpool_t *tpool = new threadpool_t{count};
	for (uint32_t i = 0; i < count; ++i) {
		tpool->threads[i] = std::thread(thread_func, tpool, i);
	}
	return tpool;
}

void threadpool_destroy(threadpool_t *tpool)
{
	// TODO
	for (uint32_t i = 0; i < tpool->threads.size(); ++i) {
		tpool->threads[i].join();
	}
	delete tpool;
}

bool threadpool_schedule(threadpool_t *tpool, job_t *job)
{
	X_DBG("%s schedule %p", task_name, job);
	return tpool->schedule(job);
}

