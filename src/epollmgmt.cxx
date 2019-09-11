
#include "defines.hxx"
#include "genref.hxx"
#include <string.h>

static job_t::retval_t epoll_job_run(job_t *job);
static void epoll_job_done(job_t *job);

static const job_ops_t epoll_job_ops = {
	epoll_job_run,
	epoll_job_done,
};

struct epoll_entry_t
{
	uint64_t init(epoll_upcall_t *upcall_) {
		assert(upcall == NULL);
		upcall = upcall_;
		job.state = job_t::STATE_NONE;
		fdevents = 0;
		return genref.init(2);
	}

	void modify_fdevents(x_fdevents_t mod_fdevents,
			x_fdevents_t *poval,
			x_fdevents_t *pnval)
	{
		x_fdevents_t oval = fdevents.load(std::memory_order_relaxed);
		x_fdevents_t nval;
		for (;;) {
			nval = oval | mod_fdevents;
			if (std::atomic_compare_exchange_weak_explicit(
						&fdevents,
						&oval,
						nval,
						std::memory_order_release,
						std::memory_order_relaxed)) {
				break;
			}
		}
		*poval = oval;
		*pnval = nval;
	}

	x_fdevents_t get_fdevents() {
		return fdevents.exchange(0);
	}

	void put() {
		if (genref.put()) {
			epoll_upcall_t *tmp_upcall = upcall;
			upcall = NULL;
			tmp_upcall->on_unmonitored();
		}
	}

	job_t job;
	genref_t genref;
	epollmgmt_t *epmgmt;
	std::atomic<x_fdevents_t> fdevents;

	epoll_upcall_t *upcall;
};

struct epollmgmt_t
{
	epollmgmt_t(int fd_, threadpool_t *tp) : epfd(fd_), tpool(tp) {
		memset(epoll_job, 0, sizeof epoll_job);
		for (auto &entry: epoll_job) {
			entry.job.ops = &epoll_job_ops;
			entry.epmgmt = this;
		}
	}

	epoll_entry_t *find_by_id(uint64_t id) {
		uint32_t fd = id;
		if (fd >= 1024) {
			return NULL;
		}
		epoll_entry_t *entry = &epoll_job[fd];
		return entry->genref.try_get(id & 0xffffffff00000000) ? entry : NULL;
	}

	int get_entry_fd(epoll_entry_t *entry) const {
		return entry - epoll_job;
	}

	void release(epoll_entry_t *entry) {
		struct epoll_event ev;
		int fd = get_entry_fd(entry);

		epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &ev);
		entry->genref.release();
		entry->put();
	}

	int epfd;
	threadpool_t *tpool;
	epoll_entry_t epoll_job[1024];
};

static job_t::retval_t epoll_job_run(job_t *job)
{
	epoll_entry_t *entry = YAPL_CONTAINER_OF(job, epoll_entry_t, job);
	x_fdevents_t fdevents = entry->get_fdevents();
	X_DBG("%s %d fdevents=%llx", task_name, entry->epmgmt->get_entry_fd(entry), fdevents);
	if (x_fdevents_processable(fdevents)) {
		if (entry->upcall->on_getevents(fdevents)) {
			entry->epmgmt->release(entry);
			return job_t::JOB_DONE;
		}
	} else {
		EVENT_LOG(epoll_job_func, spurious_wakeup);
	}

	x_fdevents_t oval, nval;
	entry->modify_fdevents(fdevents, &oval, &nval);
	X_DBG("%s fdevents=%llx, oval=%llx, nval=%llx", task_name, fdevents, oval, nval);
	uint32_t ret = x_fdevents_processable(nval);
	if (ret == 0) {
		return job_t::JOB_BLOCKED;
	} else {
		return job_t::JOB_CONTINUE;
	}
}

static void epoll_job_done(job_t *job)
{
	epoll_entry_t *entry = YAPL_CONTAINER_OF(job, epoll_entry_t, job);
	X_DBG("%p", entry);
	entry->put();
}

epollmgmt_t *epollmgmt_create(threadpool_t *tpool)
{
	int epoll_fd = epoll_create(16);
	X_ASSERT(epoll_fd >= 0);
	epollmgmt_t *ep = new epollmgmt_t(epoll_fd, tpool);
	return ep;
}

uint64_t epollmgmt_monitor(epollmgmt_t *ep, unsigned int fd, uint32_t poll_events, epoll_upcall_t * upcall)
{
	assert(fd < 1024);
	epoll_entry_t *entry = &ep->epoll_job[fd];
	uint64_t gen = entry->init(upcall);

	struct epoll_event ev;
	ev.events = poll_events | EPOLLET;
	ev.data.u64 = gen | fd;
	epoll_ctl(ep->epfd, EPOLL_CTL_ADD, fd, &ev);
	return ev.data.u64;
}


static bool epollmgmt_modify_fdevents(epollmgmt_t *ep, uint64_t id, x_fdevents_t fdevents)
{
	epoll_entry_t *entry = ep->find_by_id(id);
	if (!entry) {
		return false;
	}

	x_fdevents_t oval, nval;
	entry->modify_fdevents(fdevents, &oval, &nval);

	if (oval == nval) {
		EVENT_LOG(post_fd_event, EEXIST);
	} else if (x_fdevents_processable(nval)) {
		threadpool_schedule(ep->tpool, &entry->job);
	}
	entry->put();
	return true;
}

bool epollmgmt_enable_events(epollmgmt_t *ep, uint64_t id, uint32_t events)
{
	return epollmgmt_modify_fdevents(ep, id, x_fdevents_init(0, events));
}


static void post_fd_event(epollmgmt_t *ep, uint64_t id, uint32_t events)
{
	X_DBG("%s id=x%llx evt=x%x", task_name, id, events);
	/* TODO convert POLLHUP to POLLIN, the POLLIN event may be disable ... */
	if (events & EPOLLHUP) {
		events &= ~EPOLLHUP;
		events |= FDEVT_IN;
	}
	epollmgmt_modify_fdevents(ep, id, x_fdevents_init(events, 0));
}

#define EPOLL_WAIT_TIMEOUT -1
void epollmgmt_dispatch(epollmgmt_t *ep)
{
	struct epoll_event ev;
	int err = epoll_wait(ep->epfd, &ev, 1, EPOLL_WAIT_TIMEOUT);
	if (err > 0) {
		post_fd_event(ep, ev.data.u64, ev.events);
	} else if (err < 0) {
		X_ASSERT(errno == EINTR);
	}
}

