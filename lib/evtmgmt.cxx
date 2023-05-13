
#include "include/evtmgmt.hxx"
#include "include/atomic.hxx"
#include "include/bits.hxx"
#include <string.h>
#include <mutex>
#include <queue>
#include <unistd.h>
#include <fcntl.h>

#define EVENT_LOG(...) do { } while (0)

static x_job_t::retval_t epoll_job_run(x_job_t *job, void *data);
static void epoll_job_done(x_job_t *job, void *data);

static const x_job_ops_t epoll_job_ops = {
	epoll_job_run,
	epoll_job_done,
};

struct x_epoll_entry_t
{
	uint64_t init(x_epoll_upcall_t *upcall_) {
		assert(upcall == NULL);
		upcall = upcall_;
		job.state = x_job_t::STATE_NONE;
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
		if (genref.decref()) {
			x_epoll_upcall_t *tmp_upcall = upcall;
			upcall = NULL;
			tmp_upcall->on_unmonitored();
		}
	}

	x_job_t job{&epoll_job_ops};

	x_genref_t genref;
	std::atomic<x_fdevents_t> fdevents;

	x_epoll_upcall_t *upcall;
};

static x_job_t::retval_t timer_job_run(x_job_t *job, void *data);
static void timer_job_done(x_job_t *job, void *data);

const x_job_ops_t x_timer_job_ops = {
	timer_job_run,
	timer_job_done,
};

struct timer_comp
{
	bool operator()(const x_timer_t *t1, const x_timer_t *t2) const {
		return x_tick_cmp(t1->timeout, t2->timeout) > 0;
	}
};

X_DECLARE_MEMBER_TRAITS(timer_dlink_traits, x_timer_t, job.dlink)

struct x_evtmgmt_t
{
	x_evtmgmt_t(x_threadpool_t *tp, int efd, int tfd,
			uint32_t max_fd)
		: tpool{tp}, epfd(efd), timerfd(tfd)
       		, max_fd(max_fd)
	{
		for (uint32_t i = 0; i < max_fd; ++i) {
			new (&entries[i])x_epoll_entry_t;
		}
	}

	x_epoll_entry_t *find_by_id(uint64_t id) {
		uint32_t fd = x_convert<uint32_t>(id);
		if (fd >= max_fd) {
			return NULL;
		}
		x_epoll_entry_t *entry = &entries[fd];
		return entry->genref.try_get(id & 0xffffffff00000000) ? entry : NULL;
	}

	int get_entry_fd(x_epoll_entry_t *entry) const {
		return x_convert<int>(entry - entries);
	}

	void release(x_epoll_entry_t *entry) {
		struct epoll_event ev;
		int fd = get_entry_fd(entry);

		epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &ev);
		entry->genref.release();
		entry->put();
	}

	x_threadpool_t * const tpool;
	const int epfd;
	const int timerfd;
	const uint32_t max_fd;

	std::priority_queue<x_timer_t *, std::vector<x_timer_t *>, timer_comp> timerq{timer_comp()};
	std::mutex mutex; // protect unsorted_timers, TODO it can be lock-less?
	x_tp_sdlist_t<timer_dlink_traits> unsorted_timers;

	x_epoll_entry_t entries[];
};

static x_job_t::retval_t epoll_job_run(x_job_t *job, void *data)
{
	x_epoll_entry_t *entry = X_CONTAINER_OF(job, x_epoll_entry_t, job);
	x_fdevents_t fdevents = entry->get_fdevents();
	x_evtmgmt_t *evtmgmt = (x_evtmgmt_t *)data;
	X_DBG("%s %d fdevents=%llx", task_name, evtmgmt->get_entry_fd(entry), fdevents);
	if (x_fdevents_processable(fdevents)) {
		if (entry->upcall->on_getevents(fdevents)) {
			evtmgmt->release(entry);
			return x_job_t::JOB_DONE;
		}
	} else {
		EVENT_LOG(epoll_job_func, spurious_wakeup);
	}

	x_fdevents_t oval, nval;
	entry->modify_fdevents(fdevents, &oval, &nval);
	X_DBG("%s fdevents=%llx, oval=%llx, nval=%llx", task_name, fdevents, oval, nval);
	uint32_t ret = x_fdevents_processable(nval);
	if (ret == 0) {
		return x_job_t::JOB_BLOCKED;
	} else {
		return x_job_t::JOB_CONTINUE;
	}
}

static void epoll_job_done(x_job_t *job, void *data)
{
	x_epoll_entry_t *entry = X_CONTAINER_OF(job, x_epoll_entry_t, job);
	X_DBG("%p", entry);
	entry->put();
}

uint64_t x_evtmgmt_monitor(x_evtmgmt_t *ep, unsigned int fd, uint32_t poll_events, x_epoll_upcall_t * upcall)
{
	X_ASSERT(fd < ep->max_fd);
	x_epoll_entry_t *entry = &ep->entries[fd];
	uint64_t gen = entry->init(upcall);

	struct epoll_event ev;
	ev.events = poll_events | EPOLLET;
	ev.data.u64 = gen | fd;
	epoll_ctl(ep->epfd, EPOLL_CTL_ADD, fd, &ev);
	return ev.data.u64;
}

static inline void __evtmgmt_modify_fdevents(x_evtmgmt_t *ep, x_epoll_entry_t *entry, x_fdevents_t fdevents)
{
	x_fdevents_t oval, nval;
	entry->modify_fdevents(fdevents, &oval, &nval);

	if (oval == nval) {
		EVENT_LOG(post_fd_event, EEXIST);
	} else if (x_fdevents_processable(nval)) {
		x_threadpool_schedule(ep->tpool, &entry->job);
	}
}

static bool x_evtmgmt_modify_fdevents(x_evtmgmt_t *ep, uint64_t id, x_fdevents_t fdevents)
{
	x_epoll_entry_t *entry = ep->find_by_id(id);
	if (!entry) {
		return false;
	}
	__evtmgmt_modify_fdevents(ep, entry, fdevents);
	entry->put();
	return true;
}

bool x_evtmgmt_enable_events(x_evtmgmt_t *ep, uint64_t id, uint32_t events)
{
	return x_evtmgmt_modify_fdevents(ep, id, x_fdevents_init(0, events));
}

bool x_evtmgmt_post_events(x_evtmgmt_t *ep, uint64_t id, uint32_t events)
{
	return x_evtmgmt_modify_fdevents(ep, id, x_fdevents_init(events, 0));
}

static void __evtmgmt_add_timer(x_evtmgmt_t *ep, x_timer_t *timer)
{
	timer->job.state = x_job_t::STATE_NONE;
	{
		std::unique_lock<std::mutex> lock(ep->mutex);
		ep->unsorted_timers.push_front(timer);
	}

	const uint64_t c = 1;
	ssize_t ret = write(ep->timerfd, &c, sizeof(c));
	X_ASSERT(ret == sizeof(c));
}

static x_job_t::retval_t timer_job_run(x_job_t *job, void *data)
{
	x_timer_t *timer = X_CONTAINER_OF(job, x_timer_t, job);
	long ret = timer->on_time();
	if (ret < 0) {
		timer->timeout = 0;
		return x_job_t::JOB_DONE;
	}

	if (ret == 0) {
		return x_job_t::JOB_CONTINUE;
	}
	timer->timeout = x_tick_add(tick_now, ret);
	return x_job_t::JOB_DONE;
}

static void timer_job_done(x_job_t *job, void *data)
{
	x_timer_t *timer = X_CONTAINER_OF(job, x_timer_t, job);
	X_DBG("%p", timer);
	x_evtmgmt_t *evtmgmt = (x_evtmgmt_t *)data;
	if (timer->timeout != 0) {
		__evtmgmt_add_timer(evtmgmt, timer);
	} else {
		timer->on_unmonitored();
	}
}

static void post_fd_event(x_evtmgmt_t *ep, uint64_t id, uint32_t events)
{
	X_DBG("%s id=x%llx evt=x%x", task_name, id, events);
	/* TODO convert POLLHUP to POLLIN, the POLLIN event may be disable ... */
	if (events & EPOLLHUP) {
		events &= ~EPOLLHUP;
		events |= FDEVT_IN;
	}
	x_evtmgmt_modify_fdevents(ep, id, x_fdevents_init(events, 0));
}

/* TODO, cancel timer */
void x_evtmgmt_add_timer(x_evtmgmt_t *ep, x_timer_t *timer, unsigned long ms)
{
	timer->timeout = x_tick_add(tick_now, ms);
	__evtmgmt_add_timer(ep, timer);
}

void x_evtmgmt_dispatch(x_evtmgmt_t *ep)
{
	x_tp_sdlist_t<timer_dlink_traits> unsorted_list;
	{
		std::unique_lock<std::mutex> lock(ep->mutex);
		unsorted_list = std::move(ep->unsorted_timers);
	}

	for (x_timer_t *timer = unsorted_list.get_front(); timer; timer = unsorted_list.next(timer)) {
		ep->timerq.push(timer);
	}

	tick_now = x_tick_now();
	long wait_ns = 60 * 1000000000l;
	while (!ep->timerq.empty()) {
		x_timer_t *timer = ep->timerq.top();
		wait_ns = x_tick_cmp(timer->timeout, tick_now);
		if (wait_ns > 0) {
			break;
		}
		ep->timerq.pop();
		/* run timer */
		x_threadpool_schedule(ep->tpool, &timer->job);
	}

	struct epoll_event ev;
	int err = epoll_wait(ep->epfd, &ev, 1, std::max(x_convert<int>(wait_ns / 1000000), 1));
	if (err > 0) {
		if (ev.data.u64 == (uint64_t)ep->timerfd) {
			uint64_t c;
			ssize_t ret = read(ep->timerfd, &c, sizeof(c));
			X_ASSERT(size_t(ret) == sizeof(c));
			X_DBG("timerfd read %lu", c);
		} else {
			post_fd_event(ep, ev.data.u64, ev.events);
		}
	} else if (err < 0) {
		X_ASSERT(errno == EINTR);
	}
}

// copy from include/linux/eventfd.h
#define EFD_CLOEXEC O_CLOEXEC
#define EFD_NONBLOCK O_NONBLOCK

#define SYS_eventfd2	290
#define eventfd(count, flags) syscall(SYS_eventfd2, (count), (flags))
	
x_evtmgmt_t *x_evtmgmt_create(x_threadpool_t *tpool, uint32_t max_fd)
{
	int epfd = epoll_create(16);
	X_ASSERT(epfd >= 0);

	int timerfd = x_convert_assert<int>(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
	X_ASSERT(timerfd >= 0);

	struct epoll_event ev;
	ev.events = EPOLLIN | EPOLLET;
	ev.data.u64 = timerfd;
	int ret = epoll_ctl(epfd, EPOLL_CTL_ADD, timerfd, &ev);
	X_ASSERT(ret == 0);

	/* TODO to reduce the memory usage,
	   the number of fd monitored could be much less than max_fd */
	size_t alloc_size = sizeof(x_evtmgmt_t) + sizeof(x_epoll_entry_t) * max_fd;
	void *mem = malloc(alloc_size);
	X_ASSERT(mem);

	x_evtmgmt_t *ep = new(mem) x_evtmgmt_t(tpool, epfd, timerfd, max_fd);
	tick_now = x_tick_now();
	return ep;
}

