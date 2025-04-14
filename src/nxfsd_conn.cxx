
#include "nxfsd.hxx"
#include "smbd_conf.hxx"
#include "nxfsd_sched.hxx"
#include <sys/uio.h>

struct nxfsd_context_t
{
	x_epoll_upcall_t upcall;
	uint64_t ep_id;
	int fd;
	std::mutex mutex;
	x_tp_ddlist_t<fdevt_user_conn_traits> fdevt_user_list;
};

static nxfsd_context_t g_nxfsd_context;

static inline x_nxfsd_conn_t *x_nxfsd_conn_from_upcall(x_epoll_upcall_t *upcall)
{
	return X_CONTAINER_OF(upcall, x_nxfsd_conn_t, upcall);
}

template <>
x_nxfsd_conn_t *x_ref_inc(x_nxfsd_conn_t *nxfsd_conn)
{
	X_ASSERT(nxfsd_conn->refcnt++ > 0);
	return nxfsd_conn;
}

template <>
void x_ref_dec(x_nxfsd_conn_t *nxfsd_conn)
{
	if (x_unlikely(--nxfsd_conn->refcnt == 0)) {
		nxfsd_conn->cbs->cb_destroy(nxfsd_conn);
	}
}

static thread_local x_nxfsd_conn_t *g_nxfsd_conn_curr = nullptr;
struct nxfsd_conn_curr_t
{
	nxfsd_conn_curr_t(x_nxfsd_conn_t *nxfsd_conn) {
		g_nxfsd_conn_curr = x_ref_inc(nxfsd_conn);
	}
	~nxfsd_conn_curr_t() {
		X_REF_DEC(g_nxfsd_conn_curr);
	}
};

bool x_nxfsd_conn_start_requ(x_nxfsd_conn_t *nxfsd_conn, x_nxfsd_requ_t *nxfsd_requ)
{
	if (!x_nxfsd_requ_store(nxfsd_requ)) {
		return false;
	}
	nxfsd_requ->nxfsd_conn->pending_requ_list.push_back(nxfsd_requ);
	return true;
}

void x_nxfsd_conn_done_requ(x_nxfsd_requ_t *nxfsd_requ)
{
	x_nxfsd_conn_t *nxfsd_conn = nxfsd_requ->nxfsd_conn;
	nxfsd_conn->pending_requ_list.remove(nxfsd_requ);
	x_nxfsd_requ_remove(nxfsd_requ);
}

static ssize_t nxfsd_conn_check_header(x_nxfsd_conn_t *nxfsd_conn)
{
	if (nxfsd_conn->recv_len < nxfsd_conn->header_size) {
		return 0;
	}
	ssize_t err = nxfsd_conn->cbs->cb_check_header(nxfsd_conn);
	if (err < 0) {
		X_LOG(EVENT, ERR, "%p x%lx cb_check_header %ld",
				nxfsd_conn, nxfsd_conn->ep_id, err);
		return err;
	}
	nxfsd_conn->recv_len -= nxfsd_conn->header_size;
	if (err == 0) {
		return 0;
	}
	nxfsd_conn->recv_msgsize = x_convert_assert<uint32_t>(err);
	nxfsd_conn->recv_buf = x_buf_alloc(err);
	return err;
}

static bool x_nxfsd_conn_do_recv(x_nxfsd_conn_t *nxfsd_conn, x_fdevents_t &fdevents)
{
	X_TRACE_LOC;
	ssize_t err;
	X_LOG(EVENT, DBG, "conn %p x%lx x%lx", nxfsd_conn, nxfsd_conn->ep_id, fdevents);
	if (nxfsd_conn->recv_buf == NULL) {
		X_ASSERT(nxfsd_conn->recv_len < nxfsd_conn->header_size);
		err = read(nxfsd_conn->fd,
				(char *)nxfsd_conn->header_buf + nxfsd_conn->recv_len,
				nxfsd_conn->header_size - nxfsd_conn->recv_len);
		if (err > 0) {
			nxfsd_conn->recv_len = x_convert_assert<uint32_t>(nxfsd_conn->recv_len + err);
			err = nxfsd_conn_check_header(nxfsd_conn);
			if (err < 0) {
				return true;
			} else if (err == 0) {
				return false;
			}
		} else if (err == 0) {
			X_LOG(EVENT, CONN, "%p x%lx recv nbt_hdr EOF", nxfsd_conn, nxfsd_conn->ep_id);
			return true;
		} else if (errno == EAGAIN) {
			fdevents = x_fdevents_consume(fdevents, FDEVT_IN);
			return false;
		} else if (errno == EINTR) {
			return false;
		} else {
			X_LOG(EVENT, ERR, "%p x%lx do_recv errno=%d",
					nxfsd_conn, nxfsd_conn->ep_id, errno);
			return true;
		}
	}

	struct iovec iovec[2] = {
		{ nxfsd_conn->recv_buf->data + nxfsd_conn->recv_len, nxfsd_conn->recv_msgsize - nxfsd_conn->recv_len, },
		{ nxfsd_conn->header_buf, nxfsd_conn->header_size, }
	};

	err = readv(nxfsd_conn->fd, iovec, 2);
	if (err > 0) {
		nxfsd_conn->recv_len = x_convert_assert<uint32_t>(nxfsd_conn->recv_len + err);
		if (nxfsd_conn->recv_len >= nxfsd_conn->recv_msgsize) {
			nxfsd_conn->recv_len -= nxfsd_conn->recv_msgsize;
			x_buf_t *buf = nxfsd_conn->recv_buf;
			nxfsd_conn->recv_buf = NULL;
			int ret = nxfsd_conn->cbs->cb_process_msg(nxfsd_conn, buf, nxfsd_conn->recv_msgsize);

			if (ret) {
				X_LOG(EVENT, ERR, "%p x%lx cb_process_msg %d",
						nxfsd_conn, nxfsd_conn->ep_id, ret);
				return true;
			}

			X_ASSERT(nxfsd_conn->recv_len <= nxfsd_conn->header_size);
			err = nxfsd_conn_check_header(nxfsd_conn);
			if (err < 0) {
				return true;
			} else if (err == 0) {
				return false;
			}
		}
	} else if (err == 0) {
		X_LOG(EVENT, CONN, "%p x%lx recv nbt_body EOF", nxfsd_conn, nxfsd_conn->ep_id);
		return true;
	} else if (errno == EAGAIN) {
		fdevents = x_fdevents_consume(fdevents, FDEVT_IN);
	} else if (errno == EINTR) {
	} else {
		X_LOG(EVENT, ERR, "%p x%lx do_recv errno=%d",
				nxfsd_conn, nxfsd_conn->ep_id, errno);
		return true;
	}
	return false;
}

static bool x_nxfsd_conn_do_send(x_nxfsd_conn_t *nxfsd_conn, x_fdevents_t &fdevents)
{
	X_LOG(EVENT, DBG, "conn %p x%lx x%lx", nxfsd_conn, nxfsd_conn->ep_id, fdevents);
	bool ret = nxfsd_conn->send_queue.send(nxfsd_conn->fd, fdevents);
#if 0
	if (!ret && nxfsd_conn->count_msg < x_nxfsd_conn_t::MAX_MSG) {
		fdevents = x_fdevents_enable(fdevents, FDEVT_IN);
	}
#endif
	return ret;
}

static bool x_nxfsd_conn_do_user(x_nxfsd_conn_t *nxfsd_conn, x_fdevents_t &fdevents)
{
	X_LOG(EVENT, DBG, "%p x%lx x%lx", nxfsd_conn, nxfsd_conn->ep_id, fdevents);
	auto lock = std::unique_lock(nxfsd_conn->mutex);
	for (;;) {
		x_fdevt_user_t *fdevt_user = nxfsd_conn->fdevt_user_list.get_front();
		if (!fdevt_user) {
			break;
		}
		nxfsd_conn->fdevt_user_list.remove(fdevt_user);
		lock.unlock();

		X_LOG(EVENT, DBG, "%p %p created at: %s", nxfsd_conn,
				fdevt_user, fdevt_user->location);
		fdevt_user->func(nxfsd_conn, fdevt_user);

		lock.lock();
	}

	fdevents = x_fdevents_consume(fdevents, FDEVT_USER);
	return false;
}

static bool x_nxfsd_conn_handle_events(x_nxfsd_conn_t *nxfsd_conn, x_fdevents_t &fdevents)
{
	uint32_t events = x_fdevents_processable(fdevents);
	if (events & FDEVT_SHUTDOWN) {
		return true;
	}
	if (events & FDEVT_USER) {
		if (x_nxfsd_conn_do_user(nxfsd_conn, fdevents)) {
			return true;
		}
		events = x_fdevents_processable(fdevents);
	}
	if (events & FDEVT_OUT) {
		if (x_nxfsd_conn_do_send(nxfsd_conn, fdevents)) {
			return true;
		}
		events = x_fdevents_processable(fdevents);
	}
	if (events & FDEVT_IN) {
		return x_nxfsd_conn_do_recv(nxfsd_conn, fdevents);
	}
	return false;
}

static bool x_nxfsd_conn_upcall_cb_getevents(x_epoll_upcall_t *upcall, x_fdevents_t &fdevents)
{
	x_nxfsd_conn_t *nxfsd_conn = x_nxfsd_conn_from_upcall(upcall);
	X_LOG(EVENT, DBG, "%p x%lx", nxfsd_conn, fdevents);

	x_smbd_conf_pin_t smbd_conf_pin;
	x_nxfsd_scheduler_t smbd_scheduler(nxfsd_conn);
	nxfsd_conn_curr_t nxfsd_conn_curr(nxfsd_conn);

	return x_nxfsd_conn_handle_events(nxfsd_conn, fdevents);
}

static void x_nxfsd_conn_upcall_cb_unmonitor(x_epoll_upcall_t *upcall)
{
	x_nxfsd_conn_t *nxfsd_conn = x_nxfsd_conn_from_upcall(upcall);
	X_LOG(EVENT, CONN, "%p", nxfsd_conn);

	X_ASSERT_SYSCALL(close(nxfsd_conn->fd));
	nxfsd_conn->fd = -1;

	{
		x_smbd_conf_pin_t smbd_conf_pin;
		x_nxfsd_scheduler_t smbd_scheduler(nxfsd_conn);
		nxfsd_conn_curr_t nxfsd_conn_curr(nxfsd_conn);

		nxfsd_conn->cbs->cb_close(nxfsd_conn);

		x_nxfsd_requ_t *nxfsd_requ, *next_requ;
		for (nxfsd_requ = nxfsd_conn->pending_requ_list.get_front(); nxfsd_requ;
				nxfsd_requ = next_requ) {
			next_requ = nxfsd_conn->pending_requ_list.next(nxfsd_requ);
			if (nxfsd_conn->cbs->cb_can_remove(nxfsd_conn, nxfsd_requ)) {
				nxfsd_requ->cancel(nxfsd_conn, x_nxfsd_requ_t::CANCEL_BY_SHUTDOWN);
			}
		}
	}

	x_tp_ddlist_t<fdevt_user_conn_traits> fdevt_user_list;
	{
		auto lock = std::lock_guard(nxfsd_conn->mutex);
		nxfsd_conn->state = x_nxfsd_conn_t::STATE_DONE;
		fdevt_user_list = std::move(nxfsd_conn->fdevt_user_list);
	}

	x_ref_dec(nxfsd_conn);

	bool notify;
	{
		auto lock = std::lock_guard(g_nxfsd_context.mutex);
		notify = g_nxfsd_context.fdevt_user_list.get_front() == nullptr;
		g_nxfsd_context.fdevt_user_list.concat(fdevt_user_list);
	}
	if (notify) {
		x_evtmgmt_post_events(g_evtmgmt, g_nxfsd_context.ep_id, FDEVT_USER);
	}
}

static const x_epoll_upcall_cbs_t x_nxfsd_conn_upcall_cbs = {
	x_nxfsd_conn_upcall_cb_getevents,
	x_nxfsd_conn_upcall_cb_unmonitor,
};

x_nxfsd_conn_t::x_nxfsd_conn_t(const x_nxfsd_conn_cbs_t *cbs, int fd,
		const x_sockaddr_t &saddr, uint32_t max_msg,
		uint32_t header_size, void *header_buf)
	: upcall(&x_nxfsd_conn_upcall_cbs), cbs(cbs), saddr(saddr)
	, tick_create(tick_now), fd(fd)
	, max_msg(max_msg), header_size(header_size), header_buf(header_buf)
{
}

x_nxfsd_conn_t::~x_nxfsd_conn_t()
{
	X_ASSERT(fd == -1);

	if (recv_buf) {
		x_buf_release(recv_buf);
	}
}

std::ostream &operator<<(std::ostream &os, const x_nxfsd_conn_t &conn)
{
	return os << conn.fd << "," << conn.saddr;
}


void x_nxfsd_conn_start(x_nxfsd_conn_t *nxfsd_conn)
{
	nxfsd_conn->ep_id = x_evtmgmt_monitor(g_evtmgmt, nxfsd_conn->fd,
			FDEVT_IN | FDEVT_OUT, &nxfsd_conn->upcall);
	x_evtmgmt_enable_events(g_evtmgmt, nxfsd_conn->ep_id,
			FDEVT_IN | FDEVT_ERR | FDEVT_SHUTDOWN | FDEVT_USER);
}

void x_nxfsd_conn_queue_buf(x_nxfsd_conn_t *nxfsd_conn, x_bufref_t *buf_head,
		x_bufref_t *buf_tail)
{
	if (nxfsd_conn->send_queue.append(buf_head, buf_tail)) {
		x_evtmgmt_enable_events(g_evtmgmt, nxfsd_conn->ep_id, FDEVT_OUT);
	}
}

bool x_nxfsd_conn_post_user(x_nxfsd_conn_t *nxfsd_conn, x_fdevt_user_t *fdevt_user, bool always){
	bool notify = false;
	bool queued = false;
	{
		auto lock = std::lock_guard(nxfsd_conn->mutex);
		if (nxfsd_conn->state != x_nxfsd_conn_t::STATE_DONE) {
			notify = nxfsd_conn->fdevt_user_list.get_front() == nullptr;
			nxfsd_conn->fdevt_user_list.push_back(fdevt_user);
			queued = true;
		}
	}
	if (notify) {
		x_evtmgmt_post_events(g_evtmgmt, nxfsd_conn->ep_id, FDEVT_USER);
	}
	if (queued) {
		return true;
	}
	if (!always) {
		return false;
	}

	/* nxfsd_conn is already done, so queued to global context to handle the
	 * user event, there is no race because only 1 context and original is done
	 */
	{
		auto lock = std::lock_guard(g_nxfsd_context.mutex);
		notify = g_nxfsd_context.fdevt_user_list.get_front() == nullptr;
		g_nxfsd_context.fdevt_user_list.push_back(fdevt_user);
	}
	if (notify) {
		x_evtmgmt_post_events(g_evtmgmt, g_nxfsd_context.ep_id, FDEVT_USER);
	}
	return true;
}

struct nxfsd_cancel_evt_t
{
	static void func(void *ctx_conn, x_fdevt_user_t *fdevt_user)
	{
		nxfsd_cancel_evt_t *evt = X_CONTAINER_OF(fdevt_user, nxfsd_cancel_evt_t, base);
		x_nxfsd_requ_t *nxfsd_requ = evt->nxfsd_requ;
		X_LOG(EVENT, DBG, "evt=%p, requ=%p, conn=%p", evt, nxfsd_requ, ctx_conn);
		nxfsd_requ->cancel(ctx_conn, evt->reason);
		delete evt;
	}

	explicit nxfsd_cancel_evt_t(const char *location,
			x_nxfsd_requ_t *nxfsd_requ, int reason)
		: base(func, location), nxfsd_requ(nxfsd_requ), reason(reason)
	{
	}
	~nxfsd_cancel_evt_t()
	{
		nxfsd_requ->decref();
	}
	x_fdevt_user_t base;
	x_nxfsd_requ_t * const nxfsd_requ;
	int const reason;
};


void x_nxfsd_requ_post_cancel(x_nxfsd_requ_t *nxfsd_requ, int reason, const char *location)
{
	nxfsd_cancel_evt_t *evt = new nxfsd_cancel_evt_t(location, nxfsd_requ, reason);
	x_nxfsd_conn_post_user(nxfsd_requ->nxfsd_conn, &evt->base, true);
}

void x_nxfsd_schedule_cancel(x_nxfsd_requ_t *nxfsd_requ, int reason, const char *location)
{
	nxfsd_cancel_evt_t *evt = new nxfsd_cancel_evt_t(location, nxfsd_requ, reason);
	x_nxfsd_schedule(&evt->base);
}


/* must be in context of nxfsd_conn */
bool x_nxfsd_requ_schedule_interim(x_nxfsd_requ_t *nxfsd_requ)
{
	auto interim_timeout_ns = nxfsd_requ->interim_timeout_ns;
	X_NXFSD_REQU_LOG(DBG, nxfsd_requ, " timeout=%ld", interim_timeout_ns);
	if (nxfsd_requ->interim_state == x_nxfsd_requ_t::INTERIM_S_NONE) {
		if (interim_timeout_ns == 0) {
			nxfsd_requ->interim_state = x_nxfsd_requ_t::INTERIM_S_IMMEDIATE;
			return true;
		} else if (interim_timeout_ns > 0 && nxfsd_requ->can_async()) {
			nxfsd_requ->incref();
			x_nxfsd_add_timer(&nxfsd_requ->interim_timer, interim_timeout_ns);
			nxfsd_requ->interim_state = x_nxfsd_requ_t::INTERIM_S_SCHEDULED;
		}
	}
	return false;
}

struct send_interim_evt_t
{
	static void func(void *ctx_conn, x_fdevt_user_t *fdevt_user)
	{
		send_interim_evt_t *evt = X_CONTAINER_OF(fdevt_user,
				send_interim_evt_t, base);
		x_nxfsd_requ_t *nxfsd_requ = evt->nxfsd_requ;
		X_LOG(EVENT, DBG, "evt=%p, requ=%p, ctx_conn=%p", evt, nxfsd_requ, ctx_conn);
		if (nxfsd_requ->interim_state != x_nxfsd_requ_t::INTERIM_S_SCHEDULED) {
			X_ASSERT(nxfsd_requ->interim_state != x_nxfsd_requ_t::INTERIM_S_SENT);
		} else if (ctx_conn) {
			x_nxfsd_conn_t *nxfsd_conn = static_cast<x_nxfsd_conn_t *>(ctx_conn);
			nxfsd_conn->cbs->cb_reply_interim(nxfsd_conn, nxfsd_requ);
		}
		delete evt;
	}

	explicit send_interim_evt_t(const char *location, x_nxfsd_requ_t *nxfsd_requ)
		: base(func, location), nxfsd_requ(nxfsd_requ)
	{
	}

	~send_interim_evt_t()
	{
		nxfsd_requ->decref();
	}

	x_fdevt_user_t base;
	x_nxfsd_requ_t * const nxfsd_requ;
};

void x_nxfsd_requ_post_interim(x_nxfsd_requ_t *nxfsd_requ, const char *location)
{
	send_interim_evt_t *evt = new send_interim_evt_t(location, nxfsd_requ);
	if (!x_nxfsd_conn_post_user(nxfsd_requ->nxfsd_conn, &evt->base, false)) {
		delete evt;
	}
}

static bool nxfsd_context_upcall_cb_getevents(x_epoll_upcall_t *upcall, x_fdevents_t &fdevents)
{
	nxfsd_context_t *nxfsd_ctx = X_CONTAINER_OF(upcall, nxfsd_context_t, upcall);
	uint32_t events = x_fdevents_processable(fdevents);
	X_ASSERT(!(events & (FDEVT_IN | FDEVT_OUT)));
	if (events & FDEVT_USER) {
		x_tp_ddlist_t<fdevt_user_conn_traits> fdevt_user_list;
		{
			auto lock = std::lock_guard(nxfsd_ctx->mutex);
			fdevt_user_list = std::move(nxfsd_ctx->fdevt_user_list);
		}
		x_fdevt_user_t *fdevt_user;
		while ((fdevt_user = fdevt_user_list.get_front())) {
			fdevt_user_list.remove(fdevt_user);
			X_LOG(EVENT, DBG, "dangling %p created at: %s",
					fdevt_user, fdevt_user->location);
			fdevt_user->func(nullptr, fdevt_user);
		}
		fdevents = x_fdevents_consume(fdevents, FDEVT_USER);
	}
	return false;
}

static void nxfsd_context_upcall_cb_unmonitor(x_epoll_upcall_t *upcall)
{
	/* never reach */
	X_ASSERT(false);
}

static const x_epoll_upcall_cbs_t nxfsd_context_upcall_cbs = {
	nxfsd_context_upcall_cb_getevents,
	nxfsd_context_upcall_cb_unmonitor,
};

int x_nxfsd_context_init()
{
	int fd = x_eventfd(0);
	X_ASSERT(fd >= 0);
	g_nxfsd_context.fd = fd;
	g_nxfsd_context.upcall.cbs = &nxfsd_context_upcall_cbs;
	g_nxfsd_context.ep_id = x_evtmgmt_monitor(g_evtmgmt, fd, FDEVT_IN,
			&g_nxfsd_context.upcall);
	x_evtmgmt_enable_events(g_evtmgmt, g_nxfsd_context.ep_id,
			FDEVT_IN | FDEVT_ERR | FDEVT_USER);
	return 0;
}
