
#include "include/bits.hxx"
#include "include/wbpool.hxx"
#include "include/evtmgmt.hxx"
#include <mutex>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>


enum {
	TIMER_INTERVAL		= 5 * X_NSEC_PER_SEC, /* TODO should less than other timer */
	RECONNECT_INTERVAL	= 2 * X_NSEC_PER_SEC,
	PING_INTERVAL		= 10 * X_NSEC_PER_SEC,
	WBCLI_TIMEOUT		= 3 * X_NSEC_PER_SEC,
};

struct simple_wbcli_t
{
	simple_wbcli_t() {
		wbcli.requ = &requ;
		wbcli.resp = &resp;
	}

	x_wbcli_t wbcli;
	x_wbrequ_t requ;
	x_wbresp_t resp;
};

struct wbconn_t
{
	x_epoll_upcall_t upcall;
	uint64_t ep_id;

	x_dlink_t dlink;
	enum {
		S_DISCONNECTED,
		S_READY,
		S_SENDING,
		S_RECVING,
	} state = S_DISCONNECTED;
	bool handshaking = false;
	int fd = -1;
	x_wbpool_t *wbpool;
	x_wbcli_t *wbcli{nullptr};
	unsigned int requ_off, resp_off;
	x_tick_t timeout;

	simple_wbcli_t simple_wbcli;
};


X_DECLARE_MEMBER_TRAITS(wbcli_dlink_traits, x_wbcli_t, dlink)
X_DECLARE_MEMBER_TRAITS(wbconn_dlink_traits, wbconn_t, dlink)
	
struct x_wbpool_t
{
	x_wbpool_t(x_evtmgmt_t *ep, unsigned int count, const std::string &wbpipe);
	x_timer_job_t timer_job; // reconnect timer
	x_evtmgmt_t *evtmgmt;
	std::mutex mutex;
	enum {
		S_NONE,
		S_CONNECTING,
	} state = S_NONE;
	x_tp_ddlist_t<wbcli_dlink_traits> queue;
	x_tp_ddlist_t<wbconn_dlink_traits> ready_list; //  TODO front is ready, back is disconnected
	x_tp_ddlist_t<wbconn_dlink_traits> disconnected_list;
	std::vector<wbconn_t> wbconns;
	const std::string wbpipe;
};

static inline pid_t wbconn_getpid(wbconn_t *wbconn) 
{
	// TODO, does winbindd allow multiple connections using same pid?
	return getpid();
}

static void wbconn_set_wbcli(wbconn_t *wbconn, x_wbcli_t *wbcli)
{
	X_ASSERT(wbconn->wbcli == nullptr);
	wbconn->wbcli = wbcli;
	wbconn->requ_off = wbconn->resp_off = 0;
	wbcli->requ->header.length = sizeof(wbcli->requ->header);
	wbcli->requ->header.pid = wbconn_getpid(wbconn);
	wbconn->state = wbconn_t::S_SENDING;
}

static void handshake_wbcli_cb_reply(x_wbcli_t *wbcli, int err);
static const x_wb_cbs_t handshake_wbcli_cbs = {
	handshake_wbcli_cb_reply,
};

static void ping_wbcli_cb_reply(x_wbcli_t *wbcli, int err)
{
}

static const x_wb_cbs_t ping_wbcli_cbs = {
	ping_wbcli_cb_reply,
};

static int set_sock_flags(int fd)
{
	int flags;

	if ((flags = fcntl(fd, F_GETFL)) == -1) {
		return -1;
	}

	flags |= O_NONBLOCK;;
	if (fcntl(fd, F_SETFL, flags) == -1) {
		return -1;
	}

	if (-1 == (flags = fcntl(fd, F_GETFD, 0))) {
		return -1;
	}

	flags |= FD_CLOEXEC;
	if (-1 == fcntl(fd, F_SETFD, flags)) {
		return -1;
	}
	return 0;
}


#define WINBINDD_SOCKET_PATH "/var/run/winbindd/pipe"
#define WINBINDD_PRIV_SOCKET_PATH "/home/samba/lib/winbindd_privileged/pipe"
static int winbindd_open_pipe(const std::string &wbpipe)
{
	struct sockaddr_un sun;
	sun.sun_family = AF_UNIX;
	size_t ret = snprintf(sun.sun_path, sizeof(sun.sun_path), "%s",
			wbpipe.c_str());
	X_ASSERT(ret < sizeof(sun.sun_path));
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	X_ASSERT(fd >= 0);
	
	int err = set_sock_flags(fd);
	X_ASSERT(err == 0);

	err = connect(fd, (struct sockaddr *)&sun, sizeof(sun));
	if (err == 0) {
		return fd;
	} else if (errno == EINPROGRESS) {
		X_LOG(WBC, DBG, "connect inprogress");
		return fd;
	} else {
		X_LOG(WBC, ERR, "connect error %d", errno);
		close(fd);
		return -1;
	}
}

static inline void wbconn_send(wbconn_t *wbconn, x_wbcli_t *wbcli)
{
	wbconn_set_wbcli(wbconn, wbcli);
	x_evtmgmt_enable_events(wbconn->wbpool->evtmgmt, wbconn->ep_id, FDEVT_OUT);
}

static inline void wbconn_send_simple(wbconn_t *wbconn,
		const x_wb_cbs_t *cbs,
		enum winbindd_cmd cmd)
{
	wbconn->simple_wbcli.wbcli.cbs = cbs;
	wbconn->simple_wbcli.requ.header.cmd = cmd;
	wbconn_send(wbconn, &wbconn->simple_wbcli.wbcli);
}

static inline void wbconn_ping(wbconn_t *wbconn)
{
	X_ASSERT(wbconn->state == wbconn_t::S_READY);
	wbconn_send_simple(wbconn, &ping_wbcli_cbs, WINBINDD_PING);
}

static int wb_connect(x_wbpool_t *wbpool, wbconn_t *wbconn)
{
	X_ASSERT(wbconn->fd == -1);

	int fd = winbindd_open_pipe(wbpool->wbpipe);
	if (fd < 0) {
		return fd;
	}

	wbconn->fd = fd;
	wbconn->handshaking = true;
	wbconn->ep_id = x_evtmgmt_monitor(wbpool->evtmgmt, fd, FDEVT_IN | FDEVT_OUT, &wbconn->upcall);

	wbconn_send_simple(wbconn, &handshake_wbcli_cbs, WINBINDD_INTERFACE_VERSION);
	return 0;
}

static void wb_connect_or_schedule(x_wbpool_t *wbpool, wbconn_t *wbconn)
{
	if (wb_connect(wbpool, wbconn) != 0) {
		wbconn->timeout = tick_now + RECONNECT_INTERVAL;
		auto lock = std::lock_guard(wbpool->mutex);
		X_ASSERT(wbpool->state == x_wbpool_t::S_CONNECTING);
		wbpool->disconnected_list.push_back(wbconn);
		wbpool->state = x_wbpool_t::S_NONE;
	}
}

static void handshake_wbcli_cb_reply(x_wbcli_t *wbcli, int err)
{
	if (err < 0) {
		return;
	}

	X_ASSERT(wbcli->resp->header.result == WINBINDD_OK);
	X_ASSERT(wbcli->resp->header.data.interface_version == WINBIND_INTERFACE_VERSION);

	wbconn_t *wbconn = X_CONTAINER_OF(wbcli, wbconn_t, simple_wbcli.wbcli);
	x_wbpool_t *wbpool = wbconn->wbpool;
	wbconn_t *wbc_to_connect = nullptr;
	{
		auto lock = std::lock_guard(wbpool->mutex);
		X_ASSERT(wbpool->state == x_wbpool_t::S_CONNECTING);
		wbc_to_connect = wbpool->disconnected_list.get_front();
		if (wbc_to_connect) {
			wbpool->disconnected_list.remove(wbc_to_connect);
		} else {
			wbpool->state = x_wbpool_t::S_NONE;
		}
	}

	if (wbc_to_connect) {
		wb_connect_or_schedule(wbconn->wbpool, wbc_to_connect);
	}
}

static long wbpool_timer_job_func(x_timer_job_t *timer_job)
{
	x_wbpool_t *wbpool = X_CONTAINER_OF(timer_job, x_wbpool_t, timer_job);
	wbconn_t *wbconn_disconnected = nullptr, *wbconn_ready = nullptr;
	{
		auto lock = std::lock_guard(wbpool->mutex);
		if (wbpool->state == x_wbpool_t::S_NONE) {
			wbconn_disconnected = wbpool->disconnected_list.get_front();
			if (wbconn_disconnected) {
				wbpool->disconnected_list.remove(wbconn_disconnected);
				wbpool->state = x_wbpool_t::S_CONNECTING;
			}
		}

		wbconn_ready = wbpool->ready_list.get_front();
		if (wbconn_ready && tick_now > wbconn_ready->timeout) {
			wbpool->ready_list.remove(wbconn_ready);
		} else {
			wbconn_ready = nullptr;
		}

		x_wbcli_t *wbcli = wbpool->queue.get_front();
		if (wbcli && tick_now > wbcli->timeout) {
			wbpool->queue.remove(wbcli);
			wbcli->on_reply(-1); // TODO timeout error
		}
	}

	if (wbconn_disconnected) {
		wb_connect_or_schedule(wbpool, wbconn_disconnected);
	}

	if (wbconn_ready) {
		wbconn_ping(wbconn_ready);
	}

	return TIMER_INTERVAL;
}

x_wbpool_t::x_wbpool_t(x_evtmgmt_t *ep, unsigned int count, const std::string &wbpipe)
	: timer_job(wbpool_timer_job_func), evtmgmt{ep}, wbconns{count}, wbpipe{wbpipe}
{
}

static int wbconn_dosend(wbconn_t &wbconn)
{
	X_ASSERT(wbconn.wbcli);
	X_ASSERT(wbconn.wbcli->requ);
	x_wbrequ_t *requ = wbconn.wbcli->requ;
	X_ASSERT(wbconn.requ_off < requ->header.length);
	ssize_t err;
	if (wbconn.requ_off < sizeof(struct winbindd_request)) {
		err = write(wbconn.fd, (uint8_t *)&requ->header + wbconn.requ_off,
				sizeof(struct winbindd_request) - wbconn.requ_off);
		X_LOG(WBC, DBG, "requ_off=%u %u,%u err=%ld errno=%d",
				wbconn.requ_off, requ->header.cmd,
				requ->header.length, err, errno);
		if (err > 0) {
			wbconn.requ_off = x_convert_assert<uint32_t>(wbconn.requ_off + err);
			if (wbconn.requ_off < sizeof(struct winbindd_request)) {
				return -EAGAIN;
			}
			if (requ->extra.size() == 0) {
				return 0;
			}
		} else {
			return -errno;
		}
	}

	err = write(wbconn.fd, requ->extra.data() +
			(wbconn.requ_off - sizeof(struct winbindd_request)),
			requ->extra.size() + requ->header.length - wbconn.requ_off);
	X_LOG(WBC, DBG, "requ_off=%u %u,%u err=%ld errno=%d",
			wbconn.requ_off, requ->header.cmd,
			requ->header.length, err, errno);
	if (err < 0) {
		return -errno;
	}

	wbconn.requ_off = x_convert_assert<uint32_t>(wbconn.requ_off + err);
	if (wbconn.requ_off < requ->header.length) {
		return -EAGAIN;
	}
	return 0;
}

static int wbconn_dorecv(wbconn_t &wbconn)
{
	X_ASSERT(wbconn.wbcli);
	X_ASSERT(wbconn.wbcli->resp);
	x_wbresp_t *resp = wbconn.wbcli->resp;
	ssize_t err;
	if (wbconn.resp_off < sizeof(struct winbindd_response)) {
		err = read(wbconn.fd, ((uint8_t *)&resp->header + wbconn.resp_off),
				sizeof(struct winbindd_response) - wbconn.resp_off);
		if (err < 0) {
			return -errno;
		} else if (err == 0) {
			return -EBADMSG;
		}
		wbconn.resp_off = x_convert_assert<uint32_t>(wbconn.resp_off + err);
		if (wbconn.resp_off == sizeof(struct winbindd_response)) {
			X_ASSERT(resp->header.length >= sizeof(struct winbindd_response));
			if (wbconn.resp_off == resp->header.length) {
				resp->extra.clear();
				return 0;
			}
			X_ASSERT(resp->header.length > sizeof(struct winbindd_response));
			resp->extra.resize(resp->header.length - sizeof(struct winbindd_response));
		}
	}

	X_ASSERT(wbconn.resp_off < resp->header.length);
	err = read(wbconn.fd, resp->extra.data() +
			(wbconn.resp_off - sizeof(struct winbindd_response)),
			resp->header.length - wbconn.resp_off);
	if (err < 0) {
		return -errno;
	} else if (err == 0) {
		return -EBADMSG;
	}
	wbconn.resp_off = x_convert_assert<uint32_t>(wbconn.resp_off + err);
	if (wbconn.resp_off < resp->header.length) {
		return -EAGAIN;
	}
	return 0;
}

static inline wbconn_t *wbconn_from_upcall(x_epoll_upcall_t *upcall)
{
	return X_CONTAINER_OF(upcall, wbconn_t, upcall);
}

static bool wbconn_upcall_cb_getevents(x_epoll_upcall_t *upcall,
		x_fdevents_t &fdevents)
{
	wbconn_t *wbconn = wbconn_from_upcall(upcall);
	x_wbpool_t *wbpool = wbconn->wbpool;

	int err;
	uint32_t events = x_fdevents_processable(fdevents);

	if (events & FDEVT_ERR) {
		return true;
	}

	if (events & FDEVT_IN) {
		if (wbconn->state == wbconn_t::S_RECVING) {
			err = wbconn_dorecv(*wbconn);
			if (err == 0) {
				x_wbcli_t *wbcli = nullptr;
				std::swap(wbcli, wbconn->wbcli);
				wbconn->requ_off = wbconn->resp_off = 0;
				wbconn->state = wbconn_t::S_READY;
				wbconn->handshaking = false;
				fdevents = x_fdevents_disable(fdevents, FDEVT_IN);

				wbcli->on_reply(0);

				{
					auto lock = std::lock_guard(wbpool->mutex);
					wbcli = wbpool->queue.get_front();
					if (wbcli == nullptr) {
						wbconn->timeout = tick_now + PING_INTERVAL;
						wbpool->ready_list.push_back(wbconn);
					} else {
						wbpool->queue.remove(wbcli);
					}
				}

				if (wbcli) {
					wbconn_set_wbcli(wbconn, wbcli);
#if 0
					wbconn->wbcli = wbcli;
					wbconn->state = wbconn_t::S_SENDING;
#endif
					fdevents = x_fdevents_enable(fdevents, FDEVT_OUT);
				}
			} else if (err == -EAGAIN) {
				fdevents = x_fdevents_consume(fdevents, FDEVT_IN);
			} else if (err != -EINTR) {
				X_LOG(WBC, CONN, "wbconn_dorecv errno %d\n", -err);
				return true;
			}
		} else {
			X_ASSERT(false);
			return true;
		}
	}

	events = x_fdevents_processable(fdevents);
	if (events & FDEVT_OUT) {
		if (wbconn->state == wbconn_t::S_SENDING) {
			err = wbconn_dosend(*wbconn);
			if (err == 0) {
				wbconn->state = wbconn_t::S_RECVING;
				fdevents = x_fdevents_disable(fdevents, FDEVT_OUT);
				fdevents = x_fdevents_enable(fdevents, FDEVT_IN);
			} else if (err == -EAGAIN) {
				fdevents = x_fdevents_consume(fdevents, FDEVT_OUT);
			} else if (err != -EINTR) {
				return true;
			}
		} else {
			X_ASSERT(false);
		}
	}
	return false;
}

static void wbconn_upcall_cb_unmonitor(x_epoll_upcall_t *upcall)
{
	wbconn_t *wbconn = wbconn_from_upcall(upcall);
	X_LOG(WBC, CONN, "unmonitor wbconn %p", wbconn);
	X_ASSERT(close(wbconn->fd) == 0);
	wbconn->fd = -1;
	x_wbcli_t *wbcli = wbconn->wbcli;
	wbconn->wbcli = nullptr;
	wbconn->state = wbconn_t::S_DISCONNECTED;

	if (wbcli) {
		wbcli->on_reply(-1);
	}

	x_wbpool_t *wbpool = wbconn->wbpool;
	auto lock = std::lock_guard(wbpool->mutex);
	wbpool->disconnected_list.push_back(wbconn);
	if (wbconn->handshaking) {
		wbconn->handshaking = false;
		wbpool->state = x_wbpool_t::S_NONE;
	}
}

static const x_epoll_upcall_cbs_t wbconn_upcall_cbs = {
	wbconn_upcall_cb_getevents,
	wbconn_upcall_cb_unmonitor,
};

x_wbpool_t *x_wbpool_create(x_evtmgmt_t *evtmgmt, unsigned int count,
		const std::string &wbpipe)
{
	X_ASSERT(count != 0);
	x_wbpool_t *wbpool = new x_wbpool_t{evtmgmt, count, wbpipe};
	wbconn_t *wbconn;
	for (unsigned int i = 0; i < count; ++i) {
		wbconn = &wbpool->wbconns[i];
		wbconn->wbpool = wbpool;
		wbconn->upcall.cbs = &wbconn_upcall_cbs;
		wbconn->timeout = tick_now;
		wbpool->disconnected_list.push_back(wbconn);
	}

	x_evtmgmt_add_timer(wbpool->evtmgmt, &wbpool->timer_job, 0);
	return wbpool;
}

int x_wbpool_request(x_wbpool_t *wbpool, x_wbcli_t *wbcli)
{
	wbconn_t *wbconn = nullptr;
	wbcli->requ->header.length = sizeof(wbcli->requ->header);
	wbcli->requ->header.extra_len = x_convert_assert<uint32_t>(wbcli->requ->extra.size());
	{
		auto lock = std::lock_guard(wbpool->mutex);
		wbconn = wbpool->ready_list.get_front();
		if (!wbconn) {
			wbcli->timeout = tick_now + WBCLI_TIMEOUT;
			wbpool->queue.push_back(wbcli);
		} else {
			wbpool->ready_list.remove(wbconn);
		}
	}
	if (!wbconn) {
		X_LOG(WBC, DBG, "no ready wbconn, queued %p", wbcli);
	} else {
		X_ASSERT(wbconn->state == wbconn_t::S_READY);
		X_LOG(WBC, DBG, "wbconn %p send %p", wbconn, wbcli);
		wbconn_send(wbconn, wbcli);
	}
	return 0;
}

