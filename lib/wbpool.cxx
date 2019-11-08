
#include "include/wbpool.hxx"
#include "include/evtmgmt.hxx"
#include <mutex>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>


enum {
	TIMER_INTERVAL = 1000,
	RECONNECT_INTERVAL = 2000,
	PING_INTERVAL = 10 * 1000,
};

struct simple_wbcli_t
{
	simple_wbcli_t();
	struct x_wbcli_t wbcli;
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
		S_SENDING_HS,
		S_RECVING_HS,
		S_READY,
		S_SENDING,
		S_RECVING,
	} state = S_DISCONNECTED;

	int fd = -1;
	x_wbpool_t *wbpool;
	x_wbcli_t *wbcli{nullptr};
	unsigned int requ_off, resp_off;
	uint64_t timeout;

	simple_wbcli_t simple_wbcli;
};


X_DECLARE_MEMBER_TRAITS(wbcli_dlink_traits, x_wbcli_t, dlink)
X_DECLARE_MEMBER_TRAITS(wbconn_dlink_traits, wbconn_t, dlink)
	
struct x_wbpool_t
{
	x_wbpool_t(x_evtmgmt_t *ep, unsigned int count);
	x_timer_t timer; // reconnect timer
	x_evtmgmt_t *evtmgmt;
	std::mutex mutex;
	enum {
		S_NONE,
		S_SCHEDULED,
		S_CONNECTING,
	} state = S_NONE;
	x_tp_d2list_t<wbcli_dlink_traits> queue;
	x_tp_d2list_t<wbconn_dlink_traits> ready_list; //  TODO front is ready, back is disconnected
	x_tp_d2list_t<wbconn_dlink_traits> disconnected_list;
	std::vector<wbconn_t> wbconns;
};

static void simple_wbcli_cb_reply(x_wbcli_t *wbcli, int err)
{
	// wbconn_t *wbconn = X_CONTAINER_OF(wbcli, wbconn_t, simple_wbcli.wbcli);
}

static const x_wb_cbs_t simple_wbcli_cbs = {
	simple_wbcli_cb_reply,
};

inline simple_wbcli_t::simple_wbcli_t()
{
	requ.header.length = sizeof(struct winbindd_request);
	requ.header.cmd = WINBINDD_INTERFACE_VERSION;
	requ.header.pid = getpid(); // TODO, does winbindd allow multiple connections using same pid?

	wbcli.requ = &requ;
	wbcli.resp = &resp;
	wbcli.cbs = &simple_wbcli_cbs;
}

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
static int winbindd_open_pipe()
{
	struct sockaddr_un sun;
	sun.sun_family = AF_UNIX;
	size_t ret = snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", WINBINDD_PRIV_SOCKET_PATH);
	X_ASSERT(ret < sizeof(sun.sun_path));
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	X_ASSERT(fd >= 0);
	
	int err = set_sock_flags(fd);
	X_ASSERT(err == 0);

	err = connect(fd, (struct sockaddr *)&sun, sizeof(sun));
	if (err == 0) {
		return fd;
	} else if (errno == EINPROGRESS) {
		X_DBG("connect inprogress");
		return fd;
	} else {
		X_DBG("connect error %d", errno);
		close(fd);
		return -1;
	}
}

static int wb_connect(x_wbpool_t *wbpool, wbconn_t *wbconn)
{
	int fd = winbindd_open_pipe();
	if (fd < 0) {
		return fd;
	}

	wbconn->fd = fd;
	simple_wbcli_t *hscli = new simple_wbcli_t;
	wbconn->wbcli = &hscli->wbcli;
	wbconn->state = wbconn_t::S_SENDING_HS;
	wbconn->ep_id = x_evtmgmt_monitor(wbpool->evtmgmt, fd, FDEVT_IN | FDEVT_OUT, &wbconn->upcall);
	x_evtmgmt_enable_events(wbpool->evtmgmt, wbconn->ep_id, FDEVT_OUT | FDEVT_ERR | FDEVT_SHUTDOWN);
	return 0;
}

static void wb_connect_or_schedule(x_wbpool_t *wbpool, wbconn_t *wbconn)
{
	if (wb_connect(wbpool, wbconn) != 0) {
		wbconn->timeout = x_tick_add(tick_now, RECONNECT_INTERVAL);
		std::unique_lock<std::mutex> lock(wbpool->mutex);
		X_ASSERT(wbpool->state == x_wbpool_t::S_CONNECTING);
		wbpool->disconnected_list.push_back(wbconn);
		wbpool->state = x_wbpool_t::S_NONE;
	}
}

static inline void wbconn_send(wbconn_t *wbconn, x_wbcli_t *wbcli)
{
	X_ASSERT(wbconn->state == wbconn_t::S_READY);
	wbconn->wbcli = wbcli;
	wbconn->requ_off = wbconn->resp_off = 0;
	wbconn->state = wbconn_t::S_SENDING;
	x_evtmgmt_enable_events(wbconn->wbpool->evtmgmt, wbconn->ep_id, FDEVT_OUT);
}

static inline void wbconn_ping(wbconn_t *wbconn)
{
	wbconn->simple_wbcli.requ.header.cmd = WINBINDD_PING;
	wbconn_send(wbconn, &wbconn->simple_wbcli.wbcli);
}

static long wbpool_timer_func(x_timer_t *timer)
{
	X_DBG("");
	x_wbpool_t *wbpool = X_CONTAINER_OF(timer, x_wbpool_t, timer);
	wbconn_t *wbconn_disconnected = nullptr, *wbconn_ready = nullptr;
	{
		std::unique_lock<std::mutex> lock(wbpool->mutex);
		if (wbpool->state == x_wbpool_t::S_NONE) {
			wbconn_disconnected = wbpool->disconnected_list.get_front();
			if (wbconn_disconnected) {
				wbpool->disconnected_list.remove(wbconn_disconnected);
				wbpool->state = x_wbpool_t::S_CONNECTING;
			}
		}

		wbconn_ready = wbpool->ready_list.get_front();
		if (wbconn_ready && x_tick_cmp(wbconn_ready->timeout, tick_now) < 0) {
			wbpool->ready_list.remove(wbconn_ready);
		} else {
			wbconn_ready = nullptr;
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

static void wbpool_timer_done(x_timer_t *timer)
{
	x_wbpool_t *wbpool = X_CONTAINER_OF(timer, x_wbpool_t, timer);
	X_DBG("%p", wbpool);
}

static const x_timer_upcall_cbs_t wbpool_timer_cbs = {
	wbpool_timer_func,
	wbpool_timer_done,
};

x_wbpool_t::x_wbpool_t(x_evtmgmt_t *ep, unsigned int count)
	: evtmgmt{ep}, wbconns{count}
{
	timer.cbs = &wbpool_timer_cbs;
}

static int wbconn_dosend(wbconn_t &wbconn)
{
	X_ASSERT(wbconn.wbcli);
	X_ASSERT(wbconn.wbcli->requ);
	x_wbrequ_t *requ = wbconn.wbcli->requ;
	X_ASSERT(wbconn.requ_off < requ->header.length);
	int err;
	if (wbconn.requ_off < sizeof(struct winbindd_request)) {
		err = write(wbconn.fd, (uint8_t *)&requ->header + wbconn.requ_off,
				sizeof(struct winbindd_request) - wbconn.requ_off);
		if (err > 0) {
			wbconn.requ_off += err;
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
			requ->header.length - wbconn.requ_off);
	if (err < 0) {
		return -errno;
	}

	wbconn.requ_off += err;
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
	int err;
	if (wbconn.resp_off < sizeof(struct winbindd_response)) {
		err = read(wbconn.fd, ((uint8_t *)&resp->header + wbconn.resp_off),
				sizeof(struct winbindd_response) - wbconn.resp_off);
		if (err < 0) {
			return -errno;
		} else if (err == 0) {
			return -EBADMSG;
		}
		wbconn.resp_off += err;
		if (wbconn.resp_off == sizeof(struct winbindd_response)) {
			X_ASSERT(resp->header.length >= sizeof(struct winbindd_response));
			if (wbconn.resp_off == resp->header.length) {
				return 0;
			}
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
	wbconn.resp_off += err;
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
				fdevents = x_fdevents_disable(fdevents, FDEVT_IN);

				wbcli->on_reply(0);

				{
					std::unique_lock<std::mutex> lock(wbpool->mutex);
					wbcli = wbpool->queue.get_front();
					if (wbcli == nullptr) {
						wbconn->timeout = x_tick_add(tick_now, PING_INTERVAL);
						wbpool->ready_list.push_back(wbconn);
					} else {
						wbpool->queue.remove(wbcli);
					}
				}

				if (wbcli) {
					wbconn->wbcli = wbcli;
					wbconn->state = wbconn_t::S_SENDING;
					fdevents = x_fdevents_enable(fdevents, FDEVT_OUT);
				}
			} else if (err == -EAGAIN) {
				fdevents = x_fdevents_consume(fdevents, FDEVT_IN);
			} else if (err != -EINTR) {
				return true;
			}

		} else if (wbconn->state == wbconn_t::S_RECVING_HS) {
			err = wbconn_dorecv(*wbconn);
			if (err == 0) {
				x_wbcli_t *wbcli = nullptr;
				std::swap(wbcli, wbconn->wbcli);
				wbconn->requ_off = wbconn->resp_off = 0;
				wbconn->state = wbconn_t::S_READY;
				fdevents = x_fdevents_disable(fdevents, FDEVT_IN);

				X_DBG("result = %d", wbcli->resp->header.result);
				// wbcli->on_reply(0);
				X_ASSERT(wbcli->resp->header.data.interface_version == WINBIND_INTERFACE_VERSION);

				X_DBG("%p ready", wbconn);
				wbconn_t *wbc_to_connect = nullptr;
				{
					std::unique_lock<std::mutex> lock(wbpool->mutex);
					X_ASSERT(wbpool->state == x_wbpool_t::S_CONNECTING);
					wbcli = wbpool->queue.get_front();
					if (wbcli == nullptr) {
						wbconn->timeout = x_tick_add(tick_now, PING_INTERVAL);
						wbpool->ready_list.push_back(wbconn);
					} else {
						wbpool->queue.remove(wbcli);
					}

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

				if (wbcli) {
					wbconn->wbcli = wbcli;
					wbconn->state = wbconn_t::S_SENDING;
					fdevents = x_fdevents_enable(fdevents, FDEVT_OUT);
				}

			} else if (err == -EAGAIN) {
				fdevents = x_fdevents_consume(fdevents, FDEVT_IN);
			} else if (err != -EINTR) {
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

		} else if (wbconn->state == wbconn_t::S_SENDING_HS) {
			err = wbconn_dosend(*wbconn);
			if (err == 0) {
				wbconn->state = wbconn_t::S_RECVING_HS;
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
	close(wbconn->fd);
	x_wbcli_t *wbcli = nullptr;
	std::swap(wbcli, wbconn->wbcli);
	wbconn->state = wbconn_t::S_DISCONNECTED;

	if (wbcli) {
		wbcli->on_reply(-1);
	}

	x_wbpool_t *wbpool = wbconn->wbpool;

	std::unique_lock<std::mutex> lock(wbpool->mutex);
	wbpool->disconnected_list.push_back(wbconn);
}

static const x_epoll_upcall_cbs_t wbconn_upcall_cbs = {
	wbconn_upcall_cb_getevents,
	wbconn_upcall_cb_unmonitor,
};

x_wbpool_t *x_wbpool_create(x_evtmgmt_t *evtmgmt, unsigned int count)
{
	X_ASSERT(count != 0);
	x_wbpool_t *wbpool = new x_wbpool_t{evtmgmt, count};
	wbconn_t *wbconn;
	for (unsigned int i = 0; i < count; ++i) {
		wbconn = &wbpool->wbconns[i];
		wbconn->wbpool = wbpool;
		wbconn->upcall.cbs = &wbconn_upcall_cbs;
		wbconn->timeout = tick_now;
		wbpool->disconnected_list.push_back(wbconn);
	}

	x_evtmgmt_add_timer(wbpool->evtmgmt, &wbpool->timer, 0);
	return wbpool;
}

int x_wbpool_request(x_wbpool_t *wbpool, x_wbcli_t *wbcli)
{
	wbconn_t *wbconn = nullptr;
	{
		std::unique_lock<std::mutex> lock(wbpool->mutex);
		wbconn = wbpool->ready_list.get_front();
		if (!wbconn) {
			wbpool->queue.push_back(wbcli);
			return 0;
		} else {
			wbpool->ready_list.remove(wbconn);
		}
	}
	wbconn_send(wbconn, wbcli);
	return 0;
}

