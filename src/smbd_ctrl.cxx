
#include "smbd_ctrl.hxx"
#include <sys/un.h>

/* to access ctrl,
   socat ABSTRACT-CONNECT:nxsmbctrl -
 */

#define END_OF_MSG	">>>EOM<<<\n\0"

struct x_smbd_ctrl_t
{
	x_epoll_upcall_t upcall;
	uint64_t ep_id;
	int fd;
};

struct x_smbd_ctrl_conn_t
{
	x_smbd_ctrl_conn_t(int fd) : fd(fd) { }
	x_epoll_upcall_t upcall;
	uint64_t ep_id;
	std::unique_ptr<x_smbd_ctrl_handler_t> handler;
	std::string output;
	uint32_t output_off = 0;
	const int fd;
	uint32_t recv_len = 0;
	uint32_t recv_off = 0;
	char recv_buf[256];
};

static inline x_smbd_ctrl_conn_t *x_smbd_ctrl_conn_from_upcall(x_epoll_upcall_t *upcall)
{
	return X_CONTAINER_OF(upcall, x_smbd_ctrl_conn_t, upcall);
}

static inline socklen_t ctrl_sockaddr_init(struct sockaddr_un *sun)
{
	sun->sun_family = AF_UNIX;
	sun->sun_path[0] = '\0';
	snprintf(&sun->sun_path[1], sizeof sun->sun_path - 2, "nxsmbctrl");
	return offsetof(struct sockaddr_un, sun_path) + 10;
}

static void x_smbd_ctrl_output(x_smbd_ctrl_conn_t *smbd_ctrl_conn)
{
	bool have_more = smbd_ctrl_conn->handler->output(smbd_ctrl_conn->output);
	X_LOG_DBG("have_more %d, output %s", have_more, smbd_ctrl_conn->output.c_str());
	if (!have_more) {
		smbd_ctrl_conn->handler.reset();
		smbd_ctrl_conn->output += END_OF_MSG;
	}
	smbd_ctrl_conn->output_off = 0;
}

static void x_smbd_ctrl_command(x_smbd_ctrl_conn_t *smbd_ctrl_conn)
{
	if (strcmp(smbd_ctrl_conn->recv_buf, "stats") == 0) {
		smbd_ctrl_conn->handler.reset(x_smbd_stats_report_create());
	} else if (strcmp(smbd_ctrl_conn->recv_buf, "list-sess") == 0) {
		smbd_ctrl_conn->handler.reset(x_smbd_sess_list_create());
	} else if (strcmp(smbd_ctrl_conn->recv_buf, "list-tcon") == 0) {
		smbd_ctrl_conn->handler.reset(x_smbd_tcon_list_create());
	} else if (strcmp(smbd_ctrl_conn->recv_buf, "list-open") == 0) {
		smbd_ctrl_conn->handler.reset(x_smbd_open_list_create());
	} else if (strcmp(smbd_ctrl_conn->recv_buf, "list-lease") == 0) {
		smbd_ctrl_conn->handler.reset(x_smbd_lease_list_create());
	} else {
		smbd_ctrl_conn->output = "Invalid command" END_OF_MSG;
		return;
	}
	x_smbd_ctrl_output(smbd_ctrl_conn);
}

static bool x_smbd_ctrl_post_recv(x_smbd_ctrl_conn_t *smbd_ctrl_conn)
{
	smbd_ctrl_conn->recv_buf[smbd_ctrl_conn->recv_len] = '\0';
	char *eol = strchr(smbd_ctrl_conn->recv_buf, '\n');
	if (!eol) {
		return false;
	}

	*eol = '\0';
	smbd_ctrl_conn->recv_off = x_convert_assert<uint32_t>(eol + 1 - smbd_ctrl_conn->recv_buf);

	x_smbd_ctrl_command(smbd_ctrl_conn);

	return true;
}

static bool x_smbd_ctrl_conn_do_recv(x_smbd_ctrl_conn_t *smbd_ctrl_conn, x_fdevents_t &fdevents)
{
	X_LOG_DBG("%s %p x%lx x%llx", task_name, smbd_ctrl_conn, smbd_ctrl_conn->ep_id, fdevents);
	ssize_t ret = read(smbd_ctrl_conn->fd,
			(char *)&smbd_ctrl_conn->recv_buf + smbd_ctrl_conn->recv_len,
			sizeof(smbd_ctrl_conn->recv_buf) - smbd_ctrl_conn->recv_len - 1);
	if (ret > 0) {
		smbd_ctrl_conn->recv_len += x_convert_assert<uint32_t>(ret);
		if (x_smbd_ctrl_post_recv(smbd_ctrl_conn)) {
			fdevents = x_fdevents_disable(fdevents, FDEVT_IN);
			fdevents = x_fdevents_enable(fdevents, FDEVT_OUT);
		} else if (smbd_ctrl_conn->recv_len + 1 == sizeof(smbd_ctrl_conn->recv_buf)) {
			/* recv_buf is full, still no eol, disconnect it */
			return true;
		}
	} else if (ret == 0) {
		return true;
	} else if (errno == EAGAIN) {
		fdevents = x_fdevents_consume(fdevents, FDEVT_IN);
	} else {
		return errno != EINTR;
	}
	return false;
}

static bool x_smbd_ctrl_conn_do_send(x_smbd_ctrl_conn_t *smbd_ctrl_conn, x_fdevents_t &fdevents)
{
	X_LOG_DBG("%s %p x%lx x%llx", task_name, smbd_ctrl_conn, smbd_ctrl_conn->ep_id, fdevents);
	for (;;) {
		ssize_t ret = write(smbd_ctrl_conn->fd,
				smbd_ctrl_conn->output.data() + smbd_ctrl_conn->output_off,
				smbd_ctrl_conn->output.size() - smbd_ctrl_conn->output_off);
		if (ret > 0) {
			smbd_ctrl_conn->output_off += x_convert_assert<uint32_t>(ret);
			if (smbd_ctrl_conn->output_off < smbd_ctrl_conn->output.size()) {
				return false;
			}

			smbd_ctrl_conn->output.erase();
			if (!smbd_ctrl_conn->handler) {
				smbd_ctrl_conn->output_off = 0;

				if (smbd_ctrl_conn->recv_len == smbd_ctrl_conn->recv_off) {
					smbd_ctrl_conn->recv_len = smbd_ctrl_conn->recv_off = 0;
				} else {
					smbd_ctrl_conn->recv_len -= smbd_ctrl_conn->recv_off;
					memmove(smbd_ctrl_conn->recv_buf,
							smbd_ctrl_conn->recv_buf + smbd_ctrl_conn->recv_off,
							smbd_ctrl_conn->recv_len);
					if (x_smbd_ctrl_post_recv(smbd_ctrl_conn)) {
						continue;
					}

				}
				fdevents = x_fdevents_enable(fdevents, FDEVT_IN);
				fdevents = x_fdevents_disable(fdevents, FDEVT_OUT);
				return false;
			}

			x_smbd_ctrl_output(smbd_ctrl_conn);
		} else {
			X_ASSERT(ret != 0);
			if (errno == EAGAIN) {
				fdevents = x_fdevents_consume(fdevents, FDEVT_OUT);
				break;
			} else if (errno == EINTR) {
			} else {
				return true;
			}
		}
	}
	return false;
}

static bool x_smbd_ctrl_conn_do_timer(x_smbd_ctrl_conn_t *smbd_ctrl_conn, x_fdevents_t &fdevents)
{
	X_LOG_DBG("%s %p x%llx", task_name, smbd_ctrl_conn, fdevents);
	fdevents = x_fdevents_consume(fdevents, FDEVT_TIMER);
	return false;
}

static bool x_smbd_ctrl_conn_handle_events(x_smbd_ctrl_conn_t *smbd_ctrl_conn, x_fdevents_t &fdevents)
{
	uint32_t events = x_fdevents_processable(fdevents);
	if (events & FDEVT_TIMER) {
		if (x_smbd_ctrl_conn_do_timer(smbd_ctrl_conn, fdevents)) {
			return true;
		}
		events = x_fdevents_processable(fdevents);
	}
	if (events & FDEVT_IN) {
		if (x_smbd_ctrl_conn_do_recv(smbd_ctrl_conn, fdevents)) {
			return true;
		}
		events = x_fdevents_processable(fdevents);
	}
	if (events & FDEVT_OUT) {
		return x_smbd_ctrl_conn_do_send(smbd_ctrl_conn, fdevents);
	}
	return false;
}

static bool x_smbd_ctrl_conn_upcall_cb_getevents(x_epoll_upcall_t *upcall, x_fdevents_t &fdevents)
{
	x_smbd_ctrl_conn_t *smbd_ctrl_conn = x_smbd_ctrl_conn_from_upcall(upcall);
	X_LOG_DBG("%s %p x%llx", task_name, smbd_ctrl_conn, fdevents);

	bool ret = x_smbd_ctrl_conn_handle_events(smbd_ctrl_conn, fdevents);
	return ret;
}

static void x_smbd_ctrl_conn_upcall_cb_unmonitor(x_epoll_upcall_t *upcall)
{
	x_smbd_ctrl_conn_t *smbd_ctrl_conn = x_smbd_ctrl_conn_from_upcall(upcall);
	X_LOG_CONN("%s %p", task_name, smbd_ctrl_conn);
	X_ASSERT_SYSCALL(close(smbd_ctrl_conn->fd));
	delete smbd_ctrl_conn;
}

static const x_epoll_upcall_cbs_t x_smbd_ctrl_conn_upcall_cbs = {
	x_smbd_ctrl_conn_upcall_cb_getevents,
	x_smbd_ctrl_conn_upcall_cb_unmonitor,
};

static void x_smbd_ctrl_accepted(int fd)
{
	set_nbio(fd, 1);
	x_smbd_ctrl_conn_t *smbd_ctrl_conn = new x_smbd_ctrl_conn_t(fd);
	X_ASSERT(smbd_ctrl_conn != NULL);
	smbd_ctrl_conn->upcall.cbs = &x_smbd_ctrl_conn_upcall_cbs;
	smbd_ctrl_conn->ep_id = x_evtmgmt_monitor(g_evtmgmt, fd, FDEVT_IN | FDEVT_OUT, &smbd_ctrl_conn->upcall);
	x_evtmgmt_enable_events(g_evtmgmt, smbd_ctrl_conn->ep_id,
			FDEVT_IN | FDEVT_ERR | FDEVT_SHUTDOWN | FDEVT_TIMER | FDEVT_USER);
}

static inline x_smbd_ctrl_t *x_smbd_ctrl_from_upcall(x_epoll_upcall_t *upcall)
{
	return X_CONTAINER_OF(upcall, x_smbd_ctrl_t, upcall);
}

static bool x_smbd_ctrl_upcall_cb_getevents(x_epoll_upcall_t *upcall, x_fdevents_t &fdevents)
{
	x_smbd_ctrl_t *smbd_ctrl = x_smbd_ctrl_from_upcall(upcall);
	uint32_t events = x_fdevents_processable(fdevents);

	if (events & FDEVT_IN) {
		struct sockaddr_un sun;
		socklen_t slen = sizeof(sun);
		int fd = accept(smbd_ctrl->fd, (struct sockaddr *)&sun, &slen);
		X_LOG_DBG("%s accept %d, %d", task_name, fd, errno);
		if (fd >= 0) {
			x_smbd_ctrl_accepted(fd);
		} else if (errno == EINTR) {
		} else if (errno == EMFILE) {
		} else if (errno == EAGAIN) {
			fdevents = x_fdevents_consume(fdevents, FDEVT_IN);
		} else {
			X_PANIC("accept errno=", errno);
		}
	}
	return false;
}

static void x_smbd_ctrl_upcall_cb_unmonitor(x_epoll_upcall_t *upcall)
{
	x_smbd_ctrl_t *smbd_ctrl = x_smbd_ctrl_from_upcall(upcall);
	X_LOG_CONN("%s %p", task_name, smbd_ctrl);
	X_ASSERT_SYSCALL(close(smbd_ctrl->fd));
	smbd_ctrl->fd = -1;
	/* TODO may close all accepted client, and notify it is freed */
}

static const x_epoll_upcall_cbs_t x_smbd_ctrl_upcall_cbs = {
	x_smbd_ctrl_upcall_cb_getevents,
	x_smbd_ctrl_upcall_cb_unmonitor,
};

static x_smbd_ctrl_t g_smbd_ctrl;

int x_smbd_ctrl_init(x_evtmgmt_t *evtmgmt)
{
	int sock = socket(AF_UNIX, SOCK_STREAM, 0);
	X_ASSERT(sock >= 0);
	struct sockaddr_un sun;
	socklen_t slen = ctrl_sockaddr_init(&sun);
	int ret = bind(sock, (const struct sockaddr *)&sun, slen);
	X_ASSERT(ret == 0);
	ret = listen(sock, 5);
	set_nbio(sock, 1);

	g_smbd_ctrl.fd = sock;
	g_smbd_ctrl.upcall.cbs = &x_smbd_ctrl_upcall_cbs;

	g_smbd_ctrl.ep_id = x_evtmgmt_monitor(evtmgmt, sock, FDEVT_IN, &g_smbd_ctrl.upcall);
	x_evtmgmt_enable_events(evtmgmt, g_smbd_ctrl.ep_id, FDEVT_IN | FDEVT_ERR | FDEVT_SHUTDOWN);

	return 0;
}
