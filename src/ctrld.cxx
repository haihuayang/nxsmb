
#include "ctrld.hxx"
#include <sys/un.h>
#include <memory>

#define END_OF_MSG	">>>EOM<<<\n\0"

struct x_ctrl_conn_t
{
	x_ctrl_conn_t(x_ctrld_t *ctrld, int fd);
	x_epoll_upcall_t upcall;
	uint64_t ep_id;
	x_ctrld_t * const ctrld;
	std::unique_ptr<x_ctrl_handler_t> handler;
	std::string output;
	uint32_t output_off = 0;
	const int fd;
	uint32_t recv_len = 0;
	uint32_t recv_off = 0;
	char recv_buf[256];
};

static inline x_ctrl_conn_t *x_ctrl_conn_from_upcall(x_epoll_upcall_t *upcall)
{
	return X_CONTAINER_OF(upcall, x_ctrl_conn_t, upcall);
}

static void x_ctrl_output(x_ctrl_conn_t *ctrl_conn)
{
	bool have_more = ctrl_conn->handler->output(ctrl_conn->output);
	X_LOG(CTRL, DBG, "have_more %d, output %s", have_more, ctrl_conn->output.c_str());
	if (!have_more) {
		ctrl_conn->handler.reset();
		ctrl_conn->output += END_OF_MSG;
	}
	ctrl_conn->output_off = 0;
}

static void x_ctrl_command(x_ctrl_conn_t *ctrl_conn)
{
	x_ctrl_handler_t *handler = ctrl_conn->ctrld->create_handler(
			ctrl_conn->recv_buf);
	if (!handler) {
		ctrl_conn->output = "Invalid command" END_OF_MSG;
	} else {
		ctrl_conn->handler.reset(handler);
		x_ctrl_output(ctrl_conn);
	}
}

static bool x_ctrl_post_recv(x_ctrl_conn_t *ctrl_conn)
{
	ctrl_conn->recv_buf[ctrl_conn->recv_len] = '\0';
	char *eol = strchr(ctrl_conn->recv_buf, '\n');
	if (!eol) {
		return false;
	}

	*eol = '\0';
	ctrl_conn->recv_off = x_convert_assert<uint32_t>(eol + 1 - ctrl_conn->recv_buf);

	x_ctrl_command(ctrl_conn);

	return true;
}

static bool x_ctrl_conn_do_recv(x_ctrl_conn_t *ctrl_conn, x_fdevents_t &fdevents)
{
	X_LOG(CTRL, DBG, "%p x%lx x%lx", ctrl_conn, ctrl_conn->ep_id, fdevents);
	ssize_t ret = read(ctrl_conn->fd,
			(char *)&ctrl_conn->recv_buf + ctrl_conn->recv_len,
			sizeof(ctrl_conn->recv_buf) - ctrl_conn->recv_len - 1);
	if (ret > 0) {
		ctrl_conn->recv_len += x_convert_assert<uint32_t>(ret);
		if (x_ctrl_post_recv(ctrl_conn)) {
			fdevents = x_fdevents_disable(fdevents, FDEVT_IN);
			fdevents = x_fdevents_enable(fdevents, FDEVT_OUT);
		} else if (ctrl_conn->recv_len + 1 == sizeof(ctrl_conn->recv_buf)) {
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

static bool x_ctrl_conn_do_send(x_ctrl_conn_t *ctrl_conn, x_fdevents_t &fdevents)
{
	X_LOG(CTRL, DBG, "%p x%lx x%lx", ctrl_conn, ctrl_conn->ep_id, fdevents);
	for (;;) {
		ssize_t ret = write(ctrl_conn->fd,
				ctrl_conn->output.data() + ctrl_conn->output_off,
				ctrl_conn->output.size() - ctrl_conn->output_off);
		if (ret > 0) {
			ctrl_conn->output_off += x_convert_assert<uint32_t>(ret);
			if (ctrl_conn->output_off < ctrl_conn->output.size()) {
				return false;
			}

			ctrl_conn->output.erase();
			if (!ctrl_conn->handler) {
				ctrl_conn->output_off = 0;

				if (ctrl_conn->recv_len == ctrl_conn->recv_off) {
					ctrl_conn->recv_len = ctrl_conn->recv_off = 0;
				} else {
					ctrl_conn->recv_len -= ctrl_conn->recv_off;
					memmove(ctrl_conn->recv_buf,
							ctrl_conn->recv_buf + ctrl_conn->recv_off,
							ctrl_conn->recv_len);
					if (x_ctrl_post_recv(ctrl_conn)) {
						continue;
					}

				}
				fdevents = x_fdevents_enable(fdevents, FDEVT_IN);
				fdevents = x_fdevents_disable(fdevents, FDEVT_OUT);
				return false;
			}

			x_ctrl_output(ctrl_conn);
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

static bool x_ctrl_conn_handle_events(x_ctrl_conn_t *ctrl_conn, x_fdevents_t &fdevents)
{
	uint32_t events = x_fdevents_processable(fdevents);
	if (events & FDEVT_IN) {
		if (x_ctrl_conn_do_recv(ctrl_conn, fdevents)) {
			return true;
		}
		events = x_fdevents_processable(fdevents);
	}
	if (events & FDEVT_OUT) {
		return x_ctrl_conn_do_send(ctrl_conn, fdevents);
	}
	return false;
}

static bool x_ctrl_conn_upcall_cb_getevents(x_epoll_upcall_t *upcall, x_fdevents_t &fdevents)
{
	x_ctrl_conn_t *ctrl_conn = x_ctrl_conn_from_upcall(upcall);
	X_LOG(CTRL, DBG, "%p x%lx", ctrl_conn, fdevents);

	bool ret = x_ctrl_conn_handle_events(ctrl_conn, fdevents);
	return ret;
}

static void x_ctrl_conn_upcall_cb_unmonitor(x_epoll_upcall_t *upcall)
{
	x_ctrl_conn_t *ctrl_conn = x_ctrl_conn_from_upcall(upcall);
	X_LOG(CTRL, CONN, "%p", ctrl_conn);
	X_ASSERT_SYSCALL(close(ctrl_conn->fd));
	delete ctrl_conn;
}

static const x_epoll_upcall_cbs_t x_ctrl_conn_upcall_cbs = {
	x_ctrl_conn_upcall_cb_getevents,
	x_ctrl_conn_upcall_cb_unmonitor,
};

x_ctrl_conn_t::x_ctrl_conn_t(x_ctrld_t *ctrld, int fd)
	: upcall{&x_ctrl_conn_upcall_cbs}, ctrld{ctrld}, fd{fd}
{
}

static inline x_ctrld_t *ctrld_from_strm_srv(x_strm_srv_t *strm_srv)
{
	return X_CONTAINER_OF(strm_srv, x_ctrld_t, base);
}

static void ctrl_srv_cb_accepted(x_strm_srv_t *strm_srv, int fd,
			const struct sockaddr *sa, socklen_t slen)
{
	X_LOG(CTRL, DBG, "accept %d", fd);
	x_ctrld_t *ctrld = ctrld_from_strm_srv(strm_srv);
	set_nbio(fd, 1);
	x_ctrl_conn_t *ctrl_conn = new x_ctrl_conn_t(ctrld, fd);
	X_ASSERT(ctrl_conn != NULL);
	ctrl_conn->ep_id = x_evtmgmt_monitor(g_evtmgmt, fd, FDEVT_IN | FDEVT_OUT, &ctrl_conn->upcall);
	x_evtmgmt_enable_events(g_evtmgmt, ctrl_conn->ep_id,
			FDEVT_IN | FDEVT_ERR | FDEVT_SHUTDOWN | FDEVT_USER);
}

static void ctrl_srv_cb_shutdown(x_strm_srv_t *strm_srv)
{
	X_LOG(CTRL, CONN, "%p", strm_srv);
}

static bool ctrl_srv_cb_user(x_strm_srv_t *strm_srv)
{
	X_ASSERT(false);
	return true;
}

static const x_strm_srv_cbs_t ctrl_srv_cbs = {
	ctrl_srv_cb_accepted,
	ctrl_srv_cb_shutdown,
	ctrl_srv_cb_user,
};

int x_ctrld_init(x_ctrld_t &ctrld, const char *name)
{
	int err = x_unix_srv_init(&ctrld.base, name, true,
			&ctrl_srv_cbs);
	return err;
}
