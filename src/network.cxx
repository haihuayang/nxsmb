
#include "network.hxx"
#include "include/bits.hxx"
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/un.h>


static int tcp_bind(int port)
{
	int sock = socket(PF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		return -errno;
	}

	set_reuse(sock, 1);

	struct sockaddr_in6 sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin6_family = AF_INET6;
	sa.sin6_port = htons((unsigned short)port);
	X_ASSERT_SYSCALL(bind(sock, (struct sockaddr*) &sa, sizeof sa));

	set_tcpkeepalive(sock, 1);
	set_nbio(sock, 1);

	return sock;
}

std::string x_sockaddr_t::tostring() const
{
	char buf[INET6_ADDRSTRLEN + 16] = "";
	if (family == AF_INET) {
		snprintf(buf, sizeof buf, "%d.%d.%d.%d:%d",
			X_IPQUAD_BE(sin.sin_addr), ntohs(sin.sin_port));
	} else if (family == AF_INET6) {
		buf[0] = '[';
		size_t len = strlen(inet_ntop(AF_INET6, &sin6.sin6_addr, buf + 1, sizeof buf - 1));
		len += 1;
		snprintf(buf + len, sizeof buf - len, "]:%d",
				ntohs(sin6.sin6_port));
	} else {
		X_ASSERT(0);
	}

	return buf;
}

static inline x_strm_srv_t *x_strm_srv_from_upcall(x_epoll_upcall_t *upcall)
{
	return X_CONTAINER_OF(upcall, x_strm_srv_t, upcall);
}

static bool x_strm_srv_do_recv(x_strm_srv_t *strm_srv, x_fdevents_t &fdevents)
{
	struct sockaddr_storage ss;
	socklen_t slen = sizeof(ss);
	int fd = accept(strm_srv->fd, (struct sockaddr *)&ss, &slen);
	X_LOG(SMB, DBG, "accept %d, %d", fd, errno);
	if (fd >= 0) {
		strm_srv->strm_srv_cbs->cb_accepted(strm_srv, fd,
				(const struct sockaddr *)&ss, slen);
	} else if (errno == EINTR) {
	} else if (errno == EMFILE) {
	} else if (errno == EAGAIN) {
		fdevents = x_fdevents_consume(fdevents, FDEVT_IN);
	} else {
		X_PANIC("accept errno=", errno);
	}

	return false;
}

static bool x_strm_srv_do_user(x_strm_srv_t *strm_srv, x_fdevents_t &fdevents)
{
	X_LOG(SMB, DBG, "%p x%lx x%lx", strm_srv, strm_srv->ep_id, fdevents);
	bool ret = strm_srv->strm_srv_cbs->cb_user(strm_srv);
	fdevents = x_fdevents_consume(fdevents, FDEVT_USER);
	return ret;
}

static bool x_strm_srv_handle_events(x_strm_srv_t *strm_srv, x_fdevents_t &fdevents)
{
	uint32_t events = x_fdevents_processable(fdevents);
	if (events & FDEVT_USER) {
		if (x_strm_srv_do_user(strm_srv, fdevents)) {
			return true;
		}
		events = x_fdevents_processable(fdevents);
	}
	if (events & FDEVT_IN) {
		return x_strm_srv_do_recv(strm_srv, fdevents);
	}
	return false;
}

static bool x_strm_srv_upcall_cb_getevents(x_epoll_upcall_t *upcall, x_fdevents_t &fdevents)
{
	x_strm_srv_t *strm_srv = x_strm_srv_from_upcall(upcall);
	X_LOG(SMB, DBG, "%p x%lx", strm_srv, fdevents);
	return x_strm_srv_handle_events(strm_srv, fdevents);
}

static void x_strm_srv_upcall_cb_unmonitor(x_epoll_upcall_t *upcall)
{
	x_strm_srv_t *strm_srv = x_strm_srv_from_upcall(upcall);
	X_LOG(SMB, CONN, "%p", strm_srv);
	X_ASSERT_SYSCALL(close(strm_srv->fd));
	strm_srv->fd = -1;
	strm_srv->strm_srv_cbs->cb_shutdown(strm_srv);
}

static const x_epoll_upcall_cbs_t x_strm_srv_upcall_cbs = {
	x_strm_srv_upcall_cb_getevents,
	x_strm_srv_upcall_cb_unmonitor,
};

static int x_strm_srv_init(x_strm_srv_t *strm_srv, int sock,
		const x_strm_srv_cbs_t *cbs)
{
	X_ASSERT_SYSCALL(listen(sock, 5));

	strm_srv->fd = sock;
	strm_srv->upcall.cbs = &x_strm_srv_upcall_cbs;
	strm_srv->strm_srv_cbs = cbs;

	strm_srv->ep_id = x_evtmgmt_monitor(g_evtmgmt, sock, FDEVT_IN, &strm_srv->upcall);
	x_evtmgmt_enable_events(g_evtmgmt, strm_srv->ep_id,
			FDEVT_IN | FDEVT_ERR | FDEVT_SHUTDOWN | FDEVT_USER);
	return 0;
}

static int unix_bind(const char *name, bool abstract)
{
	int sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		return -errno;
	}

	set_reuse(sock, 1);

	struct sockaddr_un sun;
	sun.sun_family = AF_UNIX;
	char *p = sun.sun_path;
	if (abstract) {
		*p++ = '\0';
	}
	size_t len = snprintf(p, &sun.sun_path[sizeof sun.sun_path] - p - 1, "%s", name);
	p += len;
	X_ASSERT(p < &sun.sun_path[sizeof sun.sun_path]);
	socklen_t slen = x_convert<socklen_t>(p - (char *)&sun);

	int ret = bind(sock, (const struct sockaddr *)&sun, slen);
	if (ret < 0) {
		ret = -errno;
		close(sock);
		return ret;
	}
	return sock;
}

int x_unix_srv_init(x_strm_srv_t *strm_srv, const char *name, bool abstract,
		const x_strm_srv_cbs_t *cbs)
{
	int sock = unix_bind(name, abstract);
	if (sock < 0) {
		return -errno;
	}

	int err = x_strm_srv_init(strm_srv, sock, cbs);
	if (err < 0) {
		close(sock);
	}
	return err;
}

int x_tcp_srv_init(x_strm_srv_t *strm_srv, int port,
		const x_strm_srv_cbs_t *cbs)
{
	int sock = tcp_bind(port);
	if (sock < 0) {
		return -errno;
	}

	int err = x_strm_srv_init(strm_srv, sock, cbs);
	if (err < 0) {
		close(sock);
	}
	return err;
}

