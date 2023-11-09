
#ifndef __network__hxx__
#define __network__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/utils.hxx"
#include "event.hxx"
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>

union x_sockaddr_t
{
	uint16_t family;
	struct sockaddr sa;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;

	std::string tostring() const;
};

static inline void set_reuse(int s, int on)
{
	X_ASSERT_SYSCALL(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on));
}

static inline void set_tcpkeepalive(int s, int on)
{
	X_ASSERT_SYSCALL(setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on));
}

static inline void set_nbio(int s, unsigned long on)
{
	X_ASSERT_SYSCALL(ioctl(s, FIONBIO, &on));
}

struct x_strm_srv_t;
struct x_strm_srv_cbs_t
{
	void (*cb_accepted)(x_strm_srv_t *strm_srv, int fd,
			const struct sockaddr *sa, socklen_t slen);
	void (*cb_shutdown)(x_strm_srv_t *strm_srv);
	bool (*cb_user)(x_strm_srv_t *strm_srv);

};

struct x_strm_srv_t
{
	x_epoll_upcall_t upcall;
	const x_strm_srv_cbs_t *strm_srv_cbs;
	uint64_t ep_id;
	int fd;
};

int x_unix_srv_init(x_strm_srv_t *strm_srv, const char *name, bool abstract,
		const x_strm_srv_cbs_t *cbs);

int x_tcp_srv_init(x_strm_srv_t *strm_srv, int port,
		const x_strm_srv_cbs_t *cbs);


#endif /* __network__hxx__ */

