
#ifndef __network__hxx__
#define __network__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/utils.hxx"
#include "buf.hxx"
#include "event.hxx"
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>

std::string x_sockaddr_tostr(const struct sockaddr *sa, size_t slen);

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

struct x_strm_send_queue_t
{
	~x_strm_send_queue_t()
	{
		while (head) {
			auto next = head->next;
			delete head;
			head = next;
		}
	}

	bool append(x_bufref_t *buf_head, x_bufref_t *buf_tail)
	{
#if __X_DEVELOPER__
		auto tmp = buf_head;
		while (tmp) {
			X_ASSERT(tmp->buf);
			X_ASSERT(tmp->length);
			tmp = tmp->next;
		}
#endif
		bool orig_empty = (head == nullptr);
		if (orig_empty) {
			head = buf_head;
		} else {
			tail->next = buf_head;
		}
		tail = buf_tail;
		return orig_empty;
	}

	bool send(int fd, x_fdevents_t &fdevents);

	x_bufref_t *head{}, *tail{};
};

struct x_strm_srv_t;
struct x_strm_srv_cbs_t
{
	void (*cb_accepted)(x_strm_srv_t *strm_srv, int fd,
			const struct sockaddr *sa, socklen_t slen);
	void (*cb_shutdown)(x_strm_srv_t *strm_srv);
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

