
#ifndef __nxfsd__hxx__
#define __nxfsd__hxx__

#include "network.hxx"
#include "smbd_requ.hxx"
#include "include/ntstatus.hxx"
#include <memory>

X_DECLARE_MEMBER_TRAITS(smbd_requ_conn_traits, x_smbd_requ_t, conn_link)

struct x_nxfsd_conn_cbs_t;

struct x_nxfsd_conn_t
{
	enum state_t { STATE_RUNNING, STATE_DONE };
	x_nxfsd_conn_t(const x_nxfsd_conn_cbs_t *cbs, int fd, const x_sockaddr_t &saddr,
			uint32_t max_msg, uint32_t header_size, void *header_buf);
	~x_nxfsd_conn_t();
	x_epoll_upcall_t upcall;
	const x_nxfsd_conn_cbs_t *const cbs;
	uint64_t ep_id;
	std::mutex mutex;
	std::atomic<int> refcnt{1};
	std::atomic<state_t> state{STATE_RUNNING};
	const x_sockaddr_t saddr;
	const x_tick_t tick_create;

	int fd;
	unsigned int count_msg = 0;
	uint32_t const max_msg;
	uint32_t const header_size;

	uint32_t recv_len = 0, recv_msgsize = 0;
	void *const header_buf;
	x_buf_t *recv_buf{};
	x_strm_send_queue_t send_queue;

	x_tp_ddlist_t<smbd_requ_conn_traits> pending_requ_list;
	x_tp_ddlist_t<fdevt_user_conn_traits> fdevt_user_list;
};

struct x_nxfsd_conn_cbs_t
{
	ssize_t (*cb_check_header)(x_nxfsd_conn_t *nxfsd_conn);
	int (*cb_process_msg)(x_nxfsd_conn_t *nxfsd_conn, x_buf_t *buf, uint32_t msgsize);
	void (*cb_destroy)(x_nxfsd_conn_t *nxfsd_conn);
	void (*cb_close)(x_nxfsd_conn_t *nxfsd_conn);
	bool (*cb_can_remove)(x_nxfsd_conn_t *nxfsd_conn, x_smbd_requ_t *smbd_requ);
	void (*cb_reply_interim)(x_nxfsd_conn_t *nxfsd_conn, x_smbd_requ_t *smbd_requ);
};

void x_nxfsd_conn_start(x_nxfsd_conn_t *nxfsd_conn);

void x_nxfsd_conn_queue_buf(x_nxfsd_conn_t *nxfsd_conn, x_bufref_t *buf_head,
		x_bufref_t *buf_tail);

#define X_NXFSD_REQU_POST(nxfsd, evt) do { \
	auto __evt = (evt); \
	x_nxfsd_conn_post_user((nxfsd)->nxfsd_conn, &__evt->base, true); \
} while (0)

#if 0
// void x_smbd_requ_post_cancel(x_smbd_requ_t *smbd_requ, NTSTATUS status);

bool x_nxfsd_requ_async_remove(x_nxfsd_requ_t *nxfsd_requ);

void x_nxfsd_requ_async_done(void *ctx_conn, x_nxfsd_requ_t *nxfsd_requ,
		NTSTATUS status);

void x_nxfsd_conn_post_interim(x_nxfsd_requ_t *nxfsd_requ);
#endif
#endif /* __nxfsd__hxx__ */

