
#ifndef __nxfsd__hxx__
#define __nxfsd__hxx__

#include "network.hxx"
#include "smbd_user.hxx"
#include "smbd_share.hxx"
#include "include/ntstatus.hxx"
#include <memory>
#include <ostream>

struct x_nxfsd_conn_t;
struct x_smbd_open_t;
struct x_smbd_object_t;
struct x_smbd_stream_t;

struct x_nxfsd_requ_t
{
	enum {
		INTERIM_S_NONE,
		INTERIM_S_IMMEDIATE,
		INTERIM_S_SCHEDULED,
		INTERIM_S_SENT,
	};

	explicit x_nxfsd_requ_t(
			x_nxfsd_conn_t *nxfsd_conn, x_in_buf_t &in_buf,
			uint32_t in_msgsize);
	virtual ~x_nxfsd_requ_t();

	virtual NTSTATUS process(void *ctx_conn) = 0;

	virtual void async_done(void *ctx_conn, NTSTATUS status) = 0;

	enum {
		CANCEL_BY_CLIENT,
		CANCEL_BY_CLOSE,
		CANCEL_BY_SHUTDOWN,
	};
	virtual NTSTATUS cancelled(void *ctx_conn, int reason)
	{
		X_ASSERT(false);
		return NT_STATUS_INTERNAL_ERROR;
	}

	/* always called in the context of the connection */
	void cancel(void *ctx_conn, int reason);

	/* can be in any context */
	bool set_processing();

	void incref();

	void decref();

	virtual bool can_async() const = 0;
	virtual std::ostream &tostr(std::ostream &os) const = 0;

	x_out_buf_t &get_requ_out_buf() {
		X_ASSERT(!requ_out_buf.head);
		return requ_out_buf;
	}

	x_dlink_t async_link; // link into open
	x_dlink_t conn_link; // link into conn
	x_timer_job_t interim_timer;
	int64_t interim_timeout_ns = 0;
	x_nxfsd_conn_t * const nxfsd_conn{};

	uint64_t id = 0;
	// uint64_t channel_generation;
	// const uint64_t compound_id;

	const x_tick_t start;
	std::atomic<uint32_t> async_state;
	std::atomic<int32_t> async_pending = 0;
	uint8_t interim_state = INTERIM_S_NONE;
	// bool request_counters_updated = false;

	x_in_buf_t requ_in_buf;
	const uint32_t in_msgsize;

	NTSTATUS status{NT_STATUS_OK};
	const char *location = nullptr;

	x_out_buf_t compound_out_buf;
	x_out_buf_t requ_out_buf;
	x_smbd_open_t *smbd_open{};
};

static inline std::ostream &operator<<(std::ostream &os, const x_nxfsd_requ_t &requ)
{
	return requ.tostr(os);
}

X_DECLARE_MEMBER_TRAITS(requ_async_traits, x_nxfsd_requ_t, async_link)
X_DECLARE_MEMBER_TRAITS(nxfsd_requ_conn_traits, x_nxfsd_requ_t, conn_link)

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

	x_tp_ddlist_t<nxfsd_requ_conn_traits> pending_requ_list;
	x_tp_ddlist_t<fdevt_user_conn_traits> fdevt_user_list;
};

struct x_nxfsd_conn_cbs_t
{
	ssize_t (*cb_check_header)(x_nxfsd_conn_t *nxfsd_conn);
	int (*cb_process_msg)(x_nxfsd_conn_t *nxfsd_conn, x_buf_t *buf, uint32_t msgsize);
	void (*cb_destroy)(x_nxfsd_conn_t *nxfsd_conn);
	void (*cb_close)(x_nxfsd_conn_t *nxfsd_conn);
	bool (*cb_can_remove)(x_nxfsd_conn_t *nxfsd_conn, x_nxfsd_requ_t *nxfsd_requ);
	void (*cb_reply_interim)(x_nxfsd_conn_t *nxfsd_conn, x_nxfsd_requ_t *nxfsd_requ);
};

std::ostream &operator<<(std::ostream &os, const x_nxfsd_conn_t &conn);

void x_nxfsd_conn_start(x_nxfsd_conn_t *nxfsd_conn);

void x_nxfsd_conn_queue_buf(x_nxfsd_conn_t *nxfsd_conn, x_bufref_t *buf_head,
		x_bufref_t *buf_tail);

bool x_nxfsd_conn_post_user(x_nxfsd_conn_t *nxfsd_conn, x_fdevt_user_t *fdevt_user, bool always);

#define X_NXFSD_REQU_DBG_FMT "requ(%p 0x%lx %s)"
#define X_NXFSD_REQU_DBG_ARG(r) (r), (r)->id, x_tostr(*(r)).c_str()

#define X_NXFSD_REQU_LOG(level, nxfsd_requ, fmt, ...) \
	X_LOG(SMB, level, X_NXFSD_REQU_DBG_FMT fmt, X_NXFSD_REQU_DBG_ARG(nxfsd_requ), ##__VA_ARGS__)

#define X_NXFSD_REQU_RETURN_STATUS(nxfsd_requ, status) do { \
	(nxfsd_requ)->location = __location__; \
	X_LOG(SMB, OP, X_NXFSD_REQU_DBG_FMT " %s", \
			X_NXFSD_REQU_DBG_ARG(nxfsd_requ), \
			x_ntstatus_str(status)); \
	return (status); \
} while (0)

bool x_nxfsd_requ_store(x_nxfsd_requ_t *nxfsd_requ);
void x_nxfsd_requ_remove(x_nxfsd_requ_t *nxfsd_requ);

bool x_nxfsd_conn_start_requ(x_nxfsd_conn_t *nxfsd_conn, x_nxfsd_requ_t *nxfsd_requ);
void x_nxfsd_conn_done_requ(x_nxfsd_requ_t *nxfsd_requ);

uint64_t x_nxfsd_requ_get_async_id(const x_nxfsd_requ_t *nxfsd_requ);

#define X_NXFSD_REQU_POST_USER(nxfsd_requ, evt) do { \
	auto __evt = (evt); \
	x_nxfsd_conn_post_user((nxfsd_requ)->nxfsd_conn, &__evt->base, true); \
} while (0)

void x_nxfsd_requ_post_done(x_nxfsd_requ_t *nxfsd_requ, NTSTATUS status);

using x_nxfsd_requ_id_list_t = std::vector<uint64_t>;

void x_nxfsd_requ_post_cancel(x_nxfsd_requ_t *nxfsd_requ, int reason);

bool x_nxfsd_requ_schedule_interim(x_nxfsd_requ_t *nxfsd_requ);

void x_nxfsd_requ_post_interim(x_nxfsd_requ_t *nxfsd_requ);


x_nxfsd_requ_t *x_nxfsd_requ_lookup(uint64_t id);

x_nxfsd_requ_t *x_nxfsd_requ_async_lookup(uint64_t id,
		const x_nxfsd_conn_t *nxfsd_conn, bool remove);

void x_nxfsd_requ_post_resume(x_nxfsd_requ_t *nxfsd_requ);

int x_nxfsd_requ_pool_init(uint32_t count);

int x_nxfsd_context_init();

struct x_nxfsd_requ_state_open_t
{
	x_nxfsd_requ_state_open_t(const x_smb2_uuid_t &client_guid,
			uint32_t server_capabilities);
	~x_nxfsd_requ_state_open_t();
	x_smb2_uuid_t client_guid;
	uint32_t server_capabilities;

	uint8_t in_oplock_level;
	uint8_t out_oplock_level;
	uint32_t out_contexts{0};

	uint32_t in_impersonation_level;
	uint32_t in_desired_access;
	uint32_t in_file_attributes;
	uint32_t in_share_access;
	x_smb2_create_disposition_t in_create_disposition;
	uint32_t in_create_options;

	bool is_dollar_data = false;
	bool end_with_sep = false;
	std::u16string in_path;
	std::u16string in_ads_name;

	uint8_t out_create_flags = 0;
	bool replay_operation = false;
	bool replay_reserved = false;
	uint32_t open_attempt = 0;
	uint32_t out_maximal_access{0};
	uint8_t out_qfid_info[32];

	uint32_t granted_access{0}; // internally used

	x_smbd_object_t *smbd_object{};
	x_smbd_stream_t *smbd_stream{};
	x_smbd_lease_t *smbd_lease{};
	std::shared_ptr<x_smbd_share_t> smbd_share;

	uint32_t valid_flags = 0;
	x_smb2_create_requ_context_t in_context;

	std::shared_ptr<x_smbd_user_t> smbd_user;
};

#endif /* __nxfsd__hxx__ */

