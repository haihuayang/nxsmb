
#ifndef __nxfsd__hxx__
#define __nxfsd__hxx__

#include "network.hxx"
#include "smbd_user.hxx"
#include "smbd_share.hxx"
#include "include/ntstatus.hxx"
#include <memory>

struct x_nxfsd_conn_t;
struct x_nxfsd_requ_t;
struct x_smbd_open_t;
struct x_smbd_object_t;
struct x_smbd_stream_t;

struct x_nxfsd_requ_state_async_t
{
	virtual ~x_nxfsd_requ_state_async_t() { }
	virtual void async_done(void *ctx_conn, x_nxfsd_requ_t *nxfsd_requ,
			NTSTATUS status) = 0;
	virtual NTSTATUS resume(void *ctx_conn, x_nxfsd_requ_t *nxfsd_requ) {
		X_ASSERT(false);
		return NT_STATUS_INTERNAL_ERROR;
	}
};

struct x_nxfsd_requ_cbs_t
{
	void (*cb_destroy)(x_nxfsd_requ_t *nxfsd_requ);
	bool (*cb_can_async)(const x_nxfsd_requ_t *nxfsd_requ);
	std::string (*cb_tostr)(const x_nxfsd_requ_t *nxfsd_requ);
};


struct x_nxfsd_requ_t
{
	enum {
		S_INIT,
		S_PROCESSING,
		S_CANCELLED,
	};

	enum {
		INTERIM_S_NONE,
		INTERIM_S_IMMEDIATE,
		INTERIM_S_SCHEDULED,
		INTERIM_S_SENT,
	};

	explicit x_nxfsd_requ_t(const x_nxfsd_requ_cbs_t *cbs,
			x_nxfsd_conn_t *nxfsd_conn, x_buf_t *in_buf,
			uint32_t in_msgsize);
	~x_nxfsd_requ_t();

	std::tuple<const uint8_t *, uint32_t> get_in_data() const {
		return {in_buf->data + in_offset, in_requ_len};
	}

	std::tuple<x_buf_t *, uint32_t, uint32_t> get_in_buf() const {
		return {in_buf, in_offset, in_requ_len};
	}

	std::tuple<x_bufref_t *, x_bufref_t *, uint32_t> release_out_buf() {
		x_bufref_t *out_buf_head = this->out_buf_head;
		x_bufref_t *out_buf_tail = this->out_buf_tail;
		uint32_t out_length = this->out_length;
		this->out_buf_head = this->out_buf_tail = nullptr;
		this->out_length = 0;
		return {out_buf_head, out_buf_tail, out_length};
	}

	void queue_out_buf(x_bufref_t *buf_head, x_bufref_t *buf_tail, uint32_t reply_size) {
		if (out_buf_tail) {
			out_buf_tail->next = buf_head;
			out_buf_tail = buf_tail;
		} else {
			out_buf_head = buf_head;
			out_buf_tail = buf_tail;
		}
		out_length += reply_size;
	}

	bool can_async() const {
		return cbs->cb_can_async(this);
	}

	template <class T>
	std::unique_ptr<T> release_state() {
		X_ASSERT(requ_state);
		auto ptr = dynamic_cast<T *>(requ_state.get());
		if (ptr) {
			requ_state.release();
		}
		return std::unique_ptr<T>{ptr};
	}

	std::unique_ptr<x_nxfsd_requ_state_async_t> release_state() {
		X_ASSERT(requ_state);
		return std::move(requ_state);
	}

	template <class T>
	T *get_requ_state() const {
		X_ASSERT(requ_state);
		return dynamic_cast<T *>(requ_state.get());
	}

	template <class T>
	void save_requ_state(std::unique_ptr<T> &state) {
		X_ASSERT(!requ_state);
		requ_state = std::move(state);
	}

	bool set_processing() {
		uint32_t old_val = S_INIT;
		return std::atomic_compare_exchange_strong(&async_state,
				&old_val, S_PROCESSING);
	}

	bool set_cancelled() {
		uint32_t old_val = S_INIT;
		return std::atomic_compare_exchange_strong(&async_state,
				&old_val, S_CANCELLED);
	}

	x_dlink_t async_link; // link into open
	x_dlink_t conn_link; // link into conn
	x_timer_job_t interim_timer;
	std::unique_ptr<x_nxfsd_requ_state_async_t> requ_state;
	const x_nxfsd_requ_cbs_t *const cbs;
	x_nxfsd_conn_t * const nxfsd_conn{};

	x_buf_t *in_buf;
	uint64_t id = 0;
	// uint64_t channel_generation;
	// const uint64_t compound_id;

	x_tick_t start;
	uint32_t in_msgsize, in_offset, in_requ_len;
	std::atomic<uint32_t> async_state = S_INIT;
	std::atomic<int32_t> async_pending = 0;
	uint8_t interim_state = INTERIM_S_NONE;
	// bool request_counters_updated = false;
	bool done = false;

	NTSTATUS status{NT_STATUS_OK};

	uint32_t out_length = 0;
	x_bufref_t *out_buf_head{}, *out_buf_tail{};
	std::shared_ptr<x_smbd_user_t> smbd_user;
	x_smbd_open_t *smbd_open{};
	void (*cancel_fn)(x_nxfsd_conn_t *nxfsd_conn, x_nxfsd_requ_t *nxfsd_requ);
};
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

void x_nxfsd_conn_start(x_nxfsd_conn_t *nxfsd_conn);

void x_nxfsd_conn_queue_buf(x_nxfsd_conn_t *nxfsd_conn, x_bufref_t *buf_head,
		x_bufref_t *buf_tail);

bool x_nxfsd_conn_post_user(x_nxfsd_conn_t *nxfsd_conn, x_fdevt_user_t *fdevt_user, bool always);

#define X_NXFSD_REQU_DBG_FMT "requ(%p 0x%lx %s)"
#define X_NXFSD_REQU_DBG_ARG(r) (r), (r)->id, (r)->cbs->cb_tostr(r).c_str()

#define X_NXFSD_REQU_LOG(level, nxfsd_requ, fmt, ...) \
	X_LOG(SMB, level, X_NXFSD_REQU_DBG_FMT fmt, X_NXFSD_REQU_DBG_ARG(nxfsd_requ), ##__VA_ARGS__)


bool x_nxfsd_requ_init(x_nxfsd_requ_t *nxfsd_requ);

static inline void x_nxfsd_requ_start(x_nxfsd_requ_t *nxfsd_requ,
		uint32_t offset, uint32_t in_requ_len)
{
	nxfsd_requ->in_offset = offset;
	nxfsd_requ->in_requ_len = in_requ_len;
	nxfsd_requ->start = tick_now = x_tick_now();
	nxfsd_requ->cancel_fn = nullptr;
	nxfsd_requ->done = false;
}

uint64_t x_nxfsd_requ_get_async_id(const x_nxfsd_requ_t *nxfsd_requ);

#define X_NXFSD_REQU_POST_USER(nxfsd_requ, evt) do { \
	auto __evt = (evt); \
	x_nxfsd_conn_post_user((nxfsd_requ)->nxfsd_conn, &__evt->base, true); \
} while (0)

void x_nxfsd_requ_post_error(x_nxfsd_requ_t *nxfsd_requ, NTSTATUS status);

using x_nxfsd_requ_id_list_t = std::vector<uint64_t>;

void x_nxfsd_requ_post_cancel(x_nxfsd_requ_t *nxfsd_requ, NTSTATUS status);

void x_nxfsd_requ_post_interim(x_nxfsd_requ_t *nxfsd_requ);

void x_nxfsd_requ_async_done(void *ctx_conn, x_nxfsd_requ_t *nxfsd_requ,
		NTSTATUS status);

void x_nxfsd_requ_async_insert(x_nxfsd_requ_t *nxfsd_requ,
		void (*cancel_fn)(x_nxfsd_conn_t *nxfsd_conn, x_nxfsd_requ_t *nxfsd_requ),
		int64_t interim_timeout_ns);

template <class T>
void x_nxfsd_requ_async_insert(x_nxfsd_requ_t *nxfsd_requ,
		std::unique_ptr<T> &state,
		void (*cancel_fn)(x_nxfsd_conn_t *nxfsd_conn, x_nxfsd_requ_t *nxfsd_requ),
		int64_t interim_timeout_ns)
{
	nxfsd_requ->save_requ_state(state);
	x_nxfsd_requ_async_insert(nxfsd_requ, cancel_fn, interim_timeout_ns);
}

bool x_nxfsd_requ_async_remove(x_nxfsd_requ_t *nxfsd_requ);

x_nxfsd_requ_t *x_nxfsd_requ_lookup(uint64_t id);

x_nxfsd_requ_t *x_nxfsd_requ_async_lookup(uint64_t id,
		const x_nxfsd_conn_t *nxfsd_conn, bool remove);

void x_nxfsd_requ_done(x_nxfsd_requ_t *nxfsd_requ);

void x_nxfsd_requ_resume(void *ctx_conn, x_nxfsd_requ_t *nxfsd_requ);

void x_nxfsd_requ_post_resume(x_nxfsd_requ_t *nxfsd_requ);

int x_nxfsd_requ_pool_init(uint32_t count);

int x_nxfsd_context_init();

struct x_nxfsd_requ_state_open_t : x_nxfsd_requ_state_async_t
{
	x_nxfsd_requ_state_open_t(const x_smb2_uuid_t &client_guid,
			uint32_t server_capabilities);
	~x_nxfsd_requ_state_open_t();
	const x_smb2_uuid_t client_guid;
	const uint32_t server_capabilities;

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
	long open_priv_data;

	uint32_t valid_flags = 0;
	x_smb2_create_requ_context_t in_context;
};

#endif /* __nxfsd__hxx__ */

