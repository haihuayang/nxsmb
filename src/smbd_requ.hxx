
#ifndef __smbd_requ__hxx__
#define __smbd_requ__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "smbd.hxx"

struct x_smbd_requ_t
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

	explicit x_smbd_requ_t(x_buf_t *in_buf, uint32_t in_msgsize, bool encrypted);
	~x_smbd_requ_t();

	const uint8_t *get_in_data() const {
		return in_buf->data + in_offset;
	}

	bool is_signed() const {
		return (in_smb2_hdr.flags & X_SMB2_HDR_FLAG_SIGNED) != 0;
	}

	bool is_compound_related() const {
		return (in_smb2_hdr.flags & X_SMB2_HDR_FLAG_CHAINED) != 0;
	}

	bool is_compound_followed() const {
		return in_smb2_hdr.next_command != 0;
	}

	template <class T>
	std::unique_ptr<T> release_state() {
		X_ASSERT(requ_state);
		std::unique_ptr<T> state{(T *)requ_state};
		requ_state = nullptr;
		return state;
	}

	template <class T>
	T *get_requ_state() const {
		X_ASSERT(requ_state);
		return (T *)requ_state;
	}

	template <class T>
	void save_requ_state(std::unique_ptr<T> &state) {
		X_ASSERT(!requ_state);
		requ_state = state.release();
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
	void *requ_state = nullptr;

	x_buf_t *in_buf;
	uint64_t id = 0;
	uint64_t channel_generation;
	const uint64_t compound_id;

	x_tick_t start;
	x_smb2_header_t in_smb2_hdr;
	uint32_t in_msgsize, in_offset, in_requ_len;
	std::atomic<uint32_t> async_state = S_INIT;
	uint8_t interim_state = INTERIM_S_NONE;
	bool encrypted;
	bool request_counters_updated = false;
	bool done = false;

	NTSTATUS status{NT_STATUS_OK};
	NTSTATUS sess_status{NT_STATUS_OK};
	uint32_t out_hdr_flags{};

	uint16_t out_credit_granted;

	uint32_t out_length = 0;
	x_bufref_t *out_buf_head{}, *out_buf_tail{};
	x_smbd_sess_t *smbd_sess{};
	x_smbd_chan_t *smbd_chan{};
	x_smbd_tcon_t *smbd_tcon{};
	x_smbd_open_t *smbd_open{};
	void (*cancel_fn)(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
	void (*async_done_fn)(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
			NTSTATUS status);
};
X_DECLARE_MEMBER_TRAITS(requ_async_traits, x_smbd_requ_t, async_link)

int x_smbd_requ_pool_init(uint32_t count);
x_smbd_requ_t *x_smbd_requ_create(x_buf_t *in_buf, uint32_t in_msgsize, bool encrypted);
uint64_t x_smbd_requ_get_async_id(const x_smbd_requ_t *smbd_requ);
x_smbd_requ_t *x_smbd_requ_async_lookup(uint64_t id, const x_smbd_conn_t *smbd_conn, bool remove);
void x_smbd_requ_async_insert(x_smbd_requ_t *smbd_requ,
		void (*cancel_fn)(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ),
		int64_t interim_timeout_ns);
bool x_smbd_requ_async_remove(x_smbd_requ_t *smbd_requ);
void x_smbd_requ_async_done(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
		NTSTATUS status);
void x_smbd_requ_done(x_smbd_requ_t *smbd_requ);
NTSTATUS x_smbd_requ_init_open(x_smbd_requ_t *smbd_requ,
		uint64_t id_persistent, uint64_t id_volatile,
		bool modify_call);

static inline bool x_smbd_requ_verify_creditcharge(
		x_smbd_requ_t *smbd_requ, uint32_t data_length)
{
	uint32_t credit_charge = std::max(smbd_requ->in_smb2_hdr.credit_charge, uint16_t(1u));
	/* must be uint16_t so data_length is 0, it because 0 */
	uint16_t needed_charge = x_convert<uint16_t>((data_length - 1) / 65536 + 1);
	return needed_charge <= credit_charge;
}



#endif /* __smbd_requ__hxx__ */

