
#ifndef __smbd_sess__hxx__
#define __smbd_sess__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

struct x_smbd_channel_t
{
struct x_smbd_sess_t
{
	static std::atomic<int> count;
	explicit x_smbd_sess_t(x_smbd_conn_t *smbd_conn);
	~x_smbd_sess_t();
	void incref() {
		X_ASSERT(refcnt++ > 0);
	}

	void decref() {
		if (unlikely(--refcnt == 0)) {
			delete this;
		}
	}
#if 0
	enum {
		SF_PROCESSING = 1,
		SF_WAITINPUT = 1 << 1,
		SF_ACTIVE = 1 << 2,
		SF_BLOCKED = 1 << 3,
		SF_FAILED = 1 << 4,
		SF_EXPIRED = 1 << 5,
		SF_SHUTDOWN = 1 << 6,
	};
#endif
	enum {
		S_PROCESSING,
		S_WAIT_INPUT,
		S_ACTIVE,
		S_BLOCKED,
		S_FAILED,
		S_EXPIRED,
		S_SHUTDOWN,
	};

	x_dqlink_t hash_link;
	x_dlink_t conn_link;

	x_auth_upcall_t auth_upcall;

	x_smbd_conn_t *smbd_conn;
	uint64_t id;
	x_tick_t timeout;
	std::atomic<uint32_t> state{S_PROCESSING};
	std::atomic<int> refcnt;
	std::mutex mutex;
	// uint16_t security_mode = 0;
	bool signing_required = false;
	std::shared_ptr<x_smbd_user_t> smbd_user;
	x_auth_t *auth{nullptr};
	x_auto_ref_t<x_smbd_requ_t> authmsg;

	x_smb2_preauth_t preauth;
	x_smb2_key_t signing_key, decryption_key, encryption_key, application_key;

	x_tp_ddlist_t<tcon_sess_traits> tcon_list;
};
X_DECLARE_MEMBER_TRAITS(smbd_sess_conn_traits, x_smbd_sess_t, conn_link)



#endif /* __smbd_sess__hxx__ */

