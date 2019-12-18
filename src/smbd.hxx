
#ifndef __smbd__hxx__
#define __smbd__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/evtmgmt.hxx"
#include "include/wbpool.hxx"
#include <vector>
#include <memory>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "smbconf.hxx"
#include "nttime.hxx"
extern "C" {
#include "samba/libcli/smb/smb_constants.h"
#include "samba/libcli/smb/smb2_constants.h"
#include "samba/libcli/util/ntstatus.h"
#include "samba/lib/util/byteorder.h"
#include "samba/source4/heimdal/lib/gssapi/gssapi/gssapi.h"
}

#define GENSEC_FEATURE_SESSION_KEY	0x00000001
#define GENSEC_FEATURE_SIGN		0x00000002
#define GENSEC_FEATURE_SEAL		0x00000004
#define GENSEC_FEATURE_DCE_STYLE	0x00000008
#define GENSEC_FEATURE_ASYNC_REPLIES	0x00000010
#define GENSEC_FEATURE_DATAGRAM_MODE	0x00000020
#define GENSEC_FEATURE_SIGN_PKT_HEADER	0x00000040
#define GENSEC_FEATURE_NEW_SPNEGO	0x00000080
#define GENSEC_FEATURE_UNIX_TOKEN	0x00000100
#define GENSEC_FEATURE_NTLM_CCACHE	0x00000200
#define GENSEC_FEATURE_LDAP_STYLE	0x00000400

#define GENSEC_EXPIRE_TIME_INFINITY (NTTIME)0x8000000000000000LL

#define X_NT_STATUS_INTERNAL_BLOCKED	NT_STATUS(1)

struct x_smbsess_t;
struct x_gensec_context_t;

struct x_gensec_t;
struct x_gensec_upcall_t;
struct x_gensec_cbs_t
{
	void (*updated)(x_gensec_upcall_t *upcall, NTSTATUS status);
};

struct x_gensec_upcall_t
{
	const x_gensec_cbs_t *cbs;
	void updated(NTSTATUS status) {
		cbs->updated(this, status);
	}
};

struct x_gensec_ops_t
{
	NTSTATUS (*update)(x_gensec_t *gensec, const uint8_t *in_buf, size_t in_len,
			std::vector<uint8_t> &out, x_gensec_upcall_t *upcall);
	void (*destroy)(x_gensec_t *gensec);
	bool (*have_feature)(x_gensec_t *gensec, uint32_t feature);
	NTSTATUS (*check_packet)(x_gensec_t *gensec, const uint8_t *data, size_t data_len,
			const uint8_t *sig, size_t sig_len);
	NTSTATUS (*sign_packet)(x_gensec_t *gensec, const uint8_t *data, size_t data_len,
			std::vector<uint8_t> &sig);
};

struct x_gensec_t
{
	explicit x_gensec_t(x_gensec_context_t *context, const x_gensec_ops_t *ops)
		: context(context), ops(ops) { }

	NTSTATUS update(const uint8_t *in_buf, size_t in_len,
			std::vector<uint8_t> &out, x_gensec_upcall_t *upcall) {
		return ops->update(this, in_buf, in_len, out, upcall);
	}

	bool have_feature(uint32_t feature) {
		return ops->have_feature(this, feature);
	}

	NTSTATUS check_packet(const uint8_t *data, size_t data_len,
			const uint8_t *sig, size_t sig_len) {
		return ops->check_packet(this, data, data_len, sig, sig_len);
	}

	NTSTATUS sign_packet(const uint8_t *data, size_t data_len,
			std::vector<uint8_t> &sig) {
		return ops->sign_packet(this, data, data_len, sig);
	}

	x_gensec_context_t * const context;
	const x_gensec_ops_t * const ops;
};

static inline void x_gensec_destroy(x_gensec_t *gensec) {
	return gensec->ops->destroy(gensec);
}

struct x_gensec_mech_t
{
	gss_const_OID oid;
	x_gensec_t *(*create)(x_gensec_context_t *context);
};


struct x_smbconf_t
{
	x_smbconf_t() {
		strcpy((char *)guid, "rio-svr1");
	}
	std::vector<uint16_t> dialects{0x302, 0x210, 0x202};
	// std::vector<uint16_t> dialects{0x201};
	size_t max_trans = 1024 * 1024;
	size_t max_read = 1024 * 1024;
	size_t max_write = 1024 * 1024;
	uint8_t guid[16];
};

struct x_smbsrv_t
{
	x_epoll_upcall_t upcall;
	uint64_t ep_id;
	int fd;

	x_smbconf_t conf;

	x_gensec_context_t *gensec_context;
	std::vector<uint8_t> negprot_spnego;
};

struct x_msg_t
{
	explicit x_msg_t(size_t nbt_hdr) : nbt_hdr(nbt_hdr) {
		in_buf = new uint8_t[nbt_hdr & 0xffffff];
	}
	~x_msg_t() {
		if (in_buf) {
			delete[] in_buf;
		}
		if (out_buf) {
			delete[] out_buf;
		}
	}
	x_dlink_t dlink;
	uint64_t mid;
	uint16_t opcode;
	const uint32_t nbt_hdr;
	enum {
		STATE_READING,
		STATE_PROCESSING,
		STATE_COMPLETE,
		STATE_ABORT,
	} state = STATE_READING;
	unsigned int in_len = 0;
	unsigned int in_off;
	uint8_t *in_buf;
	unsigned int out_len = 0;
	unsigned int out_off;
	uint8_t *out_buf = NULL;
};
X_DECLARE_MEMBER_TRAITS(msg_dlink_traits, x_msg_t, dlink)

struct x_smbuser_t
{
	// security token
};

struct x_smbconn_t;
struct x_smbsess_t
{
	~x_smbsess_t() {
		if (gensec) {
			x_gensec_destroy(gensec);
		}
	}
	x_gensec_upcall_t gensec_upcall;
	x_smbconn_t *smbconn;
	uint64_t id;
	bool is_blocked = false;
	std::shared_ptr<x_smbuser_t> user;
	x_gensec_t *gensec{nullptr};
};
using x_smbsess_ptr_t = std::shared_ptr<x_smbsess_t>;

struct x_smbconn_t
{
	enum { MAX_MSG = 4 };
	x_smbconn_t(x_smbsrv_t *smbsrv, int fd_, const struct sockaddr_in &sin_)
		: smbsrv(smbsrv), fd(fd_), sin(sin_) { }
	~x_smbconn_t() {
		if (recving_msg) {
			delete recving_msg;
		}
		if (sending_msg) {
			delete sending_msg;
		}
		while (!send_queue.empty()) {
			x_msg_t *msg = send_queue.get_front();
			send_queue.remove(msg);
			delete msg;
		}
		X_ASSERT_SYSCALL(close(fd));
	}

	const x_smbconf_t &get_conf() const {
		return smbsrv->conf;
	}

	void incref() {
		X_ASSERT(refcnt++ > 0);
	}

	void decref() {
		if (--refcnt == 0) {
			delete this;
		}
	}

	x_epoll_upcall_t upcall;
	uint64_t ep_id;
	x_smbsrv_t * const smbsrv;
	std::atomic<int> refcnt{1};
	enum { STATE_RUNNING, STATE_DONE } state{STATE_RUNNING};
	int fd;
	unsigned int count_msg = 0;
	uint16_t dialect;
	const struct sockaddr_in sin;

	uint64_t credit_seq_low = 0;
	uint64_t credit_seq_range = 1;
	uint64_t credit_granted = 1;
	uint64_t credit_max = lp_smb2_max_credits();
	// xconn->smb2.credits.bitmap = bitmap_talloc(xconn, xconn->smb2.credits.max);
	uint32_t read_length = 0;
	uint32_t nbt_hdr;
	x_msg_t *recving_msg = NULL;
	x_msg_t *sending_msg = NULL;
	x_tp_d2list_t<msg_dlink_traits> send_queue;
	// TODO improve session lookup later
	std::vector<x_smbsess_ptr_t> sessions;
};

int x_gensec_spnego_init(x_gensec_context_t *context);
x_gensec_t *x_gensec_create_ntlmssp(x_gensec_context_t *context);
int x_gensec_ntlmssp_init(x_gensec_context_t *context);
x_gensec_t *x_gensec_create_krb5(x_gensec_context_t *context);
int x_gensec_krb5_init(x_gensec_context_t *context);

x_gensec_context_t *x_gensec_create_context();
x_gensec_t *x_gensec_create_by_oid(x_gensec_context_t *context, gss_const_OID oid);
int x_gensec_register(x_gensec_context_t *context, const x_gensec_mech_t *mech);

extern const x_gensec_mech_t x_gensec_mech_spnego;

x_gensec_t *x_smbsrv_create_gensec(x_smbsrv_t *smbsrv);

void x_smbconn_reply(x_smbconn_t *smbconn, x_msg_t *msg);
int x_smb2_reply_error(x_smbconn_t *smbconn, x_msg_t *msg,
		uint32_t status);

int x_smbconn_process_smb1negoprot(x_smbconn_t *smbconn, x_msg_t *msg,
		const uint8_t *buf, size_t len);
int x_smb2_process_NEGPROT(x_smbconn_t *smbconn, x_msg_t *msg,
		const uint8_t *in_buf, size_t in_len);
int x_smb2_process_SESSSETUP(x_smbconn_t *smbconn, x_msg_t *msg,
		const uint8_t *in_buf, size_t in_len);

void x_smbsess_auth_failed(x_smbsess_t *smbsess);

void x_smbsrv_wbpool_request(x_wbcli_t *wbcli);

#endif /* __smbd__hxx__ */

