
#include "defines.hxx"
#include <atomic>
#include <memory>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <vector>

#include "genref.hxx"
#include "smb_consts.h"
#include "smbconf.hxx"
#include "nttime.hxx"
#include "core.hxx"
#include "network.hxx"
#include "gensec.hxx"
#include "samba/libcli/util/ntstatus.h"
#include "smb2.hxx"

#if 0
static const uint8_t spnego[] = {
	0x60, 0x5e, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 0xa0, 0x54, 0x30, 0x52, 0xa0, 0x24,
	0x30, 0x22, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x06, 0x09, 0x2a,
	0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82,
	0x37, 0x02, 0x02, 0x0a, 0xa3, 0x2a, 0x30, 0x28, 0xa0, 0x26, 0x1b, 0x24, 0x6e, 0x6f, 0x74, 0x5f,
	0x64, 0x65, 0x66, 0x69, 0x6e, 0x65, 0x64, 0x5f, 0x69, 0x6e, 0x5f, 0x52, 0x46, 0x43, 0x34, 0x31,
	0x37, 0x38, 0x40, 0x70, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x5f, 0x69, 0x67, 0x6e, 0x6f, 0x72, 0x65,
};

static std::pair<const uint8_t *, size_t> get_spnego()
{
	return std::make_pair(spnego, sizeof(spnego));
}
#endif

enum {
#define X_SMB2_OP_DECL(x) X_SMB2_OP_##x,
	X_SMB2_OP_ENUM
#undef X_SMB2_OP_DECL
	X_SMB2_OP_MAX
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

static struct {
	bool do_async = false;
	threadpool_t *tpool;
	epollmgmt_t *epmgmt;
} globals;


static void main_loop()
{
	snprintf(task_name, sizeof task_name, "MAIN");
	for (;;) {
		epollmgmt_dispatch(globals.epmgmt);
	}
}

struct x_smbsrv_t
{
	epoll_upcall_t upcall;
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
	dlink_t dlink;
	uint64_t mid;
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
YAPL_DECLARE_MEMBER_TRAITS(msg_dlink_traits, x_msg_t, dlink)

static x_msg_t *x_msg_create(size_t size)
{
	x_msg_t *msg = new x_msg_t(size);
	return msg;
}

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

	epoll_upcall_t upcall;
	uint64_t ep_id;
	x_smbsrv_t * const smbsrv;
	std::atomic<int> refcnt{1};
	enum { STATE_RUNNING, STATE_DONE } state{STATE_RUNNING};
	int fd;
	unsigned int count_msg = 0;
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
	tp_d2list_t<msg_dlink_traits> send_queue;
};

static void x_smbconn_done(x_smbconn_t *smbconn)
{
	smbconn->state = x_smbconn_t::STATE_DONE;
	smbconn->decref();
}

static void x_smbconn_reply(x_smbconn_t *smbconn, x_msg_t *msg)
{
	if (msg->state == x_msg_t::STATE_COMPLETE) {
		bool orig_empty = smbconn->send_queue.empty();
		smbconn->send_queue.push_back(msg);
		if (orig_empty) {
			epollmgmt_enable_events(globals.epmgmt, smbconn->ep_id, FDEVT_OUT);
		}
	} else {
		delete msg;
		X_ASSERT(smbconn->count_msg-- > 0);
	}
}

#define MAX_MSG_SIZE 0x1000000
#define SMB_MAGIC 0x424D53FF /* 0xFF 'S' 'M' 'B' */
#define SMB2_MAGIC 0x424D53FE /* 0xFE 'S' 'M' 'B' */
#define SMB2_TF_MAGIC 0x424D53FD /* 0xFD 'S' 'M' 'B' */

static int x_smb2_reply_error(x_smbconn_t *smbconn, x_msg_t *msg,
		uint32_t status)
{
	uint8_t *outbuf = new uint8_t[8 + 0x40 + 9];
	uint8_t *outhdr = outbuf + 8;
	uint8_t *outbody = outhdr + 0x40;

	memset(outhdr, 0, 0x40 + 9);

	x_put_le16(outbody, 0x9);
	x_put_le32(outhdr + SMB2_HDR_PROTOCOL_ID, SMB2_MAGIC);
	x_put_le16(outhdr + SMB2_HDR_LENGTH,  SMB2_HDR_BODY);
	x_put_le16(outhdr + SMB2_HDR_CREDIT_CHARGE,  0);
	x_put_le32(outhdr + SMB2_HDR_STATUS, status);
	x_put_le16(outhdr + SMB2_HDR_OPCODE, SMB2_OP_NEGPROT);
	x_put_le16(outhdr + SMB2_HDR_CREDIT, 1);
	x_put_le32(outhdr + SMB2_HDR_FLAGS, SMB2_HDR_FLAG_REDIRECT);
	x_put_le32(outhdr + SMB2_HDR_NEXT_COMMAND, 0);
	x_put_le64(outhdr + SMB2_HDR_MESSAGE_ID, msg->mid);

	uint8_t *outnbt = outbuf + 4;
	put_be32(outnbt, 0x40 + 9);

	msg->out_buf = outbuf;
	msg->out_off = 4;
	msg->out_len = 4 + 0x40 + 9;

	msg->state = x_msg_t::STATE_COMPLETE;
	x_smbconn_reply(smbconn, msg);
	return 0;
}

static int x_smbconn_reply_negprot(x_smbconn_t *smbconn, x_msg_t *msg,
		uint16_t dialect,
		const std::vector<std::pair<const uint8_t *, size_t>> &negotiate_context)
{
	const x_smbsrv_t *smbsrv = smbconn->smbsrv;
	const x_smbconf_t &conf = smbconn->get_conf();
	nttime_t now = nttime_current();

	uint16_t security_mode = SMB2_NEGOTIATE_SIGNING_ENABLED;
	uint32_t capabilities = SMB2_CAP_DFS | SMB2_CAP_LARGE_MTU | SMB2_CAP_LEASING;

	uint16_t negotiate_context_off = 0;
	const std::vector<uint8_t> &security_blob = smbsrv->negprot_spnego;
	size_t dyn_len = security_blob.size();
	if (negotiate_context.size() != 0) {
		dyn_len = negotiate_context_off = x_pad_len(security_blob.size(), 8);
		for (auto &nc: negotiate_context) {
			dyn_len += nc.second;
		}
	}

	uint8_t *outbuf = new uint8_t[8 + 0x40 + 0x40 + dyn_len];
	uint8_t *outhdr = outbuf + 8;
	uint8_t *outbody = outhdr + 0x40;

	x_put_le16(outbody, 0x41);
	x_put_le16(outbody + 2, security_mode);
	x_put_le16(outbody + 4, dialect);
	x_put_le16(outbody + 6, negotiate_context.size());
	memcpy(outbody + 8, conf.guid, 16);
	x_put_le32(outbody + 0x18, capabilities);
	x_put_le32(outbody + 0x1c, conf.max_trans);
	x_put_le32(outbody + 0x20, conf.max_read);
	x_put_le32(outbody + 0x24, conf.max_write);

	x_put_le64(outbody + 0x28, now);         /* system time */
	x_put_le64(outbody + 0x30, 0);           /* server start time */

	size_t security_offset = SMB2_HDR_BODY + 0x40;

	x_put_le16(outbody + 0x38, security_offset);
	x_put_le16(outbody + 0x3a, security_blob.size());

	x_put_le32(outbody + 0x3c, negotiate_context_off);
	uint8_t *outdyn = outbody + 0x40;
	size_t dyn_off = 0;
	if (security_blob.size()) {
		memcpy(outdyn, security_blob.data(), security_blob.size());
		dyn_off += security_blob.size();
	}

	if (negotiate_context.size() != 0) {
		size_t padlen = x_pad_len(dyn_off, 8);
		memset(outdyn + dyn_off, 0, padlen - dyn_off);
		dyn_off += padlen - dyn_off;
	}
	for (auto &nc: negotiate_context) {
		memcpy(outdyn + dyn_off, nc.first, nc.second);
		dyn_off += nc.second;
	}

	// smbd_smb2_request_done_ex
	memset(outhdr, 0, 0x40);
	x_put_le32(outhdr + SMB2_HDR_PROTOCOL_ID, SMB2_MAGIC);
	x_put_le16(outhdr + SMB2_HDR_LENGTH,  SMB2_HDR_BODY);
	x_put_le16(outhdr + SMB2_HDR_CREDIT_CHARGE,  0);
	x_put_le32(outhdr + SMB2_HDR_STATUS, 0);
	x_put_le16(outhdr + SMB2_HDR_OPCODE, SMB2_OP_NEGPROT);
	x_put_le16(outhdr + SMB2_HDR_CREDIT, 1);
	x_put_le32(outhdr + SMB2_HDR_FLAGS, SMB2_HDR_FLAG_REDIRECT);
	x_put_le32(outhdr + SMB2_HDR_NEXT_COMMAND, 0);
	x_put_le64(outhdr + SMB2_HDR_MESSAGE_ID, msg->mid);

	uint8_t *outnbt = outbuf + 4;
	put_be32(outnbt, 0x80 + dyn_off);

	msg->out_buf = outbuf;
	msg->out_off = 4;
	msg->out_len = 4 + 0x80 + dyn_off;

	msg->state = x_msg_t::STATE_COMPLETE;
	x_smbconn_reply(smbconn, msg);
	return 0;
}


#define HDR_WCT 32u
#define HDR_VWV 33u
static int x_smbconn_process_smb1negoprot(x_smbconn_t *smbconn, x_msg_t *msg,
		const uint8_t *buf, size_t len)
{
	uint8_t wct = buf[HDR_WCT];
	uint16_t vwv = buf[HDR_VWV] + (buf[HDR_VWV + 1] << 8);
	if (len < HDR_WCT + 2 *wct + vwv) {
		return -EBADMSG;
	}
	if (vwv == 0) {
		// TODO reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return -EBADMSG;
	}
	const uint8_t *negobuf = buf + HDR_WCT + 3 + 2 * wct;
	if (negobuf[vwv - 1] != '\0') {
		// TODO reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return -EBADMSG;
	}
	// const uint8_t *p = negobuf + 1;
	// TODO check if support smb2
	

	return x_smbconn_reply_negprot(smbconn, msg, 0x2ff, {});
}

#define SMB2_DIALECT_INVALID       0x0222
#define SMB2_DIALECT_REVISION_202       0x0202
#define SMB2_DIALECT_REVISION_210       0x0210
#define SMB2_DIALECT_REVISION_222       0x0222
#define SMB2_DIALECT_REVISION_224       0x0224
#define SMB3_DIALECT_REVISION_300       0x0300
#define SMB3_DIALECT_REVISION_302       0x0302
#define SMB3_DIALECT_REVISION_310       0x0310
#define SMB3_DIALECT_REVISION_311       0x0311

static uint16_t x_smb2_dialect_match(x_smbconn_t *smbconn,
		const uint8_t *in_dyn,
		size_t dialect_count)
{
	const x_smbconf_t &smbconf = smbconn->get_conf();
	for (auto sdialect: smbconf.dialects) {
		for (unsigned int di = 0; di < dialect_count; ++di) {
			uint16_t cdialect = x_get_le16(in_dyn + di * 2);
			if (sdialect == cdialect) {
				return sdialect;
			}
		}
	}
	return SMB2_DIALECT_INVALID;
}

enum { SMB2_NEGPROT_BODY_LEN = 0x24, };
static int x_smb2_process_NEGPROT(x_smbconn_t *smbconn, x_msg_t *msg,
		const uint8_t *in_buf, size_t in_len)
{
	// x_smb2_verify_size(msg, X_SMB2_NEGPROT_BODY_LEN);
	if (in_len < 0x40 + 0x24) {
		return -EBADMSG;
	}

	const uint8_t *in_body = in_buf + 0x40;
	uint16_t dialect_count = x_get_le16(in_body + 0x2);
	if (dialect_count == 0) {
		return x_smb2_reply_error(smbconn, msg, NT_STATUS_INVALID_PARAMETER);
	}
	size_t dyn_len = in_len - SMB2_HDR_LENGTH - SMB2_NEGPROT_BODY_LEN;
	if (dialect_count * 2 > dyn_len) {
		return x_smb2_reply_error(smbconn, msg, NT_STATUS_INVALID_PARAMETER);
	}

	// TODO uint16_t in_security_mode = x_get_le16(in_body + 0x04);
	// TODO uint32_t in_capabilities = x_get_le32(in_body + 0x08);

	const uint8_t *in_dyn = in_body + SMB2_NEGPROT_BODY_LEN;
	uint16_t dialect = x_smb2_dialect_match(smbconn, in_dyn, dialect_count);
	if (dialect == SMB2_DIALECT_INVALID) {
		return x_smb2_reply_error(smbconn, msg, NT_STATUS_NOT_SUPPORTED);
	}
#if 0
	if (dialect >= SMB2_DIALECT_310) {
		// TODO preauth
		X_ASSERT(false);
	}
#endif
	return x_smbconn_reply_negprot(smbconn, msg, dialect, {});
}

static int x_smb2_process_SESSSETUP(x_smbconn_t *smbconn, x_msg_t *msg,
		const uint8_t *in_buf, size_t in_len)
{
	return -1;
}

static const struct {
	int (*op_func)(x_smbconn_t *cli, x_msg_t *msg, const uint8_t *in_buf, size_t in_len);
} x_smb2_op_table[] = {
#define X_SMB2_OP_DECL(X) { x_smb2_process_##X },
	X_SMB2_OP_ENUM
#undef X_SMB2_OP_DECL
};


static int x_smbconn_process_smb2(x_smbconn_t *smbconn, x_msg_t *msg)
{

	const uint8_t *in_buf = msg->in_buf;
	unsigned int in_len = msg->in_len;
	if (in_len < 0x40) {
		return -EBADMSG;
	}
	uint16_t opcode = x_get_le16(in_buf + SMB2_HDR_OPCODE);
	if (opcode >= X_SMB2_OP_MAX) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	msg->mid = x_get_le64(in_buf + SMB2_HDR_MESSAGE_ID);
	return x_smb2_op_table[opcode].op_func(smbconn, msg, in_buf, in_len);
}

static int x_smbconn_process_smb(x_smbconn_t *smbconn, x_msg_t *msg)
{
	uint32_t offset = 0;
	for (; offset < msg->in_len;) {
		size_t len = msg->in_len - offset;
		if (len < 4) {
			return -EBADMSG;
		}
		uint32_t smbhdr;
		memcpy(&smbhdr, msg->in_buf + offset, sizeof smbhdr);
		if (smbhdr == SMB2_MAGIC) {
			return x_smbconn_process_smb2(smbconn, msg);
		} else if (smbhdr == SMB_MAGIC) {
			if (len < 35) { // TODO 
				return -EBADMSG;
			}
			uint8_t cmd = msg->in_buf[4];
			if (/* TODO smbconn->is_negotiated || */cmd != SMBnegprot) {
				return -EBADMSG;
			}
			msg->mid = 0; // TODO
			return x_smbconn_process_smb1negoprot(smbconn, msg, msg->in_buf, msg->in_len);
		}
	}
	return 0;
}

static int x_smbconn_process_msg(x_smbconn_t *smbconn)
{
	x_msg_t *msg = smbconn->recving_msg;
	X_ASSERT(msg);
	smbconn->recving_msg = NULL;
	int err;

	if ((msg->nbt_hdr >> 24) == NBSSmessage) {
		err = x_smbconn_process_smb(smbconn, msg);
	} else {
		X_TODO;
		err = -EINVAL;
	}
	return err;
}

static inline x_smbconn_t *x_smbconn_from_upcall(epoll_upcall_t *upcall)
{
	return YAPL_CONTAINER_OF(upcall, x_smbconn_t, upcall);
}

static bool x_smbconn_do_recv(x_smbconn_t *smbconn, x_fdevents_t &fdevents)
{
	int err;
	X_DBG("%s %p x%llx", task_name, smbconn, fdevents);
	if (smbconn->recving_msg == NULL) {
		assert(smbconn->read_length < sizeof(smbconn->nbt_hdr));
		err = read(smbconn->fd, &smbconn->nbt_hdr, sizeof(smbconn->nbt_hdr) - smbconn->read_length);
		if (err > 0) {
			smbconn->read_length += err;
			if (smbconn->read_length == sizeof(smbconn->nbt_hdr)) {
				smbconn->read_length = 0;
				smbconn->nbt_hdr = ntohl(smbconn->nbt_hdr);
				uint8_t msgtype = smbconn->nbt_hdr >> 24;
				if (msgtype == NBSSmessage) {
					uint32_t msgsize = smbconn->nbt_hdr & 0xffffff;
					if (msgsize >= MAX_MSG_SIZE) {
						return true;
					} else if (smbconn->nbt_hdr == 0) {
						return false;
					}
				} else {
					return true;
				}	
				smbconn->recving_msg = x_msg_create(smbconn->nbt_hdr);
				smbconn->count_msg++;
			}
		} else if (err == 0) {
			return true;
		} else if (errno == EAGAIN) {
			fdevents = x_fdevents_consume(fdevents, FDEVT_IN);
			return false;
		} else {
			return errno != EINTR;
		}
	}

	// TODO only NBSSmessage, nbt_hdr is the size
	err = read(smbconn->fd, smbconn->recving_msg->in_buf + smbconn->read_length,
			smbconn->nbt_hdr - smbconn->read_length);
	if (err > 0) {
		smbconn->read_length += err;
		if (smbconn->read_length == smbconn->nbt_hdr) {
			smbconn->recving_msg->in_len = smbconn->nbt_hdr;
			smbconn->read_length = 0;
			return x_smbconn_process_msg(smbconn) != 0;
		}
	} else if (err == 0) {
		return true;
	} else if (errno == EAGAIN) {
		fdevents = x_fdevents_consume(fdevents, FDEVT_IN);
	} else {
		return errno != EINTR;
	}
	return false;
}

static bool x_smbconn_do_send(x_smbconn_t *smbconn, x_fdevents_t &fdevents)
{
	x_msg_t *msg;
	X_DBG("%s %p x%llx", task_name, smbconn, fdevents);
	for (;;) {
		msg = smbconn->sending_msg;
		if (msg == NULL) {
			msg = smbconn->send_queue.get_front();
			if (msg == NULL) {
				break;
			}
			smbconn->send_queue.remove(msg);
			// TODO msg_encode(msg);
			smbconn->sending_msg = msg;
		}
		X_ASSERT(msg->out_len > 0);
		int err = write(smbconn->fd, msg->out_buf + msg->out_off, msg->out_len);
		if (err > 0) {
			msg->out_len -= err;
			if (msg->out_len == 0) {
				delete msg;
				smbconn->count_msg--;
				smbconn->sending_msg = NULL;
			} else {
				msg->out_off += err;
			}
		} else {
			X_ASSERT(err != 0);
			if (errno == EAGAIN) {
				fdevents = x_fdevents_consume(fdevents, FDEVT_OUT);
				break;
			} else if (errno == EINTR) {
			} else {
				return true;
			}
		}
	}
	if (msg == NULL) {
		fdevents = x_fdevents_disable(fdevents, FDEVT_OUT);
	}
	if (smbconn->count_msg < x_smbconn_t::MAX_MSG) {
		fdevents = x_fdevents_enable(fdevents, FDEVT_IN);
	}
	return false;
}

static bool x_smbconn_handle_events(x_smbconn_t *smbconn, x_fdevents_t &fdevents)
{
	uint32_t events = x_fdevents_processable(fdevents);
	if (events & FDEVT_IN) {
		if (x_smbconn_do_recv(smbconn, fdevents)) {
			return true;
		}
	}
	events = x_fdevents_processable(fdevents);
	if (events & FDEVT_OUT) {
		return x_smbconn_do_send(smbconn, fdevents);
	}
	return false;
}

static bool x_smbconn_upcall_cb_getevents(epoll_upcall_t *upcall, x_fdevents_t &fdevents)
{
	x_smbconn_t *smbconn = x_smbconn_from_upcall(upcall);
	X_DBG("%s %p x%llx", task_name, smbconn, fdevents);

	bool ret = x_smbconn_handle_events(smbconn, fdevents);
	return ret;
}

static void x_smbconn_upcall_cb_unmonitor(epoll_upcall_t *upcall)
{
	x_smbconn_t *smbconn = x_smbconn_from_upcall(upcall);
	X_DBG("%s %p", task_name, smbconn);
	x_smbconn_done(smbconn);
}

static const epoll_upcall_cbs_t x_smbconn_upcall_cbs = {
	x_smbconn_upcall_cb_getevents,
	x_smbconn_upcall_cb_unmonitor,
};

static void x_smbsrv_accepted(x_smbsrv_t *smbsrv, int fd, const struct sockaddr_in &sin)
{
	set_nbio(fd, 1);
	x_smbconn_t *smbconn = new x_smbconn_t(smbsrv, fd, sin);
	X_ASSERT(smbconn != NULL);
	smbconn->upcall.cbs = &x_smbconn_upcall_cbs;
	smbconn->ep_id = epollmgmt_monitor(globals.epmgmt, fd, FDEVT_IN | FDEVT_OUT, &smbconn->upcall);
	epollmgmt_enable_events(globals.epmgmt, smbconn->ep_id, FDEVT_IN | FDEVT_ERR | FDEVT_SHUTDOWN);
}

static inline x_smbsrv_t *x_smbsrv_from_upcall(epoll_upcall_t *upcall)
{
	return YAPL_CONTAINER_OF(upcall, x_smbsrv_t, upcall);
}

static bool x_smbsrv_upcall_cb_getevents(epoll_upcall_t *upcall, x_fdevents_t &fdevents)
{
	x_smbsrv_t *smbsrv = x_smbsrv_from_upcall(upcall);
	uint32_t events = x_fdevents_processable(fdevents);

	if (events & FDEVT_IN) {
		struct sockaddr_in sin;
		socklen_t slen = sizeof(sin);
		int fd = accept(smbsrv->fd, (struct sockaddr *)&sin, &slen);
		X_DBG("%s accept %d, %d", task_name, fd, errno);
		if (fd >= 0) {
			x_smbsrv_accepted(smbsrv, fd, sin);
		} else if (errno == EINTR) {
		} else if (errno == EMFILE) {
		} else if (errno == EAGAIN) {
			fdevents = x_fdevents_consume(fdevents, FDEVT_IN);
		} else {
			X_PANIC("accept errno=", errno);
		}
	}
	return false;
}

static void x_smbsrv_upcall_cb_unmonitor(epoll_upcall_t *upcall)
{
	x_smbsrv_t *smbsrv = x_smbsrv_from_upcall(upcall);
	X_DBG("%s %p", task_name, smbsrv);
	X_ASSERT_SYSCALL(close(smbsrv->fd));
	/* TODO may close all accepted client, and notify it is freed */
}

static const epoll_upcall_cbs_t x_smbsrv_upcall_cbs = {
	x_smbsrv_upcall_cb_getevents,
	x_smbsrv_upcall_cb_unmonitor,
};

static void x_smbsrv_init(x_smbsrv_t &smbsrv, int port)
{
	int fd = tcplisten(port);
	assert(fd >= 0);

	smbsrv.fd = fd;
	smbsrv.upcall.cbs = &x_smbsrv_upcall_cbs;

	smbsrv.ep_id = epollmgmt_monitor(globals.epmgmt, fd, FDEVT_IN, &smbsrv.upcall);
	epollmgmt_enable_events(globals.epmgmt, smbsrv.ep_id, FDEVT_IN | FDEVT_ERR | FDEVT_SHUTDOWN);

	smbsrv.gensec_context = x_gensec_create_context();
	x_gensec_register(smbsrv.gensec_context, &x_gensec_mech_spnego);

	x_gensec_t *spnego = x_gensec_create_by_oid(smbsrv.gensec_context, OID_SPNEGO);
	if (spnego) {
		std::vector<uint8_t> negprot_spnego;
		int err = spnego->update(NULL, 0, negprot_spnego);
		X_ASSERT(err == 0);
		smbsrv.negprot_spnego.swap(negprot_spnego);
	}
}

int main(int argc, char **argv)
{
	argv++;
	unsigned int count = atoi(*argv);
	int port = 445;

	threadpool_t *tpool = threadpool_create(count);
	globals.tpool = tpool;

	globals.epmgmt = epollmgmt_create(tpool);

	x_smbsrv_t smbsrv;
	x_smbsrv_init(smbsrv, port);


	main_loop();

	threadpool_destroy(tpool);
	return 0;
}

