
#include "smbd.hxx"
#include "smbd_stats.hxx"
#include "smbd_conf.hxx"
extern "C" {
#include "samba/include/config.h"
#include "samba/lib/crypto/sha512.h"
}

enum {
	MAX_MSG_SIZE = 0x1000000,
};

enum {
#define X_SMB2_OP_DECL(x) X_SMB2_OP_##x,
	X_SMB2_OP_ENUM
#undef X_SMB2_OP_DECL
	X_SMB2_OP_MAX
};

struct x_smbd_srv_t
{
	x_epoll_upcall_t upcall;
	uint64_t ep_id;
	int fd;
};

struct x_smbd_conn_t
{
	enum { MAX_MSG = 4 };
	enum state_t { STATE_RUNNING, STATE_DONE };
	x_smbd_conn_t(int fd, const x_sockaddr_t &saddr, uint32_t max_credits);
	~x_smbd_conn_t();
	x_epoll_upcall_t upcall;
	uint64_t ep_id;
	std::mutex mutex;
	std::atomic<int> refcnt{1};
	std::atomic<state_t> state{STATE_RUNNING};
	int fd;
	unsigned int count_msg = 0;
	const x_sockaddr_t saddr;
	uint16_t cipher = 0;
	uint16_t dialect = SMB2_DIALECT_REVISION_000;

	uint16_t server_security_mode;
	uint16_t client_security_mode;
	uint32_t server_capabilities;
	uint32_t client_capabilities;

	x_smb2_uuid_t client_guid;

	uint64_t credit_seq_low = 0;
	uint64_t credit_seq_range = 1;
	uint64_t credit_granted = 1;
	std::vector<bool> seq_bitmap;
	// xconn->smb2.credits.bitmap = bitmap_talloc(xconn, xconn->smb2.credits.max);
	x_smb2_preauth_t preauth;

	uint32_t nbt_hdr;
	uint32_t recv_len = 0;
	x_buf_t *recv_buf{};
	x_bufref_t *send_buf_head{}, *send_buf_tail{};

	x_ddlist_t chan_list;
	x_tp_ddlist_t<fdevt_user_conn_traits> fdevt_user_list;
};

x_smbd_conn_t::x_smbd_conn_t(int fd, const x_sockaddr_t &saddr,
		uint32_t max_credits)
	: fd(fd), saddr(saddr)
	, seq_bitmap(max_credits)
{
	X_SMBD_COUNTER_INC(conn_create, 1);
}

x_smbd_conn_t::~x_smbd_conn_t()
{
	X_LOG_DBG("x_smbd_conn_t %p destroy", this);
	X_ASSERT(!chan_list.get_front());
	X_ASSERT(fd == -1);

	if (recv_buf) {
		x_buf_release(recv_buf);
	}
	while (send_buf_head) {
		auto next = send_buf_head->next;
		delete send_buf_head;
		send_buf_head = next;
	}
	X_SMBD_COUNTER_INC(conn_delete, 1);
}

template <>
x_smbd_conn_t *x_smbd_ref_inc(x_smbd_conn_t *smbd_conn)
{
	X_ASSERT(smbd_conn->refcnt++ > 0);
	return smbd_conn;
}

template <>
void x_smbd_ref_dec(x_smbd_conn_t *smbd_conn)
{
	if (unlikely(--smbd_conn->refcnt == 0)) {
		delete smbd_conn;
	}
}

void x_smbd_conn_update_preauth(x_smbd_conn_t *smbd_conn,
		const void *data, size_t length)
{
	smbd_conn->preauth.update(data, length);
}

const x_smb2_preauth_t *x_smbd_conn_get_preauth(x_smbd_conn_t *smbd_conn)
{
	if (smbd_conn->dialect >= SMB3_DIALECT_REVISION_310) {
		return &smbd_conn->preauth;
	} else {
		return nullptr;
	}
}

uint16_t x_smbd_conn_get_dialect(const x_smbd_conn_t *smbd_conn)
{
	return smbd_conn->dialect;
}

uint32_t x_smbd_conn_get_capabilities(const x_smbd_conn_t *smbd_conn)
{
	return smbd_conn->server_capabilities;
}

int x_smbd_conn_negprot(x_smbd_conn_t *smbd_conn,
		uint16_t dialect,
		uint16_t cipher,
		uint16_t client_security_mode,
		uint16_t server_security_mode,
		uint32_t client_capabilities,
		uint32_t server_capabilities,
		const x_smb2_uuid_t &client_guid)
{
	if (smbd_conn->dialect != SMB2_DIALECT_REVISION_000 &&
			smbd_conn->dialect != SMB2_DIALECT_REVISION_2FF) {
		return -EBADMSG;
	}
	smbd_conn->dialect = dialect;
	smbd_conn->cipher = cipher;
	smbd_conn->client_security_mode = client_security_mode;
	smbd_conn->server_security_mode = server_security_mode;
	smbd_conn->client_capabilities = client_capabilities;
	smbd_conn->server_capabilities = server_capabilities;
	smbd_conn->client_guid = client_guid;
	return 0;
}

int x_smbd_conn_negprot_smb1(x_smbd_conn_t *smbd_conn)
{
	if (smbd_conn->dialect != SMB2_DIALECT_REVISION_000) {
		return -EBADMSG;
	}
	smbd_conn->dialect = SMB2_DIALECT_REVISION_2FF;
	return 0;
}

static void x_smbd_conn_queue(x_smbd_conn_t *smbd_conn, x_bufref_t *buf_head,
		x_bufref_t *buf_tail, uint32_t length)
{
	x_bufref_t *bufref = buf_head;
	X_ASSERT(bufref->buf->ref == 1);
	X_ASSERT(bufref->offset >= 4);

	bufref->offset -= 4;
	bufref->length += 4;
	uint8_t *outnbt = bufref->get_data();
	x_put_be32(outnbt, length);

	bool orig_empty = smbd_conn->send_buf_head == nullptr;
	if (orig_empty) {
		smbd_conn->send_buf_head = buf_head;
	} else {
		smbd_conn->send_buf_tail->next = buf_head;
	}
	smbd_conn->send_buf_tail = buf_tail;

	if (orig_empty) {
		x_evtmgmt_enable_events(g_evtmgmt, smbd_conn->ep_id, FDEVT_OUT);
	}
}

static void x_smbd_conn_queue(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	X_ASSERT(smbd_requ->out_buf_head);
	X_ASSERT(smbd_requ->out_length > 0);

	x_smbd_conn_queue(smbd_conn, smbd_requ->out_buf_head, smbd_requ->out_buf_tail,
			smbd_requ->out_length);

	smbd_requ->out_buf_head = smbd_requ->out_buf_tail = nullptr;
	smbd_requ->out_length = 0;
}

static uint16_t x_smb2_calculate_credit(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
		NTSTATUS status)
{
	uint64_t current_max_credits = smbd_conn->seq_bitmap.size() / 16;
	current_max_credits = std::max(current_max_credits, 1ul);

	uint16_t credit_charged = std::max(smbd_requ->in_credit_charge, uint16_t(1u));
	uint16_t credit_requested = std::max(smbd_requ->in_credit_requested, uint16_t(1u));
	
	/* already checked in process smb2 input */
	X_ASSERT(credit_charged < smbd_conn->seq_bitmap.size());

	// uint32_t additional_possible = smbd_conn->seq_bitmap.size() - credit_charged;
	uint32_t additional_credits = credit_requested - 1;
	uint32_t additional_max = 0;

	if (smbd_requ->opcode == SMB2_OP_NEGPROT) {
	} else if (smbd_requ->opcode == SMB2_OP_SESSSETUP) {
		if (NT_STATUS_IS_OK(status)) {
			additional_max = 32;
		}
	} else {
		additional_max = 32;
	}
	additional_credits = std::min(additional_credits, additional_max);
	uint64_t credit_granted = credit_charged + additional_credits;

	uint64_t credits_possible = UINT64_MAX - smbd_conn->credit_seq_low;
	if (credits_possible > 0) {
		--credits_possible;
	}
	credits_possible = std::min(credits_possible, current_max_credits);
	credits_possible -= smbd_conn->credit_seq_range;
	if (credit_granted > credits_possible) {
		credit_granted = credits_possible;
	}
	smbd_conn->credit_granted += credit_granted;
	smbd_conn->credit_seq_range += credit_granted;
	return x_convert_assert<uint16_t>(std::max(credit_granted, 0xfffful));
}

static uint32_t calculate_out_hdr_flags(uint32_t in_hdr_flags, uint32_t out_hdr_flags)
{
	// TODO should consider other flags?
	out_hdr_flags |= (in_hdr_flags & (SMB2_HDR_FLAG_PRIORITY_MASK));
	return out_hdr_flags;
}

void x_smbd_chan_sign(const x_smbd_chan_t *smbd_chan, uint16_t dialect,
		x_bufref_t *buflist);

static const x_smb2_key_t *get_signing_key(const x_smbd_requ_t *smbd_requ)
{
	const x_smb2_key_t *signing_key = nullptr;
	if (smbd_requ->smbd_chan) {
		signing_key = x_smbd_chan_get_signing_key(smbd_requ->smbd_chan);
	}
	if (!signing_key) {
		signing_key = x_smbd_sess_get_signing_key(smbd_requ->smbd_sess);
		// TODO signing_key is null?
	}
	return signing_key;
}

void x_smb2_reply(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		x_bufref_t *buf_head,
		x_bufref_t *buf_tail,
		NTSTATUS status,
		size_t reply_size)
{
	smbd_requ->out_credit_granted = x_smb2_calculate_credit(smbd_conn, smbd_requ, status);
	smbd_requ->out_hdr_flags = calculate_out_hdr_flags(smbd_requ->in_hdr_flags, smbd_requ->out_hdr_flags);
	uint8_t *out_hdr = buf_head->get_data();
	memset(out_hdr, 0, SMB2_HDR_BODY);
	x_put_be32(out_hdr + SMB2_HDR_PROTOCOL_ID, X_SMB2_MAGIC);
	SSVAL(out_hdr, SMB2_HDR_LENGTH, SMB2_HDR_BODY);
	SSVAL(out_hdr, SMB2_HDR_CREDIT_CHARGE, smbd_requ->in_credit_charge);
	SIVAL(out_hdr, SMB2_HDR_STATUS, NT_STATUS_V(status));
	SIVAL(out_hdr, SMB2_HDR_OPCODE, smbd_requ->opcode);
	SSVAL(out_hdr, SMB2_HDR_CREDIT, smbd_requ->out_credit_granted);
	SIVAL(out_hdr, SMB2_HDR_FLAGS, smbd_requ->out_hdr_flags | SMB2_HDR_FLAG_REDIRECT);
	if (smbd_requ->compound_followed) {
		// assume reply_size already pad to 8 when compound_followed
		SIVAL(out_hdr, SMB2_HDR_NEXT_COMMAND, reply_size);
	}
	SBVAL(out_hdr, SMB2_HDR_MESSAGE_ID, smbd_requ->in_mid);
	if (smbd_requ->async) {
		X_ASSERT(smbd_requ->async_id != 0);
		SIVAL(out_hdr, SMB2_HDR_FLAGS, smbd_requ->out_hdr_flags | SMB2_HDR_FLAG_REDIRECT | SMB2_HDR_FLAG_ASYNC);
		// we use mid as async_id
		SBVAL(out_hdr, SMB2_HDR_ASYNC_ID, smbd_requ->async_id);
	} else {
		SIVAL(out_hdr, SMB2_HDR_FLAGS, smbd_requ->out_hdr_flags | SMB2_HDR_FLAG_REDIRECT);
		SIVAL(out_hdr, SMB2_HDR_PID, 0xfeff);
		if (smbd_requ->smbd_tcon) {
			SIVAL(out_hdr, SMB2_HDR_TID, x_smbd_tcon_get_id(smbd_requ->smbd_tcon));
		}
	}
	if (smbd_requ->smbd_sess) {
		SBVAL(out_hdr, SMB2_HDR_SESSION_ID, x_smbd_sess_get_id(smbd_requ->smbd_sess));
	}

	if (smbd_requ->out_hdr_flags & SMB2_HDR_FLAG_SIGNED) {
		const x_smb2_key_t *signing_key = get_signing_key(smbd_requ);
		x_smb2_signing_sign(smbd_conn->dialect, signing_key, buf_head);
	}

	if (smbd_requ->out_buf_tail) {
		smbd_requ->out_buf_tail->next = buf_head;
		smbd_requ->out_buf_tail = buf_tail;
	} else {
		smbd_requ->out_buf_head = buf_head;
		smbd_requ->out_buf_tail = buf_tail;
	}
	smbd_requ->out_length += x_convert_assert<uint32_t>(reply_size);
}

static int x_smbd_reply_error(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
		NTSTATUS status,
		const char *file, unsigned int line)
{
	X_LOG_OP("%ld RESP 0x%lx at %s:%d", smbd_requ->in_mid, status.v, file, line);

	x_buf_t *out_buf = x_buf_alloc_out_buf(8);

	uint8_t *out_hdr = x_buf_get_out_hdr(out_buf);

	uint8_t *out_body = out_hdr + SMB2_HDR_BODY;
	memset(out_body, 0, 8);
	x_put_le16(out_body, 0x9);

	x_bufref_t *bufref = new x_bufref_t{out_buf, 8, SMB2_HDR_BODY + 8};
	x_smb2_reply(smbd_conn, smbd_requ, bufref, bufref, status, SMB2_HDR_BODY + 8);

	return 0;
}

#define X_SMBD_REPLY_ERROR(smbd_conn, smbd_requ, status) \
	x_smbd_reply_error((smbd_conn), (smbd_requ), (status), __FILE__, __LINE__)

static int x_smbd_reply_interim(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
		const char *file, unsigned int line)
{
	X_LOG_OP("%ld RESP ASYNC at %s:%d", smbd_requ->in_mid, file, line);

	smbd_requ->out_credit_granted = x_smb2_calculate_credit(smbd_conn, smbd_requ, NT_STATUS_PENDING);
	smbd_requ->out_hdr_flags = calculate_out_hdr_flags(smbd_requ->in_hdr_flags, smbd_requ->out_hdr_flags);

	x_buf_t *out_buf = x_buf_alloc_out_buf(8);

	uint8_t *out_hdr = x_buf_get_out_hdr(out_buf);

	uint8_t *out_body = out_hdr + SMB2_HDR_BODY;
	memset(out_body, 0, 8);
	x_put_le16(out_body, 0x9);

	smbd_requ->async = true;

	x_bufref_t *bufref = new x_bufref_t{out_buf, 8, SMB2_HDR_BODY + 8};
	x_smb2_reply(smbd_conn, smbd_requ, bufref, bufref, NT_STATUS_PENDING, SMB2_HDR_BODY + 8);
	return 0;
}

#define X_SMBD_REPLY_INTERIM(smbd_conn, smbd_requ) \
	x_smbd_reply_interim((smbd_conn), (smbd_requ), __FILE__, __LINE__)

static void x_smbd_conn_cancel(x_smbd_conn_t *smbd_conn, uint64_t async_id)
{
	x_smbd_requ_t *smbd_requ = x_smbd_requ_lookup(async_id, smbd_conn, true);
	if (!smbd_requ) {
		X_LOG_ERR("%ld not found", async_id);
		return;
	}

	smbd_requ->cancel_fn(smbd_conn, smbd_requ);
	x_smbd_ref_dec(smbd_requ);
}

void x_smbd_conn_send_unsolicited(x_smbd_conn_t *smbd_conn, x_smbd_sess_t *smbd_sess,
		x_bufref_t *buf, uint16_t opcode)
{
	uint8_t *out_hdr = buf->get_data();
	memset(out_hdr, 0, SMB2_HDR_BODY);
	x_put_be32(out_hdr + SMB2_HDR_PROTOCOL_ID, X_SMB2_MAGIC);
	SSVAL(out_hdr, SMB2_HDR_LENGTH, SMB2_HDR_BODY);
	SIVAL(out_hdr, SMB2_HDR_OPCODE, opcode);
	SIVAL(out_hdr, SMB2_HDR_FLAGS, SMB2_HDR_FLAG_REDIRECT);
	SBVAL(out_hdr, SMB2_HDR_MESSAGE_ID, uint64_t(-1));
	SIVAL(out_hdr, SMB2_HDR_PID, 0xfeff);
	if (smbd_sess) {
		SBVAL(out_hdr, SMB2_HDR_SESSION_ID, x_smbd_sess_get_id(smbd_sess));
	}

	x_smbd_conn_queue(smbd_conn, buf, buf, buf->length);
}

static const struct {
	NTSTATUS (* const op_func)(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
	bool const need_channel;
	bool const need_tcon;
} x_smb2_op_table[] = {
	{ x_smb2_process_negprot, false, false, },
	{ x_smb2_process_sesssetup, false, false, },
	{ x_smb2_process_logoff, true, false, },
	{ x_smb2_process_tcon, true, false, },
	{ x_smb2_process_tdis, true, true, },
	{ x_smb2_process_create, true, true, },
	{ x_smb2_process_close, true, true, },
	{ x_smb2_process_flush, true, true, },
	{ x_smb2_process_read, true, true, },
	{ x_smb2_process_write, true, true, },
	{ x_smb2_process_lock, true, true, },
	{ x_smb2_process_ioctl, true, true, },
	{ x_smb2_process_cancel, false, false, },
	{ x_smb2_process_keepalive, false, false, },
	{ x_smb2_process_query_directory, true, true, },
	{ x_smb2_process_notify, true, true, },
	{ x_smb2_process_getinfo, true, true, },
	{ x_smb2_process_setinfo, true, true, },
	{ x_smb2_process_break, true, true, },
};



static NTSTATUS x_smbd_conn_process_smb2_intl(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	if (smbd_requ->in_hdr_flags & SMB2_HDR_FLAG_ASYNC) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	x_buf_t *buf = smbd_requ->in_buf;
	uint8_t *in_buf = buf->data + smbd_requ->in_offset;
	uint64_t in_session_id = x_get_le64(in_buf + SMB2_HDR_SESSION_ID);
	if ((smbd_requ->in_hdr_flags & SMB2_HDR_FLAG_CHAINED) == 0) {
		if (smbd_requ->smbd_chan) {
			X_SMBD_REF_DEC(smbd_requ->smbd_chan);
		}
		if (smbd_requ->smbd_sess) {
			X_SMBD_REF_DEC(smbd_requ->smbd_sess);
		}
		if (in_session_id != 0) {
			smbd_requ->smbd_sess = x_smbd_sess_lookup(in_session_id, smbd_conn->client_guid);
		}
	}
	
	bool signing_required = false;
	if (smbd_requ->smbd_sess) {
		signing_required = x_smbd_sess_is_signing_required(smbd_requ->smbd_sess);
	}

	if (smbd_requ->is_signed()) {
		if (smbd_requ->opcode == SMB2_OP_NEGPROT) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		if (!smbd_requ->smbd_sess) {
			return NT_STATUS_USER_SESSION_DELETED;
		}
		x_bufref_t bufref{x_buf_get(smbd_requ->in_buf), smbd_requ->in_offset, smbd_requ->in_requ_len};
		if (!smbd_requ->smbd_chan) {
			smbd_requ->smbd_chan = x_smbd_sess_lookup_chan(smbd_requ->smbd_sess,
				smbd_conn);
		}
		const x_smb2_key_t *signing_key = get_signing_key(smbd_requ);
		smbd_requ->out_hdr_flags |= SMB2_HDR_FLAG_SIGNED;
		if (!x_smb2_signing_check(smbd_conn->dialect, signing_key, &bufref)) {
			return NT_STATUS_ACCESS_DENIED;
		}
	} else if (signing_required) {
		return NT_STATUS_ACCESS_DENIED;
	}

	if (smbd_requ->opcode >= std::size(x_smb2_op_table)) {
		X_TODO; // more ops
	}

	const auto &op = x_smb2_op_table[smbd_requ->opcode];
	if (op.need_channel) {
		if (!smbd_requ->smbd_sess) {
			return NT_STATUS_USER_SESSION_DELETED;
		}
		if (!smbd_requ->smbd_chan) {
			smbd_requ->smbd_chan = x_smbd_sess_lookup_chan(smbd_requ->smbd_sess,
					smbd_conn);
			if (!smbd_requ->smbd_chan || !x_smbd_chan_is_active(smbd_requ->smbd_chan)) {
				return NT_STATUS_USER_SESSION_DELETED;
			}
		}
	}

	/* TODO signing/encryption */
	smbd_requ->in_tid = x_get_le32(in_buf + SMB2_HDR_TID);
	if (op.need_tcon) {
		X_ASSERT(smbd_requ->smbd_sess);
		if (!smbd_requ->smbd_tcon) {
			if (!smbd_requ->in_tid) {
				return NT_STATUS_NETWORK_NAME_DELETED;
			}
			smbd_requ->smbd_tcon = x_smbd_tcon_lookup(smbd_requ->in_tid,
					smbd_requ->smbd_sess);
			if (!smbd_requ->smbd_tcon) {
				return NT_STATUS_NETWORK_NAME_DELETED;
			}
		}
	}

	smbd_requ->async = false;

	return op.op_func(smbd_conn, smbd_requ);
}

static bool x_smb2_validate_message_id(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	if (smbd_requ->opcode == X_SMB2_OP_CANCEL) {
		return true;
	}

	uint16_t credit_charge = std::max(smbd_requ->in_credit_charge, uint16_t(1u));

	if (smbd_conn->credit_granted < credit_charge) {
		X_LOG_ERR("credit_charge %u > credit_granted %u",
				credit_charge, smbd_conn->credit_granted);
		return false;
	}

	if (!x_check_range<uint64_t>(smbd_requ->in_mid, credit_charge, smbd_conn->credit_seq_low,
				smbd_conn->credit_seq_low + smbd_conn->credit_seq_range)) {
		X_LOG_ERR("%lu+%u not in the credit range %lu+%u", smbd_requ->in_mid, credit_charge,
				smbd_conn->credit_seq_low, smbd_conn->credit_seq_range);
		return false;
	}

	auto &seq_bitmap = smbd_conn->seq_bitmap;
	uint64_t id = smbd_requ->in_mid;
	for (uint16_t i = 0; i < credit_charge; ++i, ++id) {
		uint64_t offset = id % seq_bitmap.size();
		if (seq_bitmap[offset]) {
			X_LOG_ERR("duplicated mid %lu", id);
			return false;
		}
		seq_bitmap[offset] = true;
	}

	if (smbd_requ->in_mid == smbd_conn->credit_seq_low) {
		uint64_t clear = 0;
		id = smbd_requ->in_mid;
		uint64_t offset = id % seq_bitmap.size();
		for ( ; seq_bitmap[offset]; ++clear) {
			seq_bitmap[offset] = false;
			offset = (offset + 1) % seq_bitmap.size();
		}
		smbd_conn->credit_seq_low += clear;
		smbd_conn->credit_seq_range -= clear;
	}

	smbd_conn->credit_granted -= credit_charge;
	return true;
}

static int x_smbd_conn_process_smb2(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
		uint32_t offset)
{
	x_buf_t *buf = smbd_requ->in_buf;
	uint32_t in_requ_len = 0;

	for (; offset < buf->size; offset += in_requ_len) {
		const uint8_t *in_buf = buf->data + offset;
		in_requ_len = buf->size - offset;
		X_ASSERT(in_requ_len > SMB2_HDR_BODY);

		uint32_t next_command = x_get_le32(in_buf + SMB2_HDR_NEXT_COMMAND);
		if (next_command != 0) {
			if (next_command < SMB2_HDR_BODY || next_command + SMB2_HDR_BODY >= in_requ_len) {
				return -EBADMSG;
			}
			in_requ_len = next_command;
			smbd_requ->compound_followed = true;
		} else {
			smbd_requ->compound_followed = false;
		}

		smbd_requ->opcode = x_get_le16(in_buf + SMB2_HDR_OPCODE);
		if (smbd_requ->opcode >= X_SMB2_OP_MAX) {
			/* windows server reset connection immediately,
			   while samba response STATUS_INVALID_PARAMETER */
			return -EBADMSG;
		}
		smbd_requ->in_offset = offset;
		smbd_requ->in_requ_len = in_requ_len;

		smbd_requ->in_hdr_flags = x_get_le32(in_buf + SMB2_HDR_FLAGS);

		if (smbd_requ->opcode == X_SMB2_OP_CANCEL) {
			uint64_t in_async_id;
			if (smbd_requ->in_hdr_flags & SMB2_HDR_FLAG_ASYNC) {
				in_async_id = x_get_le64(in_buf + SMB2_HDR_PID);
			} else {
				in_async_id = x_get_le64(in_buf + SMB2_HDR_MESSAGE_ID);
			}
			x_smbd_conn_cancel(smbd_conn, in_async_id);
			continue;
		}

		smbd_requ->async_id = 0;
		smbd_requ->cancel_fn = nullptr;
		smbd_requ->in_mid = x_get_le64(in_buf + SMB2_HDR_MESSAGE_ID);
		smbd_requ->in_credit_charge = x_get_le16(in_buf + SMB2_HDR_CREDIT_CHARGE);
		smbd_requ->in_credit_requested = x_get_le16(in_buf + SMB2_HDR_CREDIT);

		if (!x_smb2_validate_message_id(smbd_conn, smbd_requ)) {
			return -EBADMSG;
		}

		if (!NT_STATUS_IS_OK(smbd_requ->status) && (smbd_requ->in_hdr_flags & SMB2_HDR_FLAG_CHAINED)) {
			X_SMBD_REPLY_ERROR(smbd_conn, smbd_requ, smbd_requ->status);
			continue;
		}

		NTSTATUS status = x_smbd_conn_process_smb2_intl(
				smbd_conn, smbd_requ);
		if (NT_STATUS_IS_OK(status) || NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			continue;
		} else if (NT_STATUS_EQUAL(status, NT_STATUS_PENDING)) {
			X_SMBD_REPLY_INTERIM(smbd_conn, smbd_requ);
			if (offset + in_requ_len < buf->size) {
				X_TODO;
				return 0;
			}
		} else if (NT_STATUS_EQUAL(status, X_NT_STATUS_INTERNAL_BLOCKED)) {
			return 0;
		} else {
			X_SMBD_REPLY_ERROR(smbd_conn, smbd_requ, status);
			smbd_requ->status = status;
		}
	}

	/* CANCEL request do not have response */
	if (smbd_requ->out_length > 0) {
		x_smbd_conn_queue(smbd_conn, smbd_requ);
	}
	return 0;
}

static int x_smbd_conn_process_smb(x_smbd_conn_t *smbd_conn, x_buf_t *buf)
{
	uint32_t offset = 0;
	// uint8_t *inbuf = buf->data + offset;
	size_t len = buf->size - offset;
	if (len < 4) {
		return -EBADMSG;
	}
	int32_t smbhdr = x_get_be32(buf->data + offset);

	x_smbd_ptr_t<x_smbd_requ_t> smbd_requ{new x_smbd_requ_t(x_buf_get(buf))};
	
	if (smbhdr == X_SMB2_MAGIC) {
		if (len < SMB2_HDR_BODY) {
			return -EBADMSG;
		}
		return x_smbd_conn_process_smb2(smbd_conn, smbd_requ, 0);
	} else if (smbhdr == X_SMB1_MAGIC) {
		uint8_t cmd = buf->data[4];
		if (/* TODO smbd_conn->is_negotiated || */cmd != SMBnegprot) {
			return -EBADMSG;
		}
		smbd_requ->in_mid = 0; // TODO
		smbd_requ->in_hdr_flags = 0;
		smbd_requ->opcode = SMB2_OP_NEGPROT; 
		smbd_requ->in_credit_charge = 1;
		smbd_requ->in_credit_requested = 0;

		if (!x_smb2_validate_message_id(smbd_conn, smbd_requ)) {
			return -EBADMSG;
		}
		int ret = x_smbd_conn_process_smb1negprot(smbd_conn, smbd_requ);
		if (ret < 0) {
			return ret;
		}
		x_smbd_conn_queue(smbd_conn, smbd_requ);
		return 0;
	} else {
		return -EBADMSG;
	}
}

static int x_smbd_conn_process_nbt(x_smbd_conn_t *smbd_conn)
{
	int err;

	if ((smbd_conn->nbt_hdr >> 24) == NBSSmessage) {
		x_buf_t *buf = smbd_conn->recv_buf;
		smbd_conn->recv_buf = nullptr;
		err = x_smbd_conn_process_smb(smbd_conn, buf);
		x_buf_release(buf);
	} else {
		X_TODO;
		err = -EINVAL;
	}
	return err;
}

static inline x_smbd_conn_t *x_smbd_conn_from_upcall(x_epoll_upcall_t *upcall)
{
	return X_CONTAINER_OF(upcall, x_smbd_conn_t, upcall);
}

static int x_smbd_conn_check_nbt_hdr(x_smbd_conn_t *smbd_conn)
{
	if (smbd_conn->recv_len == sizeof(smbd_conn->nbt_hdr)) {
		smbd_conn->recv_len = 0;
		smbd_conn->nbt_hdr = ntohl(smbd_conn->nbt_hdr);
		uint32_t msgtype = smbd_conn->nbt_hdr >> 24;
		if (msgtype == NBSSmessage) {
			uint32_t msgsize = smbd_conn->nbt_hdr & 0xffffff;
			if (msgsize >= MAX_MSG_SIZE) {
				/* bad smbd_requ, shutdown it */
				return -EMSGSIZE;
			} else if (smbd_conn->nbt_hdr == 0) {
				smbd_conn->recv_len = 0;
				return 0;
			} else {
				smbd_conn->recv_buf = x_buf_alloc(msgsize);
				return msgsize;
			}
		} else {
			/* un recognize smbd_requ, shutdown it */
			return true;
		}
	}
	return 0;
}

static bool x_smbd_conn_do_recv(x_smbd_conn_t *smbd_conn, x_fdevents_t &fdevents)
{
	ssize_t err;
	X_LOG_DBG("%s %p x%lx x%llx", task_name, smbd_conn, smbd_conn->ep_id, fdevents);
	if (smbd_conn->recv_buf == NULL) {
		X_ASSERT(smbd_conn->recv_len < sizeof(smbd_conn->nbt_hdr));
		err = read(smbd_conn->fd, (char *)&smbd_conn->nbt_hdr + smbd_conn->recv_len,
				sizeof(smbd_conn->nbt_hdr) - smbd_conn->recv_len);
		if (err > 0) {
			smbd_conn->recv_len = x_convert_assert<uint32_t>(smbd_conn->recv_len + err);
			err = x_smbd_conn_check_nbt_hdr(smbd_conn);
			if (err < 0) {
				return true;
			} else if (err == 0) {
				return false;
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

	uint32_t next_nbt_hdr;
	struct iovec iovec[2] = {
		{ smbd_conn->recv_buf->data + smbd_conn->recv_len, smbd_conn->recv_buf->size - smbd_conn->recv_len, },
		{ &next_nbt_hdr, sizeof(next_nbt_hdr), }
	};

	err = readv(smbd_conn->fd, iovec, 2);
	if (err > 0) {
		smbd_conn->recv_len = x_convert_assert<uint32_t>(smbd_conn->recv_len + err);
		if (smbd_conn->recv_len >= smbd_conn->recv_buf->size) {
			smbd_conn->recv_len -= smbd_conn->recv_buf->size;
			bool ret = x_smbd_conn_process_nbt(smbd_conn);
			if (ret) {
				return true;
			}

			X_ASSERT(smbd_conn->recv_len <= sizeof(smbd_conn->nbt_hdr));
			smbd_conn->nbt_hdr = next_nbt_hdr;

			err = x_smbd_conn_check_nbt_hdr(smbd_conn);
			if (err < 0) {
				return true;
			} else {
				return false;
			}
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

static bool x_smbd_conn_do_send(x_smbd_conn_t *smbd_conn, x_fdevents_t &fdevents)
{
	X_LOG_DBG("%s %p x%lx x%llx", task_name, smbd_conn, smbd_conn->ep_id, fdevents);
	for (;;) {
		struct iovec iov[8];
		uint32_t niov = 0;

		x_bufref_t *bufref = smbd_conn->send_buf_head;
		if (!bufref) {
			break;
		}

		for ( ; niov < 8 && bufref; ++niov) {
			iov[niov].iov_base = bufref->get_data();
			iov[niov].iov_len = bufref->length;
			bufref = bufref->next;
		}

		ssize_t ret = writev(smbd_conn->fd, iov, niov);
		if (ret > 0) {
			uint32_t bytes = x_convert_assert<uint32_t>(ret);
			for ( ; bytes > 0; ) {
				bufref = smbd_conn->send_buf_head;
				if (bufref->length <= bytes) {
					smbd_conn->send_buf_head = bufref->next;
					if (!bufref->next) {
						smbd_conn->send_buf_tail = nullptr;
					}
					bytes -= bufref->length;
					delete bufref;
				} else {
					bufref->offset += bytes;
					bufref->length -= bytes;
					/* writev does not write all bytes,
					 * should it break to outside?
					 * do not find document if epoll will
					 * trigger without one more writev
					 */
					break;
				}
			}
		} else {
			X_ASSERT(ret != 0);
			if (errno == EAGAIN) {
				fdevents = x_fdevents_consume(fdevents, FDEVT_OUT);
				break;
			} else if (errno == EINTR) {
			} else {
				return true;
			}
		}
	}
	if (!smbd_conn->send_buf_head) {
		fdevents = x_fdevents_disable(fdevents, FDEVT_OUT);
	}
	if (smbd_conn->count_msg < x_smbd_conn_t::MAX_MSG) {
		fdevents = x_fdevents_enable(fdevents, FDEVT_IN);
	}
	return false;
}

static bool x_smbd_conn_do_user(x_smbd_conn_t *smbd_conn, x_fdevents_t &fdevents)
{
	X_LOG_DBG("%s %p x%lx x%llx", task_name, smbd_conn, smbd_conn->ep_id, fdevents);
	std::unique_lock<std::mutex> lock(smbd_conn->mutex);
	for (;;) {
		x_fdevt_user_t *fdevt_user = smbd_conn->fdevt_user_list.get_front();
		if (!fdevt_user) {
			break;
		}
		smbd_conn->fdevt_user_list.remove(fdevt_user);
		lock.unlock();

		fdevt_user->func(smbd_conn, fdevt_user, false);

		lock.lock();
	}

	fdevents = x_fdevents_consume(fdevents, FDEVT_USER);
	return false;
}

static bool x_smbd_conn_handle_events(x_smbd_conn_t *smbd_conn, x_fdevents_t &fdevents)
{
	uint32_t events = x_fdevents_processable(fdevents);
	if (events & FDEVT_USER) {
		if (x_smbd_conn_do_user(smbd_conn, fdevents)) {
			return true;
		}
		events = x_fdevents_processable(fdevents);
	}
	if (events & FDEVT_OUT) {
		if (x_smbd_conn_do_send(smbd_conn, fdevents)) {
			return true;
		}
		events = x_fdevents_processable(fdevents);
	}
	if (events & FDEVT_IN) {
		return x_smbd_conn_do_recv(smbd_conn, fdevents);
	}
	return false;
}

/* this function is in the smbd_conn work thread context */
static void x_smbd_conn_terminate_chans(x_smbd_conn_t *smbd_conn)
{
	x_dlink_t *link;
	while ((link = smbd_conn->chan_list.get_front()) != nullptr) {
		smbd_conn->chan_list.remove(link);
		/* unlink smbd_chan, x_smbd_chan_done need to dec the ref
		 * of smbd_chan
		 */
		x_smbd_chan_unlinked(link, smbd_conn);
	}
}

__thread x_smbd_conn_t *g_smbd_conn_curr = nullptr;

const x_smb2_uuid_t &x_smbd_conn_curr_client_guid()
{
	return g_smbd_conn_curr->client_guid;
}


static bool x_smbd_conn_upcall_cb_getevents(x_epoll_upcall_t *upcall, x_fdevents_t &fdevents)
{
	x_smbd_conn_t *smbd_conn = x_smbd_conn_from_upcall(upcall);
	X_LOG_DBG("%s %p x%llx", task_name, smbd_conn, fdevents);

	g_smbd_conn_curr = x_smbd_ref_inc(smbd_conn);
	bool ret = x_smbd_conn_handle_events(smbd_conn, fdevents);
	X_SMBD_REF_DEC(g_smbd_conn_curr);
	return ret;
}

static void x_smbd_conn_upcall_cb_unmonitor(x_epoll_upcall_t *upcall)
{
	x_smbd_conn_t *smbd_conn = x_smbd_conn_from_upcall(upcall);
	X_LOG_CONN("%s %p", task_name, smbd_conn);
	X_ASSERT_SYSCALL(close(smbd_conn->fd));
	smbd_conn->fd = -1;
	g_smbd_conn_curr = x_smbd_ref_inc(smbd_conn);
	{
		std::unique_lock<std::mutex> lock(smbd_conn->mutex);
		smbd_conn->state = x_smbd_conn_t::STATE_DONE;
		for (;;) {
			x_fdevt_user_t *fdevt_user = smbd_conn->fdevt_user_list.get_front();
			if (!fdevt_user) {
				break;
			}
			smbd_conn->fdevt_user_list.remove(fdevt_user);
			lock.unlock();

			fdevt_user->func(smbd_conn, fdevt_user, true);

			lock.lock();
		}
	}

	x_smbd_conn_terminate_chans(smbd_conn);
	X_SMBD_REF_DEC(g_smbd_conn_curr);
	x_smbd_ref_dec(smbd_conn);
}

static const x_epoll_upcall_cbs_t x_smbd_conn_upcall_cbs = {
	x_smbd_conn_upcall_cb_getevents,
	x_smbd_conn_upcall_cb_unmonitor,
};

static void x_smbd_srv_accepted(x_smbd_srv_t *smbd_srv, int fd, const x_sockaddr_t &saddr)
{
	X_LOG_CONN("accept %d from %s", fd, saddr.tostring().c_str());
	set_nbio(fd, 1);
	auto smbd_conf = x_smbd_conf_get();
	x_smbd_conn_t *smbd_conn = new x_smbd_conn_t(fd, saddr,
			smbd_conf->smb2_max_credits);
	X_ASSERT(smbd_conn != NULL);
	smbd_conn->upcall.cbs = &x_smbd_conn_upcall_cbs;
	smbd_conn->ep_id = x_evtmgmt_monitor(g_evtmgmt, fd, FDEVT_IN | FDEVT_OUT, &smbd_conn->upcall);
	x_evtmgmt_enable_events(g_evtmgmt, smbd_conn->ep_id,
			FDEVT_IN | FDEVT_ERR | FDEVT_SHUTDOWN | FDEVT_USER);
}

static inline x_smbd_srv_t *x_smbd_from_upcall(x_epoll_upcall_t *upcall)
{
	return X_CONTAINER_OF(upcall, x_smbd_srv_t, upcall);
}

static bool x_smbd_srv_upcall_cb_getevents(x_epoll_upcall_t *upcall, x_fdevents_t &fdevents)
{
	x_smbd_srv_t *smbd_srv = x_smbd_from_upcall(upcall);
	uint32_t events = x_fdevents_processable(fdevents);

	if (events & FDEVT_IN) {
		x_sockaddr_t saddr;
		socklen_t slen = sizeof(saddr);
		int fd = accept(smbd_srv->fd, &saddr.sa, &slen);
		X_LOG_DBG("%s accept %d, %d", task_name, fd, errno);
		if (fd >= 0) {
			x_smbd_srv_accepted(smbd_srv, fd, saddr);
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

static void x_smbd_srv_upcall_cb_unmonitor(x_epoll_upcall_t *upcall)
{
	x_smbd_srv_t *smbd_srv = x_smbd_from_upcall(upcall);
	X_LOG_CONN("%s %p", task_name, smbd_srv);
	X_ASSERT_SYSCALL(close(smbd_srv->fd));
	smbd_srv->fd = -1;
	/* TODO may close all accepted client, and notify it is freed */
}

static const x_epoll_upcall_cbs_t x_smbd_srv_upcall_cbs = {
	x_smbd_srv_upcall_cb_getevents,
	x_smbd_srv_upcall_cb_unmonitor,
};

static x_smbd_srv_t g_smbd_srv;
int x_smbd_conn_srv_init(int port)
{
	int fd = tcplisten(port);
	assert(fd >= 0);

	g_smbd_srv.fd = fd;
	g_smbd_srv.upcall.cbs = &x_smbd_srv_upcall_cbs;

	g_smbd_srv.ep_id = x_evtmgmt_monitor(g_evtmgmt, fd, FDEVT_IN, &g_smbd_srv.upcall);
	x_evtmgmt_enable_events(g_evtmgmt, g_smbd_srv.ep_id, FDEVT_IN | FDEVT_ERR | FDEVT_SHUTDOWN);
	return 0;
}

bool x_smbd_conn_post_user(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user)
{
	bool notify = false;
	bool queued = false;
	{
		std::lock_guard<std::mutex> lock(smbd_conn->mutex);
		if (smbd_conn->state != x_smbd_conn_t::STATE_DONE) {
			notify = smbd_conn->fdevt_user_list.get_front() == nullptr;
			smbd_conn->fdevt_user_list.push_back(fdevt_user);
			queued = true;
		}
	}
	if (notify) {
		x_evtmgmt_post_events(g_evtmgmt, smbd_conn->ep_id, FDEVT_USER);
	}
	return queued;
#if 0
	if (!queued) {
		/* cancel the event */
		fdevt_user->func(smbd_conn, fdevt_user, true);
	}
#endif
}

void x_smbd_conn_link_chan(x_smbd_conn_t *smbd_conn, x_dlink_t *link)
{
	smbd_conn->chan_list.push_back(link);
}

void x_smbd_conn_unlink_chan(x_smbd_conn_t *smbd_conn, x_dlink_t *link)
{
	smbd_conn->chan_list.remove(link);
}

void x_smbd_conn_requ_done(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
		NTSTATUS status)
{
	if (NT_STATUS_IS_OK(status) || NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
	} else if (NT_STATUS_EQUAL(status, NT_STATUS_PENDING)) {
		X_ASSERT(false); // should not happen, X_SMBD_REPLY_INTERIM(smbd_conn, smbd_requ);
	} else {
		smbd_requ->status = status;
		X_SMBD_REPLY_ERROR(smbd_conn, smbd_requ, status);
	}

	int err = x_smbd_conn_process_smb2(smbd_conn, smbd_requ, smbd_requ->in_offset + smbd_requ->in_requ_len);
	if (err < 0) {
		X_TODO; // x_smbd_conn_reset(smbd_conn);
	}
#if 0
	offset = smbd_requ->offset;
	for (; offset < buf->size; offset += in_requ_len) {
	if (NT_STATUS_EQUAL(status, 
	if (ret is blocking) {
		return;
	}
	if (ret is async) {
		queue STATUS_PENDING response;
		if (compound related) {
			return;
		}
	}
	if (ret is error) {
		queue error response;
		if (compound related) {
			foreach remaining request
				send error response;
			return;
		}
	}
#endif
}

struct x_smbd_cancel_evt_t
{
	explicit x_smbd_cancel_evt_t(x_smbd_requ_t *smbd_requ)
		: smbd_requ(smbd_requ) { }
	~x_smbd_cancel_evt_t() {
		x_smbd_ref_dec(smbd_requ);
	}
	x_fdevt_user_t base;
	x_smbd_requ_t * const smbd_requ;
};

static void x_smbd_cancel_func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user, bool cancelled)
{
	x_smbd_cancel_evt_t *evt = X_CONTAINER_OF(fdevt_user, x_smbd_cancel_evt_t, base);

	x_smbd_requ_t *smbd_requ = evt->smbd_requ;
	if (!cancelled) {
		smbd_requ->async_done_fn(smbd_conn, smbd_requ, NT_STATUS_CANCELLED);
	}

	delete evt;
}

void x_smbd_conn_post_cancel(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	x_smbd_cancel_evt_t *evt = new x_smbd_cancel_evt_t(smbd_requ);
	evt->base.func = x_smbd_cancel_func;
	x_smbd_conn_post_user(smbd_conn, &evt->base);
}

void x_smbd_conn_set_async(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
		void (*cancel_fn)(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ))
{
	X_ASSERT(!smbd_requ->cancel_fn);
	smbd_requ->cancel_fn = cancel_fn;
	x_smbd_requ_insert(smbd_requ);
}

NTSTATUS x_smbd_conn_validate_negotiate_info(const x_smbd_conn_t *smbd_conn,
		x_smb2_fsctl_validate_negotiate_info_state_t &fsctl_state)
{
	if (fsctl_state.in_capabilities != smbd_conn->client_capabilities) {
		return X_NT_STATUS_INTERNAL_TERMINATE;
	}

	if (fsctl_state.in_guid != smbd_conn->client_guid) {
		return X_NT_STATUS_INTERNAL_TERMINATE;
	}

	if (fsctl_state.in_security_mode != smbd_conn->client_security_mode) {
		return X_NT_STATUS_INTERNAL_TERMINATE;
	}

	const auto smbd_conf = x_smbd_conf_get();
	/*
	 * From: [MS-SMB2]
	 * 3.3.5.15.12 Handling a Validate Negotiate Info Request
	 *
	 * The server MUST determine the greatest common dialect
	 * between the dialects it implements and the Dialects array
	 * of the VALIDATE_NEGOTIATE_INFO request. If no dialect is
	 * matched, or if the value is not equal to Connection.Dialect,
	 * the server MUST terminate the transport connection
	 * and free the Connection object.
	 */
	uint16_t dialect = x_smb2_dialect_match(smbd_conf->dialects, 
			fsctl_state.in_dialects,
			fsctl_state.in_num_dialects);

	if (dialect != smbd_conn->dialect) {
		return X_NT_STATUS_INTERNAL_TERMINATE;
	}

	fsctl_state.out_capabilities = smbd_conn->server_capabilities;
	fsctl_state.out_guid = smbd_conf->guid;
	fsctl_state.out_security_mode = smbd_conn->server_security_mode;
	fsctl_state.out_dialect = smbd_conn->dialect;

	return NT_STATUS_OK;
}

