
#include "smbd.hxx"
#include "network.hxx"
#include "smbd_stats.hxx"
#include "smbd_conf.hxx"
#include "smbd_open.hxx"
#include <sys/uio.h>

enum {
	MAX_MSG_SIZE = 0x1000000,
};

struct x_smbd_srv_t
{
	x_strm_srv_t base;
	std::mutex mutex;
	x_tp_ddlist_t<fdevt_user_conn_traits> fdevt_user_list;
};

X_DECLARE_MEMBER_TRAITS(requ_conn_traits, x_smbd_requ_t, conn_link)
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
	const std::shared_ptr<std::u16string> machine_name;
	const x_tick_t tick_create;

	x_smbd_negprot_t negprot;

	uint64_t credit_seq_low = 0;
	uint64_t credit_seq_range = 1;
	uint64_t credit_granted = 1;
	std::vector<bool> seq_bitmap;
	// xconn->smb2.credits.bitmap = bitmap_talloc(xconn, xconn->smb2.credits.max);
	x_smb2_preauth_t preauth;

	uint32_t nbt_hdr;
	uint32_t recv_len = 0, recv_msgsize = 0;
	x_buf_t *recv_buf{};
	x_strm_send_queue_t send_queue;
	// x_bufref_t *send_buf_head{}, *send_buf_tail{};

	x_ddlist_t chan_list;
	x_tp_ddlist_t<requ_conn_traits> pending_requ_list;
	x_tp_ddlist_t<fdevt_user_conn_traits> fdevt_user_list;
};

static std::u16string machine_name_from_saddr(const x_sockaddr_t &saddr)
{
	char buf[INET6_ADDRSTRLEN] = "";
	if (saddr.family == AF_INET) {
		snprintf(buf, sizeof buf, "%d.%d.%d.%d",
			X_IPQUAD_BE(saddr.sin.sin_addr));
	} else if (saddr.family == AF_INET6) {
		auto &sin6_addr = saddr.sin6.sin6_addr;
		if (sin6_addr.s6_addr32[0] == 0 && sin6_addr.s6_addr32[1] == 0
				&& sin6_addr.s6_addr16[4] == 0
				&& sin6_addr.s6_addr16[5] == 0xffff) {
			snprintf(buf, sizeof buf, "%d.%d.%d.%d",
					sin6_addr.s6_addr[12],
					sin6_addr.s6_addr[13],
					sin6_addr.s6_addr[14],
					sin6_addr.s6_addr[15]);
		} else {
			inet_ntop(AF_INET6, &saddr.sin6.sin6_addr, buf, sizeof buf);
		}
	} else {
		X_ASSERT(false);
	}
	return x_str_convert_assert<std::u16string>(std::string_view(buf));
}

template <>
x_smbd_conn_t *x_ref_inc(x_smbd_conn_t *smbd_conn)
{
	X_ASSERT(smbd_conn->refcnt++ > 0);
	return smbd_conn;
}

template <>
void x_ref_dec(x_smbd_conn_t *smbd_conn)
{
	if (x_unlikely(--smbd_conn->refcnt == 0)) {
		delete smbd_conn;
	}
}

struct smbd_conn_curr_t
{
	smbd_conn_curr_t(x_smbd_conn_t *smbd_conn) {
		g_smbd_conn_curr = x_ref_inc(smbd_conn);
	}
	~smbd_conn_curr_t() {
		X_REF_DEC(g_smbd_conn_curr);
	}
};

void x_smbd_conn_update_preauth(x_smbd_conn_t *smbd_conn,
		const void *data, size_t length)
{
	smbd_conn->preauth.update(data, length);
}

const x_smb2_preauth_t *x_smbd_conn_get_preauth(x_smbd_conn_t *smbd_conn)
{
	if (smbd_conn->negprot.dialect >= X_SMB2_DIALECT_310) {
		return &smbd_conn->preauth;
	} else {
		return nullptr;
	}
}

const x_smbd_negprot_t &x_smbd_conn_get_negprot(const x_smbd_conn_t *smbd_conn)
{
	return smbd_conn->negprot;
}

uint16_t x_smbd_conn_get_dialect(const x_smbd_conn_t *smbd_conn)
{
	return smbd_conn->negprot.dialect;
}

uint16_t x_smbd_conn_get_cryption_algo(const x_smbd_conn_t *smbd_conn)
{
	return smbd_conn->negprot.cryption_algo;
}

uint32_t x_smbd_conn_get_capabilities(const x_smbd_conn_t *smbd_conn)
{
	return smbd_conn->negprot.server_capabilities;
}

#define X_SMBD_UPDATE_OP_HISTOGRAM(smbd_requ) do { \
	auto __now = x_tick_now(); \
	auto __elapsed = __now - (smbd_requ)->start; \
	X_ASSERT(__elapsed >= 0); \
	X_STATS_HISTOGRAM_UPDATE((smbd_requ)->in_smb2_hdr.opcode, __elapsed / 1000); \
} while (0)

int x_smbd_conn_negprot(x_smbd_conn_t *smbd_conn,
		const x_smbd_negprot_t &negprot, bool smb1)
{
	if (smb1) {
		if (smbd_conn->negprot.dialect != X_SMB2_DIALECT_000) {
			X_LOG(SMB, ERR, "Invalid smb1 negprot, curr dialect is 0x%x",
					smbd_conn->negprot.dialect);
			return -EBADMSG;
		}
	} else {
		if (smbd_conn->negprot.dialect != X_SMB2_DIALECT_000 &&
				smbd_conn->negprot.dialect != X_SMB2_DIALECT_2FF) {
			X_LOG(SMB, ERR, "Invalid smb2 negprot, curr dialect is 0x%x",
					smbd_conn->negprot.dialect);
			return -EBADMSG;
		}
	}

	smbd_conn->negprot = negprot;
	if (negprot.signing_algo == X_SMB2_SIGNING_INVALID_ALGO) {
		if (negprot.dialect >= X_SMB2_DIALECT_224) {
			smbd_conn->negprot.signing_algo = X_SMB2_SIGNING_AES128_CMAC;
		} else {
			smbd_conn->negprot.signing_algo = X_SMB2_SIGNING_HMAC_SHA256;
		}
	} else {
		smbd_conn->negprot.signing_algo = negprot.signing_algo;
	}
	return 0;
}

static void x_smbd_conn_queue_buf(x_smbd_conn_t *smbd_conn, x_bufref_t *buf_head,
		x_bufref_t *buf_tail, uint32_t length)
{
	uint32_t *outnbt = (uint32_t *)buf_head->back(4);
	*outnbt = X_H2BE32(length);

	if (smbd_conn->send_queue.append(buf_head, buf_tail)) {
		x_evtmgmt_enable_events(g_evtmgmt, smbd_conn->ep_id, FDEVT_OUT);
	}
}

static const x_smb2_key_t *get_signing_key(const x_smbd_requ_t *smbd_requ,
		uint16_t *p_signing_algo)
{
	const x_smb2_key_t *signing_key = nullptr;
	if (smbd_requ->smbd_chan) {
		signing_key = x_smbd_chan_get_signing_key(smbd_requ->smbd_chan,
				p_signing_algo);
	}
	if (!signing_key) {
		signing_key = x_smbd_sess_get_signing_key(smbd_requ->smbd_sess,
				p_signing_algo);
		// TODO signing_key is null?
	}
	return signing_key;
}

static void x_smbd_requ_sign_if(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ, x_bufref_t *buf_head)
{
	x_smb2_header_t *smb2_hdr = (x_smb2_header_t *)buf_head->get_data();
	uint32_t flags = X_LE2H32(smb2_hdr->flags);
	NTSTATUS status = { X_LE2H32(smb2_hdr->status) };
	if (!smbd_requ->encrypted && flags & (X_SMB2_HDR_FLAG_SIGNED)) {
		if (smbd_requ->smbd_sess) {
			uint16_t signing_algo;
			const x_smb2_key_t *signing_key = get_signing_key(smbd_requ,
					&signing_algo);
			x_smb2_signing_sign(signing_algo,
					signing_key, buf_head);
		} else {
			X_ASSERT(!NT_STATUS_IS_OK(status));
			memcpy(smb2_hdr->signature, smbd_requ->in_smb2_hdr.signature,
					sizeof(smb2_hdr->signature));
		}
	}
}

static int x_smbd_conn_create_smb2_tf(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		x_buf_t **out_buf)
{
	X_ASSERT(smbd_requ->out_length > 4);
	uint32_t msgsize = smbd_requ->out_length;
	x_smb2_tf_header_t *tf_hdr;
	x_buf_t *buf = x_buf_alloc(4 + sizeof(*tf_hdr) + msgsize + 32);

	tf_hdr = (x_smb2_tf_header_t *)(buf->data + 4);
	uint64_t nonce_low, nonce_high;
	const x_smb2_cryption_key_t *key = x_smbd_sess_get_encryption_key(
			smbd_requ->smbd_sess,
			&nonce_low, &nonce_high);

	if (!key) {
		return -1;
	}

	uint32_t *nonce_u32 = (uint32_t *)tf_hdr->nonce;
	nonce_u32[0] = X_H2LE32(x_convert<uint32_t>(nonce_low & 0xffffffff));
	nonce_u32[1] = X_H2LE32(x_convert<uint32_t>(nonce_low >> 32));
	nonce_u32[2] = X_H2LE32(x_convert<uint32_t>(nonce_high & 0xffffffff));
	nonce_u32[3] = X_H2LE32(x_convert<uint32_t>(nonce_high >> 32));
	tf_hdr->msgsize = X_H2LE32(msgsize);
	tf_hdr->unused0 = 0;
	tf_hdr->flags = X_H2LE16(X_SMB2_TF_FLAGS_ENCRYPTED);
	uint64_t sess_id = x_smbd_sess_get_id(smbd_requ->smbd_sess);
	tf_hdr->sess_id_low = X_H2LE32(x_convert<uint32_t>(sess_id & 0xffffffff));
	tf_hdr->sess_id_high = X_H2LE32(x_convert<uint32_t>(sess_id >> 32));

	int clen = x_smb2_signing_encrypt(smbd_conn->negprot.cryption_algo,
			key, tf_hdr,
			smbd_requ->out_buf_head, smbd_requ->out_length);

	if (clen < 0) {
		X_LOG(SMB, DBG, "x_smb2_signing_encrypt(%u) error %d",
				smbd_conn->negprot.cryption_algo, clen);
		return -1;
	}

	tf_hdr->protocol_id = X_H2BE32(X_SMB2_TF_MAGIC);
	*out_buf = buf;
	return x_convert<int>(clen + sizeof(*tf_hdr));
}

static void x_smbd_conn_queue(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	X_ASSERT(smbd_requ->out_buf_head);
	X_ASSERT(smbd_requ->out_length > 0);

	if (smbd_requ->encrypted) {
		x_buf_t *out_buf;
		int clen = x_smbd_conn_create_smb2_tf(smbd_conn, smbd_requ, &out_buf);
		if (clen < 0) {
			X_TODO;
			return;
		}
		x_bufref_t *bufref = new x_bufref_t{out_buf, 4, (uint32_t)clen};
		x_bufref_t *out_buf_head = smbd_requ->out_buf_head;
		while (out_buf_head) {
			auto next = out_buf_head->next;
			delete out_buf_head;
			out_buf_head = next;
		}

		smbd_requ->out_buf_head = smbd_requ->out_buf_tail = bufref;
		smbd_requ->out_length = clen;
	}

	x_smbd_conn_queue_buf(smbd_conn, smbd_requ->out_buf_head, smbd_requ->out_buf_tail,
			smbd_requ->out_length);

	smbd_requ->out_buf_head = smbd_requ->out_buf_tail = nullptr;
	smbd_requ->out_length = 0;
}

static uint16_t x_smb2_calculate_credit(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
		NTSTATUS status)
{
	uint64_t current_max_credits = smbd_conn->seq_bitmap.size() / 16;
	current_max_credits = std::max(current_max_credits, 1ul);

	uint16_t credit_charged = std::max(smbd_requ->in_smb2_hdr.credit_charge, uint16_t(1u));
	uint16_t credit_requested = std::max(smbd_requ->in_smb2_hdr.credit, uint16_t(1u));
	
	/* already checked in process smb2 input */
	X_ASSERT(credit_charged < smbd_conn->seq_bitmap.size());

	// uint32_t additional_possible = smbd_conn->seq_bitmap.size() - credit_charged;
	uint32_t additional_credits = credit_requested - 1;
	uint32_t additional_max = 0;

	if (smbd_requ->in_smb2_hdr.opcode == X_SMB2_OP_NEGPROT) {
	} else if (smbd_requ->in_smb2_hdr.opcode == X_SMB2_OP_SESSSETUP) {
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
	return x_convert_assert<uint16_t>(std::min(credit_granted, 0xfffful));
}

static uint32_t calculate_out_hdr_flags(uint32_t in_hdr_flags, uint32_t out_hdr_flags)
{
	// TODO should consider other flags?
	out_hdr_flags |= (in_hdr_flags & (X_SMB2_HDR_FLAG_PRIORITY_MASK));
	return out_hdr_flags;
}

static void x_smb2_reply_msg(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		x_bufref_t *buf_head,
		x_bufref_t *buf_tail,
		NTSTATUS status,
		size_t reply_size)
{
	X_LOG(SMB, DBG, X_SMBD_REQU_DBG_FMT " %s", X_SMBD_REQU_DBG_ARG(smbd_requ), x_ntstatus_str(status));
	smbd_requ->out_hdr_flags = calculate_out_hdr_flags(smbd_requ->in_smb2_hdr.flags, smbd_requ->out_hdr_flags);
	x_smb2_header_t *smb2_hdr = (x_smb2_header_t *)buf_head->get_data();
	smb2_hdr->protocol_id = X_H2BE32(X_SMB2_MAGIC);
	smb2_hdr->length = X_H2LE32(sizeof(x_smb2_header_t));
	smb2_hdr->credit_charge = X_H2LE16(smbd_requ->in_smb2_hdr.credit_charge);
	smb2_hdr->status = { X_H2LE32(NT_STATUS_V(status)) };
	smb2_hdr->opcode = X_H2LE16(smbd_requ->in_smb2_hdr.opcode);
	smb2_hdr->credit = X_H2LE16(smbd_requ->out_credit_granted);
	smb2_hdr->next_command = 0;
	smb2_hdr->mid = X_H2LE64(smbd_requ->in_smb2_hdr.mid);
	uint32_t flags = smbd_requ->out_hdr_flags | X_SMB2_HDR_FLAG_REDIRECT;
	if (smbd_requ->interim_state == x_smbd_requ_t::INTERIM_S_SENT) {
		flags |= X_SMB2_HDR_FLAG_ASYNC;
		smb2_hdr->async_id = X_H2LE64(x_smbd_requ_get_async_id(smbd_requ));
	} else {
		smb2_hdr->pid = X_H2LE32(0xfeff);
		if (smbd_requ->smbd_tcon) {
			smb2_hdr->tid = X_H2LE32(x_smbd_tcon_get_id(smbd_requ->smbd_tcon));
		} else {
			smb2_hdr->tid = X_H2LE32(smbd_requ->in_smb2_hdr.tid);
		}
	}

	if (smbd_requ->out_buf_head) {
		/* not the first in the chain */
		flags |= (smbd_requ->in_smb2_hdr.flags & X_SMB2_HDR_FLAG_CHAINED);
	}

	smb2_hdr->flags = X_H2LE32(flags);

	if (smbd_requ->smbd_sess) {
		smb2_hdr->sess_id = X_H2LE64(x_smbd_sess_get_id(smbd_requ->smbd_sess));
	} else {
		smb2_hdr->sess_id = X_H2LE64(smbd_requ->in_smb2_hdr.sess_id);
	}

	memset(smb2_hdr->signature, 0, sizeof(smb2_hdr->signature));

	if (smbd_requ->is_compound_followed() || smbd_requ->out_buf_head) {
		uint32_t pad_len = x_convert<uint32_t>(x_pad_len(reply_size, 8) - reply_size);
		if (pad_len) {
			memset(buf_tail->get_data() + buf_tail->length, 0, pad_len);
			buf_tail->length += pad_len;
			reply_size += pad_len;
		}
	}
	if (smbd_requ->is_compound_followed() && !NT_STATUS_EQUAL(status, NT_STATUS_PENDING)) {
		smb2_hdr->next_command = X_H2LE32(x_convert<uint32_t>(reply_size));
	}
	x_smbd_requ_sign_if(smbd_conn, smbd_requ, buf_head);

	if (smbd_requ->out_buf_tail) {
		smbd_requ->out_buf_tail->next = buf_head;
		smbd_requ->out_buf_tail = buf_tail;
	} else {
		smbd_requ->out_buf_head = buf_head;
		smbd_requ->out_buf_tail = buf_tail;
	}
	smbd_requ->out_length += x_convert_assert<uint32_t>(reply_size);
}

static void smbd_conn_reply_update_counts(
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ);

void x_smb2_reply(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		x_bufref_t *buf_head,
		x_bufref_t *buf_tail,
		NTSTATUS status,
		size_t reply_size)
{
	if (smbd_requ->interim_state != x_smbd_requ_t::INTERIM_S_SENT) {
		smbd_requ->out_credit_granted = x_smb2_calculate_credit(smbd_conn, smbd_requ, status);
	} else {
		smbd_requ->out_credit_granted = 0;
	}

	smbd_conn_reply_update_counts(smbd_conn, smbd_requ);
	if (smbd_requ->interim_state == x_smbd_requ_t::INTERIM_S_SCHEDULED &&
			x_smbd_del_timer(&smbd_requ->interim_timer)) {
		x_ref_dec(smbd_requ);
	}
	x_smb2_reply_msg(smbd_conn, smbd_requ, buf_head, buf_tail, status, reply_size);
	smbd_requ->interim_state = x_smbd_requ_t::INTERIM_S_NONE;
	X_SMBD_UPDATE_OP_HISTOGRAM(smbd_requ);
}

struct x_smb2_error_t
{
	uint16_t struct_size;
	uint8_t error_context_count;
	uint8_t unused0;
	uint32_t byte_count;
};

static int x_smbd_reply_error(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
		NTSTATUS status,
		const char *file, unsigned int line)
{
	X_LOG(SMB, OP, "%ld RESP 0x%x at %s:%d", smbd_requ->in_smb2_hdr.mid,
			NT_STATUS_V(status), file, line);

	x_buf_t *out_buf = x_smb2_alloc_out_buf(sizeof(x_smb2_error_t));

	uint8_t *out_hdr = x_smb2_get_out_hdr(out_buf);

	uint8_t *out_body = out_hdr + sizeof(x_smb2_header_t);
	x_smb2_error_t *smb2_err = (x_smb2_error_t *)out_body;
	smb2_err->struct_size = X_H2LE16(9);
	/* workaround test BVT_SMB2Basic_ChangeNotify_ServerReceiveSmb2Close */
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOTIFY_CLEANUP)) {
		smb2_err->error_context_count = 0x48;
	} else {
		smb2_err->error_context_count = 0;
	}
	smb2_err->unused0 = 0;
	smb2_err->byte_count = 0;

	x_bufref_t *bufref = new x_bufref_t{out_buf, 8, sizeof(x_smb2_header_t) + 8};
	x_smb2_reply(smbd_conn, smbd_requ, bufref, bufref, status, sizeof(x_smb2_header_t) + 8);

	return 0;
}

#define X_SMBD_REPLY_ERROR(smbd_conn, smbd_requ, status) \
	x_smbd_reply_error((smbd_conn), (smbd_requ), (status), __FILE__, __LINE__)

static int x_smbd_reply_interim(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
		const char *file, unsigned int line)
{
	X_LOG(SMB, OP, "%ld RESP ASYNC at %s:%d", smbd_requ->in_smb2_hdr.mid, file, line);

	smbd_requ->out_credit_granted = x_smb2_calculate_credit(smbd_conn, smbd_requ, NT_STATUS_PENDING);
	smbd_requ->out_hdr_flags = calculate_out_hdr_flags(smbd_requ->in_smb2_hdr.flags, smbd_requ->out_hdr_flags);

	x_buf_t *out_buf = x_smb2_alloc_out_buf(8);

	uint8_t *out_hdr = x_smb2_get_out_hdr(out_buf);

	uint8_t *out_body = out_hdr + sizeof(x_smb2_header_t);
	memset(out_body, 0, 8);
	x_put_le16(out_body, 0x9);

	x_bufref_t *bufref = new x_bufref_t{out_buf, 8, sizeof(x_smb2_header_t) + 8};
	smbd_requ->interim_state = x_smbd_requ_t::INTERIM_S_SENT;
	x_smb2_reply_msg(smbd_conn, smbd_requ, bufref, bufref, NT_STATUS_PENDING, sizeof(x_smb2_header_t) + 8);
	X_SMBD_COUNTER_INC(reply_interim, 1);
	x_smbd_conn_queue(smbd_conn, smbd_requ);

	return 0;
}

#define X_SMBD_REPLY_INTERIM(smbd_conn, smbd_requ) \
	x_smbd_reply_interim((smbd_conn), (smbd_requ), __FILE__, __LINE__)

/* must be in context of smbd_conn */
void x_smbd_requ_async_insert(x_smbd_requ_t *smbd_requ,
		void (*cancel_fn)(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ),
		int64_t interim_timeout_ns)
{
	X_SMBD_REQU_LOG(DBG, smbd_requ, " timeout=%ld", interim_timeout_ns);
	X_ASSERT(!smbd_requ->cancel_fn);
	smbd_requ->cancel_fn = cancel_fn;
	g_smbd_conn_curr->pending_requ_list.push_back(smbd_requ);
	x_ref_inc(smbd_requ);
	if (smbd_requ->interim_state == x_smbd_requ_t::INTERIM_S_NONE) {
		if (interim_timeout_ns == 0) {
			smbd_requ->interim_state = x_smbd_requ_t::INTERIM_S_IMMEDIATE;
		} else if (interim_timeout_ns > 0 && !smbd_requ->is_compound_followed()) {
			x_ref_inc(smbd_requ);
			x_smbd_add_timer(&smbd_requ->interim_timer, interim_timeout_ns);
			smbd_requ->interim_state = x_smbd_requ_t::INTERIM_S_SCHEDULED;
		}
	}
}

/* must be in context of smbd_conn or smbd_srv if smbd_conn is died */
bool x_smbd_requ_async_remove(x_smbd_requ_t *smbd_requ)
{
	X_SMBD_REQU_LOG(DBG, smbd_requ, " interim_state %d",
			smbd_requ->interim_state);
	if (!smbd_requ->cancel_fn) {
		return false;
	}
	x_smbd_conn_t *smbd_conn = x_smbd_chan_get_conn(smbd_requ->smbd_chan);
	X_ASSERT(!g_smbd_conn_curr || g_smbd_conn_curr == smbd_conn);
	smbd_conn->pending_requ_list.remove(smbd_requ);
	smbd_requ->cancel_fn = nullptr;
	x_ref_dec(smbd_requ);
	return true;
}

static void x_smbd_conn_cancel(x_smbd_conn_t *smbd_conn,
		const x_smb2_header_t &smb2_hdr)
{
	x_smbd_requ_t *smbd_requ;
	if (smb2_hdr.flags & X_SMB2_HDR_FLAG_ASYNC) {
		smbd_requ = x_smbd_requ_async_lookup(smb2_hdr.async_id, smbd_conn, true);
	} else {
		for (smbd_requ = smbd_conn->pending_requ_list.get_front();
				smbd_requ;
				smbd_requ = smbd_conn->pending_requ_list.next(smbd_requ)) {
			if (smbd_requ->in_smb2_hdr.mid == smb2_hdr.mid) {
				break;
			}
		}
	}

	if (!smbd_requ) {
		X_LOG(SMB, ERR, "cannot find pending requ by flags=0x%x, async_id=x%lx, mid=%lu",
				smb2_hdr.flags, smb2_hdr.async_id, smb2_hdr.mid);
		X_SMBD_COUNTER_INC(cancel_not_exist, 1);
		return;
	}

	if (!smbd_requ->set_cancelled()) {
		X_SMBD_REQU_LOG(DBG, smbd_requ, " cannot cancell async_id=x%lx, mid=%lu",
				smb2_hdr.async_id, smb2_hdr.mid);
		X_SMBD_COUNTER_INC(cancel_too_late, 1);
		return;
	}

	X_SMBD_REQU_LOG(DBG, smbd_requ, " cancelled async_id=x%lx, mid=%lu",
			smb2_hdr.async_id, smb2_hdr.mid);
	X_SMBD_COUNTER_INC(cancel_success, 1);
	auto cancel_fn = smbd_requ->cancel_fn;
	smbd_requ->cancel_fn = nullptr;
	smbd_conn->pending_requ_list.remove(smbd_requ);
	cancel_fn(smbd_conn, smbd_requ);

	x_ref_dec(smbd_requ);
}

void x_smbd_conn_send_unsolicited(x_smbd_conn_t *smbd_conn, x_smbd_sess_t *smbd_sess,
		x_bufref_t *buf, uint16_t opcode)
{
	x_smb2_header_t *smb2_hdr = (x_smb2_header_t *)buf->get_data();
	smb2_hdr->protocol_id = X_H2BE32(X_SMB2_MAGIC);
	smb2_hdr->length = X_H2LE32(sizeof(x_smb2_header_t));
	smb2_hdr->credit_charge = 0;
	smb2_hdr->status = { 0 };
	smb2_hdr->opcode = X_H2LE16(opcode);
	smb2_hdr->credit = 0;
	smb2_hdr->flags = X_H2LE32(X_SMB2_HDR_FLAG_REDIRECT);
	smb2_hdr->next_command = 0;
	smb2_hdr->mid = X_H2LE64(uint64_t(-1));
	smb2_hdr->pid = X_H2LE32(0xfeff);
	smb2_hdr->tid = 0;
	if (smbd_sess) {
		smb2_hdr->sess_id = X_H2LE64(x_smbd_sess_get_id(smbd_sess));
	} else {
		smb2_hdr->sess_id = 0;
	}

	memset(smb2_hdr->signature, 0, sizeof(smb2_hdr->signature));

	x_smbd_conn_queue_buf(smbd_conn, buf, buf, buf->length);
}

static const struct {
	NTSTATUS (* const op_func)(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
	bool const need_channel;
	bool const need_tcon;
	bool const allow_sess_expired;
} x_smb2_op_table[] = {
	{ x_smb2_process_negprot, false, false, false, },
	{ x_smb2_process_sesssetup, false, false, true, },
	{ x_smb2_process_logoff, true, false, true, },
	{ x_smb2_process_tcon, true, false, false, },
	{ x_smb2_process_tdis, true, true, false, },
	{ x_smb2_process_create, true, true, false, },
	{ x_smb2_process_close, true, true, true, },
	{ x_smb2_process_flush, true, true, false, },
	{ x_smb2_process_read, true, true, false, },
	{ x_smb2_process_write, true, true, false, },
	{ x_smb2_process_lock, true, true, true, }, // only allow unlock
	{ x_smb2_process_ioctl, true, true, false, },
	{ nullptr, false, false, true, }, // OP_CANCEL
	{ x_smb2_process_keepalive, false, false, false, },
	{ x_smb2_process_query_directory, true, true, false, },
	{ x_smb2_process_notify, true, true, false, },
	{ x_smb2_process_getinfo, true, true, false, },
	{ x_smb2_process_setinfo, true, true, false, },
	{ x_smb2_process_break, true, true, false, },
};

/* Samba smbd_smb2_request_dispatch_update_counts */
NTSTATUS x_smbd_conn_dispatch_update_counts(
		x_smbd_requ_t *smbd_requ,
		bool modify_call)
{
	// X_ASSERT(smbd_requ->smbd_conn == g_smbd_conn_curr);
	if (x_smbd_conn_curr_dialect() < X_SMB2_DIALECT_300) {
		return NT_STATUS_OK;
	}

	int generation_wrap = 0;
	bool update_open = false;
	uint16_t channel_sequence = smbd_requ->in_smb2_hdr.channel_sequence;
	x_smbd_open_t *smbd_open = smbd_requ->smbd_open;
	auto &open_state = smbd_open->open_state;

	auto lock = std::lock_guard(smbd_open->smbd_object->mutex);

	int cmp = channel_sequence - open_state.channel_sequence;
	if (cmp < 0) {
		/*
		 * csn wrap. We need to watch out for long-running
		 * requests that are still sitting on a previously
		 * used csn. SMB2_OP_NOTIFY can take VERY long.
		 */
		generation_wrap += 1;
	}

	if (abs(cmp) > INT16_MAX) {
		/*
		 * [MS-SMB2] 3.3.5.2.10 - Verifying the Channel Sequence Number:
		 *
		 * If the channel sequence number of the request and the one
		 * known to the server are not equal, the channel sequence
		 * number and outstanding request counts are only updated
		 * "... if the unsigned difference using 16-bit arithmetic
		 * between ChannelSequence and Open.ChannelSequence is less than
		 * or equal to 0x7FFF ...".
		 * Otherwise, an error is returned for the modifying
		 * calls write, set_info, and ioctl.
		 *
		 * There are currently two issues with the description:
		 *
		 * * For the other calls, the document seems to imply
		 *   that processing continues without adapting the
		 *   counters (if the sequence numbers are not equal).
		 *
		 *   TODO: This needs clarification!
		 *
		 * * Also, the behaviour if the difference is larger
		 *   than 0x7FFF is not clear. The document seems to
		 *   imply that if such a difference is reached,
		 *   the server starts to ignore the counters or
		 *   in the case of the modifying calls, return errors.
		 *
		 *   TODO: This needs clarification!
		 *
		 * At this point Samba tries to be a little more
		 * clever than the description in the MS-SMB2 document
		 * by heuristically detecting and properly treating
		 * a 16 bit overflow of the client-submitted sequence
		 * number:
		 *
		 * If the stored channel sequence number is more than
		 * 0x7FFF larger than the one from the request, then
		 * the client-provided sequence number has likely
		 * overflown. We treat this case as valid instead
		 * of as failure.
		 *
		 * The MS-SMB2 behaviour would be setting cmp = -1.
		 */
		cmp *= -1;
	}

	if (smbd_requ->in_smb2_hdr.flags & X_SMB2_HDR_FLAG_REPLAY_OPERATION) {
		if (cmp == 0 && smbd_open->pre_request_count == 0) {
			smbd_open->request_count += 1;
			smbd_requ->request_counters_updated = true;
		} else if (cmp > 0 && smbd_open->pre_request_count == 0) {
			smbd_open->pre_request_count += smbd_open->request_count;
			smbd_open->request_count = 1;
			open_state.channel_sequence = channel_sequence;
			open_state.channel_generation += generation_wrap;
			update_open = true;
			smbd_requ->request_counters_updated = true;
		} else if (modify_call) {
			return NT_STATUS_FILE_NOT_AVAILABLE;
		}
	} else {
		if (cmp == 0) {
			smbd_open->request_count += 1;
			smbd_requ->request_counters_updated = true;
		} else if (cmp > 0) {
			smbd_open->pre_request_count += smbd_open->request_count;
			smbd_open->request_count = 1;
			open_state.channel_sequence = channel_sequence;
			open_state.channel_generation += generation_wrap;
			update_open = true;
			smbd_requ->request_counters_updated = true;
		} else if (modify_call) {
			return NT_STATUS_FILE_NOT_AVAILABLE;
		}
	}
	smbd_requ->channel_generation = open_state.channel_generation;

	if (update_open && open_state.dhmode != x_smbd_dhmode_t::NONE) {
		// return smbXsrv_open_update(op);
	}

	return NT_STATUS_OK;
}

static void smbd_conn_reply_update_counts(
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ)
{
	X_ASSERT(smbd_conn == g_smbd_conn_curr);
	if (!smbd_requ->request_counters_updated) {
		return;
	}

	smbd_requ->request_counters_updated = false;

	if (smbd_conn->negprot.dialect < X_SMB2_DIALECT_300) {
		return;
	}

	x_smbd_open_t *smbd_open = smbd_requ->smbd_open;
	if (!smbd_open) {
		return;
	}

	uint16_t channel_sequence = smbd_requ->in_smb2_hdr.channel_sequence;
	auto &open_state = smbd_open->open_state;

	auto lock = std::lock_guard(smbd_open->smbd_object->mutex);
	if ((open_state.channel_sequence == channel_sequence) &&
	    (open_state.channel_generation == smbd_requ->channel_generation)) {
		X_ASSERT(smbd_open->request_count > 0);
		smbd_open->request_count -= 1;
	} else {
		X_ASSERT(smbd_open->pre_request_count > 0);
		smbd_open->pre_request_count -= 1;
	}
}

static bool x_smb2_validate_message_id(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	X_ASSERT(smbd_requ->in_smb2_hdr.opcode != X_SMB2_OP_CANCEL);

	uint16_t credit_charge = std::max(smbd_requ->in_smb2_hdr.credit_charge, uint16_t(1u));

	if (smbd_conn->credit_granted < credit_charge) {
		X_LOG(SMB, ERR, "credit_charge %u > credit_granted %lu",
				credit_charge, smbd_conn->credit_granted);
		return false;
	}

	if (!x_check_range<uint64_t>(smbd_requ->in_smb2_hdr.mid, credit_charge, smbd_conn->credit_seq_low,
				smbd_conn->credit_seq_low + smbd_conn->credit_seq_range)) {
		X_LOG(SMB, ERR, "%lu+%u not in the credit range %lu+%lu", smbd_requ->in_smb2_hdr.mid, credit_charge,
				smbd_conn->credit_seq_low, smbd_conn->credit_seq_range);
		return false;
	}

	auto &seq_bitmap = smbd_conn->seq_bitmap;
	uint64_t id = smbd_requ->in_smb2_hdr.mid;
	for (uint16_t i = 0; i < credit_charge; ++i, ++id) {
		uint64_t offset = id % seq_bitmap.size();
		if (seq_bitmap[offset]) {
			X_LOG(SMB, ERR, "duplicated mid %lu", id);
			return false;
		}
		seq_bitmap[offset] = true;
	}

	if (smbd_requ->in_smb2_hdr.mid == smbd_conn->credit_seq_low) {
		uint64_t clear = 0;
		id = smbd_requ->in_smb2_hdr.mid;
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

static NTSTATUS x_smbd_conn_process_smb2_intl(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	if (!x_smb2_validate_message_id(smbd_conn, smbd_requ)) {
		/* NOTE, WPTS CreditMgmtTestCaseS776 requires it return
		 * NT_STATUS_INVALID_PARAMETER
		 */
		return X_NT_STATUS_INTERNAL_TERMINATE;
	}

	if (smbd_requ->in_smb2_hdr.flags & X_SMB2_HDR_FLAG_ASYNC) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if ((smbd_requ->in_smb2_hdr.flags & X_SMB2_HDR_FLAG_CHAINED) == 0) {
		if (smbd_requ->smbd_open) {
			X_REF_DEC(smbd_requ->smbd_open);
		}
		if (smbd_requ->smbd_tcon) {
			X_REF_DEC(smbd_requ->smbd_tcon);
		}
		if (smbd_requ->smbd_chan) {
			X_REF_DEC(smbd_requ->smbd_chan);
		}
		if (smbd_requ->smbd_sess) {
			X_REF_DEC(smbd_requ->smbd_sess);
		}
		smbd_requ->sess_status = NT_STATUS_OK;
	}

	NTSTATUS sess_status = NT_STATUS_OK;
	if (!smbd_requ->smbd_sess && smbd_requ->in_smb2_hdr.sess_id != 0 &&
			smbd_requ->in_smb2_hdr.sess_id != UINT64_MAX) {
		smbd_requ->smbd_sess = x_smbd_sess_lookup(sess_status,
				smbd_requ->in_smb2_hdr.sess_id,
				smbd_conn->negprot.client_guid);
		if ((smbd_requ->in_smb2_hdr.flags & X_SMB2_HDR_FLAG_CHAINED) == 0) {
			smbd_requ->sess_status = sess_status;
		}
		if (smbd_requ->smbd_sess && !smbd_requ->smbd_chan) {
			smbd_requ->smbd_chan = x_smbd_sess_lookup_chan(
					smbd_requ->smbd_sess, smbd_conn);
		}
	}
	
	if (smbd_requ->is_signed()) {
		smbd_requ->out_hdr_flags |= X_SMB2_HDR_FLAG_SIGNED;
	}

	if ((smbd_requ->in_smb2_hdr.flags & X_SMB2_HDR_FLAG_CHAINED) != 0) {
		if (smbd_requ->in_offset == 0) {
			smbd_requ->sess_status = NT_STATUS_INVALID_PARAMETER;
			return NT_STATUS_INVALID_PARAMETER;
		} else if (!smbd_requ->smbd_sess || !NT_STATUS_IS_OK(smbd_requ->sess_status)) {
			return NT_STATUS_INVALID_PARAMETER;
		}
	}

	X_ASSERT(smbd_requ->in_smb2_hdr.opcode < std::size(x_smb2_op_table));

	if (smbd_requ->in_smb2_hdr.opcode == X_SMB2_OP_IOCTL) {
		NTSTATUS status = x_smb2_process_ioctl_torture(smbd_conn,
				smbd_requ);
		if (NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	const auto &op = x_smb2_op_table[smbd_requ->in_smb2_hdr.opcode];
	if (op.need_channel) {
		if (NT_STATUS_EQUAL(smbd_requ->sess_status,
					NT_STATUS_NETWORK_SESSION_EXPIRED)) {
			if (!op.allow_sess_expired) {
				X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_NETWORK_SESSION_EXPIRED);
			}
		} else if (!NT_STATUS_IS_OK(smbd_requ->sess_status)) {
			X_SMBD_REQU_RETURN_STATUS(smbd_requ, smbd_requ->sess_status);
		}
		if (!smbd_requ->smbd_sess) {
			X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_USER_SESSION_DELETED);
		}
		if (!smbd_requ->smbd_chan ||  !x_smbd_chan_is_active(smbd_requ->smbd_chan)) {
			X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_USER_SESSION_DELETED);
		}
	}

	bool signing_required = false;
	if (!smbd_requ->encrypted && smbd_requ->smbd_sess) {
		signing_required = x_smbd_sess_is_signing_required(smbd_requ->smbd_sess);
	}

	if (!smbd_requ->encrypted && smbd_requ->is_signed()) {
		if (smbd_requ->in_smb2_hdr.opcode == X_SMB2_OP_NEGPROT) {
			X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
		}
		if (!smbd_requ->smbd_sess) {
			X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_USER_SESSION_DELETED);
		}
		x_bufref_t bufref{x_buf_get(smbd_requ->in_buf), smbd_requ->in_offset, smbd_requ->in_requ_len};
#if 0
		if (!smbd_requ->smbd_chan) {
			smbd_requ->smbd_chan = x_smbd_sess_lookup_chan(smbd_requ->smbd_sess,
				smbd_conn);
		}
#endif
		uint16_t signing_algo;
		const x_smb2_key_t *signing_key = get_signing_key(smbd_requ, &signing_algo);
		if (!x_smb2_signing_check(signing_algo, signing_key, &bufref)) {
			return NT_STATUS_ACCESS_DENIED;
		}
	} else if (signing_required) {
		if (smbd_requ->in_smb2_hdr.opcode != X_SMB2_OP_SESSSETUP ||
				smbd_requ->smbd_chan ||
				!NT_STATUS_IS_OK(sess_status)) {
			X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_ACCESS_DENIED);
		}
	}

	/* TODO signing/encryption */
	if (op.need_tcon) {
		X_ASSERT(smbd_requ->smbd_sess);
		if (!smbd_requ->smbd_tcon) {
			if (!smbd_requ->in_smb2_hdr.tid) {
				return NT_STATUS_NETWORK_NAME_DELETED;
			}
			smbd_requ->smbd_tcon = x_smbd_tcon_lookup(
					smbd_requ->in_smb2_hdr.tid,
					smbd_requ->smbd_sess);
			if (!smbd_requ->smbd_tcon) {
				return NT_STATUS_NETWORK_NAME_DELETED;
			}
		}

		if (!smbd_requ->encrypted && x_smbd_tcon_encrypted(smbd_requ->smbd_tcon)) {
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	X_ASSERT(smbd_requ->interim_state == x_smbd_requ_t::INTERIM_S_NONE);
	smbd_requ->async_state = x_smbd_requ_t::S_INIT;

	return op.op_func(smbd_conn, smbd_requ);
}


static bool is_success(NTSTATUS status)
{
	return NT_STATUS_IS_OK(status) ||
		NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED) ||
		NT_STATUS_EQUAL(status, NT_STATUS_NOTIFY_ENUM_DIR);
}

static int x_smbd_conn_process_smb2(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
		uint32_t offset)
{
	x_buf_t *buf = smbd_requ->in_buf;
	uint32_t in_requ_len = 0;

	for (; offset < smbd_requ->in_msgsize; offset += in_requ_len) {
		in_requ_len = smbd_requ->in_msgsize - offset;
		X_ASSERT(in_requ_len > sizeof(x_smb2_header_t));

		auto in_smb2_hdr = (const x_smb2_header_t *)(buf->data + offset);
		smbd_requ->in_smb2_hdr.credit_charge = X_LE2H16(in_smb2_hdr->credit_charge);
		smbd_requ->in_smb2_hdr.channel_sequence = X_LE2H16(in_smb2_hdr->channel_sequence);
		smbd_requ->in_smb2_hdr.opcode = X_LE2H16(in_smb2_hdr->opcode);
		if (smbd_requ->in_smb2_hdr.opcode >= X_SMB2_OP_MAX) {
			/* windows server reset connection immediately,
			   while samba response STATUS_INVALID_PARAMETER */
			return -EBADMSG;
		}
		smbd_requ->in_smb2_hdr.credit = X_LE2H16(in_smb2_hdr->credit);
		smbd_requ->in_smb2_hdr.flags = X_LE2H32(in_smb2_hdr->flags);
		smbd_requ->in_smb2_hdr.next_command = X_LE2H32(in_smb2_hdr->next_command);
		if (smbd_requ->in_smb2_hdr.next_command != 0) {
			if (smbd_requ->in_smb2_hdr.next_command < sizeof(x_smb2_header_t) || smbd_requ->in_smb2_hdr.next_command + sizeof(x_smb2_header_t) >= in_requ_len) {
				return -EBADMSG;
			}
			in_requ_len = smbd_requ->in_smb2_hdr.next_command;
		} else {
		}
		smbd_requ->in_smb2_hdr.mid = X_LE2H64(in_smb2_hdr->mid);
		if (smbd_requ->in_smb2_hdr.flags & X_SMB2_HDR_FLAG_ASYNC) {
			smbd_requ->in_smb2_hdr.async_id = X_LE2H64(in_smb2_hdr->async_id);
		} else {
			smbd_requ->in_smb2_hdr.pid = X_LE2H32(in_smb2_hdr->pid);
			smbd_requ->in_smb2_hdr.tid = X_LE2H32(in_smb2_hdr->tid);
		}
		smbd_requ->in_smb2_hdr.sess_id = X_LE2H64(in_smb2_hdr->sess_id);

		smbd_requ->in_offset = offset;
		smbd_requ->in_requ_len = in_requ_len;

		smbd_requ->start = tick_now = x_tick_now();

		if (smbd_requ->in_smb2_hdr.opcode == X_SMB2_OP_CANCEL) {
			x_smbd_conn_cancel(smbd_conn, smbd_requ->in_smb2_hdr);
			X_SMBD_UPDATE_OP_HISTOGRAM(smbd_requ);
			continue;
		}


		smbd_requ->cancel_fn = nullptr;
		if (false && !NT_STATUS_IS_OK(smbd_requ->status) && (smbd_requ->in_smb2_hdr.flags & X_SMB2_HDR_FLAG_CHAINED)) {
			X_SMBD_REPLY_ERROR(smbd_conn, smbd_requ, smbd_requ->status);
			continue;
		}

		memcpy(smbd_requ->in_smb2_hdr.signature, in_smb2_hdr->signature,
				sizeof(in_smb2_hdr->signature));

		smbd_requ->done = false;
		NTSTATUS status = x_smbd_conn_process_smb2_intl(
				smbd_conn, smbd_requ);
		if (NT_STATUS_EQUAL(status, NT_STATUS_PENDING)) {
			if (smbd_requ->interim_state == x_smbd_requ_t::INTERIM_S_IMMEDIATE) {
				X_SMBD_REPLY_INTERIM(smbd_conn, smbd_requ);
			}
			break;
		} else if (NT_STATUS_EQUAL(status, X_NT_STATUS_INTERNAL_TERMINATE)) {
			return -EBADMSG;
		} else if (NT_STATUS_EQUAL(status, X_NT_STATUS_INTERNAL_BLOCKED)) {
			return 0;
		}

		if (!is_success(status)) {
			X_SMBD_REPLY_ERROR(smbd_conn, smbd_requ, status);
			smbd_requ->status = status;
		}
		x_smbd_requ_done(smbd_requ);
	}

	/* CANCEL request do not have response */
	if (smbd_requ->out_length > 0 && smbd_requ->done) {
		x_smbd_conn_queue(smbd_conn, smbd_requ);
	}
	return 0;
}

static int x_smbd_conn_process_smb2_tf(x_smbd_conn_t *smbd_conn,
		x_buf_t *buf, uint32_t total_size,
		x_buf_t **out_buf)
{
	if (smbd_conn->negprot.dialect < X_SMB2_DIALECT_300) {
		return -EBADMSG;
	}

	if (smbd_conn->negprot.cryption_algo == X_SMB2_ENCRYPTION_INVALID_ALGO) {
		return -EBADMSG;
	}

	const x_smb2_tf_header_t *smb2_tf = (x_smb2_tf_header_t *)buf->data;
	uint32_t msgsize = X_LE2H32(smb2_tf->msgsize);
	if (msgsize + sizeof(x_smb2_tf_header_t) > total_size) {
		return -EBADMSG;
	}

	uint16_t flags = X_LE2H16(smb2_tf->flags);
	if (flags != X_SMB2_TF_FLAGS_ENCRYPTED) {
		return -EBADMSG;
	}

	uint64_t sess_id = X_LE2H32(smb2_tf->sess_id_high);
	sess_id = sess_id << 32 | X_LE2H32(smb2_tf->sess_id_low);

	NTSTATUS status;
	x_smbd_sess_t *smbd_sess = x_smbd_sess_lookup(status,
				sess_id, smbd_conn->negprot.client_guid);
	if (!smbd_sess) {
		return -EBADMSG;
	}

	x_buf_t *pbuf = x_buf_alloc(msgsize);
	int plen = x_smb2_signing_decrypt(smbd_conn->negprot.cryption_algo,
			x_smbd_sess_get_decryption_key(smbd_sess),
			smb2_tf, smb2_tf + 1, msgsize,
			pbuf->data);

	x_ref_dec(smbd_sess);

	if (plen < 0) {
		X_LOG(SMB, DBG, "x_smb2_signing_decrypt(%u) error %d",
				smbd_conn->negprot.cryption_algo, plen);
		x_buf_release(pbuf);
		return -EBADMSG;
	}

	*out_buf = pbuf;
	return plen;
}

static int x_smbd_conn_process_smb2_ctf_unchained(x_smbd_conn_t *smbd_conn,
		x_buf_t *buf, uint32_t total_size,
		x_buf_t **out_buf,
		uint32_t original_size,
		uint16_t algo,
		uint32_t offset)
{
	if (algo >= X_SMB2_COMPRESSION_MAX ||
			!(smbd_conn->negprot.compression_algos & (1 << algo))) {
		return -EBADMSG;
	}
	uint32_t data_size = total_size - (uint32_t)sizeof(x_smb2_ctf_header_t);
	if (offset >= original_size || offset >= data_size) {
		return -EBADMSG;
	}

	const uint8_t *in_data = buf->data + sizeof(x_smb2_ctf_header_t);
	x_buf_t *pbuf = x_buf_alloc(original_size);
	uint8_t *out_data = pbuf->data;
	memcpy(out_data, in_data, offset);
	int ret = x_smb2_decompress(algo, in_data + offset, data_size - offset,
			out_data + offset, original_size - offset);
	if (ret < 0) {
		x_buf_release(pbuf);
		return ret;
	}
	*out_buf = pbuf;
	return ret;
}

static int x_smbd_conn_process_smb2_ctf(x_smbd_conn_t *smbd_conn,
		x_buf_t *buf, uint32_t total_size,
		x_buf_t **out_buf)
{
	if (total_size < sizeof(x_smb2_ctf_header_t)) {
		return -EBADMSG;
	}
	const x_smb2_ctf_header_t *smb2_ctf = (x_smb2_ctf_header_t *)buf->data;
	uint32_t original_size = X_LE2H32(smb2_ctf->original_segment_size);
	if (original_size > (256 + sizeof(x_smb2_ctf_header_t) + 
				std::max(std::max(smbd_conn->negprot.max_trans_size,
					smbd_conn->negprot.max_read_size),
					smbd_conn->negprot.max_write_size))) {
		return -EBADMSG;
	}

	uint16_t algo = X_LE2H16(smb2_ctf->compression_algorithm);
	uint16_t flags = X_LE2H16(smb2_ctf->flags);

	if (flags == 0) {
		return x_smbd_conn_process_smb2_ctf_unchained(smbd_conn,
				buf, total_size, out_buf,
				original_size, algo,
				X_LE2H32(smb2_ctf->offset));
	} else {
		return -EBADMSG;
#if 0
		return x_smbd_conn_process_smb2_ctf_chained(smbd_conn,
				buf, total_size, out_buf,
				original_size, algo,
				X_LE2H32(smb2_ctf->offset));
#endif
	}
}

#define SMBnegprot    0x72   /* negotiate protocol */
static int x_smbd_conn_process_smb(x_smbd_conn_t *smbd_conn, x_buf_t *buf, uint32_t msgsize)
{
	uint32_t offset = 0;
	// uint8_t *inbuf = buf->data + offset;
	size_t len = msgsize - offset;
	if (len < 4) {
		x_buf_release(buf);
		return -EBADMSG;
	}
	int32_t smbhdr = x_get_be32(buf->data + offset);
	bool encrypted = false;

	if (smbhdr == X_SMB2_TF_MAGIC) {
		if (len < sizeof(x_smb2_tf_header_t)) {
			x_buf_release(buf);
			return -EBADMSG;
		}
		x_buf_t *pbuf;
		int plen = x_smbd_conn_process_smb2_tf(smbd_conn, buf, msgsize,
				&pbuf);
		x_buf_release(buf);
		if (plen < 0) {
			return plen;
		}
		if (len < 4) {
			x_buf_release(pbuf);
			return -EBADMSG;
		}

		buf = pbuf;
		msgsize = plen;
		smbhdr = x_get_be32(buf->data + offset);
		encrypted = true;
	}

	if (smbhdr == X_SMB2_CTF_MAGIC) {
		x_buf_t *pbuf = nullptr;
		int plen = x_smbd_conn_process_smb2_ctf(smbd_conn, buf, msgsize,
				&pbuf);
		x_buf_release(buf);
		if (plen < 0) {
			return plen;
		}
		if (len < 4) {
			x_buf_release(pbuf);
			return -EBADMSG;
		}

		buf = pbuf;
		msgsize = plen;
		smbhdr = x_get_be32(buf->data + offset);
	}

	x_smbd_ptr_t<x_smbd_requ_t> smbd_requ{x_smbd_requ_create(buf,
			msgsize, encrypted)};
	
	if (smbhdr == X_SMB2_MAGIC) {
		if (len < sizeof(x_smb2_header_t)) {
			return -EBADMSG;
		}
		return x_smbd_conn_process_smb2(smbd_conn, smbd_requ, 0);
	} else if (smbhdr == X_SMB2_TF_MAGIC) {
		return -EBADMSG;
	} else if (smbhdr == X_SMB2_CTF_MAGIC) {
		return -EBADMSG;
	} else if (smbhdr == X_SMB1_MAGIC) {
		uint8_t cmd = buf->data[4];
		if (/* TODO smbd_conn->is_negotiated || */cmd != SMBnegprot) {
			return -EBADMSG;
		}
		smbd_requ->in_smb2_hdr = {
			.credit_charge = 1,
			.opcode = X_SMB2_OP_NEGPROT,
		};

		if (!x_smb2_validate_message_id(smbd_conn, smbd_requ)) {
			return -EBADMSG;
		}

		smbd_requ->start = tick_now = x_tick_now();

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

#define NBSSmessage     0x00   /* session message */
static int x_smbd_conn_process_nbt(x_smbd_conn_t *smbd_conn)
{
	int err;

	if ((smbd_conn->nbt_hdr >> 24) == NBSSmessage) {
		x_buf_t *buf = smbd_conn->recv_buf;
		smbd_conn->recv_buf = nullptr;
		err = x_smbd_conn_process_smb(smbd_conn, buf, smbd_conn->recv_msgsize);
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
			return -EBADMSG;
		}
	}
	return 0;
}

static bool x_smbd_conn_do_recv(x_smbd_conn_t *smbd_conn, x_fdevents_t &fdevents)
{
	X_TRACE_LOC;
	ssize_t err;
	X_LOG(SMB, DBG, "conn %p x%lx x%lx", smbd_conn, smbd_conn->ep_id, fdevents);
	if (smbd_conn->recv_buf == NULL) {
		X_ASSERT(smbd_conn->recv_len < sizeof(smbd_conn->nbt_hdr));
		err = read(smbd_conn->fd, (char *)&smbd_conn->nbt_hdr + smbd_conn->recv_len,
				sizeof(smbd_conn->nbt_hdr) - smbd_conn->recv_len);
		if (err > 0) {
			smbd_conn->recv_len = x_convert_assert<uint32_t>(smbd_conn->recv_len + err);
			err = x_smbd_conn_check_nbt_hdr(smbd_conn);
			if (err < 0) {
				X_LOG(SMB, ERR, "%p x%lx x_smbd_conn_check_nbt_hdr %ld",
						smbd_conn, smbd_conn->ep_id, err);
				return true;
			} else if (err == 0) {
				return false;
			}
			smbd_conn->recv_msgsize = x_convert_assert<uint32_t>(err);
		} else if (err == 0) {
			X_LOG(SMB, CONN, "%p x%lx recv nbt_hdr EOF", smbd_conn, smbd_conn->ep_id);
			return true;
		} else if (errno == EAGAIN) {
			fdevents = x_fdevents_consume(fdevents, FDEVT_IN);
			return false;
		} else if (errno == EINTR) {
			return false;
		} else {
			X_LOG(SMB, ERR, "%p x%lx do_recv errno=%d",
					smbd_conn, smbd_conn->ep_id, errno);
			return true;
		}
	}

	uint32_t next_nbt_hdr;
	struct iovec iovec[2] = {
		{ smbd_conn->recv_buf->data + smbd_conn->recv_len, smbd_conn->recv_msgsize - smbd_conn->recv_len, },
		{ &next_nbt_hdr, sizeof(next_nbt_hdr), }
	};

	err = readv(smbd_conn->fd, iovec, 2);
	if (err > 0) {
		smbd_conn->recv_len = x_convert_assert<uint32_t>(smbd_conn->recv_len + err);
		if (smbd_conn->recv_len >= smbd_conn->recv_msgsize) {
			smbd_conn->recv_len -= smbd_conn->recv_msgsize;
			int ret = x_smbd_conn_process_nbt(smbd_conn);
			if (ret) {
				X_LOG(SMB, ERR, "%p x%lx x_smbd_conn_process_nbt %d",
						smbd_conn, smbd_conn->ep_id, ret);
				return true;
			}

			X_ASSERT(smbd_conn->recv_len <= sizeof(smbd_conn->nbt_hdr));
			smbd_conn->nbt_hdr = next_nbt_hdr;

			err = x_smbd_conn_check_nbt_hdr(smbd_conn);
			if (err < 0) {
				X_LOG(SMB, ERR, "%p x%lx x_smbd_conn_check_nbt_hdr piggyback %ld",
						smbd_conn, smbd_conn->ep_id, err);
				return true;
			} else if (err == 0) {
				return false;
			}
			smbd_conn->recv_msgsize = x_convert_assert<uint32_t>(err);
		}
	} else if (err == 0) {
		X_LOG(SMB, CONN, "%p x%lx recv nbt_body EOF", smbd_conn, smbd_conn->ep_id);
		return true;
	} else if (errno == EAGAIN) {
		fdevents = x_fdevents_consume(fdevents, FDEVT_IN);
	} else if (errno == EINTR) {
	} else {
		X_LOG(SMB, ERR, "%p x%lx do_recv errno=%d",
				smbd_conn, smbd_conn->ep_id, errno);
		return true;
	}
	return false;
}

static bool x_smbd_conn_do_send(x_smbd_conn_t *smbd_conn, x_fdevents_t &fdevents)
{
	X_LOG(SMB, DBG, "conn %p x%lx x%lx", smbd_conn, smbd_conn->ep_id, fdevents);
	bool ret = smbd_conn->send_queue.send(smbd_conn->fd, fdevents);
	if (!ret && smbd_conn->count_msg < x_smbd_conn_t::MAX_MSG) {
		fdevents = x_fdevents_enable(fdevents, FDEVT_IN);
	}
	return ret;
}

static bool x_smbd_conn_do_user(x_smbd_conn_t *smbd_conn, x_fdevents_t &fdevents)
{
	X_LOG(SMB, DBG, "%p x%lx x%lx", smbd_conn, smbd_conn->ep_id, fdevents);
	auto lock = std::unique_lock(smbd_conn->mutex);
	for (;;) {
		x_fdevt_user_t *fdevt_user = smbd_conn->fdevt_user_list.get_front();
		if (!fdevt_user) {
			break;
		}
		smbd_conn->fdevt_user_list.remove(fdevt_user);
		lock.unlock();

		fdevt_user->func(smbd_conn, fdevt_user);

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

const x_smbd_negprot_t &x_smbd_conn_curr_negprot()
{
	return g_smbd_conn_curr->negprot;
}

const x_smb2_uuid_t &x_smbd_conn_curr_client_guid()
{
	return g_smbd_conn_curr->negprot.client_guid;
}

uint16_t x_smbd_conn_curr_dialect()
{
	return g_smbd_conn_curr->negprot.dialect;
}

uint16_t x_smbd_conn_curr_get_signing_algo()
{
	return g_smbd_conn_curr->negprot.signing_algo;
}

uint16_t x_smbd_conn_curr_get_cryption_algo()
{
	return g_smbd_conn_curr->negprot.cryption_algo;
}

std::shared_ptr<std::u16string> x_smbd_conn_curr_name()
{
	return g_smbd_conn_curr->machine_name;
}

static bool x_smbd_conn_upcall_cb_getevents(x_epoll_upcall_t *upcall, x_fdevents_t &fdevents)
{
	x_smbd_conn_t *smbd_conn = x_smbd_conn_from_upcall(upcall);
	X_LOG(SMB, DBG, "%p x%lx", smbd_conn, fdevents);

	x_smbd_conf_pin_t smbd_conf_pin;
	x_smbd_scheduler_t smbd_scheduler;
	smbd_conn_curr_t smbd_conn_curr(smbd_conn);

	return x_smbd_conn_handle_events(smbd_conn, fdevents);
}

static void x_smbd_conn_upcall_cb_unmonitor(x_epoll_upcall_t *upcall)
{
	x_smbd_conn_t *smbd_conn = x_smbd_conn_from_upcall(upcall);
	X_LOG(SMB, CONN, "%p", smbd_conn);
	X_ASSERT_SYSCALL(close(smbd_conn->fd));
	smbd_conn->fd = -1;

	x_smbd_conf_pin_t smbd_conf_pin;
	x_smbd_scheduler_t smbd_scheduler;
	smbd_conn_curr_t smbd_conn_curr(smbd_conn);

	x_smbd_conn_terminate_chans(smbd_conn);
	x_smbd_requ_t *smbd_requ, *next_requ;
	for (smbd_requ = smbd_conn->pending_requ_list.get_front(); smbd_requ;
			smbd_requ = next_requ) {
		next_requ = smbd_conn->pending_requ_list.next(smbd_requ);
		uint32_t chan_count;
		if (smbd_requ->in_smb2_hdr.opcode != X_SMB2_OP_CREATE ||
				!smbd_requ->smbd_sess ||
				(chan_count = x_smbd_sess_get_chan_count(smbd_requ->smbd_sess)) == 0) {
			x_smbd_requ_done(smbd_requ);
			X_ASSERT(x_smbd_requ_async_remove(smbd_requ));
		} else {
			X_SMBD_REQU_LOG(DBG, smbd_requ, " with %u alternate channels",
					chan_count);
		}
	}

	{
		auto lock = std::lock_guard(smbd_conn->mutex);
		smbd_conn->state = x_smbd_conn_t::STATE_DONE;
		for (;;) {
			x_fdevt_user_t *fdevt_user = smbd_conn->fdevt_user_list.get_front();
			if (!fdevt_user) {
				break;
			}
			smbd_conn->fdevt_user_list.remove(fdevt_user);
			fdevt_user->func(nullptr, fdevt_user);
		}
	}

	x_ref_dec(smbd_conn);
}

static const x_epoll_upcall_cbs_t x_smbd_conn_upcall_cbs = {
	x_smbd_conn_upcall_cb_getevents,
	x_smbd_conn_upcall_cb_unmonitor,
};

x_smbd_conn_t::x_smbd_conn_t(int fd, const x_sockaddr_t &saddr,
		uint32_t max_credits)
	: upcall{&x_smbd_conn_upcall_cbs}, fd(fd), saddr(saddr)
	, machine_name{std::make_shared<std::u16string>(machine_name_from_saddr(saddr))}
	, tick_create(tick_now)
	, seq_bitmap(max_credits)
{
	X_SMBD_COUNTER_INC_CREATE(conn, 1);
	negprot.dialect = X_SMB2_DIALECT_000;
}

x_smbd_conn_t::~x_smbd_conn_t()
{
	X_LOG(SMB, DBG, "x_smbd_conn_t %p destroy", this);
	X_ASSERT(!chan_list.get_front());
	X_ASSERT(fd == -1);

	if (recv_buf) {
		x_buf_release(recv_buf);
	}
	X_SMBD_COUNTER_INC_DELETE(conn, 1);
}

static inline x_smbd_srv_t *x_smbd_from_strm_srv(x_strm_srv_t *strm_srv)
{
	return X_CONTAINER_OF(strm_srv, x_smbd_srv_t, base);
}

static void x_smbd_srv_cb_accepted(x_strm_srv_t *strm_srv, int fd,
			const struct sockaddr *sa, socklen_t slen)
{
	x_sockaddr_t *saddr = (x_sockaddr_t *)sa;
	X_ASSERT(slen <= sizeof(*saddr));
	X_LOG(SMB, CONN, "accept %d from %s", fd, saddr->tostring().c_str());
	set_nbio(fd, 1);
	x_smbd_conf_pin_t smbd_conf_pin;
	const x_smbd_conf_t &smbd_conf = x_smbd_conf_get_curr();
	x_smbd_conn_t *smbd_conn = new x_smbd_conn_t(fd, *saddr,
			smbd_conf.smb2_max_credits);
	X_ASSERT(smbd_conn != NULL);
	smbd_conn->ep_id = x_evtmgmt_monitor(g_evtmgmt, fd, FDEVT_IN | FDEVT_OUT, &smbd_conn->upcall);
	x_evtmgmt_enable_events(g_evtmgmt, smbd_conn->ep_id,
			FDEVT_IN | FDEVT_ERR | FDEVT_SHUTDOWN | FDEVT_USER);
}

static void x_smbd_srv_cb_shutdown(x_strm_srv_t *strm_srv)
{
	x_smbd_srv_t *smbd_srv = x_smbd_from_strm_srv(strm_srv);
	X_LOG(SMB, CONN, "%p", smbd_srv);
	/* TODO may close all accepted client, and notify it is freed */
}

static bool x_smbd_srv_cb_user(x_strm_srv_t *strm_srv)
{
	x_smbd_srv_t *smbd_srv = x_smbd_from_strm_srv(strm_srv);
	auto lock = std::lock_guard(smbd_srv->mutex);
	for (;;) {
		x_fdevt_user_t *fdevt_user = smbd_srv->fdevt_user_list.get_front();
		if (!fdevt_user) {
			break;
		}
		smbd_srv->fdevt_user_list.remove(fdevt_user);
		fdevt_user->func(nullptr, fdevt_user);
	}
	return false;
}

static const x_strm_srv_cbs_t smbd_srv_cbs = {
	x_smbd_srv_cb_accepted,
	x_smbd_srv_cb_shutdown,
	x_smbd_srv_cb_user,
};

static x_smbd_srv_t g_smbd_srv;
int x_smbd_conn_srv_init(int port)
{
	return x_tcp_srv_init(&g_smbd_srv.base, port, &smbd_srv_cbs);
}

bool x_smbd_conn_post_user(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user,
		bool always)
{
	bool notify = false;
	bool queued = false;
	{
		auto lock = std::lock_guard(smbd_conn->mutex);
		if (smbd_conn->state != x_smbd_conn_t::STATE_DONE) {
			notify = smbd_conn->fdevt_user_list.get_front() == nullptr;
			smbd_conn->fdevt_user_list.push_back(fdevt_user);
			queued = true;
		}
	}
	if (notify) {
		x_evtmgmt_post_events(g_evtmgmt, smbd_conn->ep_id, FDEVT_USER);
	}
	if (queued) {
		return true;
	} else if (!always) {
		return false;
	}
	/* queued to srv's user event queue to clean up the request */
	X_LOG(SMB, WARN, "smbd_conn %p is done, queued to srv", smbd_conn);
	{
		auto lock = std::lock_guard(g_smbd_srv.mutex);
		notify = g_smbd_srv.fdevt_user_list.get_front() == nullptr;
		g_smbd_srv.fdevt_user_list.push_back(fdevt_user);
	}
	if (notify) {
		x_evtmgmt_post_events(g_evtmgmt, g_smbd_srv.base.ep_id, FDEVT_USER);
	}
	return true;
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
	X_ASSERT(!NT_STATUS_EQUAL(status, NT_STATUS_PENDING));

	if (!is_success(status)) {
		smbd_requ->status = status;
		X_SMBD_REPLY_ERROR(smbd_conn, smbd_requ, status);
	}

	x_smbd_requ_done(smbd_requ);
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
	static void func(void *arg, x_fdevt_user_t *fdevt_user)
	{
		x_smbd_conn_t *smbd_conn = (x_smbd_conn_t *)arg;
		x_smbd_cancel_evt_t *evt = X_CONTAINER_OF(fdevt_user, x_smbd_cancel_evt_t, base);
		x_smbd_requ_t *smbd_requ = evt->smbd_requ;
		X_LOG(SMB, DBG, "evt=%p, requ=%p, smbd_conn=%p", evt, smbd_requ, smbd_conn);

		x_smbd_requ_async_done(smbd_conn, smbd_requ, evt->status);

		delete evt;
	}

	explicit x_smbd_cancel_evt_t(x_smbd_requ_t *smbd_requ, NTSTATUS status)
		: base(func), smbd_requ(smbd_requ), status(status)
	{
	}
	~x_smbd_cancel_evt_t()
	{
		x_ref_dec(smbd_requ);
	}
	x_fdevt_user_t base;
	x_smbd_requ_t * const smbd_requ;
	NTSTATUS const status;
};

void x_smbd_conn_post_cancel(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
		NTSTATUS status)
{
	x_smbd_cancel_evt_t *evt = new x_smbd_cancel_evt_t(smbd_requ, status);
	x_smbd_conn_post_user(smbd_conn, &evt->base, true);
}

NTSTATUS x_smbd_conn_validate_negotiate_info(const x_smbd_conn_t *smbd_conn,
		x_smb2_fsctl_validate_negotiate_info_state_t &fsctl_state)
{
	if (fsctl_state.in_capabilities != smbd_conn->negprot.client_capabilities) {
		return X_NT_STATUS_INTERNAL_TERMINATE;
	}

	if (!(fsctl_state.in_guid == smbd_conn->negprot.client_guid)) {
		return X_NT_STATUS_INTERNAL_TERMINATE;
	}

	if (fsctl_state.in_security_mode != smbd_conn->negprot.client_security_mode) {
		return X_NT_STATUS_INTERNAL_TERMINATE;
	}

	const x_smbd_conf_t &smbd_conf = x_smbd_conf_get_curr();
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
	uint16_t dialect = x_smb2_dialect_match(smbd_conf.dialects, 
			fsctl_state.in_dialects.data(),
			fsctl_state.in_dialects.size());

	if (dialect != smbd_conn->negprot.dialect) {
		return X_NT_STATUS_INTERNAL_TERMINATE;
	}

	fsctl_state.out_capabilities = smbd_conn->negprot.server_capabilities;
	fsctl_state.out_guid = smbd_conf.guid;
	fsctl_state.out_security_mode = smbd_conn->negprot.server_security_mode;
	fsctl_state.out_dialect = smbd_conn->negprot.dialect;

	return NT_STATUS_OK;
}

struct send_interim_evt_t
{
	static void func(void *arg, x_fdevt_user_t *fdevt_user)
	{
		x_smbd_conn_t *smbd_conn = (x_smbd_conn_t *)arg;
		send_interim_evt_t *evt = X_CONTAINER_OF(fdevt_user,
				send_interim_evt_t, base);
		x_smbd_requ_t *smbd_requ = evt->smbd_requ;
		X_LOG(SMB, DBG, "evt=%p, requ=%p, smbd_conn=%p", evt, smbd_requ, smbd_conn);
		if (smbd_requ->interim_state == x_smbd_requ_t::INTERIM_S_SCHEDULED) {
			X_SMBD_REPLY_INTERIM(smbd_conn, smbd_requ);
		} else {
			X_ASSERT(smbd_requ->interim_state != x_smbd_requ_t::INTERIM_S_SENT);
		}
		delete evt;
	}

	explicit send_interim_evt_t(x_smbd_requ_t *smbd_requ)
		: base(func), smbd_requ(smbd_requ)
	{
	}

	~send_interim_evt_t()
	{
		x_ref_dec(smbd_requ);
	}

	x_fdevt_user_t base;
	x_smbd_requ_t * const smbd_requ;
};

void x_smbd_conn_post_interim(x_smbd_requ_t *smbd_requ)
{
	send_interim_evt_t *evt = new send_interim_evt_t(smbd_requ);
	x_smbd_chan_post_user(smbd_requ->smbd_chan, &evt->base, false);
}

