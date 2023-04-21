
#include "smbd.hxx"
#include "smbd_stats.hxx"
#include "smbd_conf.hxx"
#include "smbd_open.hxx"
#include <sys/uio.h>

enum {
	MAX_MSG_SIZE = 0x1000000,
};

struct x_smbd_srv_t
{
	x_epoll_upcall_t upcall;
	uint64_t ep_id;
	int fd;
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
	uint16_t cryption_algo = X_SMB2_ENCRYPTION_INVALID_ALGO;
	uint16_t signing_algo = X_SMB2_SIGNING_INVALID_ALGO;
	uint16_t dialect = X_SMB2_DIALECT_000;

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
	uint32_t recv_len = 0, recv_msgsize = 0;
	x_buf_t *recv_buf{};
	x_bufref_t *send_buf_head{}, *send_buf_tail{};

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
	return x_convert_utf8_to_utf16_assert(buf);
}

x_smbd_conn_t::x_smbd_conn_t(int fd, const x_sockaddr_t &saddr,
		uint32_t max_credits)
	: fd(fd), saddr(saddr)
	, machine_name{std::make_shared<std::u16string>(machine_name_from_saddr(saddr))}
	, tick_create(tick_now)
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
	if (x_unlikely(--smbd_conn->refcnt == 0)) {
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
	if (smbd_conn->dialect >= X_SMB2_DIALECT_310) {
		return &smbd_conn->preauth;
	} else {
		return nullptr;
	}
}

uint16_t x_smbd_conn_get_dialect(const x_smbd_conn_t *smbd_conn)
{
	return smbd_conn->dialect;
}

uint16_t x_smbd_conn_get_cryption_algo(const x_smbd_conn_t *smbd_conn)
{
	return smbd_conn->cryption_algo;
}

uint32_t x_smbd_conn_get_capabilities(const x_smbd_conn_t *smbd_conn)
{
	return smbd_conn->server_capabilities;
}

int x_smbd_conn_negprot(x_smbd_conn_t *smbd_conn,
		uint16_t dialect,
		uint16_t encryption_algo,
		uint16_t signing_algo,
		uint16_t client_security_mode,
		uint16_t server_security_mode,
		uint32_t client_capabilities,
		uint32_t server_capabilities,
		const x_smb2_uuid_t &client_guid)
{
	if (smbd_conn->dialect != X_SMB2_DIALECT_000 &&
			smbd_conn->dialect != X_SMB2_DIALECT_2FF) {
		return -EBADMSG;
	}
	smbd_conn->dialect = dialect;
	smbd_conn->cryption_algo = encryption_algo;
	if (signing_algo == X_SMB2_SIGNING_INVALID_ALGO) {
		if (dialect >= X_SMB2_DIALECT_224) {
			signing_algo = X_SMB2_SIGNING_AES128_CMAC;
		} else {
			signing_algo = X_SMB2_SIGNING_HMAC_SHA256;
		}
	}
	smbd_conn->signing_algo = signing_algo;
	smbd_conn->client_security_mode = client_security_mode;
	smbd_conn->server_security_mode = server_security_mode;
	smbd_conn->client_capabilities = client_capabilities;
	smbd_conn->server_capabilities = server_capabilities;
	smbd_conn->client_guid = client_guid;
	return 0;
}

int x_smbd_conn_negprot_smb1(x_smbd_conn_t *smbd_conn)
{
	if (smbd_conn->dialect != X_SMB2_DIALECT_000) {
		return -EBADMSG;
	}
	smbd_conn->dialect = X_SMB2_DIALECT_2FF;
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
	if (flags & X_SMB2_HDR_FLAG_SIGNED) {
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

	int clen = x_smb2_signing_encrypt(smbd_conn->cryption_algo,
			key, tf_hdr,
			smbd_requ->out_buf_head, smbd_requ->out_length);

	if (clen < 0) {
		X_LOG_DBG("x_smb2_signing_encrypt(%u) error %d",
				smbd_conn->cryption_algo, clen);
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
	smbd_requ->out_hdr_flags = calculate_out_hdr_flags(smbd_requ->in_smb2_hdr.flags, smbd_requ->out_hdr_flags);
	x_smb2_header_t *smb2_hdr = (x_smb2_header_t *)buf_head->get_data();
	smb2_hdr->protocol_id = X_H2BE32(X_SMB2_MAGIC);
	smb2_hdr->length = X_H2LE32(sizeof(x_smb2_header_t));
	smb2_hdr->credit_charge = X_H2LE16(smbd_requ->in_smb2_hdr.credit_charge);
	smb2_hdr->status = X_H2LE32(NT_STATUS_V(status));
	smb2_hdr->opcode = X_H2LE16(smbd_requ->in_smb2_hdr.opcode);
	smb2_hdr->credit = X_H2LE16(smbd_requ->out_credit_granted);
	smb2_hdr->next_command = 0;
	smb2_hdr->mid = X_H2LE64(smbd_requ->in_smb2_hdr.mid);
	if (smbd_requ->async) {
		smb2_hdr->flags = X_H2LE32(smbd_requ->out_hdr_flags |
				X_SMB2_HDR_FLAG_REDIRECT | X_SMB2_HDR_FLAG_ASYNC);
		smb2_hdr->async_id = X_H2LE64(x_smbd_requ_get_async_id(smbd_requ));
	} else {
		smb2_hdr->flags = X_H2LE32(smbd_requ->out_hdr_flags |
				X_SMB2_HDR_FLAG_REDIRECT);
		smb2_hdr->pid = X_H2LE32(0xfeff);
		if (smbd_requ->smbd_tcon) {
			smb2_hdr->tid = X_H2LE32(x_smbd_tcon_get_id(smbd_requ->smbd_tcon));
		} else {
			smb2_hdr->tid = X_H2LE32(smbd_requ->in_smb2_hdr.tid);
		}
	}

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
	if (!smbd_requ->async) {
		smbd_requ->out_credit_granted = x_smb2_calculate_credit(smbd_conn, smbd_requ, status);
	} else {
		smbd_requ->out_credit_granted = 0;
	}

	smbd_conn_reply_update_counts(smbd_conn, smbd_requ);
	x_smb2_reply_msg(smbd_conn, smbd_requ, buf_head, buf_tail, status, reply_size);
}

static int x_smbd_reply_error(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
		NTSTATUS status,
		const char *file, unsigned int line)
{
	X_LOG_OP("%ld RESP 0x%x at %s:%d", smbd_requ->in_smb2_hdr.mid,
			NT_STATUS_V(status), file, line);

	x_buf_t *out_buf = x_buf_alloc_out_buf(8);

	uint8_t *out_hdr = x_buf_get_out_hdr(out_buf);

	uint8_t *out_body = out_hdr + sizeof(x_smb2_header_t);
	memset(out_body, 0, 8);
	x_put_le16(out_body, 0x9);

	x_bufref_t *bufref = new x_bufref_t{out_buf, 8, sizeof(x_smb2_header_t) + 8};
	x_smb2_reply(smbd_conn, smbd_requ, bufref, bufref, status, sizeof(x_smb2_header_t) + 8);

	return 0;
}

#define X_SMBD_REPLY_ERROR(smbd_conn, smbd_requ, status) \
	x_smbd_reply_error((smbd_conn), (smbd_requ), (status), __FILE__, __LINE__)

static int x_smbd_reply_interim(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
		const char *file, unsigned int line)
{
	X_LOG_OP("%ld RESP ASYNC at %s:%d", smbd_requ->in_smb2_hdr.mid, file, line);

	smbd_requ->out_credit_granted = x_smb2_calculate_credit(smbd_conn, smbd_requ, NT_STATUS_PENDING);
	smbd_requ->out_hdr_flags = calculate_out_hdr_flags(smbd_requ->in_smb2_hdr.flags, smbd_requ->out_hdr_flags);

	x_buf_t *out_buf = x_buf_alloc_out_buf(8);

	uint8_t *out_hdr = x_buf_get_out_hdr(out_buf);

	uint8_t *out_body = out_hdr + sizeof(x_smb2_header_t);
	memset(out_body, 0, 8);
	x_put_le16(out_body, 0x9);

	smbd_requ->async = true;

	x_bufref_t *bufref = new x_bufref_t{out_buf, 8, sizeof(x_smb2_header_t) + 8};
	x_smb2_reply_msg(smbd_conn, smbd_requ, bufref, bufref, NT_STATUS_PENDING, sizeof(x_smb2_header_t) + 8);
	return 0;
}

#define X_SMBD_REPLY_INTERIM(smbd_conn, smbd_requ) \
	x_smbd_reply_interim((smbd_conn), (smbd_requ), __FILE__, __LINE__)

/* must be in context of smbd_conn */
void x_smbd_requ_async_insert(x_smbd_requ_t *smbd_requ,
		void (*cancel_fn)(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ))
{
	X_ASSERT(!smbd_requ->cancel_fn);
	smbd_requ->cancel_fn = cancel_fn;
	smbd_requ->async = true;
	g_smbd_conn_curr->pending_requ_list.push_back(smbd_requ);
	x_smbd_ref_inc(smbd_requ);
}

/* must be in context of smbd_conn */
bool x_smbd_requ_async_remove(x_smbd_requ_t *smbd_requ)
{
	X_ASSERT(smbd_requ->async);
	if (!smbd_requ->cancel_fn) {
		return false;
	}
	g_smbd_conn_curr->pending_requ_list.remove(smbd_requ);
	smbd_requ->cancel_fn = nullptr;
	x_smbd_ref_dec(smbd_requ);
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
		X_LOG_ERR("cannot find pending requ by flags=0x%x, async_id=x%lx, mid=%lu",
				smb2_hdr.flags, smb2_hdr.async_id, smb2_hdr.mid);
		return;
	}

	auto cancel_fn = smbd_requ->cancel_fn;
	smbd_requ->cancel_fn = nullptr;
	smbd_conn->pending_requ_list.remove(smbd_requ);
	cancel_fn(smbd_conn, smbd_requ);

	x_smbd_ref_dec(smbd_requ);
}

void x_smbd_conn_send_unsolicited(x_smbd_conn_t *smbd_conn, x_smbd_sess_t *smbd_sess,
		x_bufref_t *buf, uint16_t opcode)
{
	x_smb2_header_t *smb2_hdr = (x_smb2_header_t *)buf->get_data();
	smb2_hdr->protocol_id = X_H2BE32(X_SMB2_MAGIC);
	smb2_hdr->length = X_H2LE32(sizeof(x_smb2_header_t));
	smb2_hdr->credit_charge = 0;
	smb2_hdr->status = 0;
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

	x_smbd_conn_queue(smbd_conn, buf, buf, buf->length);
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

	if (smbd_conn->dialect < X_SMB2_DIALECT_300) {
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

static NTSTATUS x_smbd_conn_process_smb2_intl(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	if (smbd_requ->in_smb2_hdr.flags & X_SMB2_HDR_FLAG_ASYNC) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if ((smbd_requ->in_smb2_hdr.flags & X_SMB2_HDR_FLAG_CHAINED) == 0) {
		if (smbd_requ->smbd_open) {
			X_SMBD_REF_DEC(smbd_requ->smbd_open);
		}
		if (smbd_requ->smbd_tcon) {
			X_SMBD_REF_DEC(smbd_requ->smbd_tcon);
		}
		if (smbd_requ->smbd_chan) {
			X_SMBD_REF_DEC(smbd_requ->smbd_chan);
		}
		if (smbd_requ->smbd_sess) {
			X_SMBD_REF_DEC(smbd_requ->smbd_sess);
		}
		smbd_requ->sess_status = NT_STATUS_OK;
	}

	NTSTATUS sess_status = NT_STATUS_OK;
	if (!smbd_requ->smbd_sess && smbd_requ->in_smb2_hdr.sess_id != 0 &&
			smbd_requ->in_smb2_hdr.sess_id != UINT64_MAX) {
		smbd_requ->smbd_sess = x_smbd_sess_lookup(sess_status,
				smbd_requ->in_smb2_hdr.sess_id,
				smbd_conn->client_guid);
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
				RETURN_OP_STATUS(smbd_requ, NT_STATUS_NETWORK_SESSION_EXPIRED);
			}
		} else if (!NT_STATUS_IS_OK(smbd_requ->sess_status)) {
			RETURN_OP_STATUS(smbd_requ, smbd_requ->sess_status);
		}
		if (!smbd_requ->smbd_sess) {
			RETURN_OP_STATUS(smbd_requ, NT_STATUS_USER_SESSION_DELETED);
		}
		if (!smbd_requ->smbd_chan ||  !x_smbd_chan_is_active(smbd_requ->smbd_chan)) {
			RETURN_OP_STATUS(smbd_requ, NT_STATUS_USER_SESSION_DELETED);
		}
	}

	bool signing_required = false;
	if (!smbd_requ->encrypted && smbd_requ->smbd_sess) {
		signing_required = x_smbd_sess_is_signing_required(smbd_requ->smbd_sess);
	}

	if (smbd_requ->is_signed()) {
		if (smbd_requ->in_smb2_hdr.opcode == X_SMB2_OP_NEGPROT) {
			RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
		}
		if (!smbd_requ->smbd_sess) {
			RETURN_OP_STATUS(smbd_requ, NT_STATUS_USER_SESSION_DELETED);
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
			RETURN_OP_STATUS(smbd_requ, NT_STATUS_ACCESS_DENIED);
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
	}

	smbd_requ->async = false;

	return op.op_func(smbd_conn, smbd_requ);
}

static bool x_smb2_validate_message_id(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	X_ASSERT(smbd_requ->in_smb2_hdr.opcode != X_SMB2_OP_CANCEL);

	uint16_t credit_charge = std::max(smbd_requ->in_smb2_hdr.credit_charge, uint16_t(1u));

	if (smbd_conn->credit_granted < credit_charge) {
		X_LOG_ERR("credit_charge %u > credit_granted %lu",
				credit_charge, smbd_conn->credit_granted);
		return false;
	}

	if (!x_check_range<uint64_t>(smbd_requ->in_smb2_hdr.mid, credit_charge, smbd_conn->credit_seq_low,
				smbd_conn->credit_seq_low + smbd_conn->credit_seq_range)) {
		X_LOG_ERR("%lu+%u not in the credit range %lu+%lu", smbd_requ->in_smb2_hdr.mid, credit_charge,
				smbd_conn->credit_seq_low, smbd_conn->credit_seq_range);
		return false;
	}

	auto &seq_bitmap = smbd_conn->seq_bitmap;
	uint64_t id = smbd_requ->in_smb2_hdr.mid;
	for (uint16_t i = 0; i < credit_charge; ++i, ++id) {
		uint64_t offset = id % seq_bitmap.size();
		if (seq_bitmap[offset]) {
			X_LOG_ERR("duplicated mid %lu", id);
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

		if (smbd_requ->in_smb2_hdr.opcode == X_SMB2_OP_CANCEL) {
			x_smbd_conn_cancel(smbd_conn, smbd_requ->in_smb2_hdr);
			continue;
		}


		smbd_requ->cancel_fn = nullptr;
		if (!x_smb2_validate_message_id(smbd_conn, smbd_requ)) {
			return -EBADMSG;
		}

		if (false && !NT_STATUS_IS_OK(smbd_requ->status) && (smbd_requ->in_smb2_hdr.flags & X_SMB2_HDR_FLAG_CHAINED)) {
			X_SMBD_REPLY_ERROR(smbd_conn, smbd_requ, smbd_requ->status);
			continue;
		}

		memcpy(smbd_requ->in_smb2_hdr.signature, in_smb2_hdr->signature,
				sizeof(in_smb2_hdr->signature));

		NTSTATUS status = x_smbd_conn_process_smb2_intl(
				smbd_conn, smbd_requ);
		if (NT_STATUS_EQUAL(status, NT_STATUS_PENDING)) {
			X_SMBD_REPLY_INTERIM(smbd_conn, smbd_requ);
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
	if (smbd_requ->out_length > 0) {
		x_smbd_conn_queue(smbd_conn, smbd_requ);
	}
	return 0;
}

static int x_smbd_conn_process_smb2_tf(x_smbd_conn_t *smbd_conn,
		x_buf_t *buf, uint32_t total_size,
		x_buf_t **out_buf)
{
	if (smbd_conn->dialect < X_SMB2_DIALECT_300) {
		return -EBADMSG;
	}

	if (smbd_conn->cryption_algo == X_SMB2_ENCRYPTION_INVALID_ALGO) {
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
				sess_id, smbd_conn->client_guid);
	if (!smbd_sess) {
		return -EBADMSG;
	}

	x_buf_t *pbuf = x_buf_alloc(msgsize);
	int plen = x_smb2_signing_decrypt(smbd_conn->cryption_algo,
			x_smbd_sess_get_decryption_key(smbd_sess),
			smb2_tf, smb2_tf + 1, msgsize,
			pbuf->data);

	x_smbd_ref_dec(smbd_sess);

	if (plen < 0) {
		X_LOG_DBG("x_smb2_signing_decrypt(%u) error %d",
				smbd_conn->cryption_algo, plen);
		x_buf_release(pbuf);
		return -EBADMSG;
	}

	*out_buf = pbuf;
	return plen;
}

#define SMBnegprot    0x72   /* negotiate protocol */
static int x_smbd_conn_process_smb(x_smbd_conn_t *smbd_conn, x_buf_t *buf, uint32_t msgsize)
{
	uint32_t offset = 0;
	// uint8_t *inbuf = buf->data + offset;
	size_t len = msgsize - offset;
	if (len < 4) {
		return -EBADMSG;
	}
	int32_t smbhdr = x_get_be32(buf->data + offset);
	bool encrypted = false;

	if (smbhdr == X_SMB2_TF_MAGIC) {
		if (len < sizeof(x_smb2_tf_header_t)) {
			return -EBADMSG;
		}
		x_buf_t *pbuf;
		int plen = x_smbd_conn_process_smb2_tf(smbd_conn, buf, msgsize,
				&pbuf);
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

	x_smbd_ptr_t<x_smbd_requ_t> smbd_requ{x_smbd_requ_create(x_buf_get(buf),
			msgsize, encrypted)};
	
	if (smbhdr == X_SMB2_MAGIC) {
		if (len < sizeof(x_smb2_header_t)) {
			return -EBADMSG;
		}
		return x_smbd_conn_process_smb2(smbd_conn, smbd_requ, 0);
	} else if (smbhdr == X_SMB2_TF_MAGIC) {
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
			return -EBADMSG;
		}
	}
	return 0;
}

static bool x_smbd_conn_do_recv(x_smbd_conn_t *smbd_conn, x_fdevents_t &fdevents)
{
	ssize_t err;
	X_LOG_DBG("%s %p x%lx x%lx", task_name, smbd_conn, smbd_conn->ep_id, fdevents);
	if (smbd_conn->recv_buf == NULL) {
		X_ASSERT(smbd_conn->recv_len < sizeof(smbd_conn->nbt_hdr));
		err = read(smbd_conn->fd, (char *)&smbd_conn->nbt_hdr + smbd_conn->recv_len,
				sizeof(smbd_conn->nbt_hdr) - smbd_conn->recv_len);
		if (err > 0) {
			smbd_conn->recv_len = x_convert_assert<uint32_t>(smbd_conn->recv_len + err);
			err = x_smbd_conn_check_nbt_hdr(smbd_conn);
			if (err < 0) {
				X_LOG_ERR("%s %p x%lx x_smbd_conn_check_nbt_hdr %ld",
						task_name, smbd_conn, smbd_conn->ep_id, err);
				return true;
			} else if (err == 0) {
				return false;
			}
			smbd_conn->recv_msgsize = x_convert_assert<uint32_t>(err);
		} else if (err == 0) {
			X_LOG_CONN("%s %p x%lx recv nbt_hdr EOF", task_name, smbd_conn, smbd_conn->ep_id);
			return true;
		} else if (errno == EAGAIN) {
			fdevents = x_fdevents_consume(fdevents, FDEVT_IN);
			return false;
		} else if (errno == EINTR) {
			return false;
		} else {
			X_LOG_ERR("%s %p x%lx do_recv errno=%d", task_name,
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
				X_LOG_ERR("%s %p x%lx x_smbd_conn_process_nbt %d",
						task_name, smbd_conn, smbd_conn->ep_id, ret);
				return true;
			}

			X_ASSERT(smbd_conn->recv_len <= sizeof(smbd_conn->nbt_hdr));
			smbd_conn->nbt_hdr = next_nbt_hdr;

			err = x_smbd_conn_check_nbt_hdr(smbd_conn);
			if (err < 0) {
				X_LOG_ERR("%s %p x%lx x_smbd_conn_check_nbt_hdr piggyback %ld",
						task_name, smbd_conn, smbd_conn->ep_id, err);
				return true;
			} else if (err == 0) {
				return false;
			}
			smbd_conn->recv_msgsize = x_convert_assert<uint32_t>(err);
		}
	} else if (err == 0) {
		X_LOG_CONN("%s %p x%lx recv nbt_body EOF", task_name, smbd_conn, smbd_conn->ep_id);
		return true;
	} else if (errno == EAGAIN) {
		fdevents = x_fdevents_consume(fdevents, FDEVT_IN);
	} else if (errno == EINTR) {
	} else {
		X_LOG_ERR("%s %p x%lx do_recv errno=%d", task_name,
				smbd_conn, smbd_conn->ep_id, errno);
		return true;
	}
	return false;
}

static bool x_smbd_conn_do_send(x_smbd_conn_t *smbd_conn, x_fdevents_t &fdevents)
{
	X_LOG_DBG("%s %p x%lx x%lx", task_name, smbd_conn, smbd_conn->ep_id, fdevents);
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
	X_LOG_DBG("%s %p x%lx x%lx", task_name, smbd_conn, smbd_conn->ep_id, fdevents);
	std::unique_lock<std::mutex> lock(smbd_conn->mutex);
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

const x_smb2_uuid_t &x_smbd_conn_curr_client_guid()
{
	return g_smbd_conn_curr->client_guid;
}

uint16_t x_smbd_conn_curr_dialect()
{
	return g_smbd_conn_curr->dialect;
}

uint16_t x_smbd_conn_curr_get_signing_algo()
{
	return g_smbd_conn_curr->signing_algo;
}

uint16_t x_smbd_conn_curr_get_cryption_algo()
{
	return g_smbd_conn_curr->cryption_algo;
}

std::shared_ptr<std::u16string> x_smbd_conn_curr_name()
{
	return g_smbd_conn_curr->machine_name;
}


static bool x_smbd_conn_upcall_cb_getevents(x_epoll_upcall_t *upcall, x_fdevents_t &fdevents)
{
	x_smbd_conn_t *smbd_conn = x_smbd_conn_from_upcall(upcall);
	X_LOG_DBG("%s %p x%lx", task_name, smbd_conn, fdevents);

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

	x_smbd_conn_terminate_chans(smbd_conn);
	while (x_smbd_requ_t *smbd_requ = smbd_conn->pending_requ_list.get_front()) {
		X_ASSERT(x_smbd_requ_async_remove(smbd_requ));
	}

	{
		std::unique_lock<std::mutex> lock(smbd_conn->mutex);
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

static bool x_smbd_srv_do_recv(x_smbd_srv_t *smbd_srv, x_fdevents_t &fdevents)
{
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

	return false;
}

static bool x_smbd_srv_do_user(x_smbd_srv_t *smbd_srv, x_fdevents_t &fdevents)
{
	X_LOG_DBG("%s %p x%lx x%lx", task_name, smbd_srv, smbd_srv->ep_id, fdevents);
	std::unique_lock<std::mutex> lock(smbd_srv->mutex);
	for (;;) {
		x_fdevt_user_t *fdevt_user = smbd_srv->fdevt_user_list.get_front();
		if (!fdevt_user) {
			break;
		}
		smbd_srv->fdevt_user_list.remove(fdevt_user);
		fdevt_user->func(nullptr, fdevt_user);
	}

	fdevents = x_fdevents_consume(fdevents, FDEVT_USER);
	return false;
}


static bool x_smbd_srv_upcall_cb_getevents(x_epoll_upcall_t *upcall, x_fdevents_t &fdevents)
{
	x_smbd_srv_t *smbd_srv = x_smbd_from_upcall(upcall);
	X_LOG_DBG("%s %p x%lx", task_name, smbd_srv, fdevents);
	uint32_t events = x_fdevents_processable(fdevents);
	if (events & FDEVT_USER) {
		if (x_smbd_srv_do_user(smbd_srv, fdevents)) {
			return true;
		}
		events = x_fdevents_processable(fdevents);
	}
	if (events & FDEVT_IN) {
		return x_smbd_srv_do_recv(smbd_srv, fdevents);
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
	x_evtmgmt_enable_events(g_evtmgmt, g_smbd_srv.ep_id,
			FDEVT_IN | FDEVT_ERR | FDEVT_SHUTDOWN | FDEVT_USER);
	return 0;
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
	X_LOG_WARN("smbd_conn %p is done, queued to srv", smbd_conn); \
	{
		auto lock = std::lock_guard(g_smbd_srv.mutex);
		notify = g_smbd_srv.fdevt_user_list.get_front() == nullptr;
		g_smbd_srv.fdevt_user_list.push_back(fdevt_user);
	}
	if (notify) {
		x_evtmgmt_post_events(g_evtmgmt, g_smbd_srv.ep_id, FDEVT_USER);
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
	static void func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user)
	{
		x_smbd_cancel_evt_t *evt = X_CONTAINER_OF(fdevt_user, x_smbd_cancel_evt_t, base);
		x_smbd_requ_t *smbd_requ = evt->smbd_requ;
		X_LOG_DBG("evt=%p, requ=%p, smbd_conn=%p", evt, smbd_requ, smbd_conn);

		x_smbd_requ_async_done(smbd_conn, smbd_requ, evt->status);

		delete evt;
	}

	explicit x_smbd_cancel_evt_t(x_smbd_requ_t *smbd_requ, NTSTATUS status)
		: base(func), smbd_requ(smbd_requ), status(status)
	{
	}
	~x_smbd_cancel_evt_t()
	{
		x_smbd_ref_dec(smbd_requ);
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
	if (fsctl_state.in_capabilities != smbd_conn->client_capabilities) {
		return X_NT_STATUS_INTERNAL_TERMINATE;
	}

	if (!(fsctl_state.in_guid == smbd_conn->client_guid)) {
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
			fsctl_state.in_dialects.data(),
			fsctl_state.in_dialects.size());

	if (dialect != smbd_conn->dialect) {
		return X_NT_STATUS_INTERNAL_TERMINATE;
	}

	fsctl_state.out_capabilities = smbd_conn->server_capabilities;
	fsctl_state.out_guid = smbd_conf->guid;
	fsctl_state.out_security_mode = smbd_conn->server_security_mode;
	fsctl_state.out_dialect = smbd_conn->dialect;

	return NT_STATUS_OK;
}

