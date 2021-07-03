
#include "smbd.hxx"
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

// #include "smb_consts.h"
#include "smbconf.hxx"
#include "core.hxx"
#include "network.hxx"

#include "smb2.hxx"

enum {
#define X_SMB2_OP_DECL(x) X_SMB2_OP_##x,
	X_SMB2_OP_ENUM
#undef X_SMB2_OP_DECL
	X_SMB2_OP_MAX
};

static struct {
	bool do_async = false;
	x_threadpool_t *tpool_aio;
	x_threadpool_t *tpool_evtmgmt;
	x_evtmgmt_t *evtmgmt;
	x_wbpool_t *wbpool;
} globals;

std::atomic<int> x_smbd_requ_t::count;

static void main_loop()
{
	snprintf(task_name, sizeof task_name, "MAIN");
	for (;;) {
		x_evtmgmt_dispatch(globals.evtmgmt);
	}
}

x_auth_t *x_smbd_create_auth(x_smbd_t *smbd)
{
	return x_auth_create_by_oid(smbd->auth_context, GSS_SPNEGO_MECHANISM);
}

void x_smbd_conn_queue(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	x_bufref_t *bufref = smbd_requ->out_buf_head;
	X_ASSERT(bufref);
	X_ASSERT(smbd_requ->out_length > 0);

	X_ASSERT(bufref->buf->ref == 1);
	X_ASSERT(bufref->offset >= 4);

	bufref->offset -= 4;
	bufref->length += 4;
	uint8_t *outnbt = bufref->get_data();
	x_put_be32(outnbt, smbd_requ->out_length);

	bool orig_empty = smbd_conn->send_buf_head == nullptr;
	if (orig_empty) {
		smbd_conn->send_buf_head = smbd_requ->out_buf_head;
	} else {
		smbd_conn->send_buf_tail->next = smbd_requ->out_buf_head;
	}
	smbd_conn->send_buf_tail = smbd_requ->out_buf_tail;

	smbd_requ->out_buf_head = smbd_requ->out_buf_tail = nullptr;

	if (orig_empty) {
		x_evtmgmt_enable_events(globals.evtmgmt, smbd_conn->ep_id, FDEVT_OUT);
	}
}

#if 0
x_buf_t *x_smb2_alloc_reply_buf(uint32_t body_size)
{
	x_buf_t *buf = x_buf_alloc(8 + SMB2_HDR_BODY + x_pad_len(body_size, 8));
	return buf;
}
void x_smb2_requ_parse(x_smbd_sess_t *smbd_sess,
		x_smb2_requ_t *requ, uint8_t *outhdr, uint32_t body_size, NTSTATUS status)
{
	memset(outhdr, 0, SMB2_HDR_BODY);
	SIVAL(outhdr, SMB2_HDR_PROTOCOL_ID,     SMB2_MAGIC);
	SSVAL(outhdr, SMB2_HDR_LENGTH,	  SMB2_HDR_BODY);
	SSVAL(outhdr, SMB2_HDR_CREDIT_CHARGE, 1); // TODO
	SIVAL(outhdr, SMB2_HDR_STATUS, NT_STATUS_V(status));
	SIVAL(outhdr, SMB2_HDR_OPCODE, requ->opcode);
	SSVAL(outhdr, SMB2_HDR_CREDIT, std::max(uint16_t(1), requ->credits_requested)); // TODO
	SIVAL(outhdr, SMB2_HDR_FLAGS, requ->hdr_flags | SMB2_HDR_FLAG_REDIRECT); // TODO
	SIVAL(outhdr, SMB2_HDR_NEXT_COMMAND, 0);
	SBVAL(outhdr, SMB2_HDR_MESSAGE_ID, requ->mid);
	SIVAL(outhdr, SMB2_HDR_TID, requ->tid);
	SBVAL(outhdr, SMB2_HDR_SESSION_ID, smbd_sess ? smbd_sess->id : 0);

	if (requ->hdr_flags & SMB2_HDR_FLAG_SIGNED) {
		X_ASSERT(smbd_sess);
		x_smb2_sign_msg(outhdr,
				body_size + SMB2_HDR_BODY,
				smbd_sess->smbd_conn->dialect,
				smbd_sess->signing_key);
	}
}
#endif

static uint16_t x_smb2_calculate_credit(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
		NTSTATUS status)
{
	uint32_t current_max_credits = smbd_conn->seq_bitmap.size() / 16;
	current_max_credits = std::max(current_max_credits, 1u);

	uint16_t credit_charged = std::max(smbd_requ->in_credit_charge, uint16_t(1u));
	uint16_t credit_requested = std::max(smbd_requ->in_credit_requested, uint16_t(1u));
	
	/* already checked in process smb2 input */
	X_ASSERT(credit_charged < smbd_conn->seq_bitmap.size());

	// uint32_t additional_possible = smbd_conn->seq_bitmap.size() - credit_charged;
	uint16_t additional_credits = credit_requested - 1;
	uint16_t additional_max = 0;

	if (smbd_requ->opcode == SMB2_OP_NEGPROT) {
	} else if (smbd_requ->opcode == SMB2_OP_SESSSETUP) {
		if (NT_STATUS_IS_OK(status)) {
			additional_max = 32;
		}
	} else {
		additional_max = 32;
	}
	additional_credits = std::min(additional_credits, additional_max);
	uint16_t credit_granted = credit_charged + additional_credits;

	uint64_t credits_possible = UINT64_MAX - smbd_conn->credit_seq_low;
	if (credits_possible > 0) {
		--credits_possible;
	}
	credits_possible = std::min(credits_possible, uint64_t(current_max_credits));
	credits_possible -= smbd_conn->credit_seq_range;
	if (credit_granted > credits_possible) {
		credit_granted = credits_possible;
	}
	smbd_conn->credit_granted += credit_granted;
	smbd_conn->credit_seq_range += credit_granted;
	return credit_granted;
}

static uint32_t calculate_out_hdr_flags(uint32_t in_hdr_flags, uint32_t out_hdr_flags)
{
	// TODO we just check SIGNED, should consider other flags?
	out_hdr_flags |= (in_hdr_flags & (SMB2_HDR_FLAG_PRIORITY_MASK | SMB2_HDR_FLAG_SIGNED));
	return out_hdr_flags;
}

void x_smb2_reply(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		x_bufref_t *buf_head,
		x_bufref_t *buf_tail,
		NTSTATUS status,
		uint32_t reply_size)
{
	smbd_requ->out_credit_granted = x_smb2_calculate_credit(smbd_conn, smbd_requ, status);
	smbd_requ->out_hdr_flags = calculate_out_hdr_flags(smbd_requ->in_hdr_flags, smbd_requ->out_hdr_flags);
	uint8_t *out_hdr = buf_head->get_data();
	memset(out_hdr, 0, SMB2_HDR_BODY);
	SIVAL(out_hdr, SMB2_HDR_PROTOCOL_ID, SMB2_MAGIC);
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
	if (smbd_requ->smbd_tcon) {
		SIVAL(out_hdr, SMB2_HDR_TID, smbd_requ->smbd_tcon->tid);
	}
	if (smbd_requ->smbd_sess) {
		SBVAL(out_hdr, SMB2_HDR_SESSION_ID, smbd_requ->smbd_sess->id);
	}

	if (smbd_requ->out_hdr_flags & SMB2_HDR_FLAG_SIGNED) {
		X_ASSERT(smbd_requ->smbd_sess);
		x_smb2_signing_sign(smbd_requ->smbd_sess->smbd_conn->dialect,
				smbd_requ->smbd_sess->signing_key,
				buf_head);
	}

	if (smbd_requ->out_buf_tail) {
		smbd_requ->out_buf_tail->next = buf_head;
		smbd_requ->out_buf_tail = buf_tail;
	} else {
		smbd_requ->out_buf_head = buf_head;
		smbd_requ->out_buf_tail = buf_tail;
	}
	smbd_requ->out_length += reply_size;
}

int x_smbd_reply_async(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
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

	memset(out_hdr, 0, SMB2_HDR_BODY);
	SIVAL(out_hdr, SMB2_HDR_PROTOCOL_ID, SMB2_MAGIC);
	SSVAL(out_hdr, SMB2_HDR_LENGTH, SMB2_HDR_BODY);
	SSVAL(out_hdr, SMB2_HDR_CREDIT_CHARGE, smbd_requ->in_credit_charge);
	SIVAL(out_hdr, SMB2_HDR_STATUS, NT_STATUS_V(NT_STATUS_PENDING));
	SIVAL(out_hdr, SMB2_HDR_OPCODE, smbd_requ->opcode);
	SSVAL(out_hdr, SMB2_HDR_CREDIT, smbd_requ->out_credit_granted);
	SIVAL(out_hdr, SMB2_HDR_FLAGS, smbd_requ->out_hdr_flags | SMB2_HDR_FLAG_REDIRECT | SMB2_HDR_FLAG_ASYNC);
	SBVAL(out_hdr, SMB2_HDR_MESSAGE_ID, smbd_requ->in_mid);
	// we use mid as async_id
	SBVAL(out_hdr, SMB2_HDR_ASYNC_ID, smbd_requ->in_mid);
	if (smbd_requ->smbd_sess) {
		SBVAL(out_hdr, SMB2_HDR_SESSION_ID, smbd_requ->smbd_sess->id);
	}
	x_bufref_t *bufref = new x_bufref_t{out_buf, 8, SMB2_HDR_BODY + 8};
	if (smbd_requ->out_hdr_flags & SMB2_HDR_FLAG_SIGNED) {
		X_ASSERT(smbd_requ->smbd_sess);
		x_smb2_signing_sign(smbd_requ->smbd_sess->smbd_conn->dialect,
				smbd_requ->smbd_sess->signing_key,
				bufref);
	}

	if (smbd_requ->out_buf_tail) {
		smbd_requ->out_buf_tail->next = bufref;
	} else {
		smbd_requ->out_buf_head = bufref;
	}
	smbd_requ->out_buf_tail = bufref;
	smbd_requ->out_length += SMB2_HDR_BODY + 8;;
	return 0;
}

#define X_SMBD_REPLY_ASYNC(smbd_conn, smbd_requ) \
	x_smbd_reply_async((smbd_conn), (smbd_requ), __FILE__, __LINE__)
#if 0
void x_smbd_conn_reply(x_smbd_conn_t *smbd_conn, x_msg_ptr_t &smbd_requ, x_smbd_sess_t *smbd_sess,
		x_smb2_preauth_t *preauth,
		uint8_t *outbuf,
		uint32_t tid, NTSTATUS status, uint32_t body_size)
{
	uint8_t *outhdr = outbuf + 8;
	//smbd_smb2_request_setup_out
	memset(outhdr, 0, 0x40);
	SIVAL(outhdr, SMB2_HDR_PROTOCOL_ID,     SMB2_MAGIC);
	SSVAL(outhdr, SMB2_HDR_LENGTH,	  SMB2_HDR_BODY);
	SSVAL(outhdr, SMB2_HDR_CREDIT_CHARGE, 1); // TODO
	SIVAL(outhdr, SMB2_HDR_STATUS, NT_STATUS_V(status));
	SIVAL(outhdr, SMB2_HDR_OPCODE, smbd_requ->opcode);
	SSVAL(outhdr, SMB2_HDR_CREDIT, std::max(uint16_t(1), smbd_requ->credits_requested)); // TODO
	SIVAL(outhdr, SMB2_HDR_FLAGS, smbd_requ->hdr_flags | SMB2_HDR_FLAG_REDIRECT); // TODO
	SIVAL(outhdr, SMB2_HDR_NEXT_COMMAND, 0);
	SBVAL(outhdr, SMB2_HDR_MESSAGE_ID, smbd_requ->mid);
	SIVAL(outhdr, SMB2_HDR_TID, tid);
	SBVAL(outhdr, SMB2_HDR_SESSION_ID, smbd_sess ? smbd_sess->id : 0);

	uint8_t *outnbt = outbuf + 4;
	x_put_be32(outnbt, 0x40 + body_size);

	smbd_requ->out_buf = outbuf;
	smbd_requ->out_off = 4;
	smbd_requ->out_len = 4 + 0x40 + body_size;
	smbd_requ->state = x_msg_t::STATE_COMPLETE;

	if (preauth) {
		preauth->update(outbuf + 8, smbd_requ->out_len - 4);
	}

	bool orig_empty = smbd_conn->send_queue.empty();
	if (smbd_requ->do_signing || msg_is_signed(smbd_requ)) {
		X_ASSERT(smbd_sess);
		x_smb2_sign_msg(outbuf + 8,
				smbd_requ->out_len - 4,
				smbd_conn->dialect,
				smbd_sess->signing_key);
	}
	smbd_conn->send_queue.push_back(smbd_requ);
	if (orig_empty) {
		x_evtmgmt_enable_events(globals.evtmgmt, smbd_conn->ep_id, FDEVT_OUT);
	}

}

void x_smbd_conn_reply(x_smbd_conn_t *smbd_conn, x_msg_t *smbd_requ, x_smbd_sess_t *smbd_sess)
{
	if (smbd_requ->state == x_msg_t::STATE_COMPLETE) {
		bool orig_empty = smbd_conn->send_queue.empty();
		if (smbd_requ->do_signing || msg_is_signed(smbd_requ)) {
			X_ASSERT(smbd_sess);
			x_smb2_sign_msg(smbd_requ->out_buf + 8,
					smbd_requ->out_len - 4,
					smbd_conn->dialect,
					smbd_sess->signing_key);
		}
		smbd_conn->send_queue.push_back(smbd_requ);
		if (orig_empty) {
			x_evtmgmt_enable_events(globals.evtmgmt, smbd_conn->ep_id, FDEVT_OUT);
		}
	} else {
		delete smbd_requ;
		X_ASSERT(smbd_conn->count_msg-- > 0);
	}
}
#endif
#define MAX_MSG_SIZE 0x1000000
#define SMB_MAGIC 0x424D53FF /* 0xFF 'S' 'M' 'B' */
#define SMB2_MAGIC 0x424D53FE /* 0xFE 'S' 'M' 'B' */
#define SMB2_TF_MAGIC 0x424D53FD /* 0xFD 'S' 'M' 'B' */

int x_smbd_reply_error(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
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

static const struct {
	NTSTATUS (*op_func)(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
} x_smb2_op_table[] = {
#define X_SMB2_OP_DECL(X) { x_smb2_process_##X },
	X_SMB2_OP_ENUM
#undef X_SMB2_OP_DECL
};

static NTSTATUS x_smbd_conn_process_smb2__(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	x_buf_t *buf = smbd_requ->in_buf;
	uint8_t *in_buf = buf->data + smbd_requ->in_offset;
	uint64_t in_session_id = x_get_le64(in_buf + SMB2_HDR_SESSION_ID);
	bool is_signed = (smbd_requ->in_hdr_flags & SMB2_HDR_FLAG_SIGNED) != 0;
	if ((smbd_requ->in_hdr_flags & SMB2_HDR_FLAG_CHAINED) == 0) {
		if (in_session_id == 0) {
			smbd_requ->smbd_sess = nullptr;
		} else {
			smbd_requ->smbd_sess = x_smbd_sess_find(in_session_id, smbd_conn);
		}
	}
	if (is_signed) {
		if (smbd_requ->opcode == SMB2_OP_NEGPROT) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		if (!smbd_requ->smbd_sess) {
			return NT_STATUS_USER_SESSION_DELETED;
		}
		x_bufref_t bufref{x_buf_get(smbd_requ->in_buf), smbd_requ->in_offset, smbd_requ->in_requ_len};
		if (!x_smb2_signing_check(smbd_requ->smbd_sess->smbd_conn->dialect,
					smbd_requ->smbd_sess->signing_key,
					&bufref)) {
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	if (smbd_requ->in_hdr_flags & SMB2_HDR_FLAG_ASYNC) {
		smbd_requ->in_asyncid = x_get_le32(in_buf + SMB2_HDR_PID);
	} else {
		smbd_requ->in_tid = x_get_le32(in_buf + SMB2_HDR_TID);
	}
	return x_smb2_op_table[smbd_requ->opcode].op_func(smbd_conn, smbd_requ);
}

static bool x_smb2_validate_message_id(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	if (smbd_requ->opcode == SMB2_OP_CANCEL) {
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

		NTSTATUS status = x_smbd_conn_process_smb2__(
				smbd_conn, smbd_requ);
		if (NT_STATUS_IS_OK(status) || NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			continue;
		} else if (NT_STATUS_EQUAL(status, NT_STATUS_PENDING)) {
			X_SMBD_REPLY_ASYNC(smbd_conn, smbd_requ);
			if (offset + in_requ_len < buf->size) {
				return 0;
			}
		} else if (NT_STATUS_EQUAL(status, X_NT_STATUS_INTERNAL_BLOCKED)) {
			return 0;
		} else {
			X_SMBD_REPLY_ERROR(smbd_conn, smbd_requ, status);
			smbd_requ->status = status;
		}
	}

	x_smbd_conn_queue(smbd_conn, smbd_requ);
	return 0;

#if 0
		if (SMB2_HDR_BODY > len) {
	const uint8_t *in_buf = req->bufreq->data();
	uint32_t in_len = req->bufreq->length;

			return -EBADMSG;
		}
		x_smb2req_t *req = new x_smb2req_t(buf, offset);
		x_smbd_conn_process_smb2(smbd_conn, req);
	} else {

			uint32_t next_command = x_get_le32(in_buf + SMB2_HDR_NEXT_COMMAND);
			if (next_command > len) {
				reutrn -EBADMSG;
			}
			if (next_command != 0) {
				x_smb2req_t *req = new x_smb2req_t(buf, offset, next_command);
			}


	const uint8_t *in_buf = req->bufreq->data();
	uint32_t in_len = req->bufreq->length;
	req->mid = x_get_le64(in_buf + SMB2_HDR_MESSAGE_ID);
	req->hdr_flags = x_get_le32(in_buf + SMB2_HDR_FLAGS);
	req->opcode = opcode;
	req->credits_requested = x_get_le16(in_buf + SMB2_HDR_CREDIT);
	return x_smb2_op_table[opcode].op_func(smbd_conn, req);
#endif
}

static int x_smbd_conn_process_smb(x_smbd_conn_t *smbd_conn, x_buf_t *buf)
{
	uint32_t offset = 0;
	// uint8_t *inbuf = buf->data + offset;
	size_t len = buf->size - offset;
	if (len < 4) {
		return -EBADMSG;
	}
	uint32_t smbhdr;
	memcpy(&smbhdr, buf->data + offset, sizeof smbhdr);

	x_auto_ref_t<x_smbd_requ_t> smbd_requ{new x_smbd_requ_t(x_buf_get(buf))};
	
	if (smbhdr == SMB2_MAGIC) {
		if (len < SMB2_HDR_BODY) {
			return -EBADMSG;
		}
		return x_smbd_conn_process_smb2(smbd_conn, smbd_requ, 0);
	} else if (smbhdr == SMB_MAGIC) {
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
		int ret = x_smbd_conn_process_smb1negoprot(smbd_conn, smbd_requ);
		if (ret < 0) {
			return ret;
		}
		x_smbd_conn_queue(smbd_conn, smbd_requ);
		return 0;
	} else {
		return -EBADMSG;
	}
}
#if 0
static int x_smbd_conn_process_smb(x_smbd_conn_t *smbd_conn, x_buf_t *buf)
{
	X_ASSERT(offset < buf->size);
	uint32_t offset = 0;
	uint8 *inbuf = buf->data + offset;
	size_t len = buf->size - offset;
	if (len < 4) {
		return -EBADMSG;
	}
	uint32_t smbhdr;
	memcpy(&smbhdr, buf->data + offset, sizeof smbhdr);
	if (smbhdr == SMB2_MAGIC) {
		return x_smbd_conn_process_smb2(smbd_conn, req, 0);

	} else if (smbhdr == SMB_MAGIC) {
		if (len < 35) { // TODO 
			return -EBADMSG;
		}
		uint8_t cmd = buf->data[4];
		if (/* TODO smbd_conn->is_negotiated || */cmd != SMBnegprot) {
			return -EBADMSG;
		}
		x_smb2req_t *req = new x_smb2_req_t(buf, offset);
		return x_smbd_conn_process_smb1negoprot(smbd_conn, req);
	}
	return 0;
}

void x_smbd_smb2_async_reply(x_smb2_requ_t *requ, NTSTATUS status,
		x_buf_t *out_buffer)
{
	if (NT_STATUS_IS_OK(status)) {

	} else {
	}
	if (
}
#endif

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

static bool x_smbd_conn_do_user(x_smbd_conn_t *smbd_conn, x_fdevents_t &fdevents)
{
	X_LOG_DBG("%s %p x%llx", task_name, smbd_conn, fdevents);
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

static bool x_smbd_conn_do_timer(x_smbd_conn_t *smbd_conn, x_fdevents_t &fdevents)
{
	X_LOG_DBG("%s %p x%llx", task_name, smbd_conn, fdevents);
	x_smbd_sess_t *smbd_sess;
	while ((smbd_sess = smbd_conn->session_wait_input_list.get_front()) != nullptr) {
		if (x_tick_cmp(smbd_sess->timeout, tick_now) > 0) {
			break;
		}
		X_LOG_DBG("%p expired\n", smbd_sess);
		smbd_conn->session_wait_input_list.remove(smbd_sess);
		x_smbd_sess_release(smbd_sess);
		smbd_sess->decref();
	}

	fdevents = x_fdevents_consume(fdevents, FDEVT_TIMER);
	return false;
}

static int x_smbd_conn_check_nbt_hdr(x_smbd_conn_t *smbd_conn)
{
	if (smbd_conn->recv_len == sizeof(smbd_conn->nbt_hdr)) {
		smbd_conn->recv_len = 0;
		smbd_conn->nbt_hdr = ntohl(smbd_conn->nbt_hdr);
		uint8_t msgtype = smbd_conn->nbt_hdr >> 24;
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
	int err;
	X_LOG_DBG("%s %p x%llx", task_name, smbd_conn, fdevents);
	if (smbd_conn->recv_buf == NULL) {
		X_ASSERT(smbd_conn->recv_len < sizeof(smbd_conn->nbt_hdr));
		err = read(smbd_conn->fd, (char *)&smbd_conn->nbt_hdr + smbd_conn->recv_len,
				sizeof(smbd_conn->nbt_hdr) - smbd_conn->recv_len);
		if (err > 0) {
			smbd_conn->recv_len += err;
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
		smbd_conn->recv_len += err;
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
	X_LOG_DBG("%s %p x%llx", task_name, smbd_conn, fdevents);
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
			size_t bytes = ret;
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

static bool x_smbd_conn_handle_events(x_smbd_conn_t *smbd_conn, x_fdevents_t &fdevents)
{
	uint32_t events = x_fdevents_processable(fdevents);
	if (events & FDEVT_USER) {
		if (x_smbd_conn_do_user(smbd_conn, fdevents)) {
			return true;
		}
		events = x_fdevents_processable(fdevents);
	}
	if (events & FDEVT_TIMER) {
		if (x_smbd_conn_do_timer(smbd_conn, fdevents)) {
			return true;
		}
		events = x_fdevents_processable(fdevents);
	}
	if (events & FDEVT_IN) {
		if (x_smbd_conn_do_recv(smbd_conn, fdevents)) {
			return true;
		}
		events = x_fdevents_processable(fdevents);
	}
	if (events & FDEVT_OUT) {
		return x_smbd_conn_do_send(smbd_conn, fdevents);
	}
	return false;
}

static bool x_smbd_conn_upcall_cb_getevents(x_epoll_upcall_t *upcall, x_fdevents_t &fdevents)
{
	x_smbd_conn_t *smbd_conn = x_smbd_conn_from_upcall(upcall);
	X_LOG_DBG("%s %p x%llx", task_name, smbd_conn, fdevents);

	bool ret = x_smbd_conn_handle_events(smbd_conn, fdevents);
	return ret;
}

static void x_smbd_conn_upcall_cb_unmonitor(x_epoll_upcall_t *upcall)
{
	x_smbd_conn_t *smbd_conn = x_smbd_conn_from_upcall(upcall);
	X_LOG_CONN("%s %p", task_name, smbd_conn);
	X_ASSERT_SYSCALL(close(smbd_conn->fd));
	smbd_conn->fd = -1;
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

	x_smbd_conn_remove_sessions(smbd_conn);
	smbd_conn->decref();
}

static const x_epoll_upcall_cbs_t x_smbd_conn_upcall_cbs = {
	x_smbd_conn_upcall_cb_getevents,
	x_smbd_conn_upcall_cb_unmonitor,
};

static void x_smbd_accepted(x_smbd_t *smbd, int fd, const x_sockaddr_t &saddr)
{
	X_LOG_CONN("accept %d from %s", fd, saddr.tostring().c_str());
	set_nbio(fd, 1);
	x_smbd_conn_t *smbd_conn = new x_smbd_conn_t(smbd, fd, saddr);
	X_ASSERT(smbd_conn != NULL);
	smbd_conn->upcall.cbs = &x_smbd_conn_upcall_cbs;
	smbd_conn->ep_id = x_evtmgmt_monitor(globals.evtmgmt, fd, FDEVT_IN | FDEVT_OUT, &smbd_conn->upcall);
	x_evtmgmt_enable_events(globals.evtmgmt, smbd_conn->ep_id,
			FDEVT_IN | FDEVT_ERR | FDEVT_SHUTDOWN | FDEVT_TIMER | FDEVT_USER);
}

static inline x_smbd_t *x_smbd_from_upcall(x_epoll_upcall_t *upcall)
{
	return X_CONTAINER_OF(upcall, x_smbd_t, upcall);
}

static bool x_smbd_upcall_cb_getevents(x_epoll_upcall_t *upcall, x_fdevents_t &fdevents)
{
	x_smbd_t *smbd = x_smbd_from_upcall(upcall);
	uint32_t events = x_fdevents_processable(fdevents);

	if (events & FDEVT_IN) {
		x_sockaddr_t saddr;
		socklen_t slen = sizeof(saddr);
		int fd = accept(smbd->fd, &saddr.sa, &slen);
		X_LOG_DBG("%s accept %d, %d", task_name, fd, errno);
		if (fd >= 0) {
			x_smbd_accepted(smbd, fd, saddr);
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

static void x_smbd_upcall_cb_unmonitor(x_epoll_upcall_t *upcall)
{
	x_smbd_t *smbd = x_smbd_from_upcall(upcall);
	X_LOG_CONN("%s %p", task_name, smbd);
	X_ASSERT_SYSCALL(close(smbd->fd));
	smbd->fd = -1;
	/* TODO may close all accepted client, and notify it is freed */
}

static const x_epoll_upcall_cbs_t x_smbd_upcall_cbs = {
	x_smbd_upcall_cb_getevents,
	x_smbd_upcall_cb_unmonitor,
};

static void x_smbd_init(x_smbd_t &smbd)
{
	smbd.auth_context = x_auth_create_context(&smbd);
	x_auth_krb5_init(smbd.auth_context);
	x_auth_ntlmssp_init(smbd.auth_context);
	x_auth_spnego_init(smbd.auth_context);

	x_auth_t *spnego(x_smbd_create_auth(&smbd));

	if (spnego) {
		std::vector<uint8_t> negprot_spnego;
		std::shared_ptr<x_auth_info_t> auth_info;
		NTSTATUS status = spnego->update(NULL, 0, negprot_spnego, NULL, auth_info);
		X_ASSERT(NT_STATUS_IS_OK(status));
		smbd.negprot_spnego.swap(negprot_spnego);
		x_auth_destroy(spnego);
	}

	// TODO
	smbd.capabilities = SMB2_CAP_DFS | SMB2_CAP_LARGE_MTU | SMB2_CAP_LEASING
		| SMB2_CAP_DIRECTORY_LEASING; // | SMB2_CAP_MULTI_CHANNEL

	int fd = tcplisten(smbd.smbconf->port);
	assert(fd >= 0);

	smbd.fd = fd;
	smbd.upcall.cbs = &x_smbd_upcall_cbs;

	smbd.ep_id = x_evtmgmt_monitor(globals.evtmgmt, fd, FDEVT_IN, &smbd.upcall);
	x_evtmgmt_enable_events(globals.evtmgmt, smbd.ep_id, FDEVT_IN | FDEVT_ERR | FDEVT_SHUTDOWN);

	// TODO start_wbcli(1);
}

enum {
	X_SMBD_MAX_SESSION = 1024,
	X_SMBD_MAX_TCON = 1024,
	X_SMBD_MAX_OPEN = 1024,
	X_SMBD_MAX_REQUEST = 1024,
};

int main(int argc, char **argv)
{
	x_smbd_t smbd;
	int err = x_smbd_parse_cmdline(smbd.smbconf, argc, argv);
	if (err < 0) {
		fprintf(stderr, "parse_cmdline failed %d\n", err);
		exit(1);
	}

	signal(SIGPIPE, SIG_IGN);

	x_threadpool_t *tpool = x_threadpool_create(smbd.smbconf->thread_count);
	globals.tpool_evtmgmt = tpool;

	globals.evtmgmt = x_evtmgmt_create(tpool, 60 * X_NSEC_PER_SEC);
	globals.wbpool = x_wbpool_create(globals.evtmgmt, 2);

	globals.tpool_aio = x_threadpool_create(smbd.smbconf->thread_count);

	x_smbd_open_pool_init(X_SMBD_MAX_OPEN);
	x_smbd_tcon_pool_init(X_SMBD_MAX_TCON);
	x_smbd_sess_pool_init(X_SMBD_MAX_SESSION);
	x_smbd_sess_pool_init(X_SMBD_MAX_REQUEST);

	x_smbd_ipc_init();
	x_smbd_disk_init(X_SMBD_MAX_OPEN);

	x_smbd_init(smbd);


	main_loop();

	x_threadpool_destroy(tpool);
	return 0;
}

void x_smbd_wbpool_request(x_wbcli_t *wbcli)
{
	x_wbpool_request(globals.wbpool, wbcli);
}

void x_smbd_conn_post_user(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user)
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
		x_evtmgmt_post_events(globals.evtmgmt, smbd_conn->ep_id, FDEVT_USER);
	}
	if (!queued) {
		/* cancel the event */
		fdevt_user->func(smbd_conn, fdevt_user, true);
	}
}

void x_smbd_schedule_aio()
{
}

void x_smbd_conn_requ_done(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
		NTSTATUS status)
{
	if (NT_STATUS_IS_OK(status) || NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
	} else if (NT_STATUS_EQUAL(status, NT_STATUS_PENDING)) {
		X_SMBD_REPLY_ASYNC(smbd_conn, smbd_requ);
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


