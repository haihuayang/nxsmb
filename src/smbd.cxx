
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
	x_threadpool_t *tpool;
	x_evtmgmt_t *evtmgmt;
	x_wbpool_t *wbpool;
} globals;


static void main_loop()
{
	snprintf(task_name, sizeof task_name, "MAIN");
	for (;;) {
		x_evtmgmt_dispatch(globals.evtmgmt);
	}
}

static x_msg_t *x_msg_create(size_t size)
{
	x_msg_t *msg = new x_msg_t(size);
	return msg;
}

x_auth_t *x_smbd_create_auth(x_smbd_t *smbd)
{
	return x_auth_create_by_oid(smbd->auth_context, GSS_SPNEGO_MECHANISM);
}

static inline bool msg_is_signed(const x_msg_t *msg)
{
	uint32_t flags = x_get_le32(msg->in_buf + SMB2_HDR_FLAGS);
	return flags & SMB2_HDR_FLAG_SIGNED;
}

void x_smbd_conn_reply(x_smbd_conn_t *smbd_conn, x_msg_t *msg, x_smbd_sess_t *smbd_sess,
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
	SIVAL(outhdr, SMB2_HDR_OPCODE, msg->opcode);
	SSVAL(outhdr, SMB2_HDR_CREDIT, std::max(uint16_t(1), msg->credits_requested)); // TODO
	SIVAL(outhdr, SMB2_HDR_FLAGS, msg->hdr_flags | SMB2_HDR_FLAG_REDIRECT); // TODO
	SIVAL(outhdr, SMB2_HDR_NEXT_COMMAND, 0);
	SBVAL(outhdr, SMB2_HDR_MESSAGE_ID, msg->mid);
	SIVAL(outhdr, SMB2_HDR_TID, tid);
	SBVAL(outhdr, SMB2_HDR_SESSION_ID, smbd_sess ? smbd_sess->id : 0);

	uint8_t *outnbt = outbuf + 4;
	x_put_be32(outnbt, 0x40 + body_size);

	msg->out_buf = outbuf;
	msg->out_off = 4;
	msg->out_len = 4 + 0x40 + body_size;
	msg->state = x_msg_t::STATE_COMPLETE;

	bool orig_empty = smbd_conn->send_queue.empty();
	if (msg->do_signing || msg_is_signed(msg)) {
		X_ASSERT(smbd_sess);
		x_smb2_sign_msg(outbuf + 8,
				msg->out_len - 4,
				smbd_conn->dialect,
				smbd_sess->signing_key);
	}
	smbd_conn->send_queue.push_back(msg);
	if (orig_empty) {
		x_evtmgmt_enable_events(globals.evtmgmt, smbd_conn->ep_id, FDEVT_OUT);
	}

}
#if 0
void x_smbd_conn_reply(x_smbd_conn_t *smbd_conn, x_msg_t *msg, x_smbd_sess_t *smbd_sess)
{
	if (msg->state == x_msg_t::STATE_COMPLETE) {
		bool orig_empty = smbd_conn->send_queue.empty();
		if (msg->do_signing || msg_is_signed(msg)) {
			X_ASSERT(smbd_sess);
			x_smb2_sign_msg(msg->out_buf + 8,
					msg->out_len - 4,
					smbd_conn->dialect,
					smbd_sess->signing_key);
		}
		smbd_conn->send_queue.push_back(msg);
		if (orig_empty) {
			x_evtmgmt_enable_events(globals.evtmgmt, smbd_conn->ep_id, FDEVT_OUT);
		}
	} else {
		delete msg;
		X_ASSERT(smbd_conn->count_msg-- > 0);
	}
}
#endif
#define MAX_MSG_SIZE 0x1000000
#define SMB_MAGIC 0x424D53FF /* 0xFF 'S' 'M' 'B' */
#define SMB2_MAGIC 0x424D53FE /* 0xFE 'S' 'M' 'B' */
#define SMB2_TF_MAGIC 0x424D53FD /* 0xFD 'S' 'M' 'B' */

int x_smb2_reply_error(x_smbd_conn_t *smbd_conn, x_msg_t *msg,
		x_smbd_sess_t *smbd_sess, uint32_t tid,
		NTSTATUS status, const char *file, unsigned int line)
{
	X_LOG_OP("%ld RESP 0x%lx at %s:%d", msg->mid, status.v, file, line);

	uint8_t *outbuf = new uint8_t[8 + 0x40 + 9];
	uint8_t *outhdr = outbuf + 8;
	uint8_t *outbody = outhdr + 0x40;

	memset(outbody, 0, 9);
	x_put_le16(outbody, 0x9);

#if 0
	memset(outhdr, 0, 0x40 + 9);
	x_put_le32(outhdr + SMB2_HDR_PROTOCOL_ID, SMB2_MAGIC);
	x_put_le16(outhdr + SMB2_HDR_LENGTH,  SMB2_HDR_BODY);
	x_put_le16(outhdr + SMB2_HDR_CREDIT_CHARGE,  0);
	x_put_le32(outhdr + SMB2_HDR_STATUS, status.v);
	x_put_le16(outhdr + SMB2_HDR_OPCODE, msg->opcode);
	x_put_le16(outhdr + SMB2_HDR_CREDIT, 1);
	x_put_le32(outhdr + SMB2_HDR_FLAGS, SMB2_HDR_FLAG_REDIRECT);
	x_put_le32(outhdr + SMB2_HDR_NEXT_COMMAND, 0);
	x_put_le64(outhdr + SMB2_HDR_MESSAGE_ID, msg->mid);

	uint8_t *outnbt = outbuf + 4;
	x_put_be32(outnbt, 0x40 + 9);

	msg->out_buf = outbuf;
	msg->out_off = 4;
	msg->out_len = 4 + 0x40 + 9;

	msg->state = x_msg_t::STATE_COMPLETE;
	// X_DEVEL_ASSERT(false);
	x_smbd_conn_reply(smbd_conn, msg, smbd_sess);
#else
	x_smbd_conn_reply(smbd_conn, msg, smbd_sess, outbuf, tid, status, 9);
#endif
	return 0;
}

#define X_SMB2_OP_DECL(X) \
	extern int x_smb2_process_##X(x_smbd_conn_t *cli, x_msg_t *msg, const uint8_t *in_buf, size_t in_len);
	X_SMB2_OP_ENUM
#undef X_SMB2_OP_DECL

static const struct {
	int (*op_func)(x_smbd_conn_t *cli, x_msg_t *msg, const uint8_t *in_buf, size_t in_len);
} x_smb2_op_table[] = {
#define X_SMB2_OP_DECL(X) { x_smb2_process_##X },
	X_SMB2_OP_ENUM
#undef X_SMB2_OP_DECL
};

static int x_smbd_conn_process_smb2(x_smbd_conn_t *smbd_conn, x_msg_t *msg)
{

	const uint8_t *in_buf = msg->in_buf;
	unsigned int in_len = msg->in_len;
	if (in_len < 0x40) {
		return -EBADMSG;
	}
	uint16_t opcode = x_get_le16(in_buf + SMB2_HDR_OPCODE);
	if (opcode >= X_SMB2_OP_MAX) {
		return -EBADMSG; // TODO more friendly resp?
	}

	msg->mid = x_get_le64(in_buf + SMB2_HDR_MESSAGE_ID);
	msg->hdr_flags = x_get_le32(in_buf + SMB2_HDR_FLAGS);
	msg->opcode = opcode;
	msg->credits_requested = x_get_le16(in_buf + SMB2_HDR_CREDIT);
	return x_smb2_op_table[opcode].op_func(smbd_conn, msg, in_buf, in_len);
}

static int x_smbd_conn_process_smb(x_smbd_conn_t *smbd_conn, x_msg_t *msg)
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
			return x_smbd_conn_process_smb2(smbd_conn, msg);
		} else if (smbhdr == SMB_MAGIC) {
			if (len < 35) { // TODO 
				return -EBADMSG;
			}
			uint8_t cmd = msg->in_buf[4];
			if (/* TODO smbd_conn->is_negotiated || */cmd != SMBnegprot) {
				return -EBADMSG;
			}
			msg->mid = 0; // TODO
			msg->hdr_flags = 0;
			msg->opcode = SMB2_OP_NEGPROT; 
			msg->credits_requested = 0;
			return x_smbd_conn_process_smb1negoprot(smbd_conn, msg, msg->in_buf, msg->in_len);
		}
	}
	return 0;
}

static int x_smbd_conn_process_msg(x_smbd_conn_t *smbd_conn)
{
	x_msg_t *msg = smbd_conn->recving_msg;
	X_ASSERT(msg);
	smbd_conn->recving_msg = NULL;
	int err;

	if ((msg->nbt_hdr >> 24) == NBSSmessage) {
		err = x_smbd_conn_process_smb(smbd_conn, msg);
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
	X_DBG("%s %p x%llx", task_name, smbd_conn, fdevents);
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

static bool x_smbd_conn_do_timer(x_smbd_conn_t *smbd_conn, x_fdevents_t &fdevents)
{
	X_DBG("%s %p x%llx", task_name, smbd_conn, fdevents);
	x_smbd_sess_t *smbd_sess;
	while ((smbd_sess = smbd_conn->session_wait_input_list.get_front()) != nullptr) {
		if (x_tick_cmp(smbd_sess->timeout, tick_now) > 0) {
			break;
		}
		X_DBG("%p expired\n", smbd_sess);
		smbd_conn->session_wait_input_list.remove(smbd_sess);
		x_smbd_sess_release(smbd_sess);
		smbd_sess->decref();
	}

	fdevents = x_fdevents_consume(fdevents, FDEVT_TIMER);
	return false;
}

static bool x_smbd_conn_do_recv(x_smbd_conn_t *smbd_conn, x_fdevents_t &fdevents)
{
	int err;
	X_DBG("%s %p x%llx", task_name, smbd_conn, fdevents);
	if (smbd_conn->recving_msg == NULL) {
		assert(smbd_conn->read_length < sizeof(smbd_conn->nbt_hdr));
		err = read(smbd_conn->fd, &smbd_conn->nbt_hdr, sizeof(smbd_conn->nbt_hdr) - smbd_conn->read_length);
		if (err > 0) {
			smbd_conn->read_length += err;
			if (smbd_conn->read_length == sizeof(smbd_conn->nbt_hdr)) {
				smbd_conn->read_length = 0;
				smbd_conn->nbt_hdr = ntohl(smbd_conn->nbt_hdr);
				uint8_t msgtype = smbd_conn->nbt_hdr >> 24;
				if (msgtype == NBSSmessage) {
					uint32_t msgsize = smbd_conn->nbt_hdr & 0xffffff;
					if (msgsize >= MAX_MSG_SIZE) {
						return true;
					} else if (smbd_conn->nbt_hdr == 0) {
						return false;
					}
				} else {
					return true;
				}	
				smbd_conn->recving_msg = x_msg_create(smbd_conn->nbt_hdr);
				smbd_conn->count_msg++;
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
	err = read(smbd_conn->fd, smbd_conn->recving_msg->in_buf + smbd_conn->read_length,
			smbd_conn->nbt_hdr - smbd_conn->read_length);
	if (err > 0) {
		smbd_conn->read_length += err;
		if (smbd_conn->read_length == smbd_conn->nbt_hdr) {
			smbd_conn->recving_msg->in_len = smbd_conn->nbt_hdr;
			smbd_conn->read_length = 0;
			return x_smbd_conn_process_msg(smbd_conn) != 0;
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
	x_msg_t *msg;
	X_DBG("%s %p x%llx", task_name, smbd_conn, fdevents);
	for (;;) {
		msg = smbd_conn->sending_msg;
		if (msg == NULL) {
			msg = smbd_conn->send_queue.get_front();
			if (msg == NULL) {
				break;
			}
			smbd_conn->send_queue.remove(msg);
			// TODO msg_encode(msg);
			smbd_conn->sending_msg = msg;
		}
		X_ASSERT(msg->out_len > 0);
		int err = write(smbd_conn->fd, msg->out_buf + msg->out_off, msg->out_len);
		if (err > 0) {
			msg->out_len -= err;
			if (msg->out_len == 0) {
				delete msg;
				smbd_conn->count_msg--;
				smbd_conn->sending_msg = NULL;
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
	X_DBG("%s %p x%llx", task_name, smbd_conn, fdevents);

	bool ret = x_smbd_conn_handle_events(smbd_conn, fdevents);
	return ret;
}

static void x_smbd_conn_upcall_cb_unmonitor(x_epoll_upcall_t *upcall)
{
	x_smbd_conn_t *smbd_conn = x_smbd_conn_from_upcall(upcall);
	X_DBG("%s %p", task_name, smbd_conn);
	smbd_conn->state = x_smbd_conn_t::STATE_DONE;
	x_smbd_conn_remove_sessions(smbd_conn);
	smbd_conn->decref();
}

static const x_epoll_upcall_cbs_t x_smbd_conn_upcall_cbs = {
	x_smbd_conn_upcall_cb_getevents,
	x_smbd_conn_upcall_cb_unmonitor,
};

static void x_smbd_accepted(x_smbd_t *smbd, int fd, const struct sockaddr_in &sin)
{
	X_LOG_CONN("accept %d from %d.%d.%d.%d:%d", fd,
			X_IPQUAD_BE(sin.sin_addr), ntohs(sin.sin_port));

	set_nbio(fd, 1);
	x_smbd_conn_t *smbd_conn = new x_smbd_conn_t(smbd, fd, sin);
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
		struct sockaddr_in sin;
		socklen_t slen = sizeof(sin);
		int fd = accept(smbd->fd, (struct sockaddr *)&sin, &slen);
		X_DBG("%s accept %d, %d", task_name, fd, errno);
		if (fd >= 0) {
			x_smbd_accepted(smbd, fd, sin);
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
	X_DBG("%s %p", task_name, smbd);
	X_ASSERT_SYSCALL(close(smbd->fd));
	/* TODO may close all accepted client, and notify it is freed */
}

static const x_epoll_upcall_cbs_t x_smbd_upcall_cbs = {
	x_smbd_upcall_cb_getevents,
	x_smbd_upcall_cb_unmonitor,
};

static void x_smbd_init(x_smbd_t &smbd, int port)
{
	smbd.auth_context = x_auth_create_context();
	x_auth_krb5_init(smbd.auth_context);
	x_auth_ntlmssp_init(smbd.auth_context);
	x_auth_spnego_init(smbd.auth_context);

	std::unique_ptr<x_auth_t> spnego{x_smbd_create_auth(&smbd)};

	if (spnego) {
		std::vector<uint8_t> negprot_spnego;
		std::shared_ptr<x_auth_info_t> auth_info;
		NTSTATUS status = spnego->update(NULL, 0, negprot_spnego, NULL, auth_info);
		X_ASSERT(NT_STATUS_IS_OK(status));
		smbd.negprot_spnego.swap(negprot_spnego);
	}

	x_smbd_load_shares();

	// TODO
	smbd.capabilities = SMB2_CAP_DFS | SMB2_CAP_LARGE_MTU | SMB2_CAP_LEASING;

	int fd = tcplisten(port);
	assert(fd >= 0);

	smbd.fd = fd;
	smbd.upcall.cbs = &x_smbd_upcall_cbs;

	smbd.ep_id = x_evtmgmt_monitor(globals.evtmgmt, fd, FDEVT_IN, &smbd.upcall);
	x_evtmgmt_enable_events(globals.evtmgmt, smbd.ep_id, FDEVT_IN | FDEVT_ERR | FDEVT_SHUTDOWN);

	// TODO start_wbcli(1);
}

enum {
	X_SMBD_MAX_SESSION = 1024,
	X_SMBD_MAX_OPEN = 1024,
};

int main(int argc, char **argv)
{
	argv++;
	unsigned int count = atoi(*argv);
	int port = 445;

	signal(SIGPIPE, SIG_IGN);

	x_threadpool_t *tpool = x_threadpool_create(count);
	globals.tpool = tpool;

	globals.evtmgmt = x_evtmgmt_create(tpool, 2000000000);
	globals.wbpool = x_wbpool_create(globals.evtmgmt, 2);

	x_smbd_open_pool_init(globals.evtmgmt, X_SMBD_MAX_OPEN);
	x_smbd_sess_pool_init(globals.evtmgmt, X_SMBD_MAX_SESSION);

	x_smbd_ipc_init();
	x_smbd_disk_init(X_SMBD_MAX_OPEN);

	x_smbd_t smbd;
	x_smbd_init(smbd, port);


	main_loop();

	x_threadpool_destroy(tpool);
	return 0;
}

void x_smbd_wbpool_request(x_wbcli_t *wbcli)
{
	x_wbpool_request(globals.wbpool, wbcli);
}

void x_smbd_conn_post_user(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *evt_user)
{
	bool notify = false;
	{
		std::lock_guard<std::mutex> lock(smbd_conn->mutex);
		notify = smbd_conn->fdevt_user_list.get_front() == nullptr;
		smbd_conn->fdevt_user_list.push_back(evt_user);
	}
	if (notify) {
		x_evtmgmt_post_events(globals.evtmgmt, smbd_conn->ep_id, FDEVT_USER);
	}
}


