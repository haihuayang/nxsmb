
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
#include "nttime.hxx"
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

void x_smbdconn_reply(x_smbdconn_t *smbdconn, x_msg_t *msg, x_smbdsess_t *smbdsess)
{
	if (msg->state == x_msg_t::STATE_COMPLETE) {
		bool orig_empty = smbdconn->send_queue.empty();
		if (msg->do_signing) {
			X_ASSERT(smbdsess);
			x_smb2_sign_msg(msg->out_buf + 8,
					msg->out_len - 4,
					smbdconn->dialect,
					smbdsess->signing_key);
		}
		smbdconn->send_queue.push_back(msg);
		if (orig_empty) {
			x_evtmgmt_enable_events(globals.evtmgmt, smbdconn->ep_id, FDEVT_OUT);
		}
	} else {
		delete msg;
		X_ASSERT(smbdconn->count_msg-- > 0);
	}
}

#define MAX_MSG_SIZE 0x1000000
#define SMB_MAGIC 0x424D53FF /* 0xFF 'S' 'M' 'B' */
#define SMB2_MAGIC 0x424D53FE /* 0xFE 'S' 'M' 'B' */
#define SMB2_TF_MAGIC 0x424D53FD /* 0xFD 'S' 'M' 'B' */

int x_smb2_reply_error(x_smbdconn_t *smbdconn, x_msg_t *msg,
		x_smbdsess_t *smbdsess,
		NTSTATUS status)
{
	uint8_t *outbuf = new uint8_t[8 + 0x40 + 9];
	uint8_t *outhdr = outbuf + 8;
	uint8_t *outbody = outhdr + 0x40;

	memset(outhdr, 0, 0x40 + 9);

	x_put_le16(outbody, 0x9);
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
	x_smbdconn_reply(smbdconn, msg, smbdsess);
	return 0;
}

static const struct {
	int (*op_func)(x_smbdconn_t *cli, x_msg_t *msg, const uint8_t *in_buf, size_t in_len);
} x_smb2_op_table[] = {
#define X_SMB2_OP_DECL(X) { x_smb2_process_##X },
	X_SMB2_OP_ENUM
#undef X_SMB2_OP_DECL
};

static int x_smbdconn_process_smb2(x_smbdconn_t *smbdconn, x_msg_t *msg)
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
	msg->opcode = opcode;
	return x_smb2_op_table[opcode].op_func(smbdconn, msg, in_buf, in_len);
}

static int x_smbdconn_process_smb(x_smbdconn_t *smbdconn, x_msg_t *msg)
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
			return x_smbdconn_process_smb2(smbdconn, msg);
		} else if (smbhdr == SMB_MAGIC) {
			if (len < 35) { // TODO 
				return -EBADMSG;
			}
			uint8_t cmd = msg->in_buf[4];
			if (/* TODO smbdconn->is_negotiated || */cmd != SMBnegprot) {
				return -EBADMSG;
			}
			msg->mid = 0; // TODO
			return x_smbdconn_process_smb1negoprot(smbdconn, msg, msg->in_buf, msg->in_len);
		}
	}
	return 0;
}

static int x_smbdconn_process_msg(x_smbdconn_t *smbdconn)
{
	x_msg_t *msg = smbdconn->recving_msg;
	X_ASSERT(msg);
	smbdconn->recving_msg = NULL;
	int err;

	if ((msg->nbt_hdr >> 24) == NBSSmessage) {
		err = x_smbdconn_process_smb(smbdconn, msg);
	} else {
		X_TODO;
		err = -EINVAL;
	}
	return err;
}

static inline x_smbdconn_t *x_smbdconn_from_upcall(x_epoll_upcall_t *upcall)
{
	return X_CONTAINER_OF(upcall, x_smbdconn_t, upcall);
}

static bool x_smbdconn_do_user(x_smbdconn_t *smbdconn, x_fdevents_t &fdevents)
{
	X_DBG("%s %p x%llx", task_name, smbdconn, fdevents);
	std::unique_lock<std::mutex> lock(smbdconn->mutex);
	for (;;) {
		x_fdevt_user_t *fdevt_user = smbdconn->fdevt_user_list.get_front();
		if (!fdevt_user) {
			break;
		}
		smbdconn->fdevt_user_list.remove(fdevt_user);
		lock.unlock();

		fdevt_user->func(smbdconn, fdevt_user);

		lock.lock();
	}

	fdevents = x_fdevents_consume(fdevents, FDEVT_USER);
	return false;
}

static bool x_smbdconn_do_timer(x_smbdconn_t *smbdconn, x_fdevents_t &fdevents)
{
	X_DBG("%s %p x%llx", task_name, smbdconn, fdevents);
	x_smbdsess_t *smbdsess;
	while ((smbdsess = smbdconn->session_wait_input_list.get_front()) != nullptr) {
		if (x_tick_cmp(smbdsess->timeout, tick_now) > 0) {
			break;
		}
		X_DBG("%p expired\n", smbdsess);
		smbdconn->session_wait_input_list.remove(smbdsess);
		x_smbdsess_release(smbdsess);
		smbdsess->decref();
	}

	fdevents = x_fdevents_consume(fdevents, FDEVT_TIMER);
	return false;
}

static bool x_smbdconn_do_recv(x_smbdconn_t *smbdconn, x_fdevents_t &fdevents)
{
	int err;
	X_DBG("%s %p x%llx", task_name, smbdconn, fdevents);
	if (smbdconn->recving_msg == NULL) {
		assert(smbdconn->read_length < sizeof(smbdconn->nbt_hdr));
		err = read(smbdconn->fd, &smbdconn->nbt_hdr, sizeof(smbdconn->nbt_hdr) - smbdconn->read_length);
		if (err > 0) {
			smbdconn->read_length += err;
			if (smbdconn->read_length == sizeof(smbdconn->nbt_hdr)) {
				smbdconn->read_length = 0;
				smbdconn->nbt_hdr = ntohl(smbdconn->nbt_hdr);
				uint8_t msgtype = smbdconn->nbt_hdr >> 24;
				if (msgtype == NBSSmessage) {
					uint32_t msgsize = smbdconn->nbt_hdr & 0xffffff;
					if (msgsize >= MAX_MSG_SIZE) {
						return true;
					} else if (smbdconn->nbt_hdr == 0) {
						return false;
					}
				} else {
					return true;
				}	
				smbdconn->recving_msg = x_msg_create(smbdconn->nbt_hdr);
				smbdconn->count_msg++;
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
	err = read(smbdconn->fd, smbdconn->recving_msg->in_buf + smbdconn->read_length,
			smbdconn->nbt_hdr - smbdconn->read_length);
	if (err > 0) {
		smbdconn->read_length += err;
		if (smbdconn->read_length == smbdconn->nbt_hdr) {
			smbdconn->recving_msg->in_len = smbdconn->nbt_hdr;
			smbdconn->read_length = 0;
			return x_smbdconn_process_msg(smbdconn) != 0;
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

static bool x_smbdconn_do_send(x_smbdconn_t *smbdconn, x_fdevents_t &fdevents)
{
	x_msg_t *msg;
	X_DBG("%s %p x%llx", task_name, smbdconn, fdevents);
	for (;;) {
		msg = smbdconn->sending_msg;
		if (msg == NULL) {
			msg = smbdconn->send_queue.get_front();
			if (msg == NULL) {
				break;
			}
			smbdconn->send_queue.remove(msg);
			// TODO msg_encode(msg);
			smbdconn->sending_msg = msg;
		}
		X_ASSERT(msg->out_len > 0);
		int err = write(smbdconn->fd, msg->out_buf + msg->out_off, msg->out_len);
		if (err > 0) {
			msg->out_len -= err;
			if (msg->out_len == 0) {
				delete msg;
				smbdconn->count_msg--;
				smbdconn->sending_msg = NULL;
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
	if (smbdconn->count_msg < x_smbdconn_t::MAX_MSG) {
		fdevents = x_fdevents_enable(fdevents, FDEVT_IN);
	}
	return false;
}

static bool x_smbdconn_handle_events(x_smbdconn_t *smbdconn, x_fdevents_t &fdevents)
{
	uint32_t events = x_fdevents_processable(fdevents);
	if (events & FDEVT_USER) {
		if (x_smbdconn_do_user(smbdconn, fdevents)) {
			return true;
		}
		events = x_fdevents_processable(fdevents);
	}
	if (events & FDEVT_TIMER) {
		if (x_smbdconn_do_timer(smbdconn, fdevents)) {
			return true;
		}
		events = x_fdevents_processable(fdevents);
	}
	if (events & FDEVT_IN) {
		if (x_smbdconn_do_recv(smbdconn, fdevents)) {
			return true;
		}
		events = x_fdevents_processable(fdevents);
	}
	if (events & FDEVT_OUT) {
		return x_smbdconn_do_send(smbdconn, fdevents);
	}
	return false;
}

static bool x_smbdconn_upcall_cb_getevents(x_epoll_upcall_t *upcall, x_fdevents_t &fdevents)
{
	x_smbdconn_t *smbdconn = x_smbdconn_from_upcall(upcall);
	X_DBG("%s %p x%llx", task_name, smbdconn, fdevents);

	bool ret = x_smbdconn_handle_events(smbdconn, fdevents);
	return ret;
}

static void x_smbdconn_upcall_cb_unmonitor(x_epoll_upcall_t *upcall)
{
	x_smbdconn_t *smbdconn = x_smbdconn_from_upcall(upcall);
	X_DBG("%s %p", task_name, smbdconn);
	smbdconn->state = x_smbdconn_t::STATE_DONE;
	x_smbdconn_remove_sessions(smbdconn);
	smbdconn->decref();
}

static const x_epoll_upcall_cbs_t x_smbdconn_upcall_cbs = {
	x_smbdconn_upcall_cb_getevents,
	x_smbdconn_upcall_cb_unmonitor,
};

static void x_smbd_accepted(x_smbd_t *smbd, int fd, const struct sockaddr_in &sin)
{
	set_nbio(fd, 1);
	x_smbdconn_t *smbdconn = new x_smbdconn_t(smbd, fd, sin);
	X_ASSERT(smbdconn != NULL);
	smbdconn->upcall.cbs = &x_smbdconn_upcall_cbs;
	smbdconn->ep_id = x_evtmgmt_monitor(globals.evtmgmt, fd, FDEVT_IN | FDEVT_OUT, &smbdconn->upcall);
	x_evtmgmt_enable_events(globals.evtmgmt, smbdconn->ep_id,
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
		NTSTATUS status = spnego->update(NULL, 0, negprot_spnego, NULL);
		X_ASSERT(NT_STATUS_IS_OK(status));
		smbd.negprot_spnego.swap(negprot_spnego);
	}

	int fd = tcplisten(port);
	assert(fd >= 0);

	smbd.fd = fd;
	smbd.upcall.cbs = &x_smbd_upcall_cbs;

	smbd.ep_id = x_evtmgmt_monitor(globals.evtmgmt, fd, FDEVT_IN, &smbd.upcall);
	x_evtmgmt_enable_events(globals.evtmgmt, smbd.ep_id, FDEVT_IN | FDEVT_ERR | FDEVT_SHUTDOWN);

	// TODO start_wbcli(1);
}


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

	x_smbdsess_pool_init(globals.evtmgmt, 1024);

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

void x_smbdconn_post_user(x_smbdconn_t *smbdconn, x_fdevt_user_t *evt_user)
{
	bool notify = false;
	{
		std::lock_guard<std::mutex> lock(smbdconn->mutex);
		notify = smbdconn->fdevt_user_list.get_front() == nullptr;
		smbdconn->fdevt_user_list.push_back(evt_user);
	}
	if (notify) {
		x_evtmgmt_post_events(globals.evtmgmt, smbdconn->ep_id, FDEVT_USER);
	}
}


