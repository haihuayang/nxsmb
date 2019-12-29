
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

static void x_smbconn_done(x_smbconn_t *smbconn)
{
	smbconn->state = x_smbconn_t::STATE_DONE;
	smbconn->decref();
}

x_auth_t *x_smbsrv_create_auth(x_smbsrv_t *smbsrv)
{
	return x_auth_create_by_oid(smbsrv->auth_context, GSS_SPNEGO_MECHANISM);
}

void x_smbconn_reply(x_smbconn_t *smbconn, x_msg_t *msg)
{
	if (msg->state == x_msg_t::STATE_COMPLETE) {
		bool orig_empty = smbconn->send_queue.empty();
		smbconn->send_queue.push_back(msg);
		if (orig_empty) {
			x_evtmgmt_enable_events(globals.evtmgmt, smbconn->ep_id, FDEVT_OUT);
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

int x_smb2_reply_error(x_smbconn_t *smbconn, x_msg_t *msg,
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
	x_smbconn_reply(smbconn, msg);
	return 0;
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
	msg->opcode = opcode;
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

static inline x_smbconn_t *x_smbconn_from_upcall(x_epoll_upcall_t *upcall)
{
	return X_CONTAINER_OF(upcall, x_smbconn_t, upcall);
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

static bool x_smbconn_upcall_cb_getevents(x_epoll_upcall_t *upcall, x_fdevents_t &fdevents)
{
	x_smbconn_t *smbconn = x_smbconn_from_upcall(upcall);
	X_DBG("%s %p x%llx", task_name, smbconn, fdevents);

	bool ret = x_smbconn_handle_events(smbconn, fdevents);
	return ret;
}

static void x_smbconn_upcall_cb_unmonitor(x_epoll_upcall_t *upcall)
{
	x_smbconn_t *smbconn = x_smbconn_from_upcall(upcall);
	X_DBG("%s %p", task_name, smbconn);
	x_smbconn_done(smbconn);
}

static const x_epoll_upcall_cbs_t x_smbconn_upcall_cbs = {
	x_smbconn_upcall_cb_getevents,
	x_smbconn_upcall_cb_unmonitor,
};

static void x_smbsrv_accepted(x_smbsrv_t *smbsrv, int fd, const struct sockaddr_in &sin)
{
	set_nbio(fd, 1);
	x_smbconn_t *smbconn = new x_smbconn_t(smbsrv, fd, sin);
	X_ASSERT(smbconn != NULL);
	smbconn->upcall.cbs = &x_smbconn_upcall_cbs;
	smbconn->ep_id = x_evtmgmt_monitor(globals.evtmgmt, fd, FDEVT_IN | FDEVT_OUT, &smbconn->upcall);
	x_evtmgmt_enable_events(globals.evtmgmt, smbconn->ep_id, FDEVT_IN | FDEVT_ERR | FDEVT_SHUTDOWN);
}

static inline x_smbsrv_t *x_smbsrv_from_upcall(x_epoll_upcall_t *upcall)
{
	return X_CONTAINER_OF(upcall, x_smbsrv_t, upcall);
}

static bool x_smbsrv_upcall_cb_getevents(x_epoll_upcall_t *upcall, x_fdevents_t &fdevents)
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

static void x_smbsrv_upcall_cb_unmonitor(x_epoll_upcall_t *upcall)
{
	x_smbsrv_t *smbsrv = x_smbsrv_from_upcall(upcall);
	X_DBG("%s %p", task_name, smbsrv);
	X_ASSERT_SYSCALL(close(smbsrv->fd));
	/* TODO may close all accepted client, and notify it is freed */
}

static const x_epoll_upcall_cbs_t x_smbsrv_upcall_cbs = {
	x_smbsrv_upcall_cb_getevents,
	x_smbsrv_upcall_cb_unmonitor,
};

static void x_smbsrv_init(x_smbsrv_t &smbsrv, int port)
{
	smbsrv.auth_context = x_auth_create_context();
	x_auth_krb5_init(smbsrv.auth_context);
	x_auth_ntlmssp_init(smbsrv.auth_context);
	x_auth_spnego_init(smbsrv.auth_context);

	std::unique_ptr<x_auth_t> spnego{x_smbsrv_create_auth(&smbsrv)};

	if (spnego) {
		std::vector<uint8_t> negprot_spnego;
		int err = spnego->update(NULL, 0, negprot_spnego, NULL);
		X_ASSERT(err == 0);
		smbsrv.negprot_spnego.swap(negprot_spnego);
	}

	int fd = tcplisten(port);
	assert(fd >= 0);

	smbsrv.fd = fd;
	smbsrv.upcall.cbs = &x_smbsrv_upcall_cbs;

	smbsrv.ep_id = x_evtmgmt_monitor(globals.evtmgmt, fd, FDEVT_IN, &smbsrv.upcall);
	x_evtmgmt_enable_events(globals.evtmgmt, smbsrv.ep_id, FDEVT_IN | FDEVT_ERR | FDEVT_SHUTDOWN);

	// TODO start_wbcli(1);
}


int main(int argc, char **argv)
{
	argv++;
	unsigned int count = atoi(*argv);
	int port = 445;

	x_threadpool_t *tpool = x_threadpool_create(count);
	globals.tpool = tpool;

	globals.evtmgmt = x_evtmgmt_create(tpool, 2000000000);
	globals.wbpool = x_wbpool_create(globals.evtmgmt, 2);

	x_smbsrv_t smbsrv;
	x_smbsrv_init(smbsrv, port);


	main_loop();

	x_threadpool_destroy(tpool);
	return 0;
}

void x_smbsrv_wbpool_request(x_wbcli_t *wbcli)
{
	x_wbpool_request(globals.wbpool, wbcli);
}

