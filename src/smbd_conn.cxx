
#include "smbd.hxx"
extern "C" {
#include "samba/include/config.h"
#include "samba/lib/crypto/sha512.h"
}

x_smbd_conn_t::x_smbd_conn_t(x_smbd_t *smbd, int fd, const x_sockaddr_t &saddr)
	: smbd(smbd), fd(fd), saddr(saddr)
	, seq_bitmap(smbd->smbconf->smb2_max_credits)
{
}

x_smbd_conn_t::~x_smbd_conn_t()
{
	X_LOG_DBG("x_smbd_conn_t %p destroy", this);
	X_ASSERT(!session_list.get_front());
	X_ASSERT(!session_wait_input_list.get_front());
	X_ASSERT(fd == -1);

	if (recv_buf) {
		x_buf_release(recv_buf);
	}
	while (send_buf_head) {
		auto next = send_buf_head->next;
		delete send_buf_head;
		send_buf_head = next;
	}
}

/* this function is in the smbd_conn work thread context */
void x_smbd_conn_terminate_sessions(x_smbd_conn_t *smbd_conn)
{
	x_smbd_sess_t *smbd_sess;
	while ((smbd_sess = smbd_conn->session_list.get_front()) != nullptr) {
		smbd_conn->session_list.remove(smbd_sess);
		x_smbd_sess_terminate(smbd_sess);
		smbd_sess->decref();
	}
	while ((smbd_sess = smbd_conn->session_wait_input_list.get_front()) != nullptr) {
		smbd_conn->session_wait_input_list.remove(smbd_sess);
		x_smbd_sess_terminate(smbd_sess);
		smbd_sess->decref();
	}
}

