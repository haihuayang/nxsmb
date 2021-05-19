
#include "smbd.hxx"
extern "C" {
#include "samba/include/config.h"
#include "samba/lib/crypto/sha512.h"
}

x_smbd_conn_t::~x_smbd_conn_t() {
#if 0
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
#endif
	X_ASSERT(!session_list.get_front());
	X_ASSERT(!session_wait_input_list.get_front());

	X_ASSERT_SYSCALL(close(fd));
}

#if 0
void x_smbd_conn_remove_sess(x_smbd_conn_t *smbd_conn, x_smbd_sess_t *smbd_sess)
{
	std::unique_lock<std::mutex> lock(smbd_conn->mutex);

	while ((smbd_sess = smbd_conn->sessions.get_front()) != nullptr) {
		smbd_conn->sessions.remove(smbd_sess);
		lock.unlock();
		x_smbd_sess_stop(smbd_sess);
		lock.lock();
	}

}
#endif
/* this function is in the smbd_conn work thread context */
void x_smbd_conn_remove_sessions(x_smbd_conn_t *smbd_conn)
{
	x_smbd_sess_t *smbd_sess;
	while ((smbd_sess = smbd_conn->session_list.get_front()) != nullptr) {
		smbd_conn->session_list.remove(smbd_sess);
		x_smbd_sess_release(smbd_sess);
		smbd_sess->decref();
	}
	while ((smbd_sess = smbd_conn->session_wait_input_list.get_front()) != nullptr) {
		smbd_conn->session_wait_input_list.remove(smbd_sess);
		x_smbd_sess_release(smbd_sess);
		smbd_sess->decref();
	}
}

