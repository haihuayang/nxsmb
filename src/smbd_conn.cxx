
#include "smbd.hxx"

x_smbdconn_t::~x_smbdconn_t() {
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

	X_ASSERT(!session_list.get_front());
	X_ASSERT(!session_wait_input_list.get_front());

	X_ASSERT_SYSCALL(close(fd));
}

#if 0
void x_smbdconn_remove_sess(x_smbdconn_t *smbdconn, x_smbdsess_t *smbdsess)
{
	std::unique_lock<std::mutex> lock(smbdconn->mutex);

	while ((smbdsess = smbdconn->sessions.get_front()) != nullptr) {
		smbdconn->sessions.remove(smbdsess);
		lock.unlock();
		x_smbdsess_stop(smbdsess);
		lock.lock();
	}

}
#endif
/* this function is in the smbdconn work thread context */
void x_smbdconn_remove_sessions(x_smbdconn_t *smbdconn)
{
	x_smbdsess_t *smbdsess;
	while ((smbdsess = smbdconn->session_list.get_front()) != nullptr) {
		smbdconn->session_list.remove(smbdsess);
		x_smbdsess_release(smbdsess);
		smbdsess->decref();
	}
	while ((smbdsess = smbdconn->session_wait_input_list.get_front()) != nullptr) {
		smbdconn->session_wait_input_list.remove(smbdsess);
		x_smbdsess_release(smbdsess);
		smbdsess->decref();
	}
}


