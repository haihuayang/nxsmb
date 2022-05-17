
#include "smbd.hxx"

static std::atomic<uint32_t> g_smbd_requ_count = 0;

x_smbd_requ_t::x_smbd_requ_t(x_buf_t *in_buf)
	: in_buf(in_buf)
{
	++g_smbd_requ_count;
	X_LOG_DBG("create %p", this);
}

x_smbd_requ_t::~x_smbd_requ_t()
{
	X_LOG_DBG("free %p", this);
	x_buf_release(in_buf);

	while (out_buf_head) {
		auto next = out_buf_head->next;
		delete out_buf_head;
		out_buf_head = next;
	}

	x_smbd_ref_dec_if(smbd_open);
	x_smbd_ref_dec_if(smbd_tcon);
	x_smbd_ref_dec_if(smbd_chan);
	x_smbd_ref_dec_if(smbd_sess);
	/* TODO free them
	x_smbd_object_t *smbd_object{};
	*/
	--g_smbd_requ_count;
}


