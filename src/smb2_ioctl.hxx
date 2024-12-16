
#ifndef __smb2_ioctl__hxx__
#define __smb2_ioctl__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "smbd.hxx"
#include "smbd_requ.hxx"

struct x_smbd_requ_ioctl_t : x_smbd_requ_t
{
	x_smbd_requ_ioctl_t(x_smbd_conn_t *smbd_conn,
			x_in_buf_t &in_buf, uint32_t in_msgsize,
			bool encrypted,
			x_smbd_requ_state_ioctl_t &state);
	std::tuple<bool, bool, bool> get_properties() const override
	{
		return { true, true, false };
	}
	NTSTATUS done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status) override;
	x_smbd_requ_state_ioctl_t state;
};

NTSTATUS x_smbd_parse_ioctl_copychunk(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t **p_smbd_requ,
		x_in_buf_t &in_buf, uint32_t in_msgsize,
		bool encrypted, x_smbd_requ_state_ioctl_t &state);

#endif /* __smb2_ioctl__hxx__ */

