
#ifndef __smb2_ioctl__hxx__
#define __smb2_ioctl__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "smbd.hxx"
#include "smbd_requ.hxx"

NTSTATUS x_smb2_ioctl_request_resume_key(
		x_smbd_requ_t *smbd_requ,
		x_smbd_requ_state_ioctl_t &state);

NTSTATUS x_smb2_ioctl_copychunk(
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smbd_requ_state_ioctl_t> &state);

#endif /* __smb2_ioctl__hxx__ */

