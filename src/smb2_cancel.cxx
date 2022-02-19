
#include "smbd.hxx"

NTSTATUS x_smb2_process_CANCEL(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	X_ASSERT(false); // it is processed in smbd.cxx, never reach here
	return NT_STATUS_INTERNAL_ERROR;
}
