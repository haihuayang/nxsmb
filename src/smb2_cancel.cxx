
#include "smbd_open.hxx"

NTSTATUS x_smb2_process_CANCEL(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	return X_NT_STATUS_INTERNAL_BLOCKED; // TODO
	return NT_STATUS_OK;
}
