
#include "smbd_access.hxx"

/* can_set_delete_on_close */
NTSTATUS x_smbd_can_set_delete_on_close(x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream,
		uint32_t file_attributes, uint32_t access_mask)
{
	if (file_attributes & X_SMB2_FILE_ATTRIBUTE_READONLY) {
		return NT_STATUS_CANNOT_DELETE;
	}

	/* TODO readonly topdir */

	if (!(access_mask & idl::SEC_STD_DELETE)) {
		return NT_STATUS_ACCESS_DENIED;
	}
	
	if (!smbd_stream && smbd_object->type == x_smbd_object_t::type_dir) {
		/* TODO Don't allow delete on close for non-empty directories. */
	}
	return NT_STATUS_OK;
}


