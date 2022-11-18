
#ifndef __smbd_access__hxx__
#define __smbd_access__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "smbd_open.hxx"

NTSTATUS x_smbd_can_set_delete_on_close(x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream,
		uint32_t file_attributes, uint32_t access_mask);


#endif /* __smbd_access__hxx__ */

