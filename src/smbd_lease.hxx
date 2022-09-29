
#ifndef __smbd_lease__hxx__
#define __smbd_lease__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "samba/include/config.h"
#include "include/librpc/misc.hxx"
#include "include/list.hxx"
#include "smb2.hxx"
#include "smb2_state.hxx"

struct x_smbd_conn_t;
struct x_smbd_requ_t;
struct x_smbd_lease_t;
struct x_smbd_object_t;
struct x_smbd_stream_t;

int x_smbd_lease_pool_init(uint32_t count, uint32_t mutex_count);
#if 0
bool x_smbd_lease_match(const x_smbd_open_t &open,
		const x_smb2_uuid_t &client_guid,
		const x_smb2_lease_key_t &lease_key);
void x_smbd_send_break(const x_smbd_open_t &open, uint32_t break_to);
#endif
x_smbd_lease_t *x_smbd_lease_find(
		const x_smb2_uuid_t &client_guid,
		const x_smb2_lease_key_t &lease_key,
		uint8_t version,
		bool create_if);

void x_smbd_lease_release(x_smbd_lease_t *smbd_lease);

bool x_smbd_lease_grant(x_smbd_lease_t *smbd_lease,
		x_smb2_lease_t &lease,
		uint8_t granted,
		x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream,
		bool &new_lease);
void x_smbd_lease_close(x_smbd_lease_t *smbd_lease);

uint8_t x_smbd_lease_get_state(const x_smbd_lease_t *smbd_lease);

bool x_smbd_lease_require_break(x_smbd_lease_t *smbd_lease,
		const x_smb2_lease_key_t *ignore_lease_key,
		x_smb2_lease_key_t &lease_key,
		uint8_t &new_state, /* in out */
		uint8_t &curr_state,
		uint16_t &epoch,
		uint32_t &flags);
NTSTATUS x_smbd_lease_process_break(const x_smb2_state_lease_break_t &state);

bool x_smbd_lease_is_breaking(const x_smbd_lease_t *smbd_lease);
bool x_smbd_lease_set_breaking_if(x_smbd_lease_t *smbd_lease);

bool x_smbd_lease_match(const x_smbd_lease_t *smbd_lease,
		x_smbd_object_t *smbd_object,
		void *smbd_stream);

#endif /* __smbd_lease__hxx__ */

