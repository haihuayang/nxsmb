
#ifndef __smbd_lease__hxx__
#define __smbd_lease__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/librpc/misc.hxx"
#include "include/list.hxx"
#include "smb2.hxx"

struct x_smbd_conn_t;
struct x_smbd_requ_t;
struct x_smbd_lease_t;
struct x_smbd_object_t;
struct x_smbd_stream_t;
struct x_smbd_requ_state_lease_break_t;

int x_smbd_lease_pool_init(uint32_t count, uint32_t mutex_count);
#if 0
bool x_smbd_lease_match(const x_smbd_open_t &open,
		const x_smb2_uuid_t &client_guid,
		const x_smb2_lease_key_t &lease_key);
void x_smbd_send_break(const x_smbd_open_t &open, uint32_t break_to);
#endif
x_smbd_lease_t *x_smbd_lease_find(
		const x_smb2_uuid_t &client_guid,
		const x_smb2_lease_t &smb2_lease,
		bool create_if);
bool x_smbd_lease_match_get(const x_smbd_lease_t *smbd_lease,
		const x_smb2_uuid_t &client_guid,
		x_smb2_lease_t &lease);

void x_smbd_lease_release(x_smbd_lease_t *smbd_lease);

bool x_smbd_lease_grant(x_smbd_lease_t *smbd_lease,
		x_smb2_lease_t &lease,
		uint8_t granted, uint8_t requested,
		x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream,
		bool &new_lease);
void x_smbd_lease_close(x_smbd_lease_t *smbd_lease);

uint8_t x_smbd_lease_get_state(const x_smbd_lease_t *smbd_lease);

enum {
	X_SMBD_BREAK_ACTION_SEND = 0x1,
	X_SMBD_BREAK_ACTION_BLOCKED = 0x2,
};

uint32_t x_smbd_lease_require_break(x_smbd_lease_t *smbd_lease,
		const x_smb2_lease_key_t *ignore_lease_key,
		const x_smb2_uuid_t *client_guid,
		x_smb2_lease_key_t &lease_key,
		uint8_t break_mask,
		uint8_t delay_mask,
		uint8_t &curr_state,
		uint8_t &new_state,
		uint16_t &epoch,
		uint32_t &flags,
		x_smbd_requ_t *smbd_requ,
		bool block_breaking);

NTSTATUS x_smbd_lease_process_break(x_smbd_requ_state_lease_break_t &state);

bool x_smbd_lease_match(const x_smbd_lease_t *smbd_lease,
		x_smbd_object_t *smbd_object,
		x_smbd_stream_t *smbd_stream);

#endif /* __smbd_lease__hxx__ */

