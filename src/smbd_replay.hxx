
#ifndef __smbd_replay__hxx__
#define __smbd_replay__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/bits.hxx"

NTSTATUS x_smbd_replay_cache_lookup(
		x_smbd_open_t **psmbd_open,
		const x_smb2_uuid_t &create_guid,
		bool replay_operation,
		bool oplock_valid);

void x_smbd_replay_cache_clear(
		const x_smb2_uuid_t &client_guid,
		const x_smb2_uuid_t &create_guid);

void x_smbd_replay_cache_set(
		const x_smb2_uuid_t &client_guid,
		const x_smb2_uuid_t &create_guid,
		x_smbd_open_t *smbd_open);

int x_smbd_replay_cache_init(uint32_t count, uint32_t mutex_count);

#endif /* __smbd_replay__hxx__ */

