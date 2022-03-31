
#ifndef __smbd_lease__hxx__
#define __smbd_lease__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "samba/include/config.h"
#include "include/librpc/misc.hxx"
#include "include/list.hxx"
#include "smb2.hxx"

struct x_smbd_lease_t;
struct x_smbd_object_t;
struct x_smbd_lease_t
{
	x_smbd_lease_t(const idl::GUID &client_guid,
			const x_smb2_lease_key_t &lease_key,
			uint32_t hash);
	x_dqlink_t hash_link;
	idl::GUID client_guid;
	x_smbd_object_t *smbd_object;

	x_smb2_lease_key_t lease_key;
	uint32_t hash;
	uint32_t refcnt;
	uint8_t version;
	uint8_t lease_state;
	uint16_t lease_epoch;
	bool breaking{false};
	uint32_t breaking_to_requested{0}, breaking_to_required{0};
	std::atomic<uint32_t> open_cnt;
	std::atomic<uint32_t> ref_cnt;
};


int x_smbd_lease_pool_init(uint32_t count, uint32_t mutex_count);
#if 0
bool x_smbd_lease_match(const x_smbd_open_t &open,
		const idl::GUID &client_guid,
		const x_smb2_lease_key_t &lease_key);
void x_smbd_send_break(const x_smbd_open_t &open, uint32_t break_to);
#endif
x_smbd_lease_t *x_smbd_lease_find(
		const idl::GUID &client_guid,
		const x_smb2_lease_key_t &lease_key);

x_smbd_lease_t *x_smbd_lease_grant(
		const idl::GUID &client_guid,
		x_smb2_lease_t *lease,
		uint32_t granted,
		x_smbd_object_t *smbd_object);

void x_smbd_lease_release(x_smbd_lease_t *smbd_lease);

uint32_t x_smbd_lease_get_state(const x_smbd_lease_t *smbd_lease);

bool x_smbd_lease_is_breaking(const x_smbd_lease_t *smbd_lease);

bool x_smbd_lease_match(const x_smbd_lease_t *smbd_lease,
		const idl::GUID &cguid,
		const x_smb2_lease_key_t &lkey);

#endif /* __smbd_lease__hxx__ */

