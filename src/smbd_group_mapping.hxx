
#ifndef __smbd_group_mapping__hxx__
#define __smbd_group_mapping__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "util_sid.hxx"
#include "auth.hxx"

struct x_smbd_group_mapping_t;

x_smbd_group_mapping_t *x_smbd_group_mapping_create();
void x_smbd_group_mapping_delete(x_smbd_group_mapping_t *group_mapping);

int x_smbd_group_mapping_load(x_smbd_group_mapping_t *group_mapping,
		const std::string &lib_dir);

int x_smbd_group_mapping_get(const x_smbd_group_mapping_t *group_mapping,
		std::vector<idl::dom_sid> &aliases,
		uint64_t &privileges,
		const x_auth_info_t &auth_info);


#endif /* __smbd_group_mapping__hxx__ */

