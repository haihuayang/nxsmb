
#ifndef __smbd_secrets__hxx__
#define __smbd_secrets__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "defines.hxx"
#include <string>
#include "include/librpc/misc.hxx"
#include "include/librpc/security.hxx"

struct x_smbd_secrets_t
{
	idl::dom_sid sid, domain_sid;
	idl::GUID domain_guid;
	std::string machine_password, prev_machine_password;
};

int x_smbd_secrets_load(x_smbd_secrets_t &secrets,
		const std::string &private_dir,
		const std::string &workgroup,
		const std::string &netbios_name);


#endif /* __smbd_secrets__hxx__ */

