
#ifndef __smbd_secrets__hxx__
#define __smbd_secrets__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "defines.hxx"
#include <string>
#include "include/librpc/misc.hxx"
#include "include/librpc/security.hxx"

int x_smbd_secrets_init();
const std::string x_smbd_secrets_fetch_machine_password(const std::string &domain);
const std::string x_smbd_secrets_fetch_prev_machine_password(const std::string &domain);
bool x_smbd_secrets_fetch_domain_guid(const std::string &domain, idl::GUID &guid);
bool x_smbd_secrets_fetch_domain_sid(const std::string &domain, idl::dom_sid &sid);


#endif /* __smbd_secrets__hxx__ */

