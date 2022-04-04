
#ifndef __smbd_secrets__hxx__
#define __smbd_secrets__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include <string>

int x_smbd_secrets_init();
const std::string x_smbd_secrets_fetch_machine_password(const std::string &domain);
const std::string x_smbd_secrets_fetch_prev_machine_password(const std::string &domain);


#endif /* __smbd_secrets__hxx__ */

