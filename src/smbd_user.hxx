
#ifndef __smbd_user__hxx__
#define __smbd_user__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "defines.hxx"
#include "include/librpc/misc.hxx"
#include "include/librpc/samr.hxx"
#include "auth.hxx"

struct x_smbd_user_t
{
	idl::dom_sid domain_sid;
	uint32_t uid, gid;
	std::vector<idl::samr_RidWithAttribute> group_rids;
	std::vector<x_dom_sid_with_attrs_t> other_sids;
	std::string account_name, logon_domain;

	std::string tostring() const;
};



#endif /* __smbd_user__hxx__ */

