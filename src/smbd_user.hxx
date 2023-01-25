
#ifndef __smbd_user__hxx__
#define __smbd_user__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "defines.hxx"
#include "include/librpc/misc.hxx"
#include "include/librpc/samr.hxx"
#include "auth.hxx"
#include "util_sid.hxx"

struct x_smbd_user_t
{
	idl::dom_sid domain_sid;
	uint32_t uid, gid;
	std::vector<idl::samr_RidWithAttribute> group_rids;
	std::vector<x_dom_sid_with_attrs_t> other_sids;
	std::string account_name, logon_domain;

	std::string tostring() const;

	idl::dom_sid get_owner_sid() const {
		idl::dom_sid owner;
		X_ASSERT(sid_compose(owner, domain_sid, uid));
		return owner;
	}

	bool match(const idl::dom_sid &sid) const {
		return idl::dom_sid_compare_domain_and_rid(sid, domain_sid, uid) == 0;
	}
};



#endif /* __smbd_user__hxx__ */

