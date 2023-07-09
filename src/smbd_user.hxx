
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
	x_smbd_user_t(const x_auth_info_t &auth_info,
			const std::vector<idl::dom_sid> &aliases,
			uint64_t priviledge_mask);

	const bool is_anonymous;
	const idl::dom_sid domain_sid;
	const uint32_t uid, gid;
	const std::vector<idl::samr_RidWithAttribute> group_rids;
	const std::vector<x_dom_sid_with_attrs_t> other_sids;
	const uint64_t priviledge_mask;
	const std::shared_ptr<std::u16string> account_name;
	const std::string logon_domain;

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

