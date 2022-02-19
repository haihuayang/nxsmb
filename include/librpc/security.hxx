
#ifndef __librpc__security__hxx__
#define __librpc__security__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "ndr_wrap.hxx"
#include "librpc/idl/security.idl.hxx"

namespace idl {

std::ostream &operator<<(std::ostream &os, const dom_sid &val);

x_ndr_off_t dom_sid_ndr_scalars(const dom_sid &val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level);

x_ndr_off_t dom_sid_ndr_scalars(dom_sid &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level);

struct ndr_traits_dom_sid2
{
	using has_buffers = std::false_type;
	using ndr_base_type = dom_sid;
	using ndr_data_type = x_ndr_type_primary;

	x_ndr_off_t scalars(const dom_sid &val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const;

	x_ndr_off_t scalars(dom_sid &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const;

	void ostr(const dom_sid &val, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		ndr.os << val;
	}
};

long dom_sid_compare_domain(const dom_sid &sid1, const dom_sid &sid2);
long dom_sid_compare(const dom_sid &sid1, const dom_sid &sid2);
bool dom_sid_in_domain(const dom_sid &domain, const dom_sid &sid);

static inline bool operator==(const dom_sid &sid1, const dom_sid &sid2) {
	return dom_sid_compare(sid1, sid2) == 0;
}

/* domain num_auths must less than 15 */
static inline dom_sid dom_sid_from_domain_and_rid(const dom_sid &domain, uint32_t rid)
{
	X_ASSERT(domain.num_auths < domain.sub_auths.size());
	dom_sid ret = domain;
	ret.sub_auths[ret.num_auths++] = rid;
	return ret;
}

static inline bool operator==(const security_ace &ace1, const security_ace &ace2)
{
	if (ace1.type != ace2.type) {
		return false;
	}
	if (ace1.flags != ace2.flags) {
		return false;
	}
	if (ace1.access_mask != ace2.access_mask) {
		return false;
	}
	return ace1.trustee == ace2.trustee;
}

std::ostream &operator<<(std::ostream &os, const security_ace &v);

}


#endif /* __librpc__security__hxx__ */

