
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

}

#endif /* __librpc__security__hxx__ */

