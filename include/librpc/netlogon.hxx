
#ifndef __netlogon__hxx__
#define __netlogon__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "ndr.hxx"

namespace idl {
#if 0
struct netr_DELTA_POLICY_OPTIONS
{
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	x_ndr_off_t ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	std::vector<uint32_t> val;
};

template <> struct x_ndr_traits_t<netr_DELTA_POLICY_OPTIONS> {
	using has_buffers = std::true_type;
	using ndr_data_type = x_ndr_type_struct;
};
#endif
}

#include "librpc/idl/netlogon.idl.hxx"

#endif /* __netlogon__hxx__ */

