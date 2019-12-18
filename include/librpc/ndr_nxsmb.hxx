
#ifndef __ndr_nxsmb__hxx__
#define __ndr_nxsmb__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "ndr.hxx"

namespace idl {

struct NTTIME
{
	uint64_t val;
};

template <>
struct x_ndr_traits_t<NTTIME> {
	using has_buffers = std::false_type;
	using ndr_type = x_ndr_type_struct;
};

template <>
inline x_ndr_off_t x_ndr_scalars(const NTTIME &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint64(t.val, ndr, bpos, epos, flags, 4);
}

template <>
inline x_ndr_off_t x_ndr_scalars(NTTIME &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	return x_ndr_pull_uint64(t.val, ndr, bpos, epos, flags, 4);
}

void x_ndr_ostr(const NTTIME &t, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level);

struct NTTIME_hyper
{
	uint64_t val;
};

}

#endif /* __ndr_nxsmb__hxx__ */

