
#ifndef __librpc__security__hxx__
#define __librpc__security__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "librpc/idl/security.idl.hxx"

namespace idl {

std::ostream &operator<<(std::ostream &os, const dom_sid &val);

template <>
x_ndr_off_t x_ndr_scalars<dom_sid>(const dom_sid &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level);

template <>
x_ndr_off_t x_ndr_scalars<dom_sid>(dom_sid &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level);

template <>
void x_ndr_ostr<dom_sid>(const dom_sid &v, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level);

struct dom_sid2 {
	dom_sid val;
};

template <>
x_ndr_off_t x_ndr_scalars<dom_sid2>(const dom_sid2 &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level);

template <>
x_ndr_off_t x_ndr_scalars<dom_sid2>(dom_sid2 &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level);

template <>
inline void x_ndr_ostr<dom_sid2>(const dom_sid2 &v, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level)
{
	x_ndr_ostr(v.val, ndr, flags, level);
}

}

#endif /* __librpc__security__hxx__ */

