
#ifndef __ndr_security__hxx__
#define __ndr_security__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/librpc/ndr.hxx"
#include "include/librpc/ndr_misc.hxx"

namespace idl {

template <>
x_ndr_off_t x_ndr_data<dom_sid>(
	       	const dom_sid &t,
		x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level);

template <>
x_ndr_off_t x_ndr_data<dom_sid>(
	       	dom_sid &t,
		x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level);

void x_ndr_ostr(const dom_sid &v, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level);

}

#endif /* __ndr_security__hxx__ */

