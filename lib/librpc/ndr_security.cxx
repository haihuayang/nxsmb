
#include "include/librpc/ndr_ntlmssp.hxx"
#include "librpc/idl/security.h"

namespace idl {

static inline x_ndr_off_t x_ndr_push_dom_sid(const struct dom_sid &v, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	if (v.num_auths > 15) {
		return -NDR_ERR_RANGE;
	}
	X_NDR_ALIGN(4, ndr, bpos, epos, flags);
	X_NDR_DATA(v.sid_rev_num, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	X_NDR_DATA(v.num_auths, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	X_NDR_DATA(v.id_auth, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	for (uint8_t i = 0; i < v.num_auths; ++i) {
		X_NDR_DATA(v.sub_auths[i], ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	}
	return bpos;
}

static inline x_ndr_off_t x_ndr_pull_dom_sid(struct dom_sid &v, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	X_NDR_ALIGN(4, ndr, bpos, epos, flags);
	X_NDR_DATA(v.sid_rev_num, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	X_NDR_DATA(v.num_auths, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (v.num_auths > 15) {
		return -NDR_ERR_RANGE;
	}
	X_NDR_DATA(v.id_auth, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	for (uint8_t i = 0; i < v.num_auths; ++i) {
		X_NDR_DATA(v.sub_auths[i], ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	}
	return bpos;
}

template <>
x_ndr_off_t x_ndr_data<dom_sid>(
	       	const dom_sid &t,
		x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	return x_ndr_push_dom_sid(t, ndr, bpos, epos, flags);
}

template <>
x_ndr_off_t x_ndr_data<dom_sid>(
	       	dom_sid &t,
		x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	return x_ndr_pull_dom_sid(t, ndr, bpos, epos, flags);
}

}

