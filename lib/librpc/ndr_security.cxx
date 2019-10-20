
#include "include/librpc/ndr_ntlmssp.hxx"
#include "librpc/idl/security.h"

namespace idl {

static inline x_ndr_off_t x_ndr_push_dom_sid(const dom_sid &v, x_ndr_push_t &ndr,
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

static inline x_ndr_off_t x_ndr_pull_dom_sid(dom_sid &v, x_ndr_pull_t &ndr,
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

void x_ndr_ostr(const dom_sid &v, x_ndr_ostr_t &os, uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	os << "S-" << v.sid_rev_num;

	uint64_t ia = ((uint64_t)v.id_auth[5]) +
		((uint64_t)v.id_auth[4] << 8 ) +
		((uint64_t)v.id_auth[3] << 16) +
		((uint64_t)v.id_auth[2] << 24) +
		((uint64_t)v.id_auth[1] << 32) +
		((uint64_t)v.id_auth[0] << 40);
	if (ia >= UINT32_MAX) {
		os << "0x" << std::hex << ia << std::dec;
	} else {
		os << ia;
	}
	for (int i = 0; i < v.num_auths; ++i) {
		os << '-' << v.sub_auths[i];
	}
}

}

