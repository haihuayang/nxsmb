
#include "include/librpc/security.hxx"

namespace idl {

std::ostream &operator<<(std::ostream &os, const dom_sid &v)
{
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
	return os;
}

x_ndr_off_t dom_sid_ndr_scalars(const dom_sid &val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level)
{
	X_NDR_HEADER_ALIGN(4, ndr, bpos, epos, flags);
	X_NDR_SCALARS_DEFAULT(val.sid_rev_num, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS_DEFAULT(val.num_auths, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	X_NDR_PUSH_BYTES(val.id_auth.data(), val.id_auth.size(), ndr, bpos, epos);
	for (uint32_t i = 0; i < val.num_auths; ++i) {
		X_NDR_SCALARS_DEFAULT(val.sub_auths[i], ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	}
	X_NDR_TRAILER_ALIGN(4, ndr, bpos, epos, flags);
	return bpos;
}

x_ndr_off_t dom_sid_ndr_scalars(dom_sid &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level)
{
	X_NDR_HEADER_ALIGN(4, ndr, bpos, epos, flags);
	X_NDR_SCALARS_DEFAULT(val.sid_rev_num, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS_DEFAULT(val.num_auths, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (val.num_auths > 15) {
		return -NDR_ERR_RANGE;
	}
	X_NDR_PULL_BYTES(val.id_auth.data(), val.id_auth.size(), ndr, bpos, epos);
	for (uint32_t i = 0; i < val.num_auths; ++i) {
		X_NDR_SCALARS_DEFAULT(val.sub_auths[i], ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	}
	X_NDR_TRAILER_ALIGN(4, ndr, bpos, epos, flags);
	return bpos;
}

x_ndr_off_t ndr_traits_t<dom_sid>::scalars(const dom_sid &val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	return dom_sid_ndr_scalars(val, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
}
x_ndr_off_t ndr_traits_t<dom_sid>::scalars(dom_sid &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	return dom_sid_ndr_scalars(val, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
}

void ndr_traits_t<dom_sid>::ostr(const dom_sid &val, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	ndr.os << val;
}

x_ndr_off_t ndr_traits_dom_sid2::scalars(const dom_sid &val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	X_NDR_SCALARS_DEFAULT(uint3264{val.num_auths}, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	return dom_sid_ndr_scalars(val, ndr, bpos, epos, flags, level);
}

x_ndr_off_t ndr_traits_dom_sid2::scalars(dom_sid &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	uint3264 num_auths;
	X_NDR_SCALARS_DEFAULT(num_auths, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	bpos = dom_sid_ndr_scalars(val, ndr, bpos, epos, flags, level);
	if (num_auths.val != val.num_auths) {
		return -NDR_ERR_ARRAY_SIZE;
	}
	return bpos;
}

} /* namespace idl */

