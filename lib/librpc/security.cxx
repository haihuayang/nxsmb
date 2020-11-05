
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
	X_NDR_SCALARS_DEFAULT(val.id_auth, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	for (uint8_t i = 0; i < val.num_auths; ++i) {
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
	X_NDR_SCALARS_DEFAULT(val.id_auth, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	for (uint8_t i = 0; i < val.num_auths; ++i) {
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


#if 0
x_ndr_off_t ndr_traits_t<dom_sid>::scalars(dom_sid &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS_SIMPLE(__val.sid_rev_num, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS_SIMPLE(__val.num_auths, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	if (__val.num_auths > 15) {
		return -NDR_ERR_RANGE;
	}
	X_NDR_SCALARS_SIMPLE(__val.id_auth, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	for (uint8_t i = 0; i < __val.num_auths; ++i) {
		X_NDR_SCALARS(__val.sub_auths[i], ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	}
	X_NDR_TRAILER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

void ndr_traits_t<dom_sid>::ostr(const dom_sid &__val, x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	ndr.os << v;
}

template <>
void x_ndr_ostr<dom_sid>(const dom_sid &v, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	ndr.os << v;
}

static inline x_ndr_off_t x_ndr_push_dom_sid(const dom_sid &v, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	if (v.num_auths > 15) {
		return -NDR_ERR_RANGE;
	}
	X_NDR_ALIGN(4, ndr, bpos, epos, flags);
	X_NDR_SCALARS(v.sid_rev_num, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(v.num_auths, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(v.id_auth, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	for (uint8_t i = 0; i < v.num_auths; ++i) {
		X_NDR_SCALARS(v.sub_auths[i], ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	}
	return bpos;
}

static inline x_ndr_off_t x_ndr_pull_dom_sid(dom_sid &v, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	X_NDR_ALIGN(4, ndr, bpos, epos, flags);
	X_NDR_SCALARS(v.sid_rev_num, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(v.num_auths, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (v.num_auths > 15) {
		return -NDR_ERR_RANGE;
	}
	X_NDR_SCALARS(v.id_auth, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	for (uint8_t i = 0; i < v.num_auths; ++i) {
		X_NDR_SCALARS(v.sub_auths[i], ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	}
	return bpos;
}

template <>
x_ndr_off_t x_ndr_scalars<dom_sid>(const dom_sid &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	return x_ndr_push_dom_sid(t, ndr, bpos, epos, flags);
}

template <>
x_ndr_off_t x_ndr_scalars<dom_sid>(dom_sid &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	return x_ndr_pull_dom_sid(t, ndr, bpos, epos, flags);
}

template <>
x_ndr_off_t x_ndr_scalars<dom_sid2>(const dom_sid2 &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(uint3264{t.val.num_auths}, ndr, bpos, epos, flags, level);
	X_NDR_SCALARS(t.val, ndr, bpos, epos, flags, level);
	return bpos;
}

template <>
x_ndr_off_t x_ndr_scalars<dom_sid2>(dom_sid2 &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	uint3264 num_auths;
	X_NDR_SCALARS(num_auths, ndr, bpos, epos, flags, level);
	X_NDR_SCALARS(t.val, ndr, bpos, epos, flags, level);
	if (num_auths.val != t.val.num_auths) {
		return -NDR_ERR_ARRAY_SIZE;
	}
	return bpos;
}
#endif

} /* namespace idl */

