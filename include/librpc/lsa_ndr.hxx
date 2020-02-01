
#ifndef __ndr_lsa__hxx__
#define __ndr_lsa__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/librpc/ndr.hxx"

namespace idl {

struct lsa_String
{
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	x_ndr_off_t ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	mutable x_ndr_off_t __pos_ptr;
	std::shared_ptr<u16string> val;
};

template <> struct x_ndr_traits_t<lsa_String> {
	using has_buffers = std::true_type;
	using ndr_type = x_ndr_type_struct;
};

struct lsa_BinaryString
{
};

struct lsa_StringLarge
{
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	x_ndr_off_t ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	mutable x_ndr_off_t __pos_ptr;
	std::shared_ptr<u16string> val;
};

template <> struct x_ndr_traits_t<lsa_StringLarge> {
	using has_buffers = std::true_type;
	using ndr_type = x_ndr_type_struct;
};

struct lsa_AsciiStringLarge
{
};

struct lsa_SidArray
{
};

enum lsa_TrustType : uint32 {
	LSA_TRUST_TYPE_DOWNLEVEL=0x00000001,
	LSA_TRUST_TYPE_UPLEVEL=0x00000002,
	LSA_TRUST_TYPE_MIT=0x00000003,
	LSA_TRUST_TYPE_DCE=0x00000004,
}/* [v1_enum, public] */;

template <> struct x_ndr_traits_t<lsa_TrustType> {
	using ndr_type = x_ndr_type_enum;
	using ndr_base_type = uint32;
	static const std::array<std::pair<uint32, const char *>, 4> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<lsa_TrustType>(const lsa_TrustType &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint32(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<lsa_TrustType>(lsa_TrustType &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint32_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = lsa_TrustType(v);
	return __bpos;
}

enum lsa_TrustAttributes : uint32 {
	LSA_TRUST_ATTRIBUTE_NON_TRANSITIVE=0x00000001,
	LSA_TRUST_ATTRIBUTE_UPLEVEL_ONLY=0x00000002,
	LSA_TRUST_ATTRIBUTE_QUARANTINED_DOMAIN=0x00000004,
	LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE=0x00000008,
	LSA_TRUST_ATTRIBUTE_CROSS_ORGANIZATION=0x00000010,
	LSA_TRUST_ATTRIBUTE_WITHIN_FOREST=0x00000020,
	LSA_TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL=0x00000040,
	LSA_TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION=0x00000080,
}/* [bitmap32bit, public] */;

template <> struct x_ndr_traits_t<lsa_TrustAttributes> {
	using ndr_type = x_ndr_type_bitmap;
	using ndr_base_type = uint32;
	static const std::array<std::pair<uint32, const char *>, 8> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<lsa_TrustAttributes>(const lsa_TrustAttributes &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint32(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<lsa_TrustAttributes>(lsa_TrustAttributes &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint32_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = lsa_TrustAttributes(v);
	return __bpos;
}


}

#endif /* __ndr_lsa__hxx__ */

