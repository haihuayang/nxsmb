
#ifndef __ndr_pac__hxx__
#define __ndr_pac__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/librpc/ndr_nxsmb.hxx"
// #include "librpc/idl/security.h"
#include "include/librpc/ndr_netlogon.hxx"

namespace idl {

struct PAC_LOGON_NAME {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	NTTIME logon_time;
	x_ndr_s2_u16string_t account_name;
} ;

template <> struct x_ndr_traits_t<PAC_LOGON_NAME> {
	using has_buffers = std::false_type;
	using ndr_type = x_ndr_type_struct;
};


struct PAC_SIGNATURE_DATA {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	uint32 type;
	DATA_BLOB signature;/* [flag(LIBNDR_FLAG_REMAINING)] */
} /* [public, flag(LIBNDR_PRINT_ARRAY_HEX)] */;

template <> struct x_ndr_traits_t<PAC_SIGNATURE_DATA> {
	using has_buffers = std::false_type;
	using ndr_type = x_ndr_type_struct;
};


struct PAC_LOGON_INFO {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	x_ndr_off_t ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	netr_SamInfo3 info3;
	x_ndr_unique_ptr_t<dom_sid2> res_group_dom_sid;
	samr_RidWithAttributeArray res_groups;
} ;

template <> struct x_ndr_traits_t<PAC_LOGON_INFO> {
	using has_buffers = std::true_type;
	using ndr_type = x_ndr_type_struct;
};


struct PAC_CONSTRAINED_DELEGATION {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	x_ndr_off_t ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	lsa_String proxy_target;
	x_ndr_vector_unique_ptr_t<lsa_String> transited_services ;/* [size_is(num_transited_services)] */
} ;

template <> struct x_ndr_traits_t<PAC_CONSTRAINED_DELEGATION> {
	using has_buffers = std::true_type;
	using ndr_type = x_ndr_type_struct;
};

struct PAC_LOGON_INFO_CTR
{
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const {
		return x_ndr_scalars(info, __ndr, __bpos, __epos, __flags, __level);
	}
	x_ndr_off_t ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const {
		return x_ndr_buffers(info, __ndr, __bpos, __epos, __flags, __level);
	}
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) {
		return x_ndr_scalars(info, __ndr, __bpos, __epos, __flags, __level);
	}
	x_ndr_off_t ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) {
		return x_ndr_buffers(info, __ndr, __bpos, __epos, __flags, __level);
	}
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const {
		x_ndr_ostr(info, __ndr, __flags, __level);
	}
	x_ndr_unique_ptr_t<PAC_LOGON_INFO> info;
};

template <> struct x_ndr_traits_t<PAC_LOGON_INFO_CTR> {
	using has_buffers = std::true_type;
	using ndr_type = x_ndr_type_struct;
};

using PAC_CONSTRAINED_DELEGATION_CTR = x_ndr_unique_ptr_t<PAC_CONSTRAINED_DELEGATION>;
#if 0
struct PAC_CONSTRAINED_DELEGATION_CTR {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	x_ndr_off_t ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ptr_pos;
	std::shared_ptr<PAC_CONSTRAINED_DELEGATION> info;
} /* [public] */;

template <> struct x_ndr_traits_t<PAC_CONSTRAINED_DELEGATION_CTR> {
	using has_buffers = std::true_type;
	using ndr_type = x_ndr_type_struct;
};
#endif

enum PAC_TYPE : uint32 {
	PAC_TYPE_LOGON_INFO=1,
	PAC_TYPE_SRV_CHECKSUM=6,
	PAC_TYPE_KDC_CHECKSUM=7,
	PAC_TYPE_LOGON_NAME=10,
	PAC_TYPE_CONSTRAINED_DELEGATION=11,
	PAC_TYPE_UNKNOWN_12=12,
}/* [v1_enum, public] */;

template <> struct x_ndr_traits_t<PAC_TYPE> {
	using ndr_type = x_ndr_type_enum;
	using ndr_base_type = uint32;
	static const std::array<std::pair<uint32, const char *>, 6> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<PAC_TYPE>(const PAC_TYPE &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint32(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<PAC_TYPE>(PAC_TYPE &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint32_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = PAC_TYPE(v);
	return __bpos;
}

union PAC_INFO
{
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	x_ndr_off_t ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;

	PAC_INFO(x_ndr_switch_t __level) { __init(__level); }
	~PAC_INFO() { }
	void __init(x_ndr_switch_t __level);
	void __init(x_ndr_switch_t __level, const PAC_INFO &__other);
	void __uninit(x_ndr_switch_t __level);
	x_ndr_subndr_t<PAC_LOGON_INFO_CTR> logon_info;/* [subcontext(0xFFFFFC01), case(PAC_TYPE_LOGON_INFO)] */
	PAC_SIGNATURE_DATA srv_cksum;/* [case(PAC_TYPE_SRV_CHECKSUM)] */
	PAC_SIGNATURE_DATA kdc_cksum;/* [case(PAC_TYPE_KDC_CHECKSUM)] */
	PAC_LOGON_NAME logon_name;/* [case(PAC_TYPE_LOGON_NAME)] */
	x_ndr_subndr_t<PAC_CONSTRAINED_DELEGATION_CTR> constrained_delegation;/* [subcontext(0xFFFFFC01), case(PAC_TYPE_CONSTRAINED_DELEGATION)] */
	DATA_BLOB unknown;/* [subcontext(0), default] */
} /* [gensize, nodiscriminant, public] */;

template <> struct x_ndr_traits_t<PAC_INFO> {
	using has_buffers = std::false_type;
	using ndr_type = x_ndr_type_union;
};


struct PAC_BUFFER {
	~PAC_BUFFER() {
		if (info.val) {
			info.val->__uninit(type);
		}
	}

	// PAC_BUFFER(const PAC_BUFFER& other);
	// PAC_BUFFER &operator=(const PAC_BUFFER& other);
	// void set_type(PAC_TYPE v);
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	x_ndr_off_t ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	PAC_TYPE type;
	x_ndr_s4o4_ptr_t<PAC_INFO> info;/* [relative, subcontext_size(_subcontext_size_PAC_INFO(r,ndr->flags)), subcontext(0), switch_is(type), flag(LIBNDR_FLAG_ALIGN8)] */
} /* [public] */;

template <> struct x_ndr_traits_t<PAC_BUFFER> {
	using has_buffers = std::true_type;
	using ndr_type = x_ndr_type_struct;
};


struct PAC_DATA {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	x_ndr_off_t ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	uint32 version;
	x_ndr_vector_with_count_t<PAC_BUFFER> buffers;
} /* [public] */;

template <> struct x_ndr_traits_t<PAC_DATA> {
	using has_buffers = std::true_type;
	using ndr_type = x_ndr_type_struct;
};


struct PAC_BUFFER_RAW {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	x_ndr_off_t ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	PAC_TYPE type;
	x_ndr_s4o4_ptr_t<DATA_BLOB> info; /* [relative, subcontext_size(NDR_ROUND(ndr_size,8)), subcontext(0), flag(LIBNDR_FLAG_ALIGN8)] */
} /* [public] */;

template <> struct x_ndr_traits_t<PAC_BUFFER_RAW> {
	using ndr_type = x_ndr_type_struct;
};


struct PAC_DATA_RAW {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	x_ndr_off_t ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	uint32 version;
	x_ndr_vector_with_count_t<PAC_BUFFER_RAW> buffers;
} /* [public] */;

template <> struct x_ndr_traits_t<PAC_DATA_RAW> {
	using has_buffers = std::true_type;
	using ndr_type = x_ndr_type_struct;
};

const int NETLOGON_GENERIC_KRB5_PAC_VALIDATE = 3;

struct PAC_Validate {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	uint32 ChecksumLength;
	int32 SignatureType;
	uint32 SignatureLength;
	DATA_BLOB ChecksumAndSignature;/* [flag(LIBNDR_FLAG_REMAINING)] */
} /* [public] */;

template <> struct x_ndr_traits_t<PAC_Validate> {
	using ndr_type = x_ndr_type_struct;
};


struct netsamlogoncache_entry {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	uint32 timestamp;
	netr_SamInfo3 info3;
} /* [public] */;

template <> struct x_ndr_traits_t<netsamlogoncache_entry> {
	using ndr_type = x_ndr_type_struct;
};

#if 0
struct PAC_SIGNATURE_DATA {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	uint32 type;
	DATA_BLOB signature;/* [flag(LIBNDR_FLAG_REMAINING)] */
} /* [public, flag(LIBNDR_PRINT_ARRAY_HEX)] */;

template <> struct x_ndr_traits_t<PAC_SIGNATURE_DATA> {
	using ndr_type = x_ndr_type_struct;
};


enum PAC_TYPE : uint32 {
	PAC_TYPE_LOGON_INFO=1,
	PAC_TYPE_SRV_CHECKSUM=6,
	PAC_TYPE_KDC_CHECKSUM=7,
	PAC_TYPE_LOGON_NAME=10,
	PAC_TYPE_CONSTRAINED_DELEGATION=11,
	PAC_TYPE_UNKNOWN_12=12,
}/* [v1_enum, public] */;

template <> struct x_ndr_traits_t<PAC_TYPE> {
	using ndr_type = x_ndr_type_enum;
	using ndr_base_type = uint32;
	static const std::array<std::pair<uint32, const char *>, 6> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_data<PAC_TYPE>(const PAC_TYPE &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint32(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_data<PAC_TYPE>(PAC_TYPE &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint32_t v;
	X_NDR_DATA(v, __ndr, __bpos, __epos, __flags, __level);
	__val = PAC_TYPE(v);
	return __bpos;
}

typedef uint32_t netr_SamInfo3; // TODO
typedef uint32_t samr_RidWithAttributeArray; // TODO
struct PAC_LOGON_INFO {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	netr_SamInfo3 info3;
	std::shared_ptr<dom_sid> res_group_dom_sid;
	samr_RidWithAttributeArray res_groups;
} ;

template <> struct x_ndr_traits_t<PAC_LOGON_INFO> {
	using ndr_type = x_ndr_type_struct;
};

#if 0
union PAC_INFO
{
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	PAC_INFO() { }
	~PAC_INFO() { }
	void __init(x_ndr_switch_t __level);
	void __init(x_ndr_switch_t __level, const PAC_INFO &__other);
	void __uninit(x_ndr_switch_t __level);
	PAC_LOGON_INFO_CTR logon_info;/* [subcontext(0xFFFFFC01), case(PAC_TYPE_LOGON_INFO)] */
	PAC_SIGNATURE_DATA srv_cksum;/* [case(PAC_TYPE_SRV_CHECKSUM)] */
	PAC_SIGNATURE_DATA kdc_cksum;/* [case(PAC_TYPE_KDC_CHECKSUM)] */
	PAC_LOGON_NAME logon_name;/* [case(PAC_TYPE_LOGON_NAME)] */
	PAC_CONSTRAINED_DELEGATION_CTR constrained_delegation;/* [subcontext(0xFFFFFC01), case(PAC_TYPE_CONSTRAINED_DELEGATION)] */
	DATA_BLOB_REM unknown;/* [subcontext(0), default] */
} /* [gensize, nodiscriminant, public] */;

template <> struct x_ndr_traits_t<PAC_INFO> {
	using ndr_type = x_ndr_type_union;
};
#endif

struct PAC_BUFFER {
	PAC_BUFFER();
	~PAC_BUFFER();
	PAC_BUFFER(const PAC_BUFFER& other);
	PAC_BUFFER &operator=(const PAC_BUFFER& other);
	void set_type(PAC_TYPE v);
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	PAC_TYPE type;
	uint32_t info;
	// x_ndr_ptr_t<PAC_INFO> info;/* [relative, subcontext_size(_subcontext_size_PAC_INFO(r,ndr->flags)), subcontext(0), switch_is(type), flag(LIBNDR_FLAG_ALIGN8)] */
} /* [nopush, public, nopull] */;

template <> struct x_ndr_traits_t<PAC_BUFFER> {
	using ndr_type = x_ndr_type_struct;
};

struct PAC_DATA {
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	uint32 version;
	std::vector<x_ndr_ptr_t<PAC_BUFFER>> ndr_buffers;
} /* [nopush, public, nopull] */;

template <> struct x_ndr_traits_t<PAC_DATA> {
	using has_buffers = std::true_type;
	using ndr_type = x_ndr_type_struct;
};

struct DATA_BLOB_REM {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	DATA_BLOB remaining;/* [flag(LIBNDR_FLAG_REMAINING)] */
} ;

template <> struct x_ndr_traits_t<DATA_BLOB_REM> {
	using ndr_type = x_ndr_type_struct;
};

struct PAC_BUFFER_RAW {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	PAC_TYPE type;
	uint32 ndr_size;
	std::shared_ptr<DATA_BLOB_REM> info;/* [relative, subcontext_size(NDR_ROUND(ndr_size,8)), subcontext(0), flag(LIBNDR_FLAG_ALIGN8)] */
} /* [public] */;

template <> struct x_ndr_traits_t<PAC_BUFFER_RAW> {
	using ndr_type = x_ndr_type_struct;
};

struct PAC_DATA_RAW {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	uint32 version;
	std::vector<PAC_BUFFER_RAW> ndr_buffers;
} /* [public] */;

template <> struct x_ndr_traits_t<PAC_DATA_RAW> {
	using ndr_type = x_ndr_type_struct;
};

const int NETLOGON_GENERIC_KRB5_PAC_VALIDATE = 3;
#endif
}

#endif /* __ndr_pac__hxx__ */

