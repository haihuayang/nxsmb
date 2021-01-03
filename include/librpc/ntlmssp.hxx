
#ifndef __librpc__ntlmssp__hxx__
#define __librpc__ntlmssp__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/librpc/ndr_smb.hxx"
#include "include/librpc/security.hxx"
#include "librpc/idl/ntlmssp.idl.hxx"

namespace idl {

struct ndr_traits_s2u16string
{
	using has_buffers = std::false_type;
	using ndr_base_type = u16string;
	using ndr_data_type = x_ndr_type_primary;

	x_ndr_off_t scalars(const u16string &val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const;

	x_ndr_off_t scalars(u16string &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const;

	void ostr(const u16string &val, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const {
		X_ASSERT(level == X_NDR_SWITCH_NONE);
		X_TODO;
		// ndr.os << val;
	}
};

#if 0
static inline uint32_t x_ndr_ntlmssp_negotiated_string_flags(uint32_t negotiate_flags)
{
	uint32_t flags = LIBNDR_FLAG_STR_NOTERM |
			 LIBNDR_FLAG_STR_CHARLEN |
			 LIBNDR_FLAG_REMAINING;

	if (!(negotiate_flags & NTLMSSP_NEGOTIATE_UNICODE)) {
		flags |= LIBNDR_FLAG_STR_ASCII;
	}

	return flags;
}


struct ntlmssp_VERSION {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	ntlmssp_WindowsMajorVersion ProductMajorVersion;
	ntlmssp_WindowsMinorVersion ProductMinorVersion;
	uint16 ProductBuild;
	std::array<uint8, 3> Reserved;
	ntlmssp_NTLMRevisionCurrent NTLMRevisionCurrent;
} /* [public] */;

template <> struct x_ndr_traits_t<ntlmssp_VERSION> {
	using has_buffers = std::false_type;
	using ndr_data_type x_ndr_type_struct;
};

union ntlmssp_Version
{
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	ntlmssp_VERSION version;/* [case(NTLMSSP_NEGOTIATE_VERSION)] */
} /* [nodiscriminant] */;

template <> struct x_ndr_traits_t<ntlmssp_Version> {
	using has_buffers = std::false_type;
	using ndr_data_type x_ndr_type_union;
};
#endif

struct NEGOTIATE_MESSAGE {
	NEGOTIATE NegotiateFlags;
	std::shared_ptr<std::string> DomainName; // x_ndr_relative_ptr_t<sstring, uint16, uint16> DomainName;/* [relative] */
	std::shared_ptr<std::string> Workstation; // x_ndr_relative_ptr_t<sstring, uint16, uint16> Workstation;/* [relative] */
	ntlmssp_Version Version;/* [switch_is(NegotiateFlags&NTLMSSP_NEGOTIATE_VERSION)] */
} /* [public] */;

template <> struct ndr_traits_t<NEGOTIATE_MESSAGE> {
	using ndr_base_type = NEGOTIATE_MESSAGE;
	using has_buffers = std::true_type;
	using ndr_data_type = x_ndr_type_struct;

	x_ndr_off_t scalars(const NEGOTIATE_MESSAGE &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t scalars(NEGOTIATE_MESSAGE &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t buffers(const NEGOTIATE_MESSAGE &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t buffers(NEGOTIATE_MESSAGE &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	void ostr(const NEGOTIATE_MESSAGE &__val, x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
};

#if 0
enum ntlmssp_AvId : uint16 {
	MsvAvEOL=0,
	MsvAvNbComputerName=1,
	MsvAvNbDomainName=2,
	MsvAvDnsComputerName=3,
	MsvAvDnsDomainName=4,
	MsvAvDnsTreeName=5,
	MsvAvFlags=6,
	MsvAvTimestamp=7,
	MsvAvSingleHost=8,
	MsvAvTargetName=9,
	MsvChannelBindings=10,
};

template <> struct x_ndr_traits_t<ntlmssp_AvId> {
	using has_buffers = std::false_type;
	using ndr_data_type x_ndr_type_enum;
	using ndr_base_type = uint16;
	static const std::array<std::pair<uint16, const char *>, 11> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<ntlmssp_AvId>(const ntlmssp_AvId &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint1632(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<ntlmssp_AvId>(ntlmssp_AvId &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint16_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = ntlmssp_AvId(v);
	return __bpos;
}


struct ntlmssp_SingleHostData {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	LSAP_TOKEN_INFO_INTEGRITY token_info;
	DATA_BLOB remaining;/* [flag(LIBNDR_FLAG_REMAINING)] */
} /* [flag(LIBNDR_PRINT_ARRAY_HEX)] */;

template <> struct x_ndr_traits_t<ntlmssp_SingleHostData> {
	using has_buffers = std::false_type;
	using ndr_data_type x_ndr_type_struct;
};

enum ntlmssp_AvFlags : uint32 {
	NTLMSSP_AVFLAG_CONSTRAINTED_ACCOUNT=0x00000001,
	NTLMSSP_AVFLAG_MIC_IN_AUTHENTICATE_MESSAGE=0x00000002,
	NTLMSSP_AVFLAG_TARGET_SPN_FROM_UNTRUSTED_SOURCE=0x00000004,
}/* [bitmap32bit] */;

template <> struct x_ndr_traits_t<ntlmssp_AvFlags> {
	using has_buffers = std::false_type;
	using ndr_data_type x_ndr_type_bitmap;
	using ndr_base_type = uint32;
	static const std::array<std::pair<uint32, const char *>, 3> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<ntlmssp_AvFlags>(const ntlmssp_AvFlags &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint32(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<ntlmssp_AvFlags>(ntlmssp_AvFlags &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint32_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = ntlmssp_AvFlags(v);
	return __bpos;
}



union ntlmssp_AvValue
{
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	ntlmssp_AvValue() { }
	~ntlmssp_AvValue() { }
	void __init(x_ndr_switch_t __level);
	void __init(x_ndr_switch_t __level, const ntlmssp_AvValue &__other);
	void __uninit(x_ndr_switch_t __level);
	std::u16string AvNbComputerName;/* [case(MsvAvNbComputerName)] */
	std::u16string AvNbDomainName;/* [case(MsvAvNbDomainName)] */
	std::u16string AvDnsComputerName;/* [case(MsvAvDnsComputerName)] */
	std::u16string AvDnsDomainName;/* [case(MsvAvDnsDomainName)] */
	std::u16string AvDnsTreeName;/* [case(MsvAvDnsTreeName)] */
	ntlmssp_AvFlags AvFlags;/* [case(MsvAvFlags)] */
	NTTIME AvTimestamp;/* [case(MsvAvTimestamp)] */
	ntlmssp_SingleHostData AvSingleHost;/* [case(MsvAvSingleHost)] */
	std::u16string AvTargetName;/* [case(MsvAvTargetName)] */
	std::array<uint8, 16> ChannelBindings;/* [case(MsvChannelBindings)] */
	DATA_BLOB blob;/* [default, flag(LIBNDR_FLAG_REMAINING)] */
} /* [gensize, nodiscriminant, flag(LIBNDR_FLAG_NOALIGN)] */;

template <> struct x_ndr_traits_t<ntlmssp_AvValue> {
	using has_buffers = std::false_type;
	using ndr_data_type x_ndr_type_union;
};


struct AV_PAIR {
	AV_PAIR();
	~AV_PAIR();
	AV_PAIR(const AV_PAIR& other);
	AV_PAIR &operator=(const AV_PAIR& other);
	void set_AvId(ntlmssp_AvId v);
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	ntlmssp_AvId AvId;
	ntlmssp_AvValue Value;/* [switch_is(AvId)] */
} /* [public, flag(LIBNDR_FLAG_NOALIGN)] */;

template <> struct x_ndr_traits_t<AV_PAIR> {
	using has_buffers = std::true_type;
	using ndr_data_type x_ndr_type_struct;
};

struct AV_PAIR_LIST {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	std::vector<AV_PAIR> pair; // x_ndr_vector_with_count_t<AV_PAIR> pair;
} /* [gensize, public, flag(LIBNDR_FLAG_NOALIGN)] */;

template <> struct x_ndr_traits_t<AV_PAIR_LIST> {
	using has_buffers = std::false_type;
	using ndr_data_type x_ndr_type_struct;
};
#endif

struct CHALLENGE_MESSAGE {
	std::shared_ptr<gstring> TargetName;/* [relative, flag(x_ndr_ntlmssp_negotiated_string_flags(NegotiateFlags))] */
	NEGOTIATE NegotiateFlags;
	std::array<uint8, 8> ServerChallenge;
	std::array<uint8, 8> Reserved;/* [noprint] */
	std::shared_ptr<AV_PAIR_LIST> TargetInfo; //  x_ndr_relative_ptr_t<AV_PAIR_LIST, uint16, uint16> TargetInfo;/* [relative] */
	ntlmssp_Version Version;/* [switch_is(NegotiateFlags&NTLMSSP_NEGOTIATE_VERSION)] */
} /* [public, flag(LIBNDR_PRINT_ARRAY_HEX)] */;

template <> struct ndr_traits_t<CHALLENGE_MESSAGE> {
	using ndr_base_type = CHALLENGE_MESSAGE;
	using has_buffers = std::true_type;
	using ndr_data_type = x_ndr_type_struct;

	x_ndr_off_t scalars(const CHALLENGE_MESSAGE &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t scalars(CHALLENGE_MESSAGE &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t buffers(const CHALLENGE_MESSAGE &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t buffers(CHALLENGE_MESSAGE &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	void ostr(const CHALLENGE_MESSAGE &__val, x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
};
#if 0
struct LM_RESPONSE {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	std::array<uint8, 24> Response;
} /* [public, flag(LIBNDR_PRINT_ARRAY_HEX)] */;

template <> struct x_ndr_traits_t<LM_RESPONSE> {
	using has_buffers = std::false_type;
	using ndr_data_type x_ndr_type_struct;
};

struct LMv2_RESPONSE {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	std::array<uint8, 16> Response;
	std::array<uint8, 8> ChallengeFromClient;
} /* [public, flag(LIBNDR_PRINT_ARRAY_HEX)] */;

template <> struct x_ndr_traits_t<LMv2_RESPONSE> {
	using has_buffers = std::false_type;
	using ndr_data_type x_ndr_type_struct;
};

union ntlmssp_LM_RESPONSE
{
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	LM_RESPONSE v1;/* [case(24)] */
} /* [nodiscriminant] */;

template <> struct x_ndr_traits_t<ntlmssp_LM_RESPONSE> {
	using has_buffers = std::false_type;
	using ndr_data_type x_ndr_type_union;
};


struct NTLM_RESPONSE {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	std::array<uint8, 24> Response;
} /* [public, flag(LIBNDR_PRINT_ARRAY_HEX)] */;

template <> struct x_ndr_traits_t<NTLM_RESPONSE> {
	using has_buffers = std::false_type;
	using ndr_data_type x_ndr_type_struct;
};

struct NTLMv2_CLIENT_CHALLENGE {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	uint16 Reserved1;/* [noprint] */
	uint32 Reserved2;/* [noprint] */
	NTTIME TimeStamp;
	std::array<uint8, 8> ChallengeFromClient;
	uint32 Reserved3;/* [noprint] */
	AV_PAIR_LIST AvPairs;/* [flag(LIBNDR_FLAG_REMAINING)] */
} /* [flag(LIBNDR_PRINT_ARRAY_HEX)] */;

template <> struct x_ndr_traits_t<NTLMv2_CLIENT_CHALLENGE> {
	using has_buffers = std::false_type;
	using ndr_data_type x_ndr_type_struct;
};

struct NTLMv2_RESPONSE {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	std::array<uint8, 16> Response;
	NTLMv2_CLIENT_CHALLENGE Challenge;
} /* [public, flag(LIBNDR_PRINT_ARRAY_HEX)] */;

template <> struct x_ndr_traits_t<NTLMv2_RESPONSE> {
	using has_buffers = std::false_type;
	using ndr_data_type x_ndr_type_struct;
};

union ntlmssp_NTLM_RESPONSE
{
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	ntlmssp_NTLM_RESPONSE() { }
	~ntlmssp_NTLM_RESPONSE() { }
	void __init(x_ndr_switch_t __level);
	void __init(x_ndr_switch_t __level, const ntlmssp_NTLM_RESPONSE &__other);
	void __uninit(x_ndr_switch_t __level);
	NTLM_RESPONSE v1;/* [case(0x18)] */
	NTLMv2_RESPONSE v2;/* [default] */
} /* [public, nodiscriminant] */;

template <> struct x_ndr_traits_t<ntlmssp_NTLM_RESPONSE> {
	using has_buffers = std::false_type;
	using ndr_data_type x_ndr_type_union;
};

const int NTLMSSP_MIC_OFFSET = 72;
const int NTLMSSP_MIC_SIZE = 16;

struct ntlmssp_MIC {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	std::vector<uint8> MIC; // x_ndr_vector_with_count_t<uint8> MIC;
} /* [flag(LIBNDR_PRINT_ARRAY_HEX)] */;

template <> struct x_ndr_traits_t<ntlmssp_MIC> {
	using has_buffers = std::false_type;
	using ndr_data_type x_ndr_type_struct;
};
#endif
struct AUTHENTICATE_MESSAGE {
	std::shared_ptr<LM_RESPONSE> LmChallengeResponse; //x_ndr_relative_ptr_t<LM_RESPONSE, uint16, uint16> LmChallengeResponse;/* [relative] */
	std::shared_ptr<DATA_BLOB> NtChallengeResponse;/* [relative] */
	std::shared_ptr<gstring> DomainName; // x_ndr_relative_ptr_t<gstring, uint16, uint16> DomainName;/* [relative, flag(x_ndr_ntlmssp_negotiated_string_flags(NegotiateFlags))] */
	std::shared_ptr<gstring> UserName; // x_ndr_relative_ptr_t<gstring, uint16, uint16> UserName;/* [relative, flag(x_ndr_ntlmssp_negotiated_string_flags(NegotiateFlags))] */
	std::shared_ptr<gstring> Workstation; // x_ndr_relative_ptr_t<gstring, uint16, uint16> Workstation;/* [relative, flag(x_ndr_ntlmssp_negotiated_string_flags(NegotiateFlags))] */
	std::shared_ptr<DATA_BLOB> EncryptedRandomSessionKey; // x_ndr_relative_ptr_t<DATA_BLOB, uint16, uint16> EncryptedRandomSessionKey;/* [relative] */
	NEGOTIATE NegotiateFlags;
	ntlmssp_Version Version;/* [switch_is(NegotiateFlags&NTLMSSP_NEGOTIATE_VERSION)] */
	ntlmssp_MIC mic;
} /* [public, flag(LIBNDR_FLAG_REMAINING)] */;

template <> struct ndr_traits_t<AUTHENTICATE_MESSAGE> {
	using ndr_base_type = AUTHENTICATE_MESSAGE;
	using has_buffers = std::true_type;
	using ndr_data_type = x_ndr_type_struct;

	x_ndr_off_t scalars(const AUTHENTICATE_MESSAGE &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t scalars(AUTHENTICATE_MESSAGE &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t buffers(const AUTHENTICATE_MESSAGE &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t buffers(AUTHENTICATE_MESSAGE &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	void ostr(const AUTHENTICATE_MESSAGE &__val, x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
};


#if 0
const int NTLMSSP_SIGN_VERSION = 0x01;
const int NTLMSSP_SIG_SIZE = 16;

struct NTLMSSP_MESSAGE_SIGNATURE {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	uint32 RandomPad;
	uint32 Checksum;
	uint32 SeqNum;
} /* [public] */;

template <> struct x_ndr_traits_t<NTLMSSP_MESSAGE_SIGNATURE> {
	using has_buffers = std::false_type;
	using ndr_data_type x_ndr_type_struct;
};

struct NTLMSSP_MESSAGE_SIGNATURE_NTLMv2 {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	std::array<uint8, 8> Checksum;
	uint32 SeqNum;
} /* [public, flag(LIBNDR_PRINT_ARRAY_HEX)] */;

template <> struct x_ndr_traits_t<NTLMSSP_MESSAGE_SIGNATURE_NTLMv2> {
	using has_buffers = std::false_type;
	using ndr_data_type x_ndr_type_struct;
};
#endif
}

#endif /* __librpc__ntlmssp__hxx__ */

