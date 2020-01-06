
#include "include/librpc/ndr_ntlmssp.hxx"

namespace idl {

uint32_t x_ndr_ntlmssp_negotiated_string_flags(uint32_t negotiate_flags)
{
	uint32_t flags = LIBNDR_FLAG_STR_NOTERM |
			 LIBNDR_FLAG_STR_CHARLEN |
			 LIBNDR_FLAG_REMAINING;

	if (!(negotiate_flags & NTLMSSP_NEGOTIATE_UNICODE)) {
		flags |= LIBNDR_FLAG_STR_ASCII;
	}

	return flags;
}

const std::array<std::pair<uint32, const char *>, 3> x_ndr_traits_t<ntlmssp_MessageType>::value_name_map = { {
	{ NtLmNegotiate, "NtLmNegotiate" },
	{ NtLmChallenge, "NtLmChallenge" },
	{ NtLmAuthenticate, "NtLmAuthenticate" },
} };


const std::array<std::pair<uint32, const char *>, 26> x_ndr_traits_t<NEGOTIATE>::value_name_map = { {
		{ NTLMSSP_NEGOTIATE_UNICODE, "NTLMSSP_NEGOTIATE_UNICODE" },
		{ NTLMSSP_NEGOTIATE_OEM, "NTLMSSP_NEGOTIATE_OEM" },
		{ NTLMSSP_REQUEST_TARGET, "NTLMSSP_REQUEST_TARGET" },
		{ NTLMSSP_NEGOTIATE_SIGN, "NTLMSSP_NEGOTIATE_SIGN" },
		{ NTLMSSP_NEGOTIATE_SEAL, "NTLMSSP_NEGOTIATE_SEAL" },
		{ NTLMSSP_NEGOTIATE_DATAGRAM, "NTLMSSP_NEGOTIATE_DATAGRAM" },
		{ NTLMSSP_NEGOTIATE_LM_KEY, "NTLMSSP_NEGOTIATE_LM_KEY" },
		{ NTLMSSP_NEGOTIATE_NETWARE, "NTLMSSP_NEGOTIATE_NETWARE" },
		{ NTLMSSP_NEGOTIATE_NTLM, "NTLMSSP_NEGOTIATE_NTLM" },
		{ NTLMSSP_NEGOTIATE_NT_ONLY, "NTLMSSP_NEGOTIATE_NT_ONLY" },
		{ NTLMSSP_ANONYMOUS, "NTLMSSP_ANONYMOUS" },
		{ NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED, "NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED" },
		{ NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED, "NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED" },
		{ NTLMSSP_NEGOTIATE_THIS_IS_LOCAL_CALL, "NTLMSSP_NEGOTIATE_THIS_IS_LOCAL_CALL" },
		{ NTLMSSP_NEGOTIATE_ALWAYS_SIGN, "NTLMSSP_NEGOTIATE_ALWAYS_SIGN" },
		{ NTLMSSP_TARGET_TYPE_DOMAIN, "NTLMSSP_TARGET_TYPE_DOMAIN" },
		{ NTLMSSP_TARGET_TYPE_SERVER, "NTLMSSP_TARGET_TYPE_SERVER" },
		{ NTLMSSP_TARGET_TYPE_SHARE, "NTLMSSP_TARGET_TYPE_SHARE" },
		{ NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY, "NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY" },
		{ NTLMSSP_NEGOTIATE_IDENTIFY, "NTLMSSP_NEGOTIATE_IDENTIFY" },
		{ NTLMSSP_REQUEST_NON_NT_SESSION_KEY, "NTLMSSP_REQUEST_NON_NT_SESSION_KEY" },
		{ NTLMSSP_NEGOTIATE_TARGET_INFO, "NTLMSSP_NEGOTIATE_TARGET_INFO" },
		{ NTLMSSP_NEGOTIATE_VERSION, "NTLMSSP_NEGOTIATE_VERSION" },
		{ NTLMSSP_NEGOTIATE_128, "NTLMSSP_NEGOTIATE_128" },
		{ NTLMSSP_NEGOTIATE_KEY_EXCH, "NTLMSSP_NEGOTIATE_KEY_EXCH" },
		{ NTLMSSP_NEGOTIATE_56, "NTLMSSP_NEGOTIATE_56" },
} };
const std::array<std::pair<uint8, const char *>, 3> x_ndr_traits_t<ntlmssp_WindowsMajorVersion>::value_name_map = { {
	{ NTLMSSP_WINDOWS_MAJOR_VERSION_5, "NTLMSSP_WINDOWS_MAJOR_VERSION_5" },
	{ NTLMSSP_WINDOWS_MAJOR_VERSION_6, "NTLMSSP_WINDOWS_MAJOR_VERSION_6" },
	{ NTLMSSP_WINDOWS_MAJOR_VERSION_10, "NTLMSSP_WINDOWS_MAJOR_VERSION_10" },
} };


const std::array<std::pair<uint8, const char *>, 4> x_ndr_traits_t<ntlmssp_WindowsMinorVersion>::value_name_map = { {
	{ NTLMSSP_WINDOWS_MINOR_VERSION_0, "NTLMSSP_WINDOWS_MINOR_VERSION_0" },
	{ NTLMSSP_WINDOWS_MINOR_VERSION_1, "NTLMSSP_WINDOWS_MINOR_VERSION_1" },
	{ NTLMSSP_WINDOWS_MINOR_VERSION_2, "NTLMSSP_WINDOWS_MINOR_VERSION_2" },
	{ NTLMSSP_WINDOWS_MINOR_VERSION_3, "NTLMSSP_WINDOWS_MINOR_VERSION_3" },
} };


const std::array<std::pair<uint8, const char *>, 2> x_ndr_traits_t<ntlmssp_NTLMRevisionCurrent>::value_name_map = { {
	{ NTLMSSP_REVISION_W2K3_RC1, "NTLMSSP_REVISION_W2K3_RC1" },
	{ NTLMSSP_REVISION_W2K3, "NTLMSSP_REVISION_W2K3" },
} };



x_ndr_off_t ntlmssp_VERSION::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_HEADER_ALIGN(2, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(ProductMajorVersion, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(ProductMinorVersion, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(ProductBuild, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(Reserved, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(NTLMRevisionCurrent, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(2, __ndr, __bpos, __epos, __flags);
	return __bpos;
}


x_ndr_off_t ntlmssp_VERSION::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_HEADER_ALIGN(2, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(ProductMajorVersion, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(ProductMinorVersion, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(ProductBuild, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(Reserved, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(NTLMRevisionCurrent, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(2, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

void ntlmssp_VERSION::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(ProductMajorVersion, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(ProductMinorVersion, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(ProductBuild, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(Reserved, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(NTLMRevisionCurrent, __ndr, __flags, X_NDR_SWITCH_NONE);
	(__ndr) << leave;
}



x_ndr_off_t ntlmssp_Version::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_UNION_ALIGN(2, __ndr, __bpos, __epos, __flags);
	switch (__level) {
		case NTLMSSP_NEGOTIATE_VERSION: {
			X_NDR_SCALARS(version, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		default: {
		} break;
	}
	return __bpos;
}

x_ndr_off_t ntlmssp_Version::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_UNION_ALIGN(2, __ndr, __bpos, __epos, __flags);
	switch (__level) {
		case NTLMSSP_NEGOTIATE_VERSION: {
			X_NDR_SCALARS(version, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		default: {
		} break;
	}
	return __bpos;
}

void ntlmssp_Version::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	switch (__level) {
		case NTLMSSP_NEGOTIATE_VERSION: {
			X_NDR_OSTR(version, __ndr, __flags, X_NDR_SWITCH_NONE);
		} break;
		default: {
		} break;
	}
}


x_ndr_off_t NEGOTIATE_MESSAGE::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_VALUE((std::array<uint8, 8>{"NTLMSSP"}), __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_VALUE(ntlmssp_MessageType{NtLmNegotiate}, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(NegotiateFlags, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(DomainName, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(Workstation, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(Version, __ndr, __bpos, __epos, __flags, NegotiateFlags&NTLMSSP_NEGOTIATE_VERSION);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t NEGOTIATE_MESSAGE::ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_BUFFERS(DomainName, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(Workstation, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}

x_ndr_off_t NEGOTIATE_MESSAGE::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_VALUE((std::array<uint8, 8>{"NTLMSSP"}), __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_VALUE(ntlmssp_MessageType{NtLmNegotiate}, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(NegotiateFlags, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(DomainName, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(Workstation, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(Version, __ndr, __bpos, __epos, __flags, NegotiateFlags&NTLMSSP_NEGOTIATE_VERSION);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t NEGOTIATE_MESSAGE::ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_BUFFERS(DomainName, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(Workstation, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}

void NEGOTIATE_MESSAGE::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(NegotiateFlags, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(DomainName, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(Workstation, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(Version, __ndr, __flags, NegotiateFlags&NTLMSSP_NEGOTIATE_VERSION);
	(__ndr) << leave;
}


const std::array<std::pair<uint16, const char *>, 11> x_ndr_traits_t<ntlmssp_AvId>::value_name_map = { {
	{ MsvAvEOL, "MsvAvEOL" },
	{ MsvAvNbComputerName, "MsvAvNbComputerName" },
	{ MsvAvNbDomainName, "MsvAvNbDomainName" },
	{ MsvAvDnsComputerName, "MsvAvDnsComputerName" },
	{ MsvAvDnsDomainName, "MsvAvDnsDomainName" },
	{ MsvAvDnsTreeName, "MsvAvDnsTreeName" },
	{ MsvAvFlags, "MsvAvFlags" },
	{ MsvAvTimestamp, "MsvAvTimestamp" },
	{ MsvAvSingleHost, "MsvAvSingleHost" },
	{ MsvAvTargetName, "MsvAvTargetName" },
	{ MsvChannelBindings, "MsvChannelBindings" },
} };



x_ndr_off_t ntlmssp_SingleHostData::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_PRINT_ARRAY_HEX);
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	x_ndr_off_t __base = __bpos;
	X_NDR_SKIP(uint32_t, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(uint32_t(0), __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(token_info, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(remaining, __ndr, __bpos, __epos, x_ndr_set_flags(__flags, LIBNDR_FLAG_REMAINING), X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(uint32_t(__bpos - __base), __ndr, __base, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}


x_ndr_off_t ntlmssp_SingleHostData::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_PRINT_ARRAY_HEX);
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	x_ndr_off_t __base = __bpos;
	uint32 Size;
	X_NDR_SCALARS(Size, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	__epos = X_NDR_CHECK_POS(__base + Size, __bpos, __epos);
	uint32 Z4;
	X_NDR_SCALARS(Z4, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(token_info, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(remaining, __ndr, __bpos, __epos, x_ndr_set_flags(__flags, LIBNDR_FLAG_REMAINING), X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

void ntlmssp_SingleHostData::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_PRINT_ARRAY_HEX);
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(token_info, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(remaining, __ndr, x_ndr_set_flags(__flags, LIBNDR_FLAG_REMAINING), X_NDR_SWITCH_NONE);
	(__ndr) << leave;
}


const std::array<std::pair<uint32, const char *>, 3> x_ndr_traits_t<ntlmssp_AvFlags>::value_name_map = { {
		{ NTLMSSP_AVFLAG_CONSTRAINTED_ACCOUNT, "NTLMSSP_AVFLAG_CONSTRAINTED_ACCOUNT" },
		{ NTLMSSP_AVFLAG_MIC_IN_AUTHENTICATE_MESSAGE, "NTLMSSP_AVFLAG_MIC_IN_AUTHENTICATE_MESSAGE" },
		{ NTLMSSP_AVFLAG_TARGET_SPN_FROM_UNTRUSTED_SOURCE, "NTLMSSP_AVFLAG_TARGET_SPN_FROM_UNTRUSTED_SOURCE" },
} };

void ntlmssp_AvValue::__init(x_ndr_switch_t __level)
{
	switch (__level) {
		case MsvAvEOL: break;
		case MsvAvNbComputerName: construct(AvNbComputerName); break;
		case MsvAvNbDomainName: construct(AvNbDomainName); break;
		case MsvAvDnsComputerName: construct(AvDnsComputerName); break;
		case MsvAvDnsDomainName: construct(AvDnsDomainName); break;
		case MsvAvDnsTreeName: construct(AvDnsTreeName); break;
		case MsvAvFlags: construct(AvFlags); break;
		case MsvAvTimestamp: construct(AvTimestamp); break;
		case MsvAvSingleHost: construct(AvSingleHost); break;
		case MsvAvTargetName: construct(AvTargetName); break;
		case MsvChannelBindings: construct(ChannelBindings); break;
		default: construct(blob); break;
	}
}

void ntlmssp_AvValue::__init(x_ndr_switch_t __level, const ntlmssp_AvValue &other)
{
	switch (__level) {
		case MsvAvEOL: break;
		case MsvAvNbComputerName: construct(AvNbComputerName, other.AvNbComputerName); break;
		case MsvAvNbDomainName: construct(AvNbDomainName, other.AvNbDomainName); break;
		case MsvAvDnsComputerName: construct(AvDnsComputerName, other.AvDnsComputerName); break;
		case MsvAvDnsDomainName: construct(AvDnsDomainName, other.AvDnsDomainName); break;
		case MsvAvDnsTreeName: construct(AvDnsTreeName, other.AvDnsTreeName); break;
		case MsvAvFlags: construct(AvFlags, other.AvFlags); break;
		case MsvAvTimestamp: construct(AvTimestamp, other.AvTimestamp); break;
		case MsvAvSingleHost: construct(AvSingleHost, other.AvSingleHost); break;
		case MsvAvTargetName: construct(AvTargetName, other.AvTargetName); break;
		case MsvChannelBindings: construct(ChannelBindings, other.ChannelBindings); break;
		default: construct(blob, other.blob); break;
	}
}

void ntlmssp_AvValue::__uninit(x_ndr_switch_t __level)
{
	switch (__level) {
		case MsvAvEOL: break;
		case MsvAvNbComputerName: destruct(AvNbComputerName); break;
		case MsvAvNbDomainName: destruct(AvNbDomainName); break;
		case MsvAvDnsComputerName: destruct(AvDnsComputerName); break;
		case MsvAvDnsDomainName: destruct(AvDnsDomainName); break;
		case MsvAvDnsTreeName: destruct(AvDnsTreeName); break;
		case MsvAvFlags: destruct(AvFlags); break;
		case MsvAvTimestamp: destruct(AvTimestamp); break;
		case MsvAvSingleHost: destruct(AvSingleHost); break;
		case MsvAvTargetName: destruct(AvTargetName); break;
		case MsvChannelBindings: destruct(ChannelBindings); break;
		default: destruct(blob); break;
	}
}

x_ndr_off_t ntlmssp_AvValue::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_UNION_ALIGN(4, __ndr, __bpos, __epos, __flags);
	switch (__level) {
		case MsvAvEOL: {
		} break;
		case MsvAvNbComputerName: {
			X_NDR_SCALARS(AvNbComputerName, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case MsvAvNbDomainName: {
			X_NDR_SCALARS(AvNbDomainName, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case MsvAvDnsComputerName: {
			X_NDR_SCALARS(AvDnsComputerName, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case MsvAvDnsDomainName: {
			X_NDR_SCALARS(AvDnsDomainName, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case MsvAvDnsTreeName: {
			X_NDR_SCALARS(AvDnsTreeName, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case MsvAvFlags: {
			X_NDR_SCALARS(AvFlags, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case MsvAvTimestamp: {
			X_NDR_SCALARS(AvTimestamp, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case MsvAvSingleHost: {
			X_NDR_SCALARS(AvSingleHost, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case MsvAvTargetName: {
			X_NDR_SCALARS(AvTargetName, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case MsvChannelBindings: {
			X_NDR_SCALARS(ChannelBindings, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		default: {
			X_NDR_SCALARS(blob, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
	}
	return __bpos;
}

x_ndr_off_t ntlmssp_AvValue::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_UNION_ALIGN(4, __ndr, __bpos, __epos, __flags);
	switch (__level) {
		case MsvAvEOL: {
		} break;
		case MsvAvNbComputerName: {
			X_NDR_SCALARS(AvNbComputerName, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case MsvAvNbDomainName: {
			X_NDR_SCALARS(AvNbDomainName, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case MsvAvDnsComputerName: {
			X_NDR_SCALARS(AvDnsComputerName, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case MsvAvDnsDomainName: {
			X_NDR_SCALARS(AvDnsDomainName, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case MsvAvDnsTreeName: {
			X_NDR_SCALARS(AvDnsTreeName, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case MsvAvFlags: {
			X_NDR_SCALARS(AvFlags, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case MsvAvTimestamp: {
			X_NDR_SCALARS(AvTimestamp, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case MsvAvSingleHost: {
			X_NDR_SCALARS(AvSingleHost, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case MsvAvTargetName: {
			X_NDR_SCALARS(AvTargetName, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case MsvChannelBindings: {
			X_NDR_SCALARS(ChannelBindings, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		default: {
			X_NDR_SCALARS(blob, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
	}
	return __bpos;
}

void ntlmssp_AvValue::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	switch (__level) {
		case MsvAvEOL: {
		} break;
		case MsvAvNbComputerName: {
			X_NDR_OSTR(AvNbComputerName, __ndr, __flags, X_NDR_SWITCH_NONE);
		} break;
		case MsvAvNbDomainName: {
			X_NDR_OSTR(AvNbDomainName, __ndr, __flags, X_NDR_SWITCH_NONE);
		} break;
		case MsvAvDnsComputerName: {
			X_NDR_OSTR(AvDnsComputerName, __ndr, __flags, X_NDR_SWITCH_NONE);
		} break;
		case MsvAvDnsDomainName: {
			X_NDR_OSTR(AvDnsDomainName, __ndr, __flags, X_NDR_SWITCH_NONE);
		} break;
		case MsvAvDnsTreeName: {
			X_NDR_OSTR(AvDnsTreeName, __ndr, __flags, X_NDR_SWITCH_NONE);
		} break;
		case MsvAvFlags: {
			X_NDR_OSTR(AvFlags, __ndr, __flags, X_NDR_SWITCH_NONE);
		} break;
		case MsvAvTimestamp: {
			X_NDR_OSTR(AvTimestamp, __ndr, __flags, X_NDR_SWITCH_NONE);
		} break;
		case MsvAvSingleHost: {
			X_NDR_OSTR(AvSingleHost, __ndr, __flags, X_NDR_SWITCH_NONE);
		} break;
		case MsvAvTargetName: {
			X_NDR_OSTR(AvTargetName, __ndr, __flags, X_NDR_SWITCH_NONE);
		} break;
		case MsvChannelBindings: {
			X_NDR_OSTR(ChannelBindings, __ndr, __flags, X_NDR_SWITCH_NONE);
		} break;
		default: {
			X_NDR_OSTR(blob, __ndr, __flags, X_NDR_SWITCH_NONE);
		} break;
	}
}

void AV_PAIR::set_AvId(ntlmssp_AvId v)
{
	Value.__uninit(x_ndr_switch_t(AvId));
	AvId = v;
	Value.__init(x_ndr_switch_t(AvId));
}
AV_PAIR::AV_PAIR()
	: AvId((ntlmssp_AvId)MsvAvEOL)
{
	Value.__init(x_ndr_switch_t(AvId));
}

AV_PAIR::~AV_PAIR()
{
	Value.__uninit(AvId);
}

AV_PAIR::AV_PAIR(const AV_PAIR &other)
	: AvId(other.AvId)
{
	Value.__init(x_ndr_switch_t(AvId), other.Value);
}

AV_PAIR &AV_PAIR::operator=(const AV_PAIR &other)
{
	Value.__uninit(x_ndr_switch_t(AvId));
	AvId = other.AvId;
	Value.__init(x_ndr_switch_t(AvId), other.Value);
	return *this;
}

x_ndr_off_t AV_PAIR::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_FLAG_NOALIGN);
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	x_ndr_off_t __base = __bpos; (void)__base;
	x_ndr_off_t __ptr; (void)__ptr;
	X_NDR_SCALARS(AvId, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	x_ndr_off_t __tmp_1 = __bpos;
	X_NDR_SKIP(uint16, __ndr, __bpos, __epos, __flags);
	__ptr = __bpos;
	X_NDR_SCALARS(Value, __ndr, __bpos, __epos, __flags, AvId);
	X_NDR_SCALARS(uint16(__bpos - __ptr), __ndr, __tmp_1, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	return __bpos;
}


x_ndr_off_t AV_PAIR::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_FLAG_NOALIGN);
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	x_ndr_off_t __base = __bpos; (void)__base;
	x_ndr_off_t __ptr; (void)__ptr;
	X_NDR_SWITCH(ntlmssp_AvId, AvId, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	uint16 AvLen;
	X_NDR_SCALARS(AvLen, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	__ptr = __bpos;
	__epos = X_NDR_CHECK_POS(__bpos + AvLen, __bpos, __epos);
	X_NDR_SCALARS(Value, __ndr, __bpos, __epos, __flags, AvId);
	X_NDR_TRAILER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

void AV_PAIR::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_FLAG_NOALIGN);
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(AvId, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(Value, __ndr, __flags, AvId);
	(__ndr) << leave;
}



x_ndr_off_t AV_PAIR_LIST::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_FLAG_NOALIGN);
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	x_ndr_off_t __base = __bpos; (void)__base;
	x_ndr_off_t __ptr; (void)__ptr;
	X_NDR_SCALARS(pair, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	return __bpos;
}


x_ndr_off_t AV_PAIR_LIST::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_FLAG_NOALIGN);
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	x_ndr_off_t __base = __bpos; (void)__base;
	x_ndr_off_t __ptr; (void)__ptr;
	X_NDR_SCALARS(pair, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

void AV_PAIR_LIST::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_FLAG_NOALIGN);
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(pair, __ndr, __flags, X_NDR_SWITCH_NONE);
	(__ndr) << leave;
}



x_ndr_off_t CHALLENGE_MESSAGE::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_PRINT_ARRAY_HEX);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_VALUE((std::array<uint8, 8>{"NTLMSSP"}), __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_VALUE((ntlmssp_MessageType{NtLmChallenge}), __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(TargetName, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(NegotiateFlags, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(ServerChallenge, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(Reserved, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(TargetInfo, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(Version, __ndr, __bpos, __epos, __flags, NegotiateFlags&NTLMSSP_NEGOTIATE_VERSION);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t CHALLENGE_MESSAGE::ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_BUFFERS(TargetName, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(TargetInfo, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}

x_ndr_off_t CHALLENGE_MESSAGE::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_PRINT_ARRAY_HEX);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_VALUE((std::array<uint8, 8>{"NTLMSSP"}), __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_VALUE((ntlmssp_MessageType{NtLmChallenge}), __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(TargetName, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(NegotiateFlags, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(ServerChallenge, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(Reserved, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(TargetInfo, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(Version, __ndr, __bpos, __epos, __flags, NegotiateFlags&NTLMSSP_NEGOTIATE_VERSION);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t CHALLENGE_MESSAGE::ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_BUFFERS(TargetName, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(TargetInfo, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}

void CHALLENGE_MESSAGE::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_PRINT_ARRAY_HEX);
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(TargetName, __ndr, x_ndr_set_flags(__flags, x_ndr_ntlmssp_negotiated_string_flags(NegotiateFlags)), X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(NegotiateFlags, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(ServerChallenge, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(TargetInfo, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(Version, __ndr, __flags, NegotiateFlags&NTLMSSP_NEGOTIATE_VERSION);
	(__ndr) << leave;
}



x_ndr_off_t LM_RESPONSE::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_PRINT_ARRAY_HEX);
	X_NDR_HEADER_ALIGN(1, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(Response, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(1, __ndr, __bpos, __epos, __flags);
	return __bpos;
}


x_ndr_off_t LM_RESPONSE::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_PRINT_ARRAY_HEX);
	X_NDR_HEADER_ALIGN(1, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(Response, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(1, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

void LM_RESPONSE::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_PRINT_ARRAY_HEX);
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(Response, __ndr, __flags, X_NDR_SWITCH_NONE);
	(__ndr) << leave;
}



x_ndr_off_t LMv2_RESPONSE::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_PRINT_ARRAY_HEX);
	X_NDR_HEADER_ALIGN(1, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(Response, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(ChallengeFromClient, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(1, __ndr, __bpos, __epos, __flags);
	return __bpos;
}


x_ndr_off_t LMv2_RESPONSE::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_PRINT_ARRAY_HEX);
	X_NDR_HEADER_ALIGN(1, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(Response, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(ChallengeFromClient, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(1, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

void LMv2_RESPONSE::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_PRINT_ARRAY_HEX);
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(Response, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(ChallengeFromClient, __ndr, __flags, X_NDR_SWITCH_NONE);
	(__ndr) << leave;
}

x_ndr_off_t NTLMv2_RESPONSE::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_PRINT_ARRAY_HEX);
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(Response, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(Challenge, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t NTLMv2_CLIENT_CHALLENGE::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_PRINT_ARRAY_HEX);
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	x_ndr_off_t __base = __bpos; (void)__base;
	x_ndr_off_t __ptr; (void)__ptr;
	uint8 RespType;
	X_NDR_SCALARS(RespType, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	uint8 HiRespType;
	X_NDR_SCALARS(HiRespType, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(Reserved1, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(Reserved2, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(TimeStamp, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(ChallengeFromClient, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(Reserved3, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(AvPairs, __ndr, __bpos, __epos, x_ndr_set_flags(__flags, LIBNDR_FLAG_REMAINING), X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	return __bpos;
}


#if 0
x_ndr_off_t ntlmssp_LM_RESPONSE::push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_UNION_ALIGN(1, __ndr, __bpos, __epos, __flags);
	switch (__level) {
		case 24: {
			X_NDR_DATA(v1, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		default: {
		} break;
	}
	return __bpos;
}

x_ndr_off_t ntlmssp_LM_RESPONSE::pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_UNION_ALIGN(1, __ndr, __bpos, __epos, __flags);
	switch (__level) {
		case 24: {
			X_NDR_DATA(v1, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		default: {
		} break;
	}
	return __bpos;
}

void ntlmssp_LM_RESPONSE::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	switch (__level) {
		case 24: {
			X_NDR_OSTR(v1, __ndr, __flags, X_NDR_SWITCH_NONE);
		} break;
		default: {
		} break;
	}
}

x_ndr_off_t NTLM_RESPONSE::push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_PRINT_ARRAY_HEX);
	X_NDR_HEADER_ALIGN(1, __ndr, __bpos, __epos, __flags);
	x_ndr_off_t __base = __bpos; (void)__base;
	x_ndr_off_t __ptr; (void)__ptr;
	X_NDR_DATA(Response, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(1, __ndr, __bpos, __epos, __flags);
	return __bpos;
}


x_ndr_off_t NTLM_RESPONSE::pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_PRINT_ARRAY_HEX);
	X_NDR_HEADER_ALIGN(1, __ndr, __bpos, __epos, __flags);
	x_ndr_off_t __base = __bpos; (void)__base;
	x_ndr_off_t __ptr; (void)__ptr;
	X_NDR_DATA(Response, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(1, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

void NTLM_RESPONSE::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_PRINT_ARRAY_HEX);
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(Response, __ndr, __flags, X_NDR_SWITCH_NONE);
	(__ndr) << leave;
}



x_ndr_off_t NTLMv2_CLIENT_CHALLENGE::push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_PRINT_ARRAY_HEX);
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	x_ndr_off_t __base = __bpos; (void)__base;
	x_ndr_off_t __ptr; (void)__ptr;
	uint8 RespType{1};
	X_NDR_DATA(RespType, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	uint8 HiRespType{1};
	X_NDR_DATA(HiRespType, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_DATA(Reserved1, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_DATA(Reserved2, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_DATA(TimeStamp, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_DATA(ChallengeFromClient, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_DATA(Reserved3, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_DATA(AvPairs, __ndr, __bpos, __epos, x_ndr_set_flags(__flags, LIBNDR_FLAG_REMAINING), X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	return __bpos;
}


void NTLMv2_CLIENT_CHALLENGE::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_PRINT_ARRAY_HEX);
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(TimeStamp, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(ChallengeFromClient, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(AvPairs, __ndr, x_ndr_set_flags(__flags, LIBNDR_FLAG_REMAINING), X_NDR_SWITCH_NONE);
	(__ndr) << leave;
}



x_ndr_off_t NTLMv2_RESPONSE::push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_PRINT_ARRAY_HEX);
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	x_ndr_off_t __base = __bpos; (void)__base;
	x_ndr_off_t __ptr; (void)__ptr;
	X_NDR_DATA(Response, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_DATA(Challenge, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	return __bpos;
}


void NTLMv2_RESPONSE::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_PRINT_ARRAY_HEX);
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(Response, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(Challenge, __ndr, __flags, X_NDR_SWITCH_NONE);
	(__ndr) << leave;
}



void ntlmssp_NTLM_RESPONSE::__init(x_ndr_switch_t __level)
{
	switch (__level) {
		case 0x18: construct(v1); break;
		default: construct(v2); break;
	}
}

void ntlmssp_NTLM_RESPONSE::__init(x_ndr_switch_t __level, const ntlmssp_NTLM_RESPONSE &other)
{
	switch (__level) {
		case 0x18: construct(v1, other.v1); break;
		default: construct(v2, other.v2); break;
	}
}

void ntlmssp_NTLM_RESPONSE::__uninit(x_ndr_switch_t __level)
{
	switch (__level) {
		case 0x18: destruct(v1); break;
		default: destruct(v2); break;
	}
}

x_ndr_off_t ntlmssp_NTLM_RESPONSE::push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_UNION_ALIGN(4, __ndr, __bpos, __epos, __flags);
	switch (__level) {
		case 0x18: {
			X_NDR_DATA(v1, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		default: {
			X_NDR_DATA(v2, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
	}
	return __bpos;
}

x_ndr_off_t ntlmssp_NTLM_RESPONSE::pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_UNION_ALIGN(4, __ndr, __bpos, __epos, __flags);
	switch (__level) {
		case 0x18: {
			X_NDR_DATA(v1, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		default: {
			X_NDR_DATA(v2, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
	}
	return __bpos;
}

void ntlmssp_NTLM_RESPONSE::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	switch (__level) {
		case 0x18: {
			X_NDR_OSTR(v1, __ndr, __flags, X_NDR_SWITCH_NONE);
		} break;
		default: {
			X_NDR_OSTR(v2, __ndr, __flags, X_NDR_SWITCH_NONE);
		} break;
	}
}
#endif

#if 0
x_ndr_off_t ntlmssp_MIC::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_PRINT_ARRAY_HEX);
	X_NDR_HEADER_ALIGN(1, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(MIC, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(1, __ndr, __bpos, __epos, __flags);
	return __bpos;
}


x_ndr_off_t ntlmssp_MIC::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_PRINT_ARRAY_HEX);
	X_NDR_HEADER_ALIGN(1, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(MIC, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(1, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

void ntlmssp_MIC::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_PRINT_ARRAY_HEX);
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(MIC, __ndr, __flags, X_NDR_SWITCH_NONE);
	(__ndr) << leave;
}
#endif


x_ndr_off_t AUTHENTICATE_MESSAGE::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_FLAG_REMAINING);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_VALUE((std::array<uint8, 8>{"NTLMSSP"}), __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_VALUE((ntlmssp_MessageType{NtLmAuthenticate}), __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(LmChallengeResponse, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(NtChallengeResponse, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(DomainName, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(UserName, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(Workstation, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(EncryptedRandomSessionKey, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(NegotiateFlags, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	// X_NDR_SCALARS(Version, __ndr, __bpos, __epos, __flags, NegotiateFlags&NTLMSSP_NEGOTIATE_VERSION);
	// X_NDR_SCALARS(mic, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t AUTHENTICATE_MESSAGE::ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_BUFFERS(LmChallengeResponse, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(NtChallengeResponse, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(DomainName, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(UserName, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(Workstation, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(EncryptedRandomSessionKey, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}


x_ndr_off_t AUTHENTICATE_MESSAGE::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_FLAG_REMAINING);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_VALUE((std::array<uint8, 8>{"NTLMSSP"}), __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_VALUE((ntlmssp_MessageType{NtLmAuthenticate}), __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(LmChallengeResponse, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(NtChallengeResponse, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(DomainName, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(UserName, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(Workstation, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(EncryptedRandomSessionKey, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(NegotiateFlags, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	// X_NDR_SCALARS(Version, __ndr, __bpos, __epos, __flags, NegotiateFlags&NTLMSSP_NEGOTIATE_VERSION);
	// X_NDR_SCALARS(mic, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t AUTHENTICATE_MESSAGE::ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_BUFFERS(LmChallengeResponse, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(NtChallengeResponse, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(DomainName, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(UserName, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(Workstation, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(EncryptedRandomSessionKey, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}

void AUTHENTICATE_MESSAGE::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_FLAG_REMAINING);
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(LmChallengeResponse, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(NtChallengeResponse, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(DomainName, __ndr, x_ndr_set_flags(__flags, x_ndr_ntlmssp_negotiated_string_flags(NegotiateFlags)), X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(UserName, __ndr, x_ndr_set_flags(__flags, x_ndr_ntlmssp_negotiated_string_flags(NegotiateFlags)), X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(Workstation, __ndr, x_ndr_set_flags(__flags, x_ndr_ntlmssp_negotiated_string_flags(NegotiateFlags)), X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(EncryptedRandomSessionKey, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(NegotiateFlags, __ndr, __flags, X_NDR_SWITCH_NONE);
	// X_NDR_OSTR_NEXT(Version, __ndr, __flags, NegotiateFlags&NTLMSSP_NEGOTIATE_VERSION);
// 	X_NDR_OSTR_NEXT(mic, __ndr, __flags, X_NDR_SWITCH_NONE);
	(__ndr) << leave;
}



x_ndr_off_t NTLMSSP_MESSAGE_SIGNATURE::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	uint32 Version{NTLMSSP_SIGN_VERSION};
	X_NDR_SCALARS(Version, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(RandomPad, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(Checksum, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(SeqNum, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	return __bpos;
}


x_ndr_off_t NTLMSSP_MESSAGE_SIGNATURE::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	uint32 Version;
	X_NDR_SCALARS(Version, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(RandomPad, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(Checksum, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(SeqNum, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

void NTLMSSP_MESSAGE_SIGNATURE::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(RandomPad, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(Checksum, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(SeqNum, __ndr, __flags, X_NDR_SWITCH_NONE);
	(__ndr) << leave;
}



x_ndr_off_t NTLMSSP_MESSAGE_SIGNATURE_NTLMv2::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_PRINT_ARRAY_HEX);
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	uint32 Version{NTLMSSP_SIGN_VERSION};
	X_NDR_SCALARS(Version, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(Checksum, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(SeqNum, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	return __bpos;
}


x_ndr_off_t NTLMSSP_MESSAGE_SIGNATURE_NTLMv2::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_PRINT_ARRAY_HEX);
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	uint32 Version;
	X_NDR_SCALARS(Version, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(Checksum, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(SeqNum, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

void NTLMSSP_MESSAGE_SIGNATURE_NTLMv2::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_PRINT_ARRAY_HEX);
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(Checksum, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(SeqNum, __ndr, __flags, X_NDR_SWITCH_NONE);
	(__ndr) << leave;
}



} /* namespace idl */
