
#ifndef __ndr_misc__hxx__
#define __ndr_misc__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/librpc/ndr.hxx"

namespace idl {

struct GUID {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	uint32 time_low;
	uint16 time_mid;
	uint16 time_hi_and_version;
	std::array<uint8, 2> clock_seq;
	std::array<uint8, 6> node;
} /* [noprint, gensize, public] */;


struct ndr_syntax_id {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	GUID uuid;
	uint32 if_version;
} /* [public] */;

template <> struct x_ndr_traits_t<ndr_syntax_id> {
	using ndr_type = x_ndr_type_struct;
};


struct policy_handle {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	uint32 handle_type;
	GUID uuid;
} /* [public] */;

template <> struct x_ndr_traits_t<policy_handle> {
	using ndr_type = x_ndr_type_struct;
};


enum netr_SchannelType : uint16 {
	SEC_CHAN_NULL=0,
	SEC_CHAN_LOCAL=1,
	SEC_CHAN_WKSTA=2,
	SEC_CHAN_DNS_DOMAIN=3,
	SEC_CHAN_DOMAIN=4,
	SEC_CHAN_LANMAN=5,
	SEC_CHAN_BDC=6,
	SEC_CHAN_RODC=7,
}/* [public] */;

template <> struct x_ndr_traits_t<netr_SchannelType> {
	using ndr_type = x_ndr_type_enum;
	using ndr_base_type = uint16;
	static const std::array<std::pair<uint16, const char *>, 8> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<netr_SchannelType>(const netr_SchannelType &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint1632(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<netr_SchannelType>(netr_SchannelType &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint16_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = netr_SchannelType(v);
	return __bpos;
}


struct KRB5_EDATA_NTSTATUS {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	NTSTATUS ntstatus;
	uint32 unknown1;
	uint32 unknown2;
} /* [public] */;

template <> struct x_ndr_traits_t<KRB5_EDATA_NTSTATUS> {
	using ndr_type = x_ndr_type_struct;
};


enum winreg_Type : uint32 {
	REG_NONE=0,
	REG_SZ=1,
	REG_EXPAND_SZ=2,
	REG_BINARY=3,
	REG_DWORD=4,
	REG_DWORD_BIG_ENDIAN=5,
	REG_LINK=6,
	REG_MULTI_SZ=7,
	REG_RESOURCE_LIST=8,
	REG_FULL_RESOURCE_DESCRIPTOR=9,
	REG_RESOURCE_REQUIREMENTS_LIST=10,
	REG_QWORD=11,
}/* [v1_enum, public] */;

template <> struct x_ndr_traits_t<winreg_Type> {
	using ndr_type = x_ndr_type_enum;
	using ndr_base_type = uint32;
	static const std::array<std::pair<uint32, const char *>, 12> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<winreg_Type>(const winreg_Type &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint32(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<winreg_Type>(winreg_Type &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint32_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = winreg_Type(v);
	return __bpos;
}


enum netr_SamDatabaseID : uint32 {
	SAM_DATABASE_DOMAIN=0,
	SAM_DATABASE_BUILTIN=1,
	SAM_DATABASE_PRIVS=2,
}/* [v1_enum, public] */;

template <> struct x_ndr_traits_t<netr_SamDatabaseID> {
	using ndr_type = x_ndr_type_enum;
	using ndr_base_type = uint32;
	static const std::array<std::pair<uint32, const char *>, 3> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<netr_SamDatabaseID>(const netr_SamDatabaseID &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint32(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<netr_SamDatabaseID>(netr_SamDatabaseID &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint32_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = netr_SamDatabaseID(v);
	return __bpos;
}


enum svcctl_ServerType : uint32 {
	SV_TYPE_WORKSTATION=0x00000001,
	SV_TYPE_SERVER=0x00000002,
	SV_TYPE_SQLSERVER=0x00000004,
	SV_TYPE_DOMAIN_CTRL=0x00000008,
	SV_TYPE_DOMAIN_BAKCTRL=0x00000010,
	SV_TYPE_TIME_SOURCE=0x00000020,
	SV_TYPE_AFP=0x00000040,
	SV_TYPE_NOVELL=0x00000080,
	SV_TYPE_DOMAIN_MEMBER=0x00000100,
	SV_TYPE_PRINTQ_SERVER=0x00000200,
	SV_TYPE_DIALIN_SERVER=0x00000400,
	SV_TYPE_SERVER_UNIX=0x00000800,
	SV_TYPE_NT=0x00001000,
	SV_TYPE_WFW=0x00002000,
	SV_TYPE_SERVER_MFPN=0x00004000,
	SV_TYPE_SERVER_NT=0x00008000,
	SV_TYPE_POTENTIAL_BROWSER=0x00010000,
	SV_TYPE_BACKUP_BROWSER=0x00020000,
	SV_TYPE_MASTER_BROWSER=0x00040000,
	SV_TYPE_DOMAIN_MASTER=0x00080000,
	SV_TYPE_SERVER_OSF=0x00100000,
	SV_TYPE_SERVER_VMS=0x00200000,
	SV_TYPE_WIN95_PLUS=0x00400000,
	SV_TYPE_DFS_SERVER=0x00800000,
	SV_TYPE_ALTERNATE_XPORT=0x20000000,
	SV_TYPE_LOCAL_LIST_ONLY=0x40000000,
	SV_TYPE_DOMAIN_ENUM=0x80000000,
}/* [bitmap32bit, public] */;

template <> struct x_ndr_traits_t<svcctl_ServerType> {
	using ndr_type = x_ndr_type_bitmap;
	using ndr_base_type = uint32;
	static const std::array<std::pair<uint32, const char *>, 27> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<svcctl_ServerType>(const svcctl_ServerType &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint32(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<svcctl_ServerType>(svcctl_ServerType &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint32_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = svcctl_ServerType(v);
	return __bpos;
}


const uint32 SV_TYPE_ALL = 0xFFFFFFFF;
void x_ndr_ostr(const GUID &v, x_ndr_ostr_t &os, uint32_t flags, x_ndr_switch_t level);

}

#endif /* __ndr_misc__hxx__ */

