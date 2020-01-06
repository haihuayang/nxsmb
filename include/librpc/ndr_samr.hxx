
#ifndef __ndr_samr__h__
#define __ndr_samr__h__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#include "include/librpc/ndr_nxsmb.hxx"

// #include "librpc/idl/misc.h"
#include "include/librpc/ndr_security.hxx"
#include "include/librpc/ndr_lsa.hxx"

namespace idl {

enum samr_AcctFlags : uint32 {
	ACB_DISABLED=0x00000001,
	ACB_HOMDIRREQ=0x00000002,
	ACB_PWNOTREQ=0x00000004,
	ACB_TEMPDUP=0x00000008,
	ACB_NORMAL=0x00000010,
	ACB_MNS=0x00000020,
	ACB_DOMTRUST=0x00000040,
	ACB_WSTRUST=0x00000080,
	ACB_SVRTRUST=0x00000100,
	ACB_PWNOEXP=0x00000200,
	ACB_AUTOLOCK=0x00000400,
	ACB_ENC_TXT_PWD_ALLOWED=0x00000800,
	ACB_SMARTCARD_REQUIRED=0x00001000,
	ACB_TRUSTED_FOR_DELEGATION=0x00002000,
	ACB_NOT_DELEGATED=0x00004000,
	ACB_USE_DES_KEY_ONLY=0x00008000,
	ACB_DONT_REQUIRE_PREAUTH=0x00010000,
	ACB_PW_EXPIRED=0x00020000,
	ACB_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION=0x00040000,
	ACB_NO_AUTH_DATA_REQD=0x00080000,
	ACB_PARTIAL_SECRETS_ACCOUNT=0x00100000,
	ACB_USE_AES_KEYS=0x00200000,
}/* [bitmap32bit, public] */;

template <> struct x_ndr_traits_t<samr_AcctFlags> {
	using ndr_type = x_ndr_type_bitmap;
	using ndr_base_type = uint32;
	static const std::array<std::pair<uint32, const char *>, 22> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<samr_AcctFlags>(const samr_AcctFlags &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint32(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<samr_AcctFlags>(samr_AcctFlags &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint32_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = samr_AcctFlags(v);
	return __bpos;
}



enum samr_ConnectAccessMask : uint32 {
	SAMR_ACCESS_CONNECT_TO_SERVER=0x00000001,
	SAMR_ACCESS_SHUTDOWN_SERVER=0x00000002,
	SAMR_ACCESS_INITIALIZE_SERVER=0x00000004,
	SAMR_ACCESS_CREATE_DOMAIN=0x00000008,
	SAMR_ACCESS_ENUM_DOMAINS=0x00000010,
	SAMR_ACCESS_LOOKUP_DOMAIN=0x00000020,
}/* [bitmap32bit] */;

template <> struct x_ndr_traits_t<samr_ConnectAccessMask> {
	using ndr_type = x_ndr_type_bitmap;
	using ndr_base_type = uint32;
	static const std::array<std::pair<uint32, const char *>, 6> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<samr_ConnectAccessMask>(const samr_ConnectAccessMask &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint32(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<samr_ConnectAccessMask>(samr_ConnectAccessMask &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint32_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = samr_ConnectAccessMask(v);
	return __bpos;
}


const int SAMR_ACCESS_ALL_ACCESS = 0x0000003F;
const int GENERIC_RIGHTS_SAM_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED_ACCESS|SAMR_ACCESS_ALL_ACCESS);
const int GENERIC_RIGHTS_SAM_READ = (STANDARD_RIGHTS_READ_ACCESS|SAMR_ACCESS_ENUM_DOMAINS);
const int GENERIC_RIGHTS_SAM_WRITE = (STANDARD_RIGHTS_WRITE_ACCESS|SAMR_ACCESS_CREATE_DOMAIN|SAMR_ACCESS_INITIALIZE_SERVER|SAMR_ACCESS_SHUTDOWN_SERVER);
const int GENERIC_RIGHTS_SAM_EXECUTE = (STANDARD_RIGHTS_EXECUTE_ACCESS|SAMR_ACCESS_LOOKUP_DOMAIN|SAMR_ACCESS_CONNECT_TO_SERVER);

enum samr_UserAccessMask : uint32 {
	SAMR_USER_ACCESS_GET_NAME_ETC=0x00000001,
	SAMR_USER_ACCESS_GET_LOCALE=0x00000002,
	SAMR_USER_ACCESS_SET_LOC_COM=0x00000004,
	SAMR_USER_ACCESS_GET_LOGONINFO=0x00000008,
	SAMR_USER_ACCESS_GET_ATTRIBUTES=0x00000010,
	SAMR_USER_ACCESS_SET_ATTRIBUTES=0x00000020,
	SAMR_USER_ACCESS_CHANGE_PASSWORD=0x00000040,
	SAMR_USER_ACCESS_SET_PASSWORD=0x00000080,
	SAMR_USER_ACCESS_GET_GROUPS=0x00000100,
	SAMR_USER_ACCESS_GET_GROUP_MEMBERSHIP=0x00000200,
	SAMR_USER_ACCESS_CHANGE_GROUP_MEMBERSHIP=0x00000400,
}/* [bitmap32bit] */;

template <> struct x_ndr_traits_t<samr_UserAccessMask> {
	using ndr_type = x_ndr_type_bitmap;
	using ndr_base_type = uint32;
	static const std::array<std::pair<uint32, const char *>, 11> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<samr_UserAccessMask>(const samr_UserAccessMask &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint32(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<samr_UserAccessMask>(samr_UserAccessMask &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint32_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = samr_UserAccessMask(v);
	return __bpos;
}


const int SAMR_USER_ACCESS_ALL_ACCESS = 0x000007FF;
const int GENERIC_RIGHTS_USER_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED_ACCESS|SAMR_USER_ACCESS_ALL_ACCESS);
const int GENERIC_RIGHTS_USER_READ = (STANDARD_RIGHTS_READ_ACCESS|SAMR_USER_ACCESS_GET_GROUP_MEMBERSHIP|SAMR_USER_ACCESS_GET_GROUPS|SAMR_USER_ACCESS_GET_ATTRIBUTES|SAMR_USER_ACCESS_GET_LOGONINFO|SAMR_USER_ACCESS_GET_LOCALE);
const int GENERIC_RIGHTS_USER_WRITE = (STANDARD_RIGHTS_WRITE_ACCESS|SAMR_USER_ACCESS_CHANGE_PASSWORD|SAMR_USER_ACCESS_SET_LOC_COM|SAMR_USER_ACCESS_SET_ATTRIBUTES|SAMR_USER_ACCESS_SET_PASSWORD|SAMR_USER_ACCESS_CHANGE_GROUP_MEMBERSHIP);
const int GENERIC_RIGHTS_USER_EXECUTE = (STANDARD_RIGHTS_EXECUTE_ACCESS|SAMR_USER_ACCESS_CHANGE_PASSWORD|SAMR_USER_ACCESS_GET_NAME_ETC);

enum samr_DomainAccessMask : uint32 {
	SAMR_DOMAIN_ACCESS_LOOKUP_INFO_1=0x00000001,
	SAMR_DOMAIN_ACCESS_SET_INFO_1=0x00000002,
	SAMR_DOMAIN_ACCESS_LOOKUP_INFO_2=0x00000004,
	SAMR_DOMAIN_ACCESS_SET_INFO_2=0x00000008,
	SAMR_DOMAIN_ACCESS_CREATE_USER=0x00000010,
	SAMR_DOMAIN_ACCESS_CREATE_GROUP=0x00000020,
	SAMR_DOMAIN_ACCESS_CREATE_ALIAS=0x00000040,
	SAMR_DOMAIN_ACCESS_LOOKUP_ALIAS=0x00000080,
	SAMR_DOMAIN_ACCESS_ENUM_ACCOUNTS=0x00000100,
	SAMR_DOMAIN_ACCESS_OPEN_ACCOUNT=0x00000200,
	SAMR_DOMAIN_ACCESS_SET_INFO_3=0x00000400,
}/* [bitmap32bit] */;

template <> struct x_ndr_traits_t<samr_DomainAccessMask> {
	using ndr_type = x_ndr_type_bitmap;
	using ndr_base_type = uint32;
	static const std::array<std::pair<uint32, const char *>, 11> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<samr_DomainAccessMask>(const samr_DomainAccessMask &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint32(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<samr_DomainAccessMask>(samr_DomainAccessMask &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint32_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = samr_DomainAccessMask(v);
	return __bpos;
}


const int SAMR_DOMAIN_ACCESS_ALL_ACCESS = 0x000007FF;
const int GENERIC_RIGHTS_DOMAIN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED_ACCESS|SAMR_DOMAIN_ACCESS_ALL_ACCESS);
const int GENERIC_RIGHTS_DOMAIN_READ = (STANDARD_RIGHTS_READ_ACCESS|SAMR_DOMAIN_ACCESS_LOOKUP_ALIAS|SAMR_DOMAIN_ACCESS_LOOKUP_INFO_2);
const int GENERIC_RIGHTS_DOMAIN_WRITE = (STANDARD_RIGHTS_WRITE_ACCESS|SAMR_DOMAIN_ACCESS_SET_INFO_3|SAMR_DOMAIN_ACCESS_CREATE_ALIAS|SAMR_DOMAIN_ACCESS_CREATE_GROUP|SAMR_DOMAIN_ACCESS_CREATE_USER|SAMR_DOMAIN_ACCESS_SET_INFO_2|SAMR_DOMAIN_ACCESS_SET_INFO_1);
const int GENERIC_RIGHTS_DOMAIN_EXECUTE = (STANDARD_RIGHTS_EXECUTE_ACCESS|SAMR_DOMAIN_ACCESS_OPEN_ACCOUNT|SAMR_DOMAIN_ACCESS_ENUM_ACCOUNTS|SAMR_DOMAIN_ACCESS_LOOKUP_INFO_1);

enum samr_GroupAccessMask : uint32 {
	SAMR_GROUP_ACCESS_LOOKUP_INFO=0x00000001,
	SAMR_GROUP_ACCESS_SET_INFO=0x00000002,
	SAMR_GROUP_ACCESS_ADD_MEMBER=0x00000004,
	SAMR_GROUP_ACCESS_REMOVE_MEMBER=0x00000008,
	SAMR_GROUP_ACCESS_GET_MEMBERS=0x00000010,
}/* [bitmap32bit] */;

template <> struct x_ndr_traits_t<samr_GroupAccessMask> {
	using ndr_type = x_ndr_type_bitmap;
	using ndr_base_type = uint32;
	static const std::array<std::pair<uint32, const char *>, 5> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<samr_GroupAccessMask>(const samr_GroupAccessMask &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint32(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<samr_GroupAccessMask>(samr_GroupAccessMask &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint32_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = samr_GroupAccessMask(v);
	return __bpos;
}


const int SAMR_GROUP_ACCESS_ALL_ACCESS = 0x0000001F;
const int GENERIC_RIGHTS_GROUP_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED_ACCESS|SAMR_GROUP_ACCESS_ALL_ACCESS);
const int GENERIC_RIGHTS_GROUP_READ = (STANDARD_RIGHTS_READ_ACCESS|SAMR_GROUP_ACCESS_GET_MEMBERS);
const int GENERIC_RIGHTS_GROUP_WRITE = (STANDARD_RIGHTS_WRITE_ACCESS|SAMR_GROUP_ACCESS_REMOVE_MEMBER|SAMR_GROUP_ACCESS_ADD_MEMBER|SAMR_GROUP_ACCESS_SET_INFO);
const int GENERIC_RIGHTS_GROUP_EXECUTE = (STANDARD_RIGHTS_EXECUTE_ACCESS|SAMR_GROUP_ACCESS_LOOKUP_INFO);

enum samr_AliasAccessMask : uint32 {
	SAMR_ALIAS_ACCESS_ADD_MEMBER=0x00000001,
	SAMR_ALIAS_ACCESS_REMOVE_MEMBER=0x00000002,
	SAMR_ALIAS_ACCESS_GET_MEMBERS=0x00000004,
	SAMR_ALIAS_ACCESS_LOOKUP_INFO=0x00000008,
	SAMR_ALIAS_ACCESS_SET_INFO=0x00000010,
}/* [bitmap32bit] */;

template <> struct x_ndr_traits_t<samr_AliasAccessMask> {
	using ndr_type = x_ndr_type_bitmap;
	using ndr_base_type = uint32;
	static const std::array<std::pair<uint32, const char *>, 5> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<samr_AliasAccessMask>(const samr_AliasAccessMask &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint32(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<samr_AliasAccessMask>(samr_AliasAccessMask &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint32_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = samr_AliasAccessMask(v);
	return __bpos;
}


const int SAMR_ALIAS_ACCESS_ALL_ACCESS = 0x0000001F;
const int GENERIC_RIGHTS_ALIAS_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED_ACCESS|SAMR_ALIAS_ACCESS_ALL_ACCESS);
const int GENERIC_RIGHTS_ALIAS_READ = (STANDARD_RIGHTS_READ_ACCESS|SAMR_ALIAS_ACCESS_GET_MEMBERS);
const int GENERIC_RIGHTS_ALIAS_WRITE = (STANDARD_RIGHTS_WRITE_ACCESS|SAMR_ALIAS_ACCESS_REMOVE_MEMBER|SAMR_ALIAS_ACCESS_ADD_MEMBER|SAMR_ALIAS_ACCESS_SET_INFO);
const int GENERIC_RIGHTS_ALIAS_EXECUTE = (STANDARD_RIGHTS_EXECUTE_ACCESS|SAMR_ALIAS_ACCESS_LOOKUP_INFO);

struct samr_SamEntry {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	uint32 idx;
	lsa_String name;
} ;

template <> struct x_ndr_traits_t<samr_SamEntry> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_SamArray {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	std::vector<samr_SamEntry> entries;/* [size_is(count)] */
} ;

template <> struct x_ndr_traits_t<samr_SamArray> {
	using ndr_type = x_ndr_type_struct;
};


enum samr_DomainInfoClass : uint16 {
	DomainPasswordInformation=1,
	DomainGeneralInformation=2,
	DomainLogoffInformation=3,
	DomainOemInformation=4,
	DomainNameInformation=5,
	DomainReplicationInformation=6,
	DomainServerRoleInformation=7,
	DomainModifiedInformation=8,
	DomainStateInformation=9,
	DomainUasInformation=10,
	DomainGeneralInformation2=11,
	DomainLockoutInformation=12,
	DomainModifiedInformation2=13,
};

template <> struct x_ndr_traits_t<samr_DomainInfoClass> {
	using ndr_type = x_ndr_type_enum;
	using ndr_base_type = uint16;
	static const std::array<std::pair<uint16, const char *>, 13> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<samr_DomainInfoClass>(const samr_DomainInfoClass &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint1632(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<samr_DomainInfoClass>(samr_DomainInfoClass &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint16_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = samr_DomainInfoClass(v);
	return __bpos;
}


enum samr_Role : uint32 {
	SAMR_ROLE_STANDALONE=0,
	SAMR_ROLE_DOMAIN_MEMBER=1,
	SAMR_ROLE_DOMAIN_BDC=2,
	SAMR_ROLE_DOMAIN_PDC=3,
}/* [v1_enum] */;

template <> struct x_ndr_traits_t<samr_Role> {
	using ndr_type = x_ndr_type_enum;
	using ndr_base_type = uint32;
	static const std::array<std::pair<uint32, const char *>, 4> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<samr_Role>(const samr_Role &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint32(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<samr_Role>(samr_Role &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint32_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = samr_Role(v);
	return __bpos;
}


enum samr_PasswordProperties : uint32 {
	DOMAIN_PASSWORD_COMPLEX=0x00000001,
	DOMAIN_PASSWORD_NO_ANON_CHANGE=0x00000002,
	DOMAIN_PASSWORD_NO_CLEAR_CHANGE=0x00000004,
	DOMAIN_PASSWORD_LOCKOUT_ADMINS=0x00000008,
	DOMAIN_PASSWORD_STORE_CLEARTEXT=0x00000010,
	DOMAIN_REFUSE_PASSWORD_CHANGE=0x00000020,
}/* [bitmap32bit, public] */;

template <> struct x_ndr_traits_t<samr_PasswordProperties> {
	using ndr_type = x_ndr_type_bitmap;
	using ndr_base_type = uint32;
	static const std::array<std::pair<uint32, const char *>, 6> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<samr_PasswordProperties>(const samr_PasswordProperties &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint32(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<samr_PasswordProperties>(samr_PasswordProperties &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint32_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = samr_PasswordProperties(v);
	return __bpos;
}



enum samr_DomainServerState : uint32 {
	DOMAIN_SERVER_ENABLED=1,
	DOMAIN_SERVER_DISABLED=2,
}/* [v1_enum] */;

template <> struct x_ndr_traits_t<samr_DomainServerState> {
	using ndr_type = x_ndr_type_enum;
	using ndr_base_type = uint32;
	static const std::array<std::pair<uint32, const char *>, 2> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<samr_DomainServerState>(const samr_DomainServerState &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint32(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<samr_DomainServerState>(samr_DomainServerState &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint32_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = samr_DomainServerState(v);
	return __bpos;
}


struct samr_DomInfo1 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	uint16 min_password_length;
	uint16 password_history_length;
	samr_PasswordProperties password_properties;
	dlong max_password_age;
	dlong min_password_age;
} ;

template <> struct x_ndr_traits_t<samr_DomInfo1> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_DomGeneralInformation {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	NTTIME force_logoff_time;
	lsa_String oem_information;
	lsa_String domain_name;
	lsa_String primary;
	udlong sequence_num;
	samr_DomainServerState domain_server_state;
	samr_Role role;
	uint32 unknown3;
	uint32 num_users;
	uint32 num_groups;
	uint32 num_aliases;
} ;

template <> struct x_ndr_traits_t<samr_DomGeneralInformation> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_DomInfo3 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	NTTIME force_logoff_time;
} ;

template <> struct x_ndr_traits_t<samr_DomInfo3> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_DomOEMInformation {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	lsa_String oem_information;
} ;

template <> struct x_ndr_traits_t<samr_DomOEMInformation> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_DomInfo5 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	lsa_String domain_name;
} ;

template <> struct x_ndr_traits_t<samr_DomInfo5> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_DomInfo6 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	lsa_String primary;
} ;

template <> struct x_ndr_traits_t<samr_DomInfo6> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_DomInfo7 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	samr_Role role;
} ;

template <> struct x_ndr_traits_t<samr_DomInfo7> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_DomInfo8 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	uint64 sequence_num;
	NTTIME domain_create_time;
} ;

template <> struct x_ndr_traits_t<samr_DomInfo8> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_DomInfo9 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	samr_DomainServerState domain_server_state;
} ;

template <> struct x_ndr_traits_t<samr_DomInfo9> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_DomGeneralInformation2 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	samr_DomGeneralInformation general;
	uint64 lockout_duration;
	uint64 lockout_window;
	uint16 lockout_threshold;
} ;

template <> struct x_ndr_traits_t<samr_DomGeneralInformation2> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_DomInfo12 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	uint64 lockout_duration;
	uint64 lockout_window;
	uint16 lockout_threshold;
} ;

template <> struct x_ndr_traits_t<samr_DomInfo12> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_DomInfo13 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	uint64 sequence_num;
	NTTIME domain_create_time;
	uint64 modified_count_at_last_promotion;
} ;

template <> struct x_ndr_traits_t<samr_DomInfo13> {
	using ndr_type = x_ndr_type_struct;
};


union samr_DomainInfo
{
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	samr_DomainInfo() { }
	~samr_DomainInfo() { }
	void __init(x_ndr_switch_t __level);
	void __init(x_ndr_switch_t __level, const samr_DomainInfo &__other);
	void __uninit(x_ndr_switch_t __level);
	samr_DomInfo1 info1;/* [case] */
	samr_DomGeneralInformation general;/* [case(2)] */
	samr_DomInfo3 info3;/* [case(3)] */
	samr_DomOEMInformation oem;/* [case(4)] */
	samr_DomInfo5 info5;/* [case(5)] */
	samr_DomInfo6 info6;/* [case(6)] */
	samr_DomInfo7 info7;/* [case(7)] */
	samr_DomInfo8 info8;/* [case(8)] */
	samr_DomInfo9 info9;/* [case(9)] */
	samr_DomGeneralInformation2 general2;/* [case(11)] */
	samr_DomInfo12 info12;/* [case(12)] */
	samr_DomInfo13 info13;/* [case(13)] */
} /* [switch_type(uint16)] */;

template <> struct x_ndr_traits_t<samr_DomainInfo> {
	using ndr_type = x_ndr_type_union;
};

const int SAMR_ENUM_USERS_MULTIPLIER = 54;

struct samr_Ids {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	std::vector<uint32> ids;/* [size_is(count)] */
} ;

template <> struct x_ndr_traits_t<samr_Ids> {
	using ndr_type = x_ndr_type_struct;
};


enum samr_GroupAttrs : uint32 {
	SE_GROUP_MANDATORY=0x00000001,
	SE_GROUP_ENABLED_BY_DEFAULT=0x00000002,
	SE_GROUP_ENABLED=0x00000004,
	SE_GROUP_OWNER=0x00000008,
	SE_GROUP_USE_FOR_DENY_ONLY=0x00000010,
	SE_GROUP_RESOURCE=0x20000000,
	SE_GROUP_LOGON_ID=0xC0000000,
}/* [bitmap32bit, public] */;

template <> struct x_ndr_traits_t<samr_GroupAttrs> {
	using ndr_type = x_ndr_type_bitmap;
	using ndr_base_type = uint32;
	static const std::array<std::pair<uint32, const char *>, 7> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<samr_GroupAttrs>(const samr_GroupAttrs &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint32(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<samr_GroupAttrs>(samr_GroupAttrs &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint32_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = samr_GroupAttrs(v);
	return __bpos;
}



struct samr_GroupInfoAll {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	lsa_String name;
	samr_GroupAttrs attributes;
	uint32 num_members;
	lsa_String description;
} ;

template <> struct x_ndr_traits_t<samr_GroupInfoAll> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_GroupInfoAttributes {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	samr_GroupAttrs attributes;
} ;

template <> struct x_ndr_traits_t<samr_GroupInfoAttributes> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_GroupInfoDescription {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	lsa_String description;
} ;

template <> struct x_ndr_traits_t<samr_GroupInfoDescription> {
	using ndr_type = x_ndr_type_struct;
};


enum samr_GroupInfoEnum : uint16 {
	GROUPINFOALL=1,
	GROUPINFONAME=2,
	GROUPINFOATTRIBUTES=3,
	GROUPINFODESCRIPTION=4,
	GROUPINFOALL2=5,
};

template <> struct x_ndr_traits_t<samr_GroupInfoEnum> {
	using ndr_type = x_ndr_type_enum;
	using ndr_base_type = uint16;
	static const std::array<std::pair<uint16, const char *>, 5> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<samr_GroupInfoEnum>(const samr_GroupInfoEnum &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint1632(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<samr_GroupInfoEnum>(samr_GroupInfoEnum &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint16_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = samr_GroupInfoEnum(v);
	return __bpos;
}


union samr_GroupInfo
{
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	samr_GroupInfo() { }
	~samr_GroupInfo() { }
	void __init(x_ndr_switch_t __level);
	void __init(x_ndr_switch_t __level, const samr_GroupInfo &__other);
	void __uninit(x_ndr_switch_t __level);
	samr_GroupInfoAll all;/* [case(GROUPINFOALL)] */
	lsa_String name;/* [case(GROUPINFONAME)] */
	samr_GroupInfoAttributes attributes;/* [case(GROUPINFOATTRIBUTES)] */
	lsa_String description;/* [case(GROUPINFODESCRIPTION)] */
	samr_GroupInfoAll all2;/* [case(GROUPINFOALL2)] */
} /* [switch_type(samr_GroupInfoEnum)] */;

template <> struct x_ndr_traits_t<samr_GroupInfo> {
	using ndr_type = x_ndr_type_union;
};


struct samr_RidAttrArray {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	std::vector<uint32> rids;/* [size_is(count)] */
	std::vector<samr_GroupAttrs> attributes;/* [size_is(count)] */
} ;

template <> struct x_ndr_traits_t<samr_RidAttrArray> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_AliasInfoAll {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	lsa_String name;
	uint32 num_members;
	lsa_String description;
} ;

template <> struct x_ndr_traits_t<samr_AliasInfoAll> {
	using ndr_type = x_ndr_type_struct;
};


enum samr_AliasInfoEnum : uint16 {
	ALIASINFOALL=1,
	ALIASINFONAME=2,
	ALIASINFODESCRIPTION=3,
};

template <> struct x_ndr_traits_t<samr_AliasInfoEnum> {
	using ndr_type = x_ndr_type_enum;
	using ndr_base_type = uint16;
	static const std::array<std::pair<uint16, const char *>, 3> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<samr_AliasInfoEnum>(const samr_AliasInfoEnum &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint1632(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<samr_AliasInfoEnum>(samr_AliasInfoEnum &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint16_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = samr_AliasInfoEnum(v);
	return __bpos;
}


union samr_AliasInfo
{
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	samr_AliasInfo() { }
	~samr_AliasInfo() { }
	void __init(x_ndr_switch_t __level);
	void __init(x_ndr_switch_t __level, const samr_AliasInfo &__other);
	void __uninit(x_ndr_switch_t __level);
	samr_AliasInfoAll all;/* [case(ALIASINFOALL)] */
	lsa_String name;/* [case(ALIASINFONAME)] */
	lsa_String description;/* [case(ALIASINFODESCRIPTION)] */
} /* [switch_type(samr_AliasInfoEnum)] */;

template <> struct x_ndr_traits_t<samr_AliasInfo> {
	using ndr_type = x_ndr_type_union;
};


enum samr_UserInfoLevel : uint16 {
	UserGeneralInformation=1,
	UserPreferencesInformation=2,
	UserLogonInformation=3,
	UserLogonHoursInformation=4,
	UserAccountInformation=5,
	UserNameInformation=6,
	UserAccountNameInformation=7,
	UserFullNameInformation=8,
	UserPrimaryGroupInformation=9,
	UserHomeInformation=10,
	UserScriptInformation=11,
	UserProfileInformation=12,
	UserAdminCommentInformation=13,
	UserWorkStationsInformation=14,
	UserControlInformation=16,
	UserExpiresInformation=17,
	UserInternal1Information=18,
	UserParametersInformation=20,
	UserAllInformation=21,
	UserInternal4Information=23,
	UserInternal5Information=24,
	UserInternal4InformationNew=25,
	UserInternal5InformationNew=26,
};

template <> struct x_ndr_traits_t<samr_UserInfoLevel> {
	using ndr_type = x_ndr_type_enum;
	using ndr_base_type = uint16;
	static const std::array<std::pair<uint16, const char *>, 23> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<samr_UserInfoLevel>(const samr_UserInfoLevel &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint1632(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<samr_UserInfoLevel>(samr_UserInfoLevel &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint16_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = samr_UserInfoLevel(v);
	return __bpos;
}


struct samr_UserInfo1 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	lsa_String account_name;
	lsa_String full_name;
	uint32 primary_gid;
	lsa_String description;
	lsa_String comment;
} ;

template <> struct x_ndr_traits_t<samr_UserInfo1> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_UserInfo2 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	lsa_String comment;
	lsa_String reserved;
	uint16 country_code;
	uint16 code_page;
} ;

template <> struct x_ndr_traits_t<samr_UserInfo2> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_LogonHours {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	uint16 units_per_week;
	std::array<uint8, 1260> bits;/* [length_is(units_per_week/8), size_is(1260)] */
} /* [public, flag(LIBNDR_PRINT_ARRAY_HEX)] */;

template <> struct x_ndr_traits_t<samr_LogonHours> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_UserInfo3 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	lsa_String account_name;
	lsa_String full_name;
	uint32 rid;
	uint32 primary_gid;
	lsa_String home_directory;
	lsa_String home_drive;
	lsa_String logon_script;
	lsa_String profile_path;
	lsa_String workstations;
	NTTIME last_logon;
	NTTIME last_logoff;
	NTTIME last_password_change;
	NTTIME allow_password_change;
	NTTIME force_password_change;
	samr_LogonHours logon_hours;
	uint16 bad_password_count;
	uint16 logon_count;
	samr_AcctFlags acct_flags;
} ;

template <> struct x_ndr_traits_t<samr_UserInfo3> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_UserInfo4 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	samr_LogonHours logon_hours;
} ;

template <> struct x_ndr_traits_t<samr_UserInfo4> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_UserInfo5 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	lsa_String account_name;
	lsa_String full_name;
	uint32 rid;
	uint32 primary_gid;
	lsa_String home_directory;
	lsa_String home_drive;
	lsa_String logon_script;
	lsa_String profile_path;
	lsa_String description;
	lsa_String workstations;
	NTTIME last_logon;
	NTTIME last_logoff;
	samr_LogonHours logon_hours;
	uint16 bad_password_count;
	uint16 logon_count;
	NTTIME last_password_change;
	NTTIME acct_expiry;
	samr_AcctFlags acct_flags;
} ;

template <> struct x_ndr_traits_t<samr_UserInfo5> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_UserInfo6 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	lsa_String account_name;
	lsa_String full_name;
} ;

template <> struct x_ndr_traits_t<samr_UserInfo6> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_UserInfo7 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	lsa_String account_name;
} ;

template <> struct x_ndr_traits_t<samr_UserInfo7> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_UserInfo8 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	lsa_String full_name;
} ;

template <> struct x_ndr_traits_t<samr_UserInfo8> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_UserInfo9 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	uint32 primary_gid;
} ;

template <> struct x_ndr_traits_t<samr_UserInfo9> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_UserInfo10 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	lsa_String home_directory;
	lsa_String home_drive;
} ;

template <> struct x_ndr_traits_t<samr_UserInfo10> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_UserInfo11 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	lsa_String logon_script;
} ;

template <> struct x_ndr_traits_t<samr_UserInfo11> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_UserInfo12 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	lsa_String profile_path;
} ;

template <> struct x_ndr_traits_t<samr_UserInfo12> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_UserInfo13 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	lsa_String description;
} ;

template <> struct x_ndr_traits_t<samr_UserInfo13> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_UserInfo14 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	lsa_String workstations;
} ;

template <> struct x_ndr_traits_t<samr_UserInfo14> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_UserInfo16 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	samr_AcctFlags acct_flags;
} ;

template <> struct x_ndr_traits_t<samr_UserInfo16> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_UserInfo17 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	NTTIME acct_expiry;
} ;

template <> struct x_ndr_traits_t<samr_UserInfo17> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_Password {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	std::array<uint8, 16> hash;
} /* [public, flag(LIBNDR_PRINT_ARRAY_HEX)] */;

template <> struct x_ndr_traits_t<samr_Password> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_UserInfo18 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	samr_Password nt_pwd;
	samr_Password lm_pwd;
	uint8 nt_pwd_active;
	uint8 lm_pwd_active;
	uint8 password_expired;
} ;

template <> struct x_ndr_traits_t<samr_UserInfo18> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_UserInfo20 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	lsa_BinaryString parameters;
} ;

template <> struct x_ndr_traits_t<samr_UserInfo20> {
	using ndr_type = x_ndr_type_struct;
};


enum samr_FieldsPresent : uint32 {
	SAMR_FIELD_ACCOUNT_NAME=0x00000001,
	SAMR_FIELD_FULL_NAME=0x00000002,
	SAMR_FIELD_RID=0x00000004,
	SAMR_FIELD_PRIMARY_GID=0x00000008,
	SAMR_FIELD_DESCRIPTION=0x00000010,
	SAMR_FIELD_COMMENT=0x00000020,
	SAMR_FIELD_HOME_DIRECTORY=0x00000040,
	SAMR_FIELD_HOME_DRIVE=0x00000080,
	SAMR_FIELD_LOGON_SCRIPT=0x00000100,
	SAMR_FIELD_PROFILE_PATH=0x00000200,
	SAMR_FIELD_WORKSTATIONS=0x00000400,
	SAMR_FIELD_LAST_LOGON=0x00000800,
	SAMR_FIELD_LAST_LOGOFF=0x00001000,
	SAMR_FIELD_LOGON_HOURS=0x00002000,
	SAMR_FIELD_BAD_PWD_COUNT=0x00004000,
	SAMR_FIELD_NUM_LOGONS=0x00008000,
	SAMR_FIELD_ALLOW_PWD_CHANGE=0x00010000,
	SAMR_FIELD_FORCE_PWD_CHANGE=0x00020000,
	SAMR_FIELD_LAST_PWD_CHANGE=0x00040000,
	SAMR_FIELD_ACCT_EXPIRY=0x00080000,
	SAMR_FIELD_ACCT_FLAGS=0x00100000,
	SAMR_FIELD_PARAMETERS=0x00200000,
	SAMR_FIELD_COUNTRY_CODE=0x00400000,
	SAMR_FIELD_CODE_PAGE=0x00800000,
	SAMR_FIELD_NT_PASSWORD_PRESENT=0x01000000,
	SAMR_FIELD_LM_PASSWORD_PRESENT=0x02000000,
	SAMR_FIELD_PRIVATE_DATA=0x04000000,
	SAMR_FIELD_EXPIRED_FLAG=0x08000000,
	SAMR_FIELD_SEC_DESC=0x10000000,
	SAMR_FIELD_OWF_PWD=0x20000000,
}/* [bitmap32bit] */;

template <> struct x_ndr_traits_t<samr_FieldsPresent> {
	using ndr_type = x_ndr_type_bitmap;
	using ndr_base_type = uint32;
	static const std::array<std::pair<uint32, const char *>, 30> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<samr_FieldsPresent>(const samr_FieldsPresent &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint32(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<samr_FieldsPresent>(samr_FieldsPresent &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint32_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = samr_FieldsPresent(v);
	return __bpos;
}


const int PASS_MUST_CHANGE_AT_NEXT_LOGON = 0x01;
const int PASS_DONT_CHANGE_AT_NEXT_LOGON = 0x00;

struct samr_UserInfo21 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	NTTIME last_logon;
	NTTIME last_logoff;
	NTTIME last_password_change;
	NTTIME acct_expiry;
	NTTIME allow_password_change;
	NTTIME force_password_change;
	lsa_String account_name;
	lsa_String full_name;
	lsa_String home_directory;
	lsa_String home_drive;
	lsa_String logon_script;
	lsa_String profile_path;
	lsa_String description;
	lsa_String workstations;
	lsa_String comment;
	lsa_BinaryString parameters;
	lsa_BinaryString lm_owf_password;
	lsa_BinaryString nt_owf_password;
	lsa_String private_data;
	std::vector<uint8> buffer;/* [size_is(buf_count)] */
	uint32 rid;
	uint32 primary_gid;
	samr_AcctFlags acct_flags;
	samr_FieldsPresent fields_present;
	samr_LogonHours logon_hours;
	uint16 bad_password_count;
	uint16 logon_count;
	uint16 country_code;
	uint16 code_page;
	uint8 lm_password_set;
	uint8 nt_password_set;
	uint8 password_expired;
	uint8 private_data_sensitive;
} ;

template <> struct x_ndr_traits_t<samr_UserInfo21> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_CryptPassword {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	std::array<uint8, 516> data;
} /* [public, flag(LIBNDR_PRINT_ARRAY_HEX)] */;

template <> struct x_ndr_traits_t<samr_CryptPassword> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_UserInfo23 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	samr_UserInfo21 info;
	samr_CryptPassword password;
} ;

template <> struct x_ndr_traits_t<samr_UserInfo23> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_UserInfo24 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	samr_CryptPassword password;
	uint8 password_expired;
} ;

template <> struct x_ndr_traits_t<samr_UserInfo24> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_CryptPasswordEx {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	std::array<uint8, 532> data;
} /* [flag(LIBNDR_PRINT_ARRAY_HEX)] */;

template <> struct x_ndr_traits_t<samr_CryptPasswordEx> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_UserInfo25 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	samr_UserInfo21 info;
	samr_CryptPasswordEx password;
} ;

template <> struct x_ndr_traits_t<samr_UserInfo25> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_UserInfo26 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	samr_CryptPasswordEx password;
	uint8 password_expired;
} ;

template <> struct x_ndr_traits_t<samr_UserInfo26> {
	using ndr_type = x_ndr_type_struct;
};


union samr_UserInfo
{
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	samr_UserInfo() { }
	~samr_UserInfo() { }
	void __init(x_ndr_switch_t __level);
	void __init(x_ndr_switch_t __level, const samr_UserInfo &__other);
	void __uninit(x_ndr_switch_t __level);
	samr_UserInfo1 info1;/* [case] */
	samr_UserInfo2 info2;/* [case(2)] */
	samr_UserInfo3 info3;/* [case(3)] */
	samr_UserInfo4 info4;/* [case(4)] */
	samr_UserInfo5 info5;/* [case(5)] */
	samr_UserInfo6 info6;/* [case(6)] */
	samr_UserInfo7 info7;/* [case(7)] */
	samr_UserInfo8 info8;/* [case(8)] */
	samr_UserInfo9 info9;/* [case(9)] */
	samr_UserInfo10 info10;/* [case(10)] */
	samr_UserInfo11 info11;/* [case(11)] */
	samr_UserInfo12 info12;/* [case(12)] */
	samr_UserInfo13 info13;/* [case(13)] */
	samr_UserInfo14 info14;/* [case(14)] */
	samr_UserInfo16 info16;/* [case(16)] */
	samr_UserInfo17 info17;/* [case(17)] */
	samr_UserInfo18 info18;/* [case(18)] */
	samr_UserInfo20 info20;/* [case(20)] */
	samr_UserInfo21 info21;/* [case(21)] */
	samr_UserInfo23 info23;/* [case(23)] */
	samr_UserInfo24 info24;/* [case(24)] */
	samr_UserInfo25 info25;/* [case(25)] */
	samr_UserInfo26 info26;/* [case(26)] */
} /* [switch_type(uint16)] */;

template <> struct x_ndr_traits_t<samr_UserInfo> {
	using ndr_type = x_ndr_type_union;
};


struct samr_RidWithAttribute {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	uint32 rid;
	samr_GroupAttrs attributes;
} /* [public] */;

template <> struct x_ndr_traits_t<samr_RidWithAttribute> {
	using has_buffers = std::false_type;
	using ndr_type = x_ndr_type_struct;
};


struct samr_RidWithAttributeArray {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	x_ndr_off_t ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_vector_unique_ptr_t<samr_RidWithAttribute> rids;/* [size_is(count)] */
} /* [public] */;

template <> struct x_ndr_traits_t<samr_RidWithAttributeArray> {
	using has_buffers = std::true_type;
	using ndr_type = x_ndr_type_struct;
};

std::ostream &operator<<(std::ostream &os, samr_RidWithAttribute rid_with_attr);

struct samr_DispEntryGeneral {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	uint32 idx;
	uint32 rid;
	samr_AcctFlags acct_flags;
	lsa_String account_name;
	lsa_String description;
	lsa_String full_name;
} ;

template <> struct x_ndr_traits_t<samr_DispEntryGeneral> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_DispInfoGeneral {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	std::vector<samr_DispEntryGeneral> entries;/* [size_is(count)] */
} ;

template <> struct x_ndr_traits_t<samr_DispInfoGeneral> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_DispEntryFull {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	uint32 idx;
	uint32 rid;
	samr_AcctFlags acct_flags;
	lsa_String account_name;
	lsa_String description;
} ;

template <> struct x_ndr_traits_t<samr_DispEntryFull> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_DispInfoFull {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	std::vector<samr_DispEntryFull> entries;/* [size_is(count)] */
} ;

template <> struct x_ndr_traits_t<samr_DispInfoFull> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_DispEntryFullGroup {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	uint32 idx;
	uint32 rid;
	samr_GroupAttrs acct_flags;
	lsa_String account_name;
	lsa_String description;
} ;

template <> struct x_ndr_traits_t<samr_DispEntryFullGroup> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_DispInfoFullGroups {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	std::vector<samr_DispEntryFullGroup> entries;/* [size_is(count)] */
} ;

template <> struct x_ndr_traits_t<samr_DispInfoFullGroups> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_DispEntryAscii {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	uint32 idx;
	lsa_AsciiStringLarge account_name;
} ;

template <> struct x_ndr_traits_t<samr_DispEntryAscii> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_DispInfoAscii {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	std::vector<samr_DispEntryAscii> entries;/* [size_is(count)] */
} ;

template <> struct x_ndr_traits_t<samr_DispInfoAscii> {
	using ndr_type = x_ndr_type_struct;
};


union samr_DispInfo
{
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	samr_DispInfo() { }
	~samr_DispInfo() { }
	void __init(x_ndr_switch_t __level);
	void __init(x_ndr_switch_t __level, const samr_DispInfo &__other);
	void __uninit(x_ndr_switch_t __level);
	samr_DispInfoGeneral info1;/* [case] */
	samr_DispInfoFull info2;/* [case(2)] */
	samr_DispInfoFullGroups info3;/* [case(3)] */
	samr_DispInfoAscii info4;/* [case(4)] */
	samr_DispInfoAscii info5;/* [case(5)] */
} /* [switch_type(uint16)] */;

template <> struct x_ndr_traits_t<samr_DispInfo> {
	using ndr_type = x_ndr_type_union;
};


struct samr_PwInfo {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	uint16 min_password_length;
	samr_PasswordProperties password_properties;
} ;

template <> struct x_ndr_traits_t<samr_PwInfo> {
	using ndr_type = x_ndr_type_struct;
};


enum samr_ConnectVersion : uint32 {
	SAMR_CONNECT_PRE_W2K=1,
	SAMR_CONNECT_W2K=2,
	SAMR_CONNECT_AFTER_W2K=3,
}/* [v1_enum] */;

template <> struct x_ndr_traits_t<samr_ConnectVersion> {
	using ndr_type = x_ndr_type_enum;
	using ndr_base_type = uint32;
	static const std::array<std::pair<uint32, const char *>, 3> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<samr_ConnectVersion>(const samr_ConnectVersion &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint32(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<samr_ConnectVersion>(samr_ConnectVersion &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint32_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = samr_ConnectVersion(v);
	return __bpos;
}


enum samPwdChangeReason : uint32 {
	SAM_PWD_CHANGE_NO_ERROR=0,
	SAM_PWD_CHANGE_PASSWORD_TOO_SHORT=1,
	SAM_PWD_CHANGE_PWD_IN_HISTORY=2,
	SAM_PWD_CHANGE_USERNAME_IN_PASSWORD=3,
	SAM_PWD_CHANGE_FULLNAME_IN_PASSWORD=4,
	SAM_PWD_CHANGE_NOT_COMPLEX=5,
	SAM_PWD_CHANGE_MACHINE_NOT_DEFAULT=6,
	SAM_PWD_CHANGE_FAILED_BY_FILTER=7,
	SAM_PWD_CHANGE_PASSWORD_TOO_LONG=8,
}/* [v1_enum, public] */;

template <> struct x_ndr_traits_t<samPwdChangeReason> {
	using ndr_type = x_ndr_type_enum;
	using ndr_base_type = uint32;
	static const std::array<std::pair<uint32, const char *>, 9> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<samPwdChangeReason>(const samPwdChangeReason &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint32(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<samPwdChangeReason>(samPwdChangeReason &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint32_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = samPwdChangeReason(v);
	return __bpos;
}


struct userPwdChangeFailureInformation {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	samPwdChangeReason extendedFailureReason;
	lsa_String filterModuleName;
} ;

template <> struct x_ndr_traits_t<userPwdChangeFailureInformation> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_ConnectInfo1 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	samr_ConnectVersion client_version;
	uint32 unknown2;
} ;

template <> struct x_ndr_traits_t<samr_ConnectInfo1> {
	using ndr_type = x_ndr_type_struct;
};


union samr_ConnectInfo
{
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	samr_ConnectInfo1 info1;/* [case] */
} ;

template <> struct x_ndr_traits_t<samr_ConnectInfo> {
	using ndr_type = x_ndr_type_union;
};


enum samr_ValidateFieldsPresent : uint32 {
	SAMR_VALIDATE_FIELD_PASSWORD_LAST_SET=0x00000001,
	SAMR_VALIDATE_FIELD_BAD_PASSWORD_TIME=0x00000002,
	SAMR_VALIDATE_FIELD_LOCKOUT_TIME=0x00000004,
	SAMR_VALIDATE_FIELD_BAD_PASSWORD_COUNT=0x00000008,
	SAMR_VALIDATE_FIELD_PASSWORD_HISTORY_LENGTH=0x00000010,
	SAMR_VALIDATE_FIELD_PASSWORD_HISTORY=0x00000020,
}/* [bitmap32bit] */;

template <> struct x_ndr_traits_t<samr_ValidateFieldsPresent> {
	using ndr_type = x_ndr_type_bitmap;
	using ndr_base_type = uint32;
	static const std::array<std::pair<uint32, const char *>, 6> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<samr_ValidateFieldsPresent>(const samr_ValidateFieldsPresent &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint32(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<samr_ValidateFieldsPresent>(samr_ValidateFieldsPresent &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint32_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = samr_ValidateFieldsPresent(v);
	return __bpos;
}



enum samr_ValidatePasswordLevel : uint16 {
	NetValidateAuthentication=1,
	NetValidatePasswordChange=2,
	NetValidatePasswordReset=3,
};

template <> struct x_ndr_traits_t<samr_ValidatePasswordLevel> {
	using ndr_type = x_ndr_type_enum;
	using ndr_base_type = uint16;
	static const std::array<std::pair<uint16, const char *>, 3> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<samr_ValidatePasswordLevel>(const samr_ValidatePasswordLevel &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint1632(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<samr_ValidatePasswordLevel>(samr_ValidatePasswordLevel &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint16_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = samr_ValidatePasswordLevel(v);
	return __bpos;
}


enum samr_ValidationStatus : uint16 {
	SAMR_VALIDATION_STATUS_SUCCESS=0,
	SAMR_VALIDATION_STATUS_PASSWORD_MUST_CHANGE=1,
	SAMR_VALIDATION_STATUS_ACCOUNT_LOCKED_OUT=2,
	SAMR_VALIDATION_STATUS_PASSWORD_EXPIRED=3,
	SAMR_VALIDATION_STATUS_BAD_PASSWORD=4,
	SAMR_VALIDATION_STATUS_PWD_HISTORY_CONFLICT=5,
	SAMR_VALIDATION_STATUS_PWD_TOO_SHORT=6,
	SAMR_VALIDATION_STATUS_PWD_TOO_LONG=7,
	SAMR_VALIDATION_STATUS_NOT_COMPLEX_ENOUGH=8,
	SAMR_VALIDATION_STATUS_PASSWORD_TOO_RECENT=9,
	SAMR_VALIDATION_STATUS_PASSWORD_FILTER_ERROR=10,
};

template <> struct x_ndr_traits_t<samr_ValidationStatus> {
	using ndr_type = x_ndr_type_enum;
	using ndr_base_type = uint16;
	static const std::array<std::pair<uint16, const char *>, 11> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<samr_ValidationStatus>(const samr_ValidationStatus &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint1632(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<samr_ValidationStatus>(samr_ValidationStatus &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint16_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = samr_ValidationStatus(v);
	return __bpos;
}


struct samr_ValidationBlob {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	std::vector<uint8> data;/* [size_is(length)] */
} ;

template <> struct x_ndr_traits_t<samr_ValidationBlob> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_ValidatePasswordInfo {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	samr_ValidateFieldsPresent fields_present;
	NTTIME_hyper last_password_change;
	NTTIME_hyper bad_password_time;
	NTTIME_hyper lockout_time;
	uint32 bad_pwd_count;
	std::vector<samr_ValidationBlob> pwd_history;/* [size_is(pwd_history_len)] */
} ;

template <> struct x_ndr_traits_t<samr_ValidatePasswordInfo> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_ValidatePasswordRepCtr {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	samr_ValidatePasswordInfo info;
	samr_ValidationStatus status;
} ;

template <> struct x_ndr_traits_t<samr_ValidatePasswordRepCtr> {
	using ndr_type = x_ndr_type_struct;
};


union samr_ValidatePasswordRep
{
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	samr_ValidatePasswordRep() { }
	~samr_ValidatePasswordRep() { }
	void __init(x_ndr_switch_t __level);
	void __init(x_ndr_switch_t __level, const samr_ValidatePasswordRep &__other);
	void __uninit(x_ndr_switch_t __level);
	samr_ValidatePasswordRepCtr ctr1;/* [case] */
	samr_ValidatePasswordRepCtr ctr2;/* [case(2)] */
	samr_ValidatePasswordRepCtr ctr3;/* [case(3)] */
} /* [switch_type(uint16)] */;

template <> struct x_ndr_traits_t<samr_ValidatePasswordRep> {
	using ndr_type = x_ndr_type_union;
};


struct samr_ValidatePasswordReq3 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	samr_ValidatePasswordInfo info;
	lsa_StringLarge password;
	lsa_StringLarge account;
	samr_ValidationBlob hash;
	uint8 pwd_must_change_at_next_logon;
	uint8 clear_lockout;
} ;

template <> struct x_ndr_traits_t<samr_ValidatePasswordReq3> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_ValidatePasswordReq2 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	samr_ValidatePasswordInfo info;
	lsa_StringLarge password;
	lsa_StringLarge account;
	samr_ValidationBlob hash;
	uint8 password_matched;
} ;

template <> struct x_ndr_traits_t<samr_ValidatePasswordReq2> {
	using ndr_type = x_ndr_type_struct;
};


struct samr_ValidatePasswordReq1 {
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	samr_ValidatePasswordInfo info;
	uint8 password_matched;
} ;

template <> struct x_ndr_traits_t<samr_ValidatePasswordReq1> {
	using ndr_type = x_ndr_type_struct;
};


union samr_ValidatePasswordReq
{
	x_ndr_off_t push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t pull(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	samr_ValidatePasswordReq() { }
	~samr_ValidatePasswordReq() { }
	void __init(x_ndr_switch_t __level);
	void __init(x_ndr_switch_t __level, const samr_ValidatePasswordReq &__other);
	void __uninit(x_ndr_switch_t __level);
	samr_ValidatePasswordReq1 req1;/* [case] */
	samr_ValidatePasswordReq2 req2;/* [case(2)] */
	samr_ValidatePasswordReq3 req3;/* [case(3)] */
} /* [switch_type(uint16)] */;

template <> struct x_ndr_traits_t<samr_ValidatePasswordReq> {
	using ndr_type = x_ndr_type_union;
};

} /* namespace idl */


#endif /* __ndr_samr__h__ */

