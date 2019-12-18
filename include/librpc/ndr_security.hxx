
#ifndef __ndr_security__hxx__
#define __ndr_security__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/librpc/ndr.hxx"
#include "include/librpc/ndr_misc.hxx"

namespace idl {

enum lsa_SystemAccessModeFlags : uint32 {
	LSA_POLICY_MODE_INTERACTIVE=0x00000001,
	LSA_POLICY_MODE_NETWORK=0x00000002,
	LSA_POLICY_MODE_BATCH=0x00000004,
	LSA_POLICY_MODE_SERVICE=0x00000010,
	LSA_POLICY_MODE_PROXY=0x00000020,
	LSA_POLICY_MODE_DENY_INTERACTIVE=0x00000040,
	LSA_POLICY_MODE_DENY_NETWORK=0x00000080,
	LSA_POLICY_MODE_DENY_BATCH=0x00000100,
	LSA_POLICY_MODE_DENY_SERVICE=0x00000200,
	LSA_POLICY_MODE_REMOTE_INTERACTIVE=0x00000400,
	LSA_POLICY_MODE_DENY_REMOTE_INTERACTIVE=0x00000800,
	LSA_POLICY_MODE_ALL=0x00000FF7,
	LSA_POLICY_MODE_ALL_NT4=0x00000037,
}/* [bitmap32bit] */;

template <> struct x_ndr_traits_t<lsa_SystemAccessModeFlags> {
	using ndr_type = x_ndr_type_bitmap;
	using ndr_base_type = uint32;
	static const std::array<std::pair<uint32, const char *>, 13> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<lsa_SystemAccessModeFlags>(const lsa_SystemAccessModeFlags &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint32(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<lsa_SystemAccessModeFlags>(lsa_SystemAccessModeFlags &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint32_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = lsa_SystemAccessModeFlags(v);
	return __bpos;
}



struct dom_sid {
	uint8 sid_rev_num;
	uint8 num_auths;/* [range(0,15)] */
	std::array<uint8, 6> id_auth;
	std::array<uint32, 15> sub_auths;
} /* [noprint, gensize, nopull, public, nopush, nosize] */;

struct dom_sid2 {
	dom_sid val;
};

const int SEC_MASK_GENERIC = 0xF0000000;
const int SEC_MASK_FLAGS = 0x0F000000;
const int SEC_MASK_STANDARD = 0x00FF0000;
const int SEC_MASK_SPECIFIC = 0x0000FFFF;
const int SEC_GENERIC_ALL = 0x10000000;
const int SEC_GENERIC_EXECUTE = 0x20000000;
const int SEC_GENERIC_WRITE = 0x40000000;
const int SEC_GENERIC_READ = 0x80000000;
const int SEC_FLAG_SYSTEM_SECURITY = 0x01000000;
const int SEC_FLAG_MAXIMUM_ALLOWED = 0x02000000;
const int SEC_STD_DELETE = 0x00010000;
const int SEC_STD_READ_CONTROL = 0x00020000;
const int SEC_STD_WRITE_DAC = 0x00040000;
const int SEC_STD_WRITE_OWNER = 0x00080000;
const int SEC_STD_SYNCHRONIZE = 0x00100000;
const int SEC_STD_REQUIRED = 0x000F0000;
const int SEC_STD_ALL = 0x001F0000;
const int SEC_FILE_READ_DATA = 0x00000001;
const int SEC_FILE_WRITE_DATA = 0x00000002;
const int SEC_FILE_APPEND_DATA = 0x00000004;
const int SEC_FILE_READ_EA = 0x00000008;
const int SEC_FILE_WRITE_EA = 0x00000010;
const int SEC_FILE_EXECUTE = 0x00000020;
const int SEC_FILE_READ_ATTRIBUTE = 0x00000080;
const int SEC_FILE_WRITE_ATTRIBUTE = 0x00000100;
const int SEC_FILE_ALL = 0x000001ff;
const int SEC_DIR_LIST = 0x00000001;
const int SEC_DIR_ADD_FILE = 0x00000002;
const int SEC_DIR_ADD_SUBDIR = 0x00000004;
const int SEC_DIR_READ_EA = 0x00000008;
const int SEC_DIR_WRITE_EA = 0x00000010;
const int SEC_DIR_TRAVERSE = 0x00000020;
const int SEC_DIR_DELETE_CHILD = 0x00000040;
const int SEC_DIR_READ_ATTRIBUTE = 0x00000080;
const int SEC_DIR_WRITE_ATTRIBUTE = 0x00000100;
const int SEC_REG_QUERY_VALUE = 0x00000001;
const int SEC_REG_SET_VALUE = 0x00000002;
const int SEC_REG_CREATE_SUBKEY = 0x00000004;
const int SEC_REG_ENUM_SUBKEYS = 0x00000008;
const int SEC_REG_NOTIFY = 0x00000010;
const int SEC_REG_CREATE_LINK = 0x00000020;
const int SEC_ADS_CREATE_CHILD = 0x00000001;
const int SEC_ADS_DELETE_CHILD = 0x00000002;
const int SEC_ADS_LIST = 0x00000004;
const int SEC_ADS_SELF_WRITE = 0x00000008;
const int SEC_ADS_READ_PROP = 0x00000010;
const int SEC_ADS_WRITE_PROP = 0x00000020;
const int SEC_ADS_DELETE_TREE = 0x00000040;
const int SEC_ADS_LIST_OBJECT = 0x00000080;
const int SEC_ADS_CONTROL_ACCESS = 0x00000100;
const int SEC_MASK_INVALID = 0x0ce0fe00;
const int SEC_RIGHTS_FILE_READ = SEC_STD_READ_CONTROL|SEC_STD_SYNCHRONIZE|SEC_FILE_READ_DATA|SEC_FILE_READ_ATTRIBUTE|SEC_FILE_READ_EA;
const int SEC_RIGHTS_FILE_WRITE = SEC_STD_READ_CONTROL|SEC_STD_SYNCHRONIZE|SEC_FILE_WRITE_DATA|SEC_FILE_WRITE_ATTRIBUTE|SEC_FILE_WRITE_EA|SEC_FILE_APPEND_DATA;
const int SEC_RIGHTS_FILE_EXECUTE = SEC_STD_SYNCHRONIZE|SEC_STD_READ_CONTROL|SEC_FILE_READ_ATTRIBUTE|SEC_FILE_EXECUTE;
const int SEC_RIGHTS_FILE_ALL = SEC_STD_ALL|SEC_FILE_ALL;
const int SEC_RIGHTS_DIR_READ = SEC_RIGHTS_FILE_READ;
const int SEC_RIGHTS_DIR_WRITE = SEC_RIGHTS_FILE_WRITE;
const int SEC_RIGHTS_DIR_EXECUTE = SEC_RIGHTS_FILE_EXECUTE;
const int SEC_RIGHTS_DIR_ALL = SEC_RIGHTS_FILE_ALL;
const int SEC_RIGHTS_PRIV_BACKUP = SEC_STD_READ_CONTROL|SEC_FLAG_SYSTEM_SECURITY|SEC_RIGHTS_FILE_READ|SEC_DIR_TRAVERSE;
const int SEC_RIGHTS_PRIV_RESTORE = SEC_STD_WRITE_DAC|SEC_STD_WRITE_OWNER|SEC_FLAG_SYSTEM_SECURITY|SEC_RIGHTS_FILE_WRITE|SEC_DIR_ADD_FILE|SEC_DIR_ADD_SUBDIR|SEC_STD_DELETE;
const int STANDARD_RIGHTS_ALL_ACCESS = SEC_STD_ALL;
const int STANDARD_RIGHTS_MODIFY_ACCESS = SEC_STD_READ_CONTROL;
const int STANDARD_RIGHTS_EXECUTE_ACCESS = SEC_STD_READ_CONTROL;
const int STANDARD_RIGHTS_READ_ACCESS = SEC_STD_READ_CONTROL;
const int STANDARD_RIGHTS_WRITE_ACCESS = (SEC_STD_WRITE_OWNER|SEC_STD_WRITE_DAC|SEC_STD_DELETE);
const int STANDARD_RIGHTS_REQUIRED_ACCESS = (SEC_STD_DELETE|SEC_STD_READ_CONTROL|SEC_STD_WRITE_DAC|SEC_STD_WRITE_OWNER);
const int SEC_ADS_GENERIC_ALL_DS = (SEC_STD_DELETE|SEC_STD_WRITE_DAC|SEC_STD_WRITE_OWNER|SEC_ADS_CREATE_CHILD|SEC_ADS_DELETE_CHILD|SEC_ADS_DELETE_TREE|SEC_ADS_CONTROL_ACCESS);
const int SEC_ADS_GENERIC_EXECUTE = SEC_STD_READ_CONTROL|SEC_ADS_LIST;
const int SEC_ADS_GENERIC_WRITE = (SEC_STD_READ_CONTROL|SEC_ADS_SELF_WRITE|SEC_ADS_WRITE_PROP);
const int SEC_ADS_GENERIC_READ = (SEC_STD_READ_CONTROL|SEC_ADS_LIST|SEC_ADS_READ_PROP|SEC_ADS_LIST_OBJECT);
const int SEC_ADS_GENERIC_ALL = (SEC_ADS_GENERIC_EXECUTE|SEC_ADS_GENERIC_WRITE|SEC_ADS_GENERIC_READ|SEC_ADS_GENERIC_ALL_DS);
const string SID_NULL = "S-1-0-0";
const string NAME_WORLD = "WORLD";
const string SID_WORLD_DOMAIN = "S-1-1";
const string SID_WORLD = "S-1-1-0";
const string SID_CREATOR_OWNER_DOMAIN = "S-1-3";
const string SID_CREATOR_OWNER = "S-1-3-0";
const string SID_CREATOR_GROUP = "S-1-3-1";
const string SID_OWNER_RIGHTS = "S-1-3-4";
const string NAME_NT_AUTHORITY = "NT AUTHORITY";
const string SID_NT_AUTHORITY = "S-1-5";
const string SID_NT_DIALUP = "S-1-5-1";
const string SID_NT_NETWORK = "S-1-5-2";
const string SID_NT_BATCH = "S-1-5-3";
const string SID_NT_INTERACTIVE = "S-1-5-4";
const string SID_NT_SERVICE = "S-1-5-6";
const string SID_NT_ANONYMOUS = "S-1-5-7";
const string SID_NT_PROXY = "S-1-5-8";
const string SID_NT_ENTERPRISE_DCS = "S-1-5-9";
const string SID_NT_SELF = "S-1-5-10";
const string SID_NT_AUTHENTICATED_USERS = "S-1-5-11";
const string SID_NT_RESTRICTED = "S-1-5-12";
const string SID_NT_TERMINAL_SERVER_USERS = "S-1-5-13";
const string SID_NT_REMOTE_INTERACTIVE = "S-1-5-14";
const string SID_NT_THIS_ORGANISATION = "S-1-5-15";
const string SID_NT_IUSR = "S-1-5-17";
const string SID_NT_SYSTEM = "S-1-5-18";
const string SID_NT_LOCAL_SERVICE = "S-1-5-19";
const string SID_NT_NETWORK_SERVICE = "S-1-5-20";
const string SID_NT_DIGEST_AUTHENTICATION = "S-1-5-64-21";
const string SID_NT_NTLM_AUTHENTICATION = "S-1-5-64-10";
const string SID_NT_SCHANNEL_AUTHENTICATION = "S-1-5-64-14";
const string SID_NT_OTHER_ORGANISATION = "S-1-5-1000";
const string NAME_BUILTIN = "BUILTIN";
const string SID_BUILTIN = "S-1-5-32";
const string SID_BUILTIN_ADMINISTRATORS = "S-1-5-32-544";
const string SID_BUILTIN_USERS = "S-1-5-32-545";
const string SID_BUILTIN_GUESTS = "S-1-5-32-546";
const string SID_BUILTIN_POWER_USERS = "S-1-5-32-547";
const string SID_BUILTIN_ACCOUNT_OPERATORS = "S-1-5-32-548";
const string SID_BUILTIN_SERVER_OPERATORS = "S-1-5-32-549";
const string SID_BUILTIN_PRINT_OPERATORS = "S-1-5-32-550";
const string SID_BUILTIN_BACKUP_OPERATORS = "S-1-5-32-551";
const string SID_BUILTIN_REPLICATOR = "S-1-5-32-552";
const string SID_BUILTIN_RAS_SERVERS = "S-1-5-32-553";
const string SID_BUILTIN_PREW2K = "S-1-5-32-554";
const string SID_BUILTIN_REMOTE_DESKTOP_USERS = "S-1-5-32-555";
const string SID_BUILTIN_NETWORK_CONF_OPERATORS = "S-1-5-32-556";
const string SID_BUILTIN_INCOMING_FOREST_TRUST = "S-1-5-32-557";
const string SID_BUILTIN_PERFMON_USERS = "S-1-5-32-558";
const string SID_BUILTIN_PERFLOG_USERS = "S-1-5-32-559";
const string SID_BUILTIN_AUTH_ACCESS = "S-1-5-32-560";
const string SID_BUILTIN_TS_LICENSE_SERVERS = "S-1-5-32-561";
const string SID_BUILTIN_DISTRIBUTED_COM_USERS = "S-1-5-32-562";
const string SID_BUILTIN_CRYPTO_OPERATORS = "S-1-5-32-569";
const string SID_BUILTIN_EVENT_LOG_READERS = "S-1-5-32-573";
const string SID_BUILTIN_CERT_SERV_DCOM_ACCESS = "S-1-5-32-574";
const string NAME_NT_SERVICE = "NT SERVICE";
const string SID_NT_NT_SERVICE = "S-1-5-80";
const string SID_NT_TRUSTED_INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
const int DOMAIN_RID_LOGON = 9;
const int DOMAIN_RID_ENTERPRISE_READONLY_DCS = 498;
const int DOMAIN_RID_ADMINISTRATOR = 500;
const int DOMAIN_RID_GUEST = 501;
const int DOMAIN_RID_KRBTGT = 502;
const int DOMAIN_RID_ADMINS = 512;
const int DOMAIN_RID_USERS = 513;
const int DOMAIN_RID_GUESTS = 514;
const int DOMAIN_RID_DOMAIN_MEMBERS = 515;
const int DOMAIN_RID_DCS = 516;
const int DOMAIN_RID_CERT_ADMINS = 517;
const int DOMAIN_RID_SCHEMA_ADMINS = 518;
const int DOMAIN_RID_ENTERPRISE_ADMINS = 519;
const int DOMAIN_RID_POLICY_ADMINS = 520;
const int DOMAIN_RID_READONLY_DCS = 521;
const int DOMAIN_RID_RAS_SERVERS = 553;
const int DOMAIN_RID_RODC_ALLOW = 571;
const int DOMAIN_RID_RODC_DENY = 572;
const int BUILTIN_RID_ADMINISTRATORS = 544;
const int BUILTIN_RID_USERS = 545;
const int BUILTIN_RID_GUESTS = 546;
const int BUILTIN_RID_POWER_USERS = 547;
const int BUILTIN_RID_ACCOUNT_OPERATORS = 548;
const int BUILTIN_RID_SERVER_OPERATORS = 549;
const int BUILTIN_RID_PRINT_OPERATORS = 550;
const int BUILTIN_RID_BACKUP_OPERATORS = 551;
const int BUILTIN_RID_REPLICATOR = 552;
const int BUILTIN_RID_RAS_SERVERS = 553;
const int BUILTIN_RID_PRE_2K_ACCESS = 554;
const int BUILTIN_RID_REMOTE_DESKTOP_USERS = 555;
const int BUILTIN_RID_NETWORK_CONF_OPERATORS = 556;
const int BUILTIN_RID_INCOMING_FOREST_TRUST = 557;
const int BUILTIN_RID_PERFMON_USERS = 558;
const int BUILTIN_RID_PERFLOG_USERS = 559;
const int BUILTIN_RID_AUTH_ACCESS = 560;
const int BUILTIN_RID_TS_LICENSE_SERVERS = 561;
const int BUILTIN_RID_DISTRIBUTED_COM_USERS = 562;
const int BUILTIN_RID_CRYPTO_OPERATORS = 569;
const int BUILTIN_RID_EVENT_LOG_READERS = 573;
const int BUILTIN_RID_CERT_SERV_DCOM_ACCESS = 574;

enum sec_privilege : uint16 {
	SEC_PRIV_INVALID=0x0,
	SEC_PRIV_INCREASE_QUOTA=0x5,
	SEC_PRIV_MACHINE_ACCOUNT=0x6,
	SEC_PRIV_SECURITY=0x8,
	SEC_PRIV_TAKE_OWNERSHIP=0x09,
	SEC_PRIV_LOAD_DRIVER=0x0a,
	SEC_PRIV_SYSTEM_PROFILE=0x0b,
	SEC_PRIV_SYSTEMTIME=0x0c,
	SEC_PRIV_PROFILE_SINGLE_PROCESS=0x0d,
	SEC_PRIV_INCREASE_BASE_PRIORITY=0x0e,
	SEC_PRIV_CREATE_PAGEFILE=0x0f,
	SEC_PRIV_BACKUP=0x11,
	SEC_PRIV_RESTORE=0x12,
	SEC_PRIV_SHUTDOWN=0x13,
	SEC_PRIV_DEBUG=0x14,
	SEC_PRIV_SYSTEM_ENVIRONMENT=0x16,
	SEC_PRIV_CHANGE_NOTIFY=0x17,
	SEC_PRIV_REMOTE_SHUTDOWN=0x18,
	SEC_PRIV_UNDOCK=0x19,
	SEC_PRIV_ENABLE_DELEGATION=0x1b,
	SEC_PRIV_MANAGE_VOLUME=0x1c,
	SEC_PRIV_IMPERSONATE=0x1d,
	SEC_PRIV_CREATE_GLOBAL=0x1e,
	SEC_PRIV_PRINT_OPERATOR=0x1001,
	SEC_PRIV_ADD_USERS=0x1002,
	SEC_PRIV_DISK_OPERATOR=0x1003,
};

template <> struct x_ndr_traits_t<sec_privilege> {
	using ndr_type = x_ndr_type_enum;
	using ndr_base_type = uint16;
	static const std::array<std::pair<uint16, const char *>, 26> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<sec_privilege>(const sec_privilege &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint1632(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<sec_privilege>(sec_privilege &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint16_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = sec_privilege(v);
	return __bpos;
}


enum se_privilege : uint64 {
	SEC_PRIV_MACHINE_ACCOUNT_BIT=0x00000010,
	SEC_PRIV_PRINT_OPERATOR_BIT=0x00000020,
	SEC_PRIV_ADD_USERS_BIT=0x00000040,
	SEC_PRIV_DISK_OPERATOR_BIT=0x00000080,
	SEC_PRIV_REMOTE_SHUTDOWN_BIT=0x00000100,
	SEC_PRIV_BACKUP_BIT=0x00000200,
	SEC_PRIV_RESTORE_BIT=0x00000400,
	SEC_PRIV_TAKE_OWNERSHIP_BIT=0x00000800,
	SEC_PRIV_INCREASE_QUOTA_BIT=0x00001000,
	SEC_PRIV_SECURITY_BIT=0x00002000,
	SEC_PRIV_LOAD_DRIVER_BIT=0x00004000,
	SEC_PRIV_SYSTEM_PROFILE_BIT=0x00008000,
	SEC_PRIV_SYSTEMTIME_BIT=0x00010000,
	SEC_PRIV_PROFILE_SINGLE_PROCESS_BIT=0x00020000,
	SEC_PRIV_INCREASE_BASE_PRIORITY_BIT=0x00040000,
	SEC_PRIV_CREATE_PAGEFILE_BIT=0x00080000,
	SEC_PRIV_SHUTDOWN_BIT=0x00100000,
	SEC_PRIV_DEBUG_BIT=0x00200000,
	SEC_PRIV_SYSTEM_ENVIRONMENT_BIT=0x00400000,
	SEC_PRIV_CHANGE_NOTIFY_BIT=0x00800000,
	SEC_PRIV_UNDOCK_BIT=0x01000000,
	SEC_PRIV_ENABLE_DELEGATION_BIT=0x02000000,
	SEC_PRIV_MANAGE_VOLUME_BIT=0x04000000,
	SEC_PRIV_IMPERSONATE_BIT=0x08000000,
	SEC_PRIV_CREATE_GLOBAL_BIT=0x10000000,
}/* [bitmap64bit] */;

template <> struct x_ndr_traits_t<se_privilege> {
	using ndr_type = x_ndr_type_bitmap;
	using ndr_base_type = uint64;
	static const std::array<std::pair<uint64, const char *>, 25> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<se_privilege>(const se_privilege &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint64(__val, __ndr, __bpos, __epos, __flags, 8);
}

template <> inline x_ndr_off_t x_ndr_scalars<se_privilege>(se_privilege &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint64_t v;
	x_ndr_off_t ret = x_ndr_pull_uint64(v, __ndr, __bpos, __epos, __flags, 8);
	if (ret < 0) {
		return ret;
	}
	__val = se_privilege(v);
	return ret;
}



enum security_ace_flags : uint8 {
	SEC_ACE_FLAG_OBJECT_INHERIT=0x01,
	SEC_ACE_FLAG_CONTAINER_INHERIT=0x02,
	SEC_ACE_FLAG_NO_PROPAGATE_INHERIT=0x04,
	SEC_ACE_FLAG_INHERIT_ONLY=0x08,
	SEC_ACE_FLAG_INHERITED_ACE=0x10,
	SEC_ACE_FLAG_VALID_INHERIT=0x0f,
	SEC_ACE_FLAG_SUCCESSFUL_ACCESS=0x40,
	SEC_ACE_FLAG_FAILED_ACCESS=0x80,
}/* [public, bitmap8bit] */;

template <> struct x_ndr_traits_t<security_ace_flags> {
	using ndr_type = x_ndr_type_bitmap;
	using ndr_base_type = uint8;
	static const std::array<std::pair<uint8, const char *>, 8> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<security_ace_flags>(const security_ace_flags &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint8(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<security_ace_flags>(security_ace_flags &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint8_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = security_ace_flags(v);
	return __bpos;
}



enum security_ace_type : uint8 {
	SEC_ACE_TYPE_ACCESS_ALLOWED=0,
	SEC_ACE_TYPE_ACCESS_DENIED=1,
	SEC_ACE_TYPE_SYSTEM_AUDIT=2,
	SEC_ACE_TYPE_SYSTEM_ALARM=3,
	SEC_ACE_TYPE_ALLOWED_COMPOUND=4,
	SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT=5,
	SEC_ACE_TYPE_ACCESS_DENIED_OBJECT=6,
	SEC_ACE_TYPE_SYSTEM_AUDIT_OBJECT=7,
	SEC_ACE_TYPE_SYSTEM_ALARM_OBJECT=8,
}/* [public, enum8bit] */;

template <> struct x_ndr_traits_t<security_ace_type> {
	using ndr_type = x_ndr_type_enum;
	using ndr_base_type = uint8;
	static const std::array<std::pair<uint8, const char *>, 9> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<security_ace_type>(const security_ace_type &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint8(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<security_ace_type>(security_ace_type &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint8_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = security_ace_type(v);
	return __bpos;
}


enum security_ace_object_flags : uint32 {
	SEC_ACE_OBJECT_TYPE_PRESENT=0x00000001,
	SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT=0x00000002,
}/* [bitmap32bit] */;

template <> struct x_ndr_traits_t<security_ace_object_flags> {
	using ndr_type = x_ndr_type_bitmap;
	using ndr_base_type = uint32;
	static const std::array<std::pair<uint32, const char *>, 2> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<security_ace_object_flags>(const security_ace_object_flags &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint32(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<security_ace_object_flags>(security_ace_object_flags &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint32_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = security_ace_object_flags(v);
	return __bpos;
}



union security_ace_object_type
{
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	GUID type;/* [case(SEC_ACE_OBJECT_TYPE_PRESENT)] */
} /* [nodiscriminant] */;

template <> struct x_ndr_traits_t<security_ace_object_type> {
	using has_buffers = std::false_type;
	using ndr_type = x_ndr_type_union;
};


union security_ace_object_inherited_type
{
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	GUID inherited_type;/* [case(SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT)] */
} /* [nodiscriminant] */;

template <> struct x_ndr_traits_t<security_ace_object_inherited_type> {
	using has_buffers = std::false_type;
	using ndr_type = x_ndr_type_union;
};


struct security_ace_object {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	security_ace_object_flags flags;
	security_ace_object_type type;/* [switch_is(flags&SEC_ACE_OBJECT_TYPE_PRESENT)] */
	security_ace_object_inherited_type inherited_type;/* [switch_is(flags&SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT)] */
} ;

template <> struct x_ndr_traits_t<security_ace_object> {
	using has_buffers = std::false_type;
	using ndr_type = x_ndr_type_struct;
};


union security_ace_object_ctr
{
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	security_ace_object object;/* [case(SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT)] */
} /* [public, nodiscriminant] */;

template <> struct x_ndr_traits_t<security_ace_object_ctr> {
	using has_buffers = std::false_type;
	using ndr_type = x_ndr_type_union;
};


struct security_ace {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	security_ace_type type;
	security_ace_flags flags;
	uint32 access_mask;
	security_ace_object_ctr object;/* [switch_is(type)] */
	dom_sid trustee;
} /* [gensize, public, nosize] */;

template <> struct x_ndr_traits_t<security_ace> {
	using has_buffers = std::false_type;
	using ndr_type = x_ndr_type_struct;
};


enum security_acl_revision : uint16 {
	SECURITY_ACL_REVISION_NT4=2,
	SECURITY_ACL_REVISION_ADS=4,
};

template <> struct x_ndr_traits_t<security_acl_revision> {
	using ndr_type = x_ndr_type_enum;
	using ndr_base_type = uint16;
	static const std::array<std::pair<uint16, const char *>, 2> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<security_acl_revision>(const security_acl_revision &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint1632(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<security_acl_revision>(security_acl_revision &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint16_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = security_acl_revision(v);
	return __bpos;
}

const uint NT4_ACL_REVISION = SECURITY_ACL_REVISION_NT4;

struct security_acl {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	security_acl_revision revision;
	x_ndr_vector_with_count_t<security_ace> aces;
} /* [gensize, public, nosize] */;

template <> struct x_ndr_traits_t<security_acl> {
	using has_buffers = std::false_type;
	using ndr_type = x_ndr_type_struct;
};


enum security_descriptor_revision : uint8 {
	SECURITY_DESCRIPTOR_REVISION_1=1,
}/* [public, enum8bit] */;

template <> struct x_ndr_traits_t<security_descriptor_revision> {
	using has_buffers = std::false_type;
	using ndr_type = x_ndr_type_enum;
	using ndr_base_type = uint8;
	static const std::array<std::pair<uint8, const char *>, 1> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<security_descriptor_revision>(const security_descriptor_revision &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint8(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<security_descriptor_revision>(security_descriptor_revision &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint8_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = security_descriptor_revision(v);
	return __bpos;
}

const int SD_REVISION = SECURITY_DESCRIPTOR_REVISION_1;

enum security_descriptor_type : uint16 {
	SEC_DESC_OWNER_DEFAULTED=0x0001,
	SEC_DESC_GROUP_DEFAULTED=0x0002,
	SEC_DESC_DACL_PRESENT=0x0004,
	SEC_DESC_DACL_DEFAULTED=0x0008,
	SEC_DESC_SACL_PRESENT=0x0010,
	SEC_DESC_SACL_DEFAULTED=0x0020,
	SEC_DESC_DACL_TRUSTED=0x0040,
	SEC_DESC_SERVER_SECURITY=0x0080,
	SEC_DESC_DACL_AUTO_INHERIT_REQ=0x0100,
	SEC_DESC_SACL_AUTO_INHERIT_REQ=0x0200,
	SEC_DESC_DACL_AUTO_INHERITED=0x0400,
	SEC_DESC_SACL_AUTO_INHERITED=0x0800,
	SEC_DESC_DACL_PROTECTED=0x1000,
	SEC_DESC_SACL_PROTECTED=0x2000,
	SEC_DESC_RM_CONTROL_VALID=0x4000,
	SEC_DESC_SELF_RELATIVE=0x8000,
}/* [bitmap16bit, public] */;

template <> struct x_ndr_traits_t<security_descriptor_type> {
	using has_buffers = std::false_type;
	using ndr_type = x_ndr_type_bitmap;
	using ndr_base_type = uint16;
	static const std::array<std::pair<uint16, const char *>, 16> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<security_descriptor_type>(const security_descriptor_type &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint16(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<security_descriptor_type>(security_descriptor_type &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint16_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = security_descriptor_type(v);
	return __bpos;
}



struct security_descriptor {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	x_ndr_off_t ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	security_descriptor_revision revision;
	security_descriptor_type type;
	x_ndr_relative_ptr_t<dom_sid> owner_sid;/* [x_relative] */
	x_ndr_relative_ptr_t<dom_sid> group_sid;/* [x_relative] */
	x_ndr_relative_ptr_t<security_acl> sacl;/* [x_relative] */
	x_ndr_relative_ptr_t<security_acl> dacl;/* [x_relative] */
} /* [gensize, public, flag(LIBNDR_FLAG_LITTLE_ENDIAN), nosize] */;

template <> struct x_ndr_traits_t<security_descriptor> {
	using has_buffers = std::true_type;
	using ndr_type = x_ndr_type_struct;
};


struct sec_desc_buf {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	std::shared_ptr<security_descriptor> sd;
} /* [public] */;

template <> struct x_ndr_traits_t<sec_desc_buf> {
	using has_buffers = std::true_type;
	using ndr_type = x_ndr_type_struct;
};


struct security_token {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_vector_with_count_t<dom_sid> sids;/* [size_is(num_sids)] */
	se_privilege privilege_mask;
	lsa_SystemAccessModeFlags rights_mask;
} /* [public] */;

template <> struct x_ndr_traits_t<security_token> {
	using has_buffers = std::false_type;
	using ndr_type = x_ndr_type_struct;
};


struct security_unix_token {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	uid_t uid;
	gid_t gid;
	std::vector<gid_t> groups;/* [size_is(ngroups)] */
} /* [public] */;

template <> struct x_ndr_traits_t<security_unix_token> {
	using has_buffers = std::false_type;
	using ndr_type = x_ndr_type_struct;
};


enum security_secinfo : uint32 {
	SECINFO_OWNER=0x00000001,
	SECINFO_GROUP=0x00000002,
	SECINFO_DACL=0x00000004,
	SECINFO_SACL=0x00000008,
	SECINFO_LABEL=0x00000010,
	SECINFO_ATTRIBUTE=0x00000020,
	SECINFO_SCOPE=0x00000040,
	SECINFO_BACKUP=0x00010000,
	SECINFO_UNPROTECTED_SACL=0x10000000,
	SECINFO_UNPROTECTED_DACL=0x20000000,
	SECINFO_PROTECTED_SACL=0x40000000,
	SECINFO_PROTECTED_DACL=0x80000000,
}/* [bitmap32bit, public] */;

template <> struct x_ndr_traits_t<security_secinfo> {
	using has_buffers = std::false_type;
	using ndr_type = x_ndr_type_bitmap;
	using ndr_base_type = uint32;
	static const std::array<std::pair<uint32, const char *>, 12> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<security_secinfo>(const security_secinfo &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint32(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<security_secinfo>(security_secinfo &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint32_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = security_secinfo(v);
	return __bpos;
}


const int SMB_SUPPORTED_SECINFO_FLAGS = (SECINFO_OWNER|SECINFO_GROUP|SECINFO_DACL|SECINFO_SACL|SECINFO_LABEL|SECINFO_ATTRIBUTE|SECINFO_SCOPE|SECINFO_BACKUP|0);

struct LSAP_TOKEN_INFO_INTEGRITY {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	uint32 Flags;
	uint32 TokenIL;
	std::array<uint8, 32> MachineId;
} /* [gensize, public, flag(LIBNDR_PRINT_ARRAY_HEX)] */;

template <> struct x_ndr_traits_t<LSAP_TOKEN_INFO_INTEGRITY> {
	using has_buffers = std::false_type;
	using ndr_type = x_ndr_type_struct;
};


enum kerb_EncTypes : uint32 {
	KERB_ENCTYPE_DES_CBC_CRC=0x00000001,
	KERB_ENCTYPE_DES_CBC_MD5=0x00000002,
	KERB_ENCTYPE_RC4_HMAC_MD5=0x00000004,
	KERB_ENCTYPE_AES128_CTS_HMAC_SHA1_96=0x00000008,
	KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96=0x00000010,
	KERB_ENCTYPE_FAST_SUPPORTED=0x00010000,
	KERB_ENCTYPE_COMPOUND_IDENTITY_SUPPORTED=0x00020000,
	KERB_ENCTYPE_CLAIMS_SUPPORTED=0x00040000,
	KERB_ENCTYPE_RESOURCE_SID_COMPRESSION_DISABLED=0x00080000,
}/* [bitmap32bit, public] */;

template <> struct x_ndr_traits_t<kerb_EncTypes> {
	using has_buffers = std::false_type;
	using ndr_type = x_ndr_type_bitmap;
	using ndr_base_type = uint32;
	static const std::array<std::pair<uint32, const char *>, 9> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<kerb_EncTypes>(const kerb_EncTypes &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint32(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<kerb_EncTypes>(kerb_EncTypes &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint32_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = kerb_EncTypes(v);
	return __bpos;
}



enum security_autoinherit : uint32 {
	SEC_DACL_AUTO_INHERIT=0x00000001,
	SEC_SACL_AUTO_INHERIT=0x00000002,
	SEC_DEFAULT_DESCRIPTOR=0x00000004,
	SEC_OWNER_FROM_PARENT=0x00000008,
	SEC_GROUP_FROM_PARENT=0x00000010,
}/* [bitmap32bit, public] */;

template <> struct x_ndr_traits_t<security_autoinherit> {
	using has_buffers = std::false_type;
	using ndr_type = x_ndr_type_bitmap;
	using ndr_base_type = uint32;
	static const std::array<std::pair<uint32, const char *>, 5> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<security_autoinherit>(const security_autoinherit &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint32(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<security_autoinherit>(security_autoinherit &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint32_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = security_autoinherit(v);
	return __bpos;
}


const string GUID_DRS_ALLOCATE_RIDS = "1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd";
const string GUID_DRS_CHANGE_DOMAIN_MASTER = "014bf69c-7b3b-11d1-85f6-08002be74fab";
const string GUID_DRS_CHANGE_INFR_MASTER = "cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd";
const string GUID_DRS_CHANGE_PDC = "bae50096-4752-11d1-9052-00c04fc2d4cf";
const string GUID_DRS_CHANGE_RID_MASTER = "d58d5f36-0a98-11d1-adbb-00c04fd8d5cd";
const string GUID_DRS_CHANGE_SCHEMA_MASTER = "e12b56b6-0a95-11d1-adbb-00c04fd8d5cd";
const string GUID_DRS_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2";
const string GUID_DRS_REPL_SYNCRONIZE = "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2";
const string GUID_DRS_MANAGE_TOPOLOGY = "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2";
const string GUID_DRS_GET_ALL_CHANGES = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2";
const string GUID_DRS_RO_REPL_SECRET_SYNC = "1131f6ae-9c07-11d1-f79f-00c04fc2dcd2";
const string GUID_DRS_GET_FILTERED_ATTRIBUTES = "89e95b76-444d-4c62-991a-0facbeda640c";
const string GUID_DRS_MONITOR_TOPOLOGY = "f98340fb-7c5b-4cdb-a00b-2ebdfa115a96";
const string GUID_DRS_USER_CHANGE_PASSWORD = "ab721a53-1e2f-11d0-9819-00aa0040529b";
const string GUID_DRS_FORCE_CHANGE_PASSWORD = "00299570-246d-11d0-a768-00aa006e0529";
const string GUID_DRS_UPDATE_PASSWORD_NOT_REQUIRED_BIT = "280f369c-67c7-438e-ae98-1d46f3c6f541";
const string GUID_DRS_UNEXPIRE_PASSWORD = "ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501";
const string GUID_DRS_ENABLE_PER_USER_REVERSIBLY_ENCRYPTED_PASSWORD = "05c74c5e-4deb-43b4-bd9f-86664c2a7fd5";
const string GUID_DRS_DS_INSTALL_REPLICA = "9923a32a-3607-11d2-b9be-0000f87a36b2";
const string GUID_DRS_REANIMATE_TOMBSTONE = "45ec5156-db7e-47bb-b53f-dbeb2d03c40f";
const string GUID_DRS_VALIDATE_SPN = "f3a64788-5306-11d1-a9c5-0000f80367c1";
const string GUID_DRS_SELF_MEMBERSHIP = "bf9679c0-0de6-11d0-a285-00aa003049e2";
const string GUID_DRS_DNS_HOST_NAME = "72e39547-7b18-11d1-adef-00c04fd8d5cd";
const string GUID_DRS_ADD_DNS_HOST_NAME = "80863791-dbe9-4eb8-837e-7f0ab55d9ac7";
const string GUID_DRS_BEHAVIOR_VERSION = "d31a8757-2447-4545-8081-3bb610cacbf2";

struct generic_mapping {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	uint32 generic_read;
	uint32 generic_write;
	uint32 generic_execute;
	uint32 generic_all;
} ;

template <> struct x_ndr_traits_t<generic_mapping> {
	using has_buffers = std::false_type;
	using ndr_type = x_ndr_type_struct;
};


struct standard_mapping {
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	uint32 std_read;
	uint32 std_write;
	uint32 std_execute;
	uint32 std_all;
} ;

template <> struct x_ndr_traits_t<standard_mapping> {
	using has_buffers = std::false_type;
	using ndr_type = x_ndr_type_struct;
};

template <>
x_ndr_off_t x_ndr_scalars<dom_sid>(const dom_sid &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level);

template <>
x_ndr_off_t x_ndr_scalars<dom_sid>(dom_sid &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level);

template <>
void x_ndr_ostr<dom_sid>(const dom_sid &v, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level);

template <>
x_ndr_off_t x_ndr_scalars<dom_sid2>(const dom_sid2 &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level);

template <>
x_ndr_off_t x_ndr_scalars<dom_sid2>(dom_sid2 &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level);

template <>
inline void x_ndr_ostr<dom_sid2>(const dom_sid2 &v, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level)
{
	x_ndr_ostr(v.val, ndr, flags, level);
}

}

#endif /* __ndr_security__hxx__ */

