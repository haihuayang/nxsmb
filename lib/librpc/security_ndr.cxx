
#include "include/librpc/security_ndr.hxx"

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

const std::array<std::pair<uint32, const char *>, 13> x_ndr_traits_t<lsa_SystemAccessModeFlags>::value_name_map = { {
		{ LSA_POLICY_MODE_INTERACTIVE, "LSA_POLICY_MODE_INTERACTIVE" },
		{ LSA_POLICY_MODE_NETWORK, "LSA_POLICY_MODE_NETWORK" },
		{ LSA_POLICY_MODE_BATCH, "LSA_POLICY_MODE_BATCH" },
		{ LSA_POLICY_MODE_SERVICE, "LSA_POLICY_MODE_SERVICE" },
		{ LSA_POLICY_MODE_PROXY, "LSA_POLICY_MODE_PROXY" },
		{ LSA_POLICY_MODE_DENY_INTERACTIVE, "LSA_POLICY_MODE_DENY_INTERACTIVE" },
		{ LSA_POLICY_MODE_DENY_NETWORK, "LSA_POLICY_MODE_DENY_NETWORK" },
		{ LSA_POLICY_MODE_DENY_BATCH, "LSA_POLICY_MODE_DENY_BATCH" },
		{ LSA_POLICY_MODE_DENY_SERVICE, "LSA_POLICY_MODE_DENY_SERVICE" },
		{ LSA_POLICY_MODE_REMOTE_INTERACTIVE, "LSA_POLICY_MODE_REMOTE_INTERACTIVE" },
		{ LSA_POLICY_MODE_DENY_REMOTE_INTERACTIVE, "LSA_POLICY_MODE_DENY_REMOTE_INTERACTIVE" },
		{ LSA_POLICY_MODE_ALL, "LSA_POLICY_MODE_ALL" },
		{ LSA_POLICY_MODE_ALL_NT4, "LSA_POLICY_MODE_ALL_NT4" },
} };
const std::array<std::pair<uint16, const char *>, 26> x_ndr_traits_t<sec_privilege>::value_name_map = { {
	{ SEC_PRIV_INVALID, "SEC_PRIV_INVALID" },
	{ SEC_PRIV_INCREASE_QUOTA, "SEC_PRIV_INCREASE_QUOTA" },
	{ SEC_PRIV_MACHINE_ACCOUNT, "SEC_PRIV_MACHINE_ACCOUNT" },
	{ SEC_PRIV_SECURITY, "SEC_PRIV_SECURITY" },
	{ SEC_PRIV_TAKE_OWNERSHIP, "SEC_PRIV_TAKE_OWNERSHIP" },
	{ SEC_PRIV_LOAD_DRIVER, "SEC_PRIV_LOAD_DRIVER" },
	{ SEC_PRIV_SYSTEM_PROFILE, "SEC_PRIV_SYSTEM_PROFILE" },
	{ SEC_PRIV_SYSTEMTIME, "SEC_PRIV_SYSTEMTIME" },
	{ SEC_PRIV_PROFILE_SINGLE_PROCESS, "SEC_PRIV_PROFILE_SINGLE_PROCESS" },
	{ SEC_PRIV_INCREASE_BASE_PRIORITY, "SEC_PRIV_INCREASE_BASE_PRIORITY" },
	{ SEC_PRIV_CREATE_PAGEFILE, "SEC_PRIV_CREATE_PAGEFILE" },
	{ SEC_PRIV_BACKUP, "SEC_PRIV_BACKUP" },
	{ SEC_PRIV_RESTORE, "SEC_PRIV_RESTORE" },
	{ SEC_PRIV_SHUTDOWN, "SEC_PRIV_SHUTDOWN" },
	{ SEC_PRIV_DEBUG, "SEC_PRIV_DEBUG" },
	{ SEC_PRIV_SYSTEM_ENVIRONMENT, "SEC_PRIV_SYSTEM_ENVIRONMENT" },
	{ SEC_PRIV_CHANGE_NOTIFY, "SEC_PRIV_CHANGE_NOTIFY" },
	{ SEC_PRIV_REMOTE_SHUTDOWN, "SEC_PRIV_REMOTE_SHUTDOWN" },
	{ SEC_PRIV_UNDOCK, "SEC_PRIV_UNDOCK" },
	{ SEC_PRIV_ENABLE_DELEGATION, "SEC_PRIV_ENABLE_DELEGATION" },
	{ SEC_PRIV_MANAGE_VOLUME, "SEC_PRIV_MANAGE_VOLUME" },
	{ SEC_PRIV_IMPERSONATE, "SEC_PRIV_IMPERSONATE" },
	{ SEC_PRIV_CREATE_GLOBAL, "SEC_PRIV_CREATE_GLOBAL" },
	{ SEC_PRIV_PRINT_OPERATOR, "SEC_PRIV_PRINT_OPERATOR" },
	{ SEC_PRIV_ADD_USERS, "SEC_PRIV_ADD_USERS" },
	{ SEC_PRIV_DISK_OPERATOR, "SEC_PRIV_DISK_OPERATOR" },
} };


const std::array<std::pair<uint64, const char *>, 25> x_ndr_traits_t<se_privilege>::value_name_map = { {
		{ SEC_PRIV_MACHINE_ACCOUNT_BIT, "SEC_PRIV_MACHINE_ACCOUNT_BIT" },
		{ SEC_PRIV_PRINT_OPERATOR_BIT, "SEC_PRIV_PRINT_OPERATOR_BIT" },
		{ SEC_PRIV_ADD_USERS_BIT, "SEC_PRIV_ADD_USERS_BIT" },
		{ SEC_PRIV_DISK_OPERATOR_BIT, "SEC_PRIV_DISK_OPERATOR_BIT" },
		{ SEC_PRIV_REMOTE_SHUTDOWN_BIT, "SEC_PRIV_REMOTE_SHUTDOWN_BIT" },
		{ SEC_PRIV_BACKUP_BIT, "SEC_PRIV_BACKUP_BIT" },
		{ SEC_PRIV_RESTORE_BIT, "SEC_PRIV_RESTORE_BIT" },
		{ SEC_PRIV_TAKE_OWNERSHIP_BIT, "SEC_PRIV_TAKE_OWNERSHIP_BIT" },
		{ SEC_PRIV_INCREASE_QUOTA_BIT, "SEC_PRIV_INCREASE_QUOTA_BIT" },
		{ SEC_PRIV_SECURITY_BIT, "SEC_PRIV_SECURITY_BIT" },
		{ SEC_PRIV_LOAD_DRIVER_BIT, "SEC_PRIV_LOAD_DRIVER_BIT" },
		{ SEC_PRIV_SYSTEM_PROFILE_BIT, "SEC_PRIV_SYSTEM_PROFILE_BIT" },
		{ SEC_PRIV_SYSTEMTIME_BIT, "SEC_PRIV_SYSTEMTIME_BIT" },
		{ SEC_PRIV_PROFILE_SINGLE_PROCESS_BIT, "SEC_PRIV_PROFILE_SINGLE_PROCESS_BIT" },
		{ SEC_PRIV_INCREASE_BASE_PRIORITY_BIT, "SEC_PRIV_INCREASE_BASE_PRIORITY_BIT" },
		{ SEC_PRIV_CREATE_PAGEFILE_BIT, "SEC_PRIV_CREATE_PAGEFILE_BIT" },
		{ SEC_PRIV_SHUTDOWN_BIT, "SEC_PRIV_SHUTDOWN_BIT" },
		{ SEC_PRIV_DEBUG_BIT, "SEC_PRIV_DEBUG_BIT" },
		{ SEC_PRIV_SYSTEM_ENVIRONMENT_BIT, "SEC_PRIV_SYSTEM_ENVIRONMENT_BIT" },
		{ SEC_PRIV_CHANGE_NOTIFY_BIT, "SEC_PRIV_CHANGE_NOTIFY_BIT" },
		{ SEC_PRIV_UNDOCK_BIT, "SEC_PRIV_UNDOCK_BIT" },
		{ SEC_PRIV_ENABLE_DELEGATION_BIT, "SEC_PRIV_ENABLE_DELEGATION_BIT" },
		{ SEC_PRIV_MANAGE_VOLUME_BIT, "SEC_PRIV_MANAGE_VOLUME_BIT" },
		{ SEC_PRIV_IMPERSONATE_BIT, "SEC_PRIV_IMPERSONATE_BIT" },
		{ SEC_PRIV_CREATE_GLOBAL_BIT, "SEC_PRIV_CREATE_GLOBAL_BIT" },
} };
const std::array<std::pair<uint8, const char *>, 8> x_ndr_traits_t<security_ace_flags>::value_name_map = { {
		{ SEC_ACE_FLAG_OBJECT_INHERIT, "SEC_ACE_FLAG_OBJECT_INHERIT" },
		{ SEC_ACE_FLAG_CONTAINER_INHERIT, "SEC_ACE_FLAG_CONTAINER_INHERIT" },
		{ SEC_ACE_FLAG_NO_PROPAGATE_INHERIT, "SEC_ACE_FLAG_NO_PROPAGATE_INHERIT" },
		{ SEC_ACE_FLAG_INHERIT_ONLY, "SEC_ACE_FLAG_INHERIT_ONLY" },
		{ SEC_ACE_FLAG_INHERITED_ACE, "SEC_ACE_FLAG_INHERITED_ACE" },
		{ SEC_ACE_FLAG_VALID_INHERIT, "SEC_ACE_FLAG_VALID_INHERIT" },
		{ SEC_ACE_FLAG_SUCCESSFUL_ACCESS, "SEC_ACE_FLAG_SUCCESSFUL_ACCESS" },
		{ SEC_ACE_FLAG_FAILED_ACCESS, "SEC_ACE_FLAG_FAILED_ACCESS" },
} };
const std::array<std::pair<uint8, const char *>, 9> x_ndr_traits_t<security_ace_type>::value_name_map = { {
	{ SEC_ACE_TYPE_ACCESS_ALLOWED, "SEC_ACE_TYPE_ACCESS_ALLOWED" },
	{ SEC_ACE_TYPE_ACCESS_DENIED, "SEC_ACE_TYPE_ACCESS_DENIED" },
	{ SEC_ACE_TYPE_SYSTEM_AUDIT, "SEC_ACE_TYPE_SYSTEM_AUDIT" },
	{ SEC_ACE_TYPE_SYSTEM_ALARM, "SEC_ACE_TYPE_SYSTEM_ALARM" },
	{ SEC_ACE_TYPE_ALLOWED_COMPOUND, "SEC_ACE_TYPE_ALLOWED_COMPOUND" },
	{ SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT, "SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT" },
	{ SEC_ACE_TYPE_ACCESS_DENIED_OBJECT, "SEC_ACE_TYPE_ACCESS_DENIED_OBJECT" },
	{ SEC_ACE_TYPE_SYSTEM_AUDIT_OBJECT, "SEC_ACE_TYPE_SYSTEM_AUDIT_OBJECT" },
	{ SEC_ACE_TYPE_SYSTEM_ALARM_OBJECT, "SEC_ACE_TYPE_SYSTEM_ALARM_OBJECT" },
} };


const std::array<std::pair<uint32, const char *>, 2> x_ndr_traits_t<security_ace_object_flags>::value_name_map = { {
		{ SEC_ACE_OBJECT_TYPE_PRESENT, "SEC_ACE_OBJECT_TYPE_PRESENT" },
		{ SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT, "SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT" },
} };

x_ndr_off_t security_ace_object_type::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_UNION_ALIGN(4, __ndr, __bpos, __epos, __flags);
	switch (__level) {
		case SEC_ACE_OBJECT_TYPE_PRESENT: {
			X_NDR_SCALARS(type, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		default: {
		} break;
	}
	return __bpos;
}

x_ndr_off_t security_ace_object_type::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_UNION_ALIGN(4, __ndr, __bpos, __epos, __flags);
	switch (__level) {
		case SEC_ACE_OBJECT_TYPE_PRESENT: {
			X_NDR_SCALARS(type, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		default: {
		} break;
	}
	return __bpos;
}

void security_ace_object_type::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	switch (__level) {
		case SEC_ACE_OBJECT_TYPE_PRESENT: {
			X_NDR_OSTR(type, __ndr, __flags, X_NDR_SWITCH_NONE);
		} break;
		default: {
		} break;
	}
}


x_ndr_off_t security_ace_object_inherited_type::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_UNION_ALIGN(4, __ndr, __bpos, __epos, __flags);
	switch (__level) {
		case SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT: {
			X_NDR_SCALARS(inherited_type, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		default: {
		} break;
	}
	return __bpos;
}

x_ndr_off_t security_ace_object_inherited_type::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_UNION_ALIGN(4, __ndr, __bpos, __epos, __flags);
	switch (__level) {
		case SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT: {
			X_NDR_SCALARS(inherited_type, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		default: {
		} break;
	}
	return __bpos;
}

void security_ace_object_inherited_type::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	switch (__level) {
		case SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT: {
			X_NDR_OSTR(inherited_type, __ndr, __flags, X_NDR_SWITCH_NONE);
		} break;
		default: {
		} break;
	}
}


x_ndr_off_t security_ace_object::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	x_ndr_off_t __base = __bpos; (void)__base;
	x_ndr_off_t __ptr; (void)__ptr;
	X_NDR_SCALARS(flags, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(type, __ndr, __bpos, __epos, __flags, flags&SEC_ACE_OBJECT_TYPE_PRESENT);
	X_NDR_SCALARS(inherited_type, __ndr, __bpos, __epos, __flags, flags&SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT);
	X_NDR_TRAILER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	return __bpos;
}


x_ndr_off_t security_ace_object::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	x_ndr_off_t __base = __bpos; (void)__base;
	x_ndr_off_t __ptr; (void)__ptr;
	X_NDR_SCALARS(flags, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(type, __ndr, __bpos, __epos, __flags, flags&SEC_ACE_OBJECT_TYPE_PRESENT);
	X_NDR_SCALARS(inherited_type, __ndr, __bpos, __epos, __flags, flags&SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT);
	X_NDR_TRAILER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

void security_ace_object::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(flags, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(type, __ndr, __flags, flags&SEC_ACE_OBJECT_TYPE_PRESENT);
	X_NDR_OSTR_NEXT(inherited_type, __ndr, __flags, flags&SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT);
	(__ndr) << leave;
}



x_ndr_off_t security_ace_object_ctr::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_UNION_ALIGN(4, __ndr, __bpos, __epos, __flags);
	switch (__level) {
		case SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT: {
			X_NDR_SCALARS(object, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case SEC_ACE_TYPE_ACCESS_DENIED_OBJECT: {
			X_NDR_SCALARS(object, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case SEC_ACE_TYPE_SYSTEM_AUDIT_OBJECT: {
			X_NDR_SCALARS(object, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case SEC_ACE_TYPE_SYSTEM_ALARM_OBJECT: {
			X_NDR_SCALARS(object, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		default: {
		} break;
	}
	return __bpos;
}

x_ndr_off_t security_ace_object_ctr::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_UNION_ALIGN(4, __ndr, __bpos, __epos, __flags);
	switch (__level) {
		case SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT: {
			X_NDR_SCALARS(object, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case SEC_ACE_TYPE_ACCESS_DENIED_OBJECT: {
			X_NDR_SCALARS(object, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case SEC_ACE_TYPE_SYSTEM_AUDIT_OBJECT: {
			X_NDR_SCALARS(object, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case SEC_ACE_TYPE_SYSTEM_ALARM_OBJECT: {
			X_NDR_SCALARS(object, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		default: {
		} break;
	}
	return __bpos;
}

void security_ace_object_ctr::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	switch (__level) {
		case SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT: {
			X_NDR_OSTR(object, __ndr, __flags, X_NDR_SWITCH_NONE);
		} break;
		case SEC_ACE_TYPE_ACCESS_DENIED_OBJECT: {
			X_NDR_OSTR(object, __ndr, __flags, X_NDR_SWITCH_NONE);
		} break;
		case SEC_ACE_TYPE_SYSTEM_AUDIT_OBJECT: {
			X_NDR_OSTR(object, __ndr, __flags, X_NDR_SWITCH_NONE);
		} break;
		case SEC_ACE_TYPE_SYSTEM_ALARM_OBJECT: {
			X_NDR_OSTR(object, __ndr, __flags, X_NDR_SWITCH_NONE);
		} break;
		default: {
		} break;
	}
}


x_ndr_off_t security_ace::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	x_ndr_off_t __base = __bpos;
	X_NDR_SCALARS(type, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(flags, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	x_ndr_off_t __tmp_2 = __bpos;
	X_NDR_SKIP(uint16, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(access_mask, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(object, __ndr, __bpos, __epos, __flags, type);
	X_NDR_SCALARS(trustee, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(uint16(__bpos - __base), __ndr, __tmp_2, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}


x_ndr_off_t security_ace::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	x_ndr_off_t __base = __bpos; (void)__base;
	x_ndr_off_t __ptr; (void)__ptr;
	X_NDR_SCALARS(type, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(flags, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	uint16 size;
	X_NDR_SCALARS(size, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	__epos = X_NDR_CHECK_POS(__base + size, __bpos, __epos);
	X_NDR_SCALARS(access_mask, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(object, __ndr, __bpos, __epos, __flags, type);
	X_NDR_SCALARS(trustee, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __epos;
}

void security_ace::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(type, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(flags, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(access_mask, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(object, __ndr, __flags, type);
	X_NDR_OSTR_NEXT(trustee, __ndr, __flags, X_NDR_SWITCH_NONE);
	(__ndr) << leave;
}


const std::array<std::pair<uint16, const char *>, 2> x_ndr_traits_t<security_acl_revision>::value_name_map = { {
	{ SECURITY_ACL_REVISION_NT4, "SECURITY_ACL_REVISION_NT4" },
	{ SECURITY_ACL_REVISION_ADS, "SECURITY_ACL_REVISION_ADS" },
} };



x_ndr_off_t security_acl::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	X_NDR_CHECK_RANGE(get_size(aces), 0, 2000);
	x_ndr_off_t __base = __bpos;
	X_NDR_SCALARS(revision, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	x_ndr_off_t __tmp_1 = __bpos;
	X_NDR_SKIP(uint16, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(uint32(get_size(aces)), __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(aces, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(uint16(__bpos - __base), __ndr, __tmp_1, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}


x_ndr_off_t security_acl::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	x_ndr_off_t __base = __bpos; (void)__base;
	X_NDR_SCALARS(revision, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	uint16 size;
	X_NDR_SCALARS(size, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	__epos = X_NDR_CHECK_POS(__base + size, __bpos, __epos);
	uint32 num_aces;
	X_NDR_SCALARS(num_aces, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_CHECK_RANGE(num_aces, 0, 2000);
	aces.resize(num_aces);
	X_NDR_SCALARS(aces, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __epos;
}

void security_acl::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(revision, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(aces, __ndr, __flags, X_NDR_SWITCH_NONE);
	(__ndr) << leave;
}


const std::array<std::pair<uint8, const char *>, 1> x_ndr_traits_t<security_descriptor_revision>::value_name_map = { {
	{ SECURITY_DESCRIPTOR_REVISION_1, "SECURITY_DESCRIPTOR_REVISION_1" },
} };


const std::array<std::pair<uint16, const char *>, 16> x_ndr_traits_t<security_descriptor_type>::value_name_map = { {
		{ SEC_DESC_OWNER_DEFAULTED, "SEC_DESC_OWNER_DEFAULTED" },
		{ SEC_DESC_GROUP_DEFAULTED, "SEC_DESC_GROUP_DEFAULTED" },
		{ SEC_DESC_DACL_PRESENT, "SEC_DESC_DACL_PRESENT" },
		{ SEC_DESC_DACL_DEFAULTED, "SEC_DESC_DACL_DEFAULTED" },
		{ SEC_DESC_SACL_PRESENT, "SEC_DESC_SACL_PRESENT" },
		{ SEC_DESC_SACL_DEFAULTED, "SEC_DESC_SACL_DEFAULTED" },
		{ SEC_DESC_DACL_TRUSTED, "SEC_DESC_DACL_TRUSTED" },
		{ SEC_DESC_SERVER_SECURITY, "SEC_DESC_SERVER_SECURITY" },
		{ SEC_DESC_DACL_AUTO_INHERIT_REQ, "SEC_DESC_DACL_AUTO_INHERIT_REQ" },
		{ SEC_DESC_SACL_AUTO_INHERIT_REQ, "SEC_DESC_SACL_AUTO_INHERIT_REQ" },
		{ SEC_DESC_DACL_AUTO_INHERITED, "SEC_DESC_DACL_AUTO_INHERITED" },
		{ SEC_DESC_SACL_AUTO_INHERITED, "SEC_DESC_SACL_AUTO_INHERITED" },
		{ SEC_DESC_DACL_PROTECTED, "SEC_DESC_DACL_PROTECTED" },
		{ SEC_DESC_SACL_PROTECTED, "SEC_DESC_SACL_PROTECTED" },
		{ SEC_DESC_RM_CONTROL_VALID, "SEC_DESC_RM_CONTROL_VALID" },
		{ SEC_DESC_SELF_RELATIVE, "SEC_DESC_SELF_RELATIVE" },
} };

x_ndr_off_t security_descriptor::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_FLAG_LITTLE_ENDIAN);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(revision, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(type, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(owner_sid, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(group_sid, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(sacl, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(dacl, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);

	return __bpos;
}

x_ndr_off_t security_descriptor::ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_FLAG_LITTLE_ENDIAN);
	X_NDR_BUFFERS(owner_sid, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(group_sid, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(sacl, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(dacl, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}


x_ndr_off_t security_descriptor::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_FLAG_LITTLE_ENDIAN);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(revision, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(type, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(owner_sid, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(group_sid, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(sacl, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(dacl, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);

	return __bpos;
}

x_ndr_off_t security_descriptor::ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_FLAG_LITTLE_ENDIAN);
	X_NDR_BUFFERS(owner_sid, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(group_sid, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(sacl, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(dacl, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}

void security_descriptor::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_FLAG_LITTLE_ENDIAN);
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(revision, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(type, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(owner_sid, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(group_sid, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(sacl, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(dacl, __ndr, __flags, X_NDR_SWITCH_NONE);
	(__ndr) << leave;
}

#if 0

x_ndr_off_t sec_desc_buf::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	x_ndr_off_t __base = __bpos; (void)__base;
	x_ndr_off_t __ptr; (void)__ptr;
	X_NDR_ALIGN(sizeof(uint32), __ndr, __bpos, __epos, __flags);
	x_ndr_off_t __tmp_0 = __bpos;
	X_NDR_RESERVE(sizeof(uint32), __ndr, __bpos, __epos, __flags);
	__ptr = __bpos;
	X_NDR_DATA(sd, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_FILL(uint32(__bpos - __ptr), __ndr, __tmp_0, __epos, __flags);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}


x_ndr_off_t sec_desc_buf::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	x_ndr_off_t __base = __bpos; (void)__base;
	x_ndr_off_t __ptr; (void)__ptr;
	uint32 sd_size;
	X_NDR_DATA(sd_size, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	__ptr = __bpos;
	X_NDR_DATA(sd, __ndr, __bpos, X_NDR_ELEM_EPOS(sd_size, __base, __bpos, __epos), __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

void sec_desc_buf::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(sd, __ndr, __flags, X_NDR_SWITCH_NONE);
	(__ndr) << leave;
}



x_ndr_off_t security_token::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_HEADER_ALIGN(8, __ndr, __bpos, __epos, __flags);
	x_ndr_off_t __base = __bpos; (void)__base;
	x_ndr_off_t __ptr; (void)__ptr;
	X_NDR_DATA(uint32(get_size(sids)), __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_DATA(sids, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_DATA(privilege_mask, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_DATA(rights_mask, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(8, __ndr, __bpos, __epos, __flags);
	return __bpos;
}


x_ndr_off_t security_token::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_HEADER_ALIGN(8, __ndr, __bpos, __epos, __flags);
	x_ndr_off_t __base = __bpos; (void)__base;
	x_ndr_off_t __ptr; (void)__ptr;
	uint32 num_sids;
	X_NDR_DATA(num_sids, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_DATA(sids, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE, num_sids);
	X_NDR_DATA(privilege_mask, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_DATA(rights_mask, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(8, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

void security_token::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(sids, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(privilege_mask, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(rights_mask, __ndr, __flags, X_NDR_SWITCH_NONE);
	(__ndr) << leave;
}



x_ndr_off_t security_unix_token::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_HEADER_ALIGN(8, __ndr, __bpos, __epos, __flags);
	x_ndr_off_t __base = __bpos; (void)__base;
	x_ndr_off_t __ptr; (void)__ptr;
	X_NDR_DATA(uid, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_DATA(gid, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_DATA(uint32(get_size(groups)), __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_DATA(groups, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(8, __ndr, __bpos, __epos, __flags);
	return __bpos;
}


x_ndr_off_t security_unix_token::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_HEADER_ALIGN(8, __ndr, __bpos, __epos, __flags);
	x_ndr_off_t __base = __bpos; (void)__base;
	x_ndr_off_t __ptr; (void)__ptr;
	X_NDR_DATA(uid, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_DATA(gid, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	uint32 ngroups;
	X_NDR_DATA(ngroups, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_DATA(groups, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE, ngroups);
	X_NDR_TRAILER_ALIGN(8, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

void security_unix_token::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(uid, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(gid, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(groups, __ndr, __flags, X_NDR_SWITCH_NONE);
	(__ndr) << leave;
}


const std::array<std::pair<uint32, const char *>, 12> x_ndr_traits_t<security_secinfo>::value_name_map = { {
		{ SECINFO_OWNER, "SECINFO_OWNER" },
		{ SECINFO_GROUP, "SECINFO_GROUP" },
		{ SECINFO_DACL, "SECINFO_DACL" },
		{ SECINFO_SACL, "SECINFO_SACL" },
		{ SECINFO_LABEL, "SECINFO_LABEL" },
		{ SECINFO_ATTRIBUTE, "SECINFO_ATTRIBUTE" },
		{ SECINFO_SCOPE, "SECINFO_SCOPE" },
		{ SECINFO_BACKUP, "SECINFO_BACKUP" },
		{ SECINFO_UNPROTECTED_SACL, "SECINFO_UNPROTECTED_SACL" },
		{ SECINFO_UNPROTECTED_DACL, "SECINFO_UNPROTECTED_DACL" },
		{ SECINFO_PROTECTED_SACL, "SECINFO_PROTECTED_SACL" },
		{ SECINFO_PROTECTED_DACL, "SECINFO_PROTECTED_DACL" },
} };
#endif
x_ndr_off_t LSAP_TOKEN_INFO_INTEGRITY::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_PRINT_ARRAY_HEX);
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(Flags, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(TokenIL, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(MachineId, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	return __bpos;
}


x_ndr_off_t LSAP_TOKEN_INFO_INTEGRITY::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_PRINT_ARRAY_HEX);
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(Flags, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(TokenIL, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(MachineId, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

void LSAP_TOKEN_INFO_INTEGRITY::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_PRINT_ARRAY_HEX);
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(Flags, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(TokenIL, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(MachineId, __ndr, __flags, X_NDR_SWITCH_NONE);
	(__ndr) << leave;
}

#if 0
const std::array<std::pair<uint32, const char *>, 9> x_ndr_traits_t<kerb_EncTypes>::value_name_map = { {
		{ KERB_ENCTYPE_DES_CBC_CRC, "KERB_ENCTYPE_DES_CBC_CRC" },
		{ KERB_ENCTYPE_DES_CBC_MD5, "KERB_ENCTYPE_DES_CBC_MD5" },
		{ KERB_ENCTYPE_RC4_HMAC_MD5, "KERB_ENCTYPE_RC4_HMAC_MD5" },
		{ KERB_ENCTYPE_AES128_CTS_HMAC_SHA1_96, "KERB_ENCTYPE_AES128_CTS_HMAC_SHA1_96" },
		{ KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96, "KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96" },
		{ KERB_ENCTYPE_FAST_SUPPORTED, "KERB_ENCTYPE_FAST_SUPPORTED" },
		{ KERB_ENCTYPE_COMPOUND_IDENTITY_SUPPORTED, "KERB_ENCTYPE_COMPOUND_IDENTITY_SUPPORTED" },
		{ KERB_ENCTYPE_CLAIMS_SUPPORTED, "KERB_ENCTYPE_CLAIMS_SUPPORTED" },
		{ KERB_ENCTYPE_RESOURCE_SID_COMPRESSION_DISABLED, "KERB_ENCTYPE_RESOURCE_SID_COMPRESSION_DISABLED" },
} };
const std::array<std::pair<uint32, const char *>, 5> x_ndr_traits_t<security_autoinherit>::value_name_map = { {
		{ SEC_DACL_AUTO_INHERIT, "SEC_DACL_AUTO_INHERIT" },
		{ SEC_SACL_AUTO_INHERIT, "SEC_SACL_AUTO_INHERIT" },
		{ SEC_DEFAULT_DESCRIPTOR, "SEC_DEFAULT_DESCRIPTOR" },
		{ SEC_OWNER_FROM_PARENT, "SEC_OWNER_FROM_PARENT" },
		{ SEC_GROUP_FROM_PARENT, "SEC_GROUP_FROM_PARENT" },
} };

x_ndr_off_t generic_mapping::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	x_ndr_off_t __base = __bpos; (void)__base;
	x_ndr_off_t __ptr; (void)__ptr;
	X_NDR_DATA(generic_read, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_DATA(generic_write, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_DATA(generic_execute, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_DATA(generic_all, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	return __bpos;
}


x_ndr_off_t generic_mapping::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	x_ndr_off_t __base = __bpos; (void)__base;
	x_ndr_off_t __ptr; (void)__ptr;
	X_NDR_DATA(generic_read, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_DATA(generic_write, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_DATA(generic_execute, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_DATA(generic_all, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

void generic_mapping::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(generic_read, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(generic_write, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(generic_execute, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(generic_all, __ndr, __flags, X_NDR_SWITCH_NONE);
	(__ndr) << leave;
}



x_ndr_off_t standard_mapping::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	x_ndr_off_t __base = __bpos; (void)__base;
	x_ndr_off_t __ptr; (void)__ptr;
	X_NDR_DATA(std_read, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_DATA(std_write, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_DATA(std_execute, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_DATA(std_all, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	return __bpos;
}


x_ndr_off_t standard_mapping::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	x_ndr_off_t __base = __bpos; (void)__base;
	x_ndr_off_t __ptr; (void)__ptr;
	X_NDR_DATA(std_read, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_DATA(std_write, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_DATA(std_execute, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_DATA(std_all, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

void standard_mapping::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(std_read, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(std_write, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(std_execute, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(std_all, __ndr, __flags, X_NDR_SWITCH_NONE);
	(__ndr) << leave;
}
#endif

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
void x_ndr_ostr<dom_sid>(const dom_sid &v, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	ndr.os << v;
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


} /* namespace idl */

