
#include "include/librpc/ndr_netlogon.hxx"

namespace idl {

const std::array<std::pair<uint32, const char *>, 11> x_ndr_traits_t<netr_UserFlags>::value_name_map = { {
		{ NETLOGON_GUEST, "NETLOGON_GUEST" },
		{ NETLOGON_NOENCRYPTION, "NETLOGON_NOENCRYPTION" },
		{ NETLOGON_CACHED_ACCOUNT, "NETLOGON_CACHED_ACCOUNT" },
		{ NETLOGON_USED_LM_PASSWORD, "NETLOGON_USED_LM_PASSWORD" },
		{ NETLOGON_EXTRA_SIDS, "NETLOGON_EXTRA_SIDS" },
		{ NETLOGON_SUBAUTH_SESSION_KEY, "NETLOGON_SUBAUTH_SESSION_KEY" },
		{ NETLOGON_SERVER_TRUST_ACCOUNT, "NETLOGON_SERVER_TRUST_ACCOUNT" },
		{ NETLOGON_NTLMV2_ENABLED, "NETLOGON_NTLMV2_ENABLED" },
		{ NETLOGON_RESOURCE_GROUPS, "NETLOGON_RESOURCE_GROUPS" },
		{ NETLOGON_PROFILE_PATH_RETURNED, "NETLOGON_PROFILE_PATH_RETURNED" },
		{ NETLOGON_GRACE_LOGON, "NETLOGON_GRACE_LOGON" },
} };

x_ndr_off_t netr_SidAttr::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(sid, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(attributes, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t netr_SidAttr::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(sid, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(attributes, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t netr_SidAttr::ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_BUFFERS(sid, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}

x_ndr_off_t netr_SidAttr::ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_BUFFERS(sid, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}

void netr_SidAttr::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(sid, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(attributes, __ndr, __flags, X_NDR_SWITCH_NONE);
	(__ndr) << leave;
}

x_ndr_off_t netr_SamBaseInfo::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(logon_time, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(logoff_time, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(kickoff_time, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(last_password_change, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(allow_password_change, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(force_password_change, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(account_name, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(full_name, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(logon_script, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(profile_path, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(home_directory, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(home_drive, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(logon_count, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(bad_password_count, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(rid, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(primary_gid, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(groups, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(user_flags, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(key, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(logon_server, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(logon_domain, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(domain_sid, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(LMSessKey, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(acct_flags, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(sub_auth_status, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(last_successful_logon, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(last_failed_logon, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(failed_logon_count, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(uint32_t{0}, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t netr_SamBaseInfo::ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(account_name, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(full_name, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(logon_script, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(profile_path, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(home_directory, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(home_drive, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(groups, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(logon_server, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(logon_domain, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(domain_sid, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}

x_ndr_off_t netr_SamBaseInfo::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(logon_time, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(logoff_time, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(kickoff_time, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(last_password_change, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(allow_password_change, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(force_password_change, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(account_name, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(full_name, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(logon_script, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(profile_path, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(home_directory, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(home_drive, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(logon_count, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(bad_password_count, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(rid, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(primary_gid, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(groups, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(user_flags, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(key, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(logon_server, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(logon_domain, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(domain_sid, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(LMSessKey, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(acct_flags, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(sub_auth_status, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(last_successful_logon, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(last_failed_logon, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(failed_logon_count, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SKIP(uint32_t, __ndr, __bpos, __epos, __flags);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t netr_SamBaseInfo::ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(account_name, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(full_name, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(logon_script, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(profile_path, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(home_directory, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(home_drive, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(groups, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(logon_server, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(logon_domain, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(domain_sid, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}

void netr_SamBaseInfo::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(logon_time, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(logoff_time, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(kickoff_time, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(last_password_change, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(allow_password_change, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(force_password_change, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(account_name, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(full_name, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(logon_script, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(profile_path, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(home_directory, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(home_drive, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(logon_count, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(bad_password_count, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(rid, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(primary_gid, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(groups, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(user_flags, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(key, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(logon_server, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(logon_domain, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(domain_sid, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(LMSessKey, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(acct_flags, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(sub_auth_status, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(last_successful_logon, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(last_failed_logon, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(failed_logon_count, __ndr, __flags, X_NDR_SWITCH_NONE);
	(__ndr) << leave;
}


x_ndr_off_t netr_SamInfo3::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(base, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(sids, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}


x_ndr_off_t netr_SamInfo3::ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(base, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(sids, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}

x_ndr_off_t netr_SamInfo3::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(base, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(sids, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}


x_ndr_off_t netr_SamInfo3::ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(base, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(sids, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}

void netr_SamInfo3::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(base, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(sids, __ndr, __flags, X_NDR_SWITCH_NONE);
	(__ndr) << leave;
}


#if 0
x_ndr_off_t x_ndr_ptr(netr_SamBaseInfo &val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_PTR(val.base, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_PTR(val.sids, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t x_ndr_ptr(netr_SamInfo3 &val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_PTR(val.base, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_PTR(val.sids, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}
#endif
}

