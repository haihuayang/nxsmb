
#include "smbd_dcerpc.hxx"
#include "include/librpc/lsa.hxx"
#include "smbd_conf.hxx"
#include "smbd_secrets.hxx"
#include "smbd_ntacl.hxx"

enum lsa_handle_type_t {
	LSA_HANDLE_POLICY_TYPE = 1,
	LSA_HANDLE_ACCOUNT_TYPE = 2,
	LSA_HANDLE_TRUST_TYPE = 3,
	LSA_HANDLE_SECRET_TYPE = 4,
};

struct lsa_info_t
{
	lsa_handle_type_t type;
	uint32_t access;
};

static const generic_mapping_t lsa_policy_mapping = {
	idl::LSA_POLICY_READ,
	idl::LSA_POLICY_WRITE,
	idl::LSA_POLICY_EXECUTE,
	idl::LSA_POLICY_ALL_ACCESS
};

template <class Arg>
static idl::dcerpc_nca_status lsa_OpenPolicy2(
		x_dcerpc_pipe_t &rpc_pipe,
		const std::shared_ptr<x_smbd_user_t> &smbd_user,
		Arg &arg)
{
	// _lsa_OpenPolicy2
	// TODO only allow LOCAL INFORMATION for now

	uint32_t access_mask = se_rpc_map_maximal_access(
			*smbd_user, arg.access_mask);

	access_mask = se_map_generic(access_mask, lsa_policy_mapping);

#if 0
	TODO disable access check for now
	if ((access_mask & ~(idl::LSA_POLICY_VIEW_LOCAL_INFORMATION)) != 0) {
		X_LOG(SMB, ERR, "not supported access_mask 0x%x", arg.access_mask);
		arg.__result = NT_STATUS_ACCESS_DENIED;
		return true;
	}
#endif

	idl::policy_handle wire_handle;
	auto info = std::make_shared<lsa_info_t>();
	info->type = LSA_HANDLE_POLICY_TYPE;
	info->access = arg.access_mask;

	if (!x_smbd_dcerpc_create_handle(rpc_pipe, wire_handle,
				info)) {
		// samba return NOT_FOUND for any error
		arg.__result = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		return X_SMBD_DCERPC_NCA_STATUS_OK;
	}

	arg.handle = wire_handle;
	arg.__result = NT_STATUS_OK;
	return X_SMBD_DCERPC_NCA_STATUS_OK;
}


static idl::dcerpc_nca_status x_smbd_dcerpc_impl_lsa_Close(
		x_dcerpc_pipe_t &rpc_pipe,
		const std::shared_ptr<x_smbd_user_t> &smbd_user,
		idl::lsa_Close &arg)
{
	if (!x_smbd_dcerpc_close_handle(rpc_pipe, arg.handle)) {
		return idl::DCERPC_NCA_S_FAULT_CONTEXT_MISMATCH;
	}

	arg.__result = NT_STATUS_OK;
	return X_SMBD_DCERPC_NCA_STATUS_OK;
}

X_SMBD_DCERPC_IMPL_TODO(lsa_Delete)
X_SMBD_DCERPC_IMPL_TODO(lsa_EnumPrivs)
X_SMBD_DCERPC_IMPL_TODO(lsa_QuerySecurity)
X_SMBD_DCERPC_IMPL_TODO(lsa_SetSecObj)
X_SMBD_DCERPC_IMPL_TODO(lsa_ChangePassword)

static idl::dcerpc_nca_status x_smbd_dcerpc_impl_lsa_OpenPolicy(
		x_dcerpc_pipe_t &rpc_pipe,
		const std::shared_ptr<x_smbd_user_t> &smbd_user,
		idl::lsa_OpenPolicy &arg)
{
	return lsa_OpenPolicy2(rpc_pipe, smbd_user, arg);
}


/* _lsa_QueryInfoPolicy */
template <class Arg>
static inline idl::dcerpc_nca_status lsa_QueryInfoPolicy(
		x_dcerpc_pipe_t &rpc_pipe,
		const std::shared_ptr<x_smbd_user_t> &smbd_user,
		Arg &arg)
{
	auto [ found, data ] = x_smbd_dcerpc_find_handle(rpc_pipe, arg.handle);
	if (!found) {
		arg.__result = NT_STATUS_INVALID_HANDLE;
		return X_SMBD_DCERPC_NCA_STATUS_OK;
	}

	auto lsa_info = std::static_pointer_cast<lsa_info_t>(data);
	const x_smbd_conf_t &smbd_conf = x_smbd_conf_get_curr();

	//uint32_t acc_required = 0;
	switch (arg.level) {
#if 0
		case idl::LSA_POLICY_INFO_AUDIT_LOG:
		case idl::LSA_POLICY_INFO_AUDIT_EVENTS:
			acc_required = idl::LSA_POLICY_VIEW_AUDIT_INFORMATION;
			break;
#endif
	case idl::LSA_POLICY_INFO_DOMAIN: {
		// check access, acc_required = idl::LSA_POLICY_VIEW_LOCAL_INFORMATION;
		auto info = std::make_shared<idl::lsa_PolicyInformation>();
		info->__init(arg.level);
		info->domain.name.string = smbd_conf.workgroup_u16;
		info->domain.sid = std::make_shared<idl::dom_sid>(
				smbd_conf.secrets.domain_sid);
		arg.info = info;
		arg.__result = NT_STATUS_OK;
						  }
		break;
#if 0
		case idl::LSA_POLICY_INFO_PD:
			acc_required = idl::LSA_POLICY_GET_PRIVATE_INFORMATION;
			break;
#endif
	case idl::LSA_POLICY_INFO_ACCOUNT_DOMAIN: {
		// check access has idl::LSA_POLICY_VIEW_LOCAL_INFORMATION
		auto info = std::make_shared<idl::lsa_PolicyInformation>();
		info->__init(arg.level);
		info->account_domain.name.string = smbd_conf.netbios_name_u16;
		info->account_domain.sid = std::make_shared<idl::dom_sid>(
				smbd_conf.secrets.sid);
		arg.info = info;
		arg.__result = NT_STATUS_OK;
						  }
		break;
#if 0
		case idl::LSA_POLICY_INFO_ROLE:
		case idl::LSA_POLICY_INFO_REPLICA:
			acc_required = idl::LSA_POLICY_VIEW_LOCAL_INFORMATION;
			break;
		case idl::LSA_POLICY_INFO_QUOTA:
			acc_required = idl::LSA_POLICY_VIEW_LOCAL_INFORMATION;
			break;
		case idl::LSA_POLICY_INFO_MOD:
		case idl::LSA_POLICY_INFO_AUDIT_FULL_SET:
			/* according to MS-LSAD 3.1.4.4.3 */
			arg.__result = NT_STATUS_INVALID_PARAMETER;
			return true;
		case idl::LSA_POLICY_INFO_AUDIT_FULL_QUERY:
			acc_required = idl::LSA_POLICY_VIEW_AUDIT_INFORMATION;
			break;
		case idl::LSA_POLICY_INFO_DNS:
		case idl::LSA_POLICY_INFO_DNS_INT:
		case idl::LSA_POLICY_INFO_L_ACCOUNT_DOMAIN:
			acc_required = idl::LSA_POLICY_VIEW_LOCAL_INFORMATION;
			break;
#endif
	default:
		arg.__result = NT_STATUS_INVALID_INFO_CLASS;
		break;
	}
	return X_SMBD_DCERPC_NCA_STATUS_OK;
}

static idl::dcerpc_nca_status x_smbd_dcerpc_impl_lsa_QueryInfoPolicy(
		x_dcerpc_pipe_t &rpc_pipe,
		const std::shared_ptr<x_smbd_user_t> &smbd_user,
		idl::lsa_QueryInfoPolicy &arg)
{
	return lsa_QueryInfoPolicy(rpc_pipe, smbd_user, arg);
}

X_SMBD_DCERPC_IMPL_TODO(lsa_SetInfoPolicy)
X_SMBD_DCERPC_IMPL_TODO(lsa_ClearAuditLog)
X_SMBD_DCERPC_IMPL_TODO(lsa_CreateAccount)
X_SMBD_DCERPC_IMPL_TODO(lsa_EnumAccounts)
X_SMBD_DCERPC_IMPL_TODO(lsa_CreateTrustedDomain)
X_SMBD_DCERPC_IMPL_TODO(lsa_EnumTrustDom)
X_SMBD_DCERPC_IMPL_TODO(lsa_LookupNames)
X_SMBD_DCERPC_IMPL_NT_NOT_SUPPORTED(lsa_LookupSids)
X_SMBD_DCERPC_IMPL_TODO(lsa_CreateSecret)
X_SMBD_DCERPC_IMPL_TODO(lsa_OpenAccount)
X_SMBD_DCERPC_IMPL_TODO(lsa_EnumPrivsAccount)
X_SMBD_DCERPC_IMPL_TODO(lsa_AddPrivilegesToAccount)
X_SMBD_DCERPC_IMPL_TODO(lsa_RemovePrivilegesFromAccount)
X_SMBD_DCERPC_IMPL_TODO(lsa_GetQuotasForAccount)
X_SMBD_DCERPC_IMPL_TODO(lsa_SetQuotasForAccount)
X_SMBD_DCERPC_IMPL_TODO(lsa_GetSystemAccessAccount)
X_SMBD_DCERPC_IMPL_TODO(lsa_SetSystemAccessAccount)
X_SMBD_DCERPC_IMPL_TODO(lsa_OpenTrustedDomain)
X_SMBD_DCERPC_IMPL_TODO(lsa_QueryTrustedDomainInfo)
X_SMBD_DCERPC_IMPL_TODO(lsa_SetInformationTrustedDomain)
X_SMBD_DCERPC_IMPL_TODO(lsa_OpenSecret)
X_SMBD_DCERPC_IMPL_TODO(lsa_SetSecret)
X_SMBD_DCERPC_IMPL_TODO(lsa_QuerySecret)
X_SMBD_DCERPC_IMPL_TODO(lsa_LookupPrivValue)
X_SMBD_DCERPC_IMPL_TODO(lsa_LookupPrivName)
X_SMBD_DCERPC_IMPL_TODO(lsa_LookupPrivDisplayName)
X_SMBD_DCERPC_IMPL_TODO(lsa_DeleteObject)
X_SMBD_DCERPC_IMPL_TODO(lsa_EnumAccountsWithUserRight)
X_SMBD_DCERPC_IMPL_TODO(lsa_EnumAccountRights)
X_SMBD_DCERPC_IMPL_TODO(lsa_AddAccountRights)
X_SMBD_DCERPC_IMPL_TODO(lsa_RemoveAccountRights)
X_SMBD_DCERPC_IMPL_TODO(lsa_QueryTrustedDomainInfoBySid)
X_SMBD_DCERPC_IMPL_TODO(lsa_SetTrustedDomainInfo)
X_SMBD_DCERPC_IMPL_TODO(lsa_DeleteTrustedDomain)
X_SMBD_DCERPC_IMPL_TODO(lsa_StorePrivateData)
X_SMBD_DCERPC_IMPL_TODO(lsa_RetrievePrivateData)

static idl::dcerpc_nca_status x_smbd_dcerpc_impl_lsa_OpenPolicy2(
		x_dcerpc_pipe_t &rpc_pipe,
		const std::shared_ptr<x_smbd_user_t> &smbd_user,
		idl::lsa_OpenPolicy2 &arg)
{
	return lsa_OpenPolicy2(rpc_pipe, smbd_user, arg);
}

X_SMBD_DCERPC_IMPL_TODO(lsa_GetUserName)

static idl::dcerpc_nca_status x_smbd_dcerpc_impl_lsa_QueryInfoPolicy2(
		x_dcerpc_pipe_t &rpc_pipe,
		const std::shared_ptr<x_smbd_user_t> &smbd_user,
		idl::lsa_QueryInfoPolicy2 &arg)
{
	return lsa_QueryInfoPolicy(rpc_pipe, smbd_user, arg);
}

X_SMBD_DCERPC_IMPL_TODO(lsa_SetInfoPolicy2)
X_SMBD_DCERPC_IMPL_TODO(lsa_QueryTrustedDomainInfoByName)
X_SMBD_DCERPC_IMPL_TODO(lsa_SetTrustedDomainInfoByName)
X_SMBD_DCERPC_IMPL_TODO(lsa_EnumTrustedDomainsEx)
X_SMBD_DCERPC_IMPL_TODO(lsa_CreateTrustedDomainEx)
X_SMBD_DCERPC_IMPL_TODO(lsa_CloseTrustedDomainEx)
X_SMBD_DCERPC_IMPL_TODO(lsa_QueryDomainInformationPolicy)
X_SMBD_DCERPC_IMPL_TODO(lsa_SetDomainInformationPolicy)
X_SMBD_DCERPC_IMPL_TODO(lsa_OpenTrustedDomainByName)
X_SMBD_DCERPC_IMPL_TODO(lsa_TestCall)
X_SMBD_DCERPC_IMPL_NT_NOT_SUPPORTED(lsa_LookupSids2)
X_SMBD_DCERPC_IMPL_TODO(lsa_LookupNames2)
X_SMBD_DCERPC_IMPL_TODO(lsa_CreateTrustedDomainEx2)
X_SMBD_DCERPC_IMPL_TODO(lsa_CREDRWRITE)
X_SMBD_DCERPC_IMPL_TODO(lsa_CREDRREAD)
X_SMBD_DCERPC_IMPL_TODO(lsa_CREDRENUMERATE)
X_SMBD_DCERPC_IMPL_TODO(lsa_CREDRWRITEDOMAINCREDENTIALS)
X_SMBD_DCERPC_IMPL_TODO(lsa_CREDRREADDOMAINCREDENTIALS)
X_SMBD_DCERPC_IMPL_TODO(lsa_CREDRDELETE)
X_SMBD_DCERPC_IMPL_TODO(lsa_CREDRGETTARGETINFO)
X_SMBD_DCERPC_IMPL_TODO(lsa_CREDRPROFILELOADED)
X_SMBD_DCERPC_IMPL_TODO(lsa_LookupNames3)
X_SMBD_DCERPC_IMPL_TODO(lsa_CREDRGETSESSIONTYPES)
X_SMBD_DCERPC_IMPL_TODO(lsa_LSARREGISTERAUDITEVENT)
X_SMBD_DCERPC_IMPL_TODO(lsa_LSARGENAUDITEVENT)
X_SMBD_DCERPC_IMPL_TODO(lsa_LSARUNREGISTERAUDITEVENT)
X_SMBD_DCERPC_IMPL_TODO(lsa_lsaRQueryForestTrustInformation)
X_SMBD_DCERPC_IMPL_TODO(lsa_lsaRSetForestTrustInformation)
X_SMBD_DCERPC_IMPL_TODO(lsa_CREDRRENAME)
X_SMBD_DCERPC_IMPL_NT_NOT_SUPPORTED(lsa_LookupSids3)
X_SMBD_DCERPC_IMPL_TODO(lsa_LookupNames4)
X_SMBD_DCERPC_IMPL_TODO(lsa_LSAROPENPOLICYSCE)
X_SMBD_DCERPC_IMPL_TODO(lsa_LSARADTREGISTERSECURITYEVENTSOURCE)
X_SMBD_DCERPC_IMPL_TODO(lsa_LSARADTUNREGISTERSECURITYEVENTSOURCE)
X_SMBD_DCERPC_IMPL_TODO(lsa_LSARADTREPORTSECURITYEVENT)

#define X_DCERPC_FUNCTION_DEF(x) X_SMBD_DCERPC_FUNCTION(x)
X_DCERPC_FUNCTION_ENUM_lsarpc
#undef X_DCERPC_FUNCTION_DEF

static const x_dcerpc_rpc_fn_t lsarpc_fns[] = {
#define X_DCERPC_FUNCTION_DEF(x) x_smbd_dcerpc_fn_##x,
X_DCERPC_FUNCTION_ENUM_lsarpc
#undef X_DCERPC_FUNCTION_DEF
};

const x_dcerpc_iface_t x_smbd_dcerpc_lsarpc = {
	{ idl::lsarpc_uuid, idl::lsarpc_version },
	X_ARRAY_SIZE(lsarpc_fns),
	lsarpc_fns,
};


