
#include "smbd_dcerpc.hxx"
#include "include/librpc/lsa.hxx"

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

static auto find_handle(x_dcerpc_pipe_t &rpc_pipe, const idl::policy_handle &handle)
{
	auto it = std::begin(rpc_pipe.handles);
	for ( ; it != std::end(rpc_pipe.handles); ++it) {
		if (it->wire_handle == handle) {
			break;
		}
	}
	return it;
}

static std::shared_ptr<void> get_handle_data(x_dcerpc_pipe_t &rpc_pipe, const idl::policy_handle &handle)
{
	for (auto it = std::begin(rpc_pipe.handles); it != std::end(rpc_pipe.handles); ++it) {
		if (it->wire_handle == handle) {
			return it->data;
		}
	}
	return nullptr;
}

static bool x_smbd_dcerpc_impl_lsa_Close(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::lsa_Close &arg)
{
	auto it = find_handle(rpc_pipe, arg.handle);
	if (it != std::end(rpc_pipe.handles)) {
		rpc_pipe.handles.erase(it);
		arg.__result = NT_STATUS_OK;
	} else {
		arg.__result = NT_STATUS_INVALID_HANDLE;
	}
	return true;
}

X_SMBD_DCERPC_IMPL_TODO(lsa_Delete)
X_SMBD_DCERPC_IMPL_TODO(lsa_EnumPrivs)
X_SMBD_DCERPC_IMPL_TODO(lsa_QuerySecurity)
X_SMBD_DCERPC_IMPL_TODO(lsa_SetSecObj)
X_SMBD_DCERPC_IMPL_TODO(lsa_ChangePassword)
X_SMBD_DCERPC_IMPL_TODO(lsa_OpenPolicy)

static bool x_smbd_dcerpc_impl_lsa_QueryInfoPolicy(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::lsa_QueryInfoPolicy &arg)
{
	auto handle_data = get_handle_data(rpc_pipe, arg.handle);
	if (!handle_data) {
		arg.__result = NT_STATUS_INVALID_HANDLE;
		return true;
	}

	auto lsa_info = std::static_pointer_cast<lsa_info_t>(handle_data);
	auto smbconf = smbd_sess->smbd_conn->get_conf();

	//uint32_t acc_required = 0;
	switch (arg.level) {
	case idl::LSA_POLICY_INFO_ACCOUNT_DOMAIN: {
		// check access has idl::LSA_POLICY_VIEW_LOCAL_INFORMATION
		auto info = std::make_shared<idl::lsa_PolicyInformation>();
		info->__init(arg.level);
		info->account_domain.name.string = std::make_shared<std::u16string>(x_convert_utf8_to_utf16(smbconf->netbios_name));
		info->account_domain.sid = std::make_shared<idl::dom_sid>(smbd_sess->smbd_user->domain_sid); // TODO we use user's domain_sid for now
		arg.info = info;
		arg.__result = NT_STATUS_OK;
						  }
		break;

#if 0
		case idl::LSA_POLICY_INFO_AUDIT_LOG:
		case idl::LSA_POLICY_INFO_AUDIT_EVENTS:
			acc_required = idl::LSA_POLICY_VIEW_AUDIT_INFORMATION;
			break;
		case idl::LSA_POLICY_INFO_DOMAIN:
			acc_required = idl::LSA_POLICY_VIEW_LOCAL_INFORMATION;
			break;
		case idl::LSA_POLICY_INFO_PD:
			acc_required = idl::LSA_POLICY_GET_PRIVATE_INFORMATION;
			break;
		case idl::LSA_POLICY_INFO_ACCOUNT_DOMAIN:
			acc_required = idl::LSA_POLICY_VIEW_LOCAL_INFORMATION;
			break;
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
			X_TODO;
			break;
	}
	return true;
}

X_SMBD_DCERPC_IMPL_TODO(lsa_SetInfoPolicy)
X_SMBD_DCERPC_IMPL_TODO(lsa_ClearAuditLog)
X_SMBD_DCERPC_IMPL_TODO(lsa_CreateAccount)
X_SMBD_DCERPC_IMPL_TODO(lsa_EnumAccounts)
X_SMBD_DCERPC_IMPL_TODO(lsa_CreateTrustedDomain)
X_SMBD_DCERPC_IMPL_TODO(lsa_EnumTrustDom)
X_SMBD_DCERPC_IMPL_TODO(lsa_LookupNames)
X_SMBD_DCERPC_IMPL_TODO(lsa_LookupSids)
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

#ifndef MAX_OPEN_POLS
#define MAX_OPEN_POLS 2048
#endif

static std::atomic<uint64_t> pol_hnd{0};
static std::atomic<uint64_t> pol_hnd_random{0}; // TODO samba use time(), and pid()

static bool x_smbd_dcerpc_impl_lsa_OpenPolicy2(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::lsa_OpenPolicy2 &arg)
{
	// _lsa_OpenPolicy2
	// TODO only allow LOCAL INFORMATION for now
	if ((arg.access_mask & ~(idl::LSA_POLICY_VIEW_LOCAL_INFORMATION)) != 0) {
		X_LOG_ERR("not supported access_mask 0x%x", arg.access_mask);
		arg.__result = NT_STATUS_ACCESS_DENIED;
		return true;
	}

	if (rpc_pipe.handles.size() >= MAX_OPEN_POLS) {
		// samba return NOT_FOUND for any error
		arg.__result = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		return true;
	}

	rpc_pipe.handles.resize(rpc_pipe.handles.size() + 1);
	auto &handle = rpc_pipe.handles.back();
	handle.wire_handle.handle_type = 0;
	*(uint64_t *)&handle.wire_handle.uuid = ++pol_hnd;
	*((uint64_t *)&handle.wire_handle.uuid + 1) = ++pol_hnd_random;
	auto info = std::make_shared<lsa_info_t>();
	info->type = LSA_HANDLE_POLICY_TYPE;
	info->access = arg.access_mask;
	handle.data = info;

	arg.handle = handle.wire_handle;
	arg.__result = NT_STATUS_OK;
	return true;
}

X_SMBD_DCERPC_IMPL_TODO(lsa_GetUserName)
X_SMBD_DCERPC_IMPL_TODO(lsa_QueryInfoPolicy2)
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
X_SMBD_DCERPC_IMPL_TODO(lsa_LookupSids2)
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
X_SMBD_DCERPC_IMPL_TODO(lsa_LookupSids3)
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
	"lsarpc",
	X_ARRAY_SIZE(lsarpc_fns),
	lsarpc_fns,
};


