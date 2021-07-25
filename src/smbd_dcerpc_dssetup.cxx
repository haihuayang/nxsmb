
#include "smbd_dcerpc.hxx"
#include "include/librpc/dssetup.hxx"

static bool x_smbd_dcerpc_impl_dssetup_DsRoleGetPrimaryDomainInformation(
		x_smbd_conn_t *smbd_conn,
		idl::dssetup_DsRoleGetPrimaryDomainInformation &arg)
{
	const std::shared_ptr<x_smbconf_t> smbconf = smbd_conn->get_smbconf();
	switch (arg.level) {
	case idl::DS_ROLE_BASIC_INFORMATION: {
		auto &info = arg.info;
		X_ASSERT(!info);
		info = std::make_shared<idl::dssetup_DsRoleInfo>();
		info->__init(arg.level);
		// fill_dsrole_dominfo_basic
		info->basic.role = idl::DS_ROLE_MEMBER_SERVER;
		info->basic.flags = idl::DS_ROLE_PRIMARY_DOMAIN_GUID_PRESENT;
		info->basic.domain = std::make_shared<std::u16string>(x_convert_utf8_to_utf16(smbconf->workgroup));
		info->basic.dns_domain = std::make_shared<std::u16string>(x_convert_utf8_to_utf16(smbconf->realm));
		info->basic.forest = info->basic.dns_domain;
		arg.__result = WERR_OK;
		break;
	}

	default:
		arg.__result = WERR_INVALID_LEVEL;
	}
	return true;
}

X_SMBD_DCERPC_IMPL_TODO(dssetup_DsRoleDnsNameToFlatName)
X_SMBD_DCERPC_IMPL_TODO(dssetup_DsRoleDcAsDc)
X_SMBD_DCERPC_IMPL_TODO(dssetup_DsRoleDcAsReplica)
X_SMBD_DCERPC_IMPL_TODO(dssetup_DsRoleDemoteDc)
X_SMBD_DCERPC_IMPL_TODO(dssetup_DsRoleGetDcOperationProgress)
X_SMBD_DCERPC_IMPL_TODO(dssetup_DsRoleGetDcOperationResults)
X_SMBD_DCERPC_IMPL_TODO(dssetup_DsRoleCancel)
X_SMBD_DCERPC_IMPL_TODO(dssetup_DsRoleServerSaveStateForUpgrade)
X_SMBD_DCERPC_IMPL_TODO(dssetup_DsRoleUpgradeDownlevelServer)
X_SMBD_DCERPC_IMPL_TODO(dssetup_DsRoleAbortDownlevelServerUpgrade)

#define X_DCERPC_FUNCTION_DEF(x) X_SMBD_DCERPC_FUNCTION(x)
X_DCERPC_FUNCTION_ENUM_dssetup
#undef X_DCERPC_FUNCTION_DEF

static const x_dcerpc_rpc_fn_t dssetup_fns[] = {
#define X_DCERPC_FUNCTION_DEF(x) x_smbd_dcerpc_fn_##x,
X_DCERPC_FUNCTION_ENUM_dssetup
#undef X_DCERPC_FUNCTION_DEF
};

const x_dcerpc_iface_t x_smbd_dcerpc_dssetup = {
	{ idl::dssetup_uuid, idl::dssetup_version },
	"dssetup",
	X_ARRAY_SIZE(dssetup_fns),
	dssetup_fns,
};

