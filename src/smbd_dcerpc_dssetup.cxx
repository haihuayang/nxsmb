
#include "smbd_dcerpc.hxx"
#include "include/librpc/dssetup.hxx"
#include "smbd_conf.hxx"
#include "smbd_secrets.hxx"

static std::shared_ptr<idl::dssetup_DsRoleInfo> &make_dssetup_DsRoleInfo(
		idl::dssetup_DsRoleGetPrimaryDomainInformation &arg)
{
	auto &info = arg.info;
	X_ASSERT(!info);
	info = std::make_shared<idl::dssetup_DsRoleInfo>();
	info->__init(arg.level);
	return info;
}

static idl::dcerpc_nca_status x_smbd_dcerpc_impl_dssetup_DsRoleGetPrimaryDomainInformation(
		x_dcerpc_pipe_t &rpc_pipe,
		const std::shared_ptr<x_smbd_user_t> &smbd_user,
		idl::dssetup_DsRoleGetPrimaryDomainInformation &arg)
{
	const x_smbd_conf_t &smbd_conf = x_smbd_conf_get_curr();

	switch (arg.level) {
	case idl::DS_ROLE_BASIC_INFORMATION: {
		auto &info = make_dssetup_DsRoleInfo(arg);
		// fill_dsrole_dominfo_basic
		info->basic.role = idl::DS_ROLE_MEMBER_SERVER;
		info->basic.flags = idl::DS_ROLE_PRIMARY_DOMAIN_GUID_PRESENT;
		info->basic.domain = smbd_conf.workgroup_u16;
		/* TODO should make dns_domain upper case */
		info->basic.dns_domain = smbd_conf.dns_domain_l16;
		info->basic.forest = info->basic.dns_domain;
		info->basic.domain_guid = smbd_conf.secrets.domain_guid;
		arg.__result = WERR_OK;
		break;
	}

	case idl::DS_ROLE_UPGRADE_STATUS: {
		auto &info = make_dssetup_DsRoleInfo(arg);
		/* TODO */
		info->upgrade.upgrading = idl::DS_ROLE_NOT_UPGRADING;
		info->upgrade.previous_role = idl::DS_ROLE_PREVIOUS_UNKNOWN;
		arg.__result = WERR_OK;
		break;
	}

	case idl::DS_ROLE_OP_STATUS: {
		auto &info = make_dssetup_DsRoleInfo(arg);
		/* TODO */
		info->opstatus.status = idl::DS_ROLE_OP_IDLE;
		arg.__result = WERR_OK;
		break;
	}

	default:
		arg.__result = WERR_INVALID_LEVEL;
	}
	return X_SMBD_DCERPC_NCA_STATUS_OK;
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
	X_ARRAY_SIZE(dssetup_fns),
	dssetup_fns,
};


