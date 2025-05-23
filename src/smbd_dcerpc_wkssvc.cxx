
#include "smbd_dcerpc.hxx"
#include "include/librpc/wkssvc.hxx"
#include "smbd_conf.hxx"

template <class T>
static void __wkssvc_NetWkstaGetInfo(std::shared_ptr<T> &info)
{
	X_ASSERT(!info);
	const x_smbd_conf_t &smbd_conf = x_smbd_conf_get_curr();

	info = std::make_shared<T>();
	info->platform_id = idl::PLATFORM_ID_NT;
	info->version_major = std::get<0>(smbd_conf.my_nbt_version);
	info->version_minor = std::get<1>(smbd_conf.my_nbt_version);
	info->server_name = smbd_conf.netbios_name_u16;
	info->domain_name = smbd_conf.workgroup_u16;
}

static idl::dcerpc_nca_status x_smbd_dcerpc_impl_wkssvc_NetWkstaGetInfo(
		x_dcerpc_pipe_t &rpc_pipe,
		const std::shared_ptr<x_smbd_user_t> &smbd_user,
		idl::wkssvc_NetWkstaGetInfo &arg)
{
	switch (arg.level) {
	case 100:
		__wkssvc_NetWkstaGetInfo(arg.info.info100);
		arg.__result = WERR_OK;
		break;

	case 101:
		__wkssvc_NetWkstaGetInfo(arg.info.info101);
		arg.__result = WERR_OK;
		break;

	case 102:
		X_SMBD_DCERPC_CHECK_ADMIN_ACCESS(smbd_user, arg);

		__wkssvc_NetWkstaGetInfo(arg.info.info102);
		/* TODO does a user logon multiple time count 1 or multi? */
		arg.info.info102->logged_on_users = x_smbd_sess_get_count();
		arg.__result = WERR_OK;
		break;

	default:
		arg.__result = WERR_INVALID_LEVEL;
	}
	return X_SMBD_DCERPC_NCA_STATUS_OK;
}


X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(wkssvc_NetWkstaSetInfo)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(wkssvc_NetWkstaEnumUsers)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(wkssvc_NetrWkstaUserGetInfo)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(wkssvc_NetrWkstaUserSetInfo)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(wkssvc_NetWkstaTransportEnum)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(wkssvc_NetrWkstaTransportAdd)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(wkssvc_NetrWkstaTransportDel)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(wkssvc_NetrUseAdd)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(wkssvc_NetrUseGetInfo)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(wkssvc_NetrUseDel)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(wkssvc_NetrUseEnum)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(wkssvc_NetrMessageBufferSend)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(wkssvc_NetrWorkstationStatisticsGet)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(wkssvc_NetrLogonDomainNameAdd)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(wkssvc_NetrLogonDomainNameDel)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(wkssvc_NetrJoinDomain)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(wkssvc_NetrUnjoinDomain)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(wkssvc_NetrRenameMachineInDomain)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(wkssvc_NetrValidateName)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(wkssvc_NetrGetJoinInformation)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(wkssvc_NetrGetJoinableOus)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(wkssvc_NetrJoinDomain2)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(wkssvc_NetrUnjoinDomain2)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(wkssvc_NetrRenameMachineInDomain2)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(wkssvc_NetrValidateName2)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(wkssvc_NetrGetJoinableOus2)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(wkssvc_NetrAddAlternateComputerName)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(wkssvc_NetrRemoveAlternateComputerName)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(wkssvc_NetrSetPrimaryComputername)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(wkssvc_NetrEnumerateComputerNames)


#define X_DCERPC_FUNCTION_DEF(x) X_SMBD_DCERPC_FUNCTION(x)
X_DCERPC_FUNCTION_ENUM_wkssvc
#undef X_DCERPC_FUNCTION_DEF

static const x_dcerpc_rpc_fn_t wkssvc_fns[] = {
#define X_DCERPC_FUNCTION_DEF(x) x_smbd_dcerpc_fn_##x,
X_DCERPC_FUNCTION_ENUM_wkssvc
#undef X_DCERPC_FUNCTION_DEF
};

const x_dcerpc_iface_t x_smbd_dcerpc_wkssvc = {
	{ idl::wkssvc_uuid, idl::wkssvc_version },
	X_ARRAY_SIZE(wkssvc_fns),
	wkssvc_fns,
};


