
#include "smbd_dcerpc.hxx"
#include "include/librpc/wkssvc.hxx"

static bool x_smbd_dcerpc_impl_wkssvc_NetWkstaGetInfo(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::wkssvc_NetWkstaGetInfo &arg)
{
	const std::shared_ptr<x_smbd_conf_t> smbd_conf = x_smbd_conf_get();

	switch (arg.level) {
	case 100: {
		auto &info = arg.info.info100;
		X_ASSERT(!info);
		info = std::make_shared<idl::wkssvc_NetWkstaInfo100>();
		info->platform_id = idl::PLATFORM_ID_NT;
		info->version_major = 0x06;
		info->version_minor = 0x01;
		info->server_name = std::make_shared<std::u16string>(x_convert_utf8_to_utf16(smbd_conf->netbios_name));
		info->domain_name = std::make_shared<std::u16string>(x_convert_utf8_to_utf16(smbd_conf->workgroup));
		arg.__result = WERR_OK;
		}
		break;

	default:
		X_TODO;
		arg.__result = WERR_INVALID_LEVEL;
	}
	return true;
}


X_SMBD_DCERPC_IMPL_TODO(wkssvc_NetWkstaSetInfo)
X_SMBD_DCERPC_IMPL_TODO(wkssvc_NetWkstaEnumUsers)
X_SMBD_DCERPC_IMPL_TODO(wkssvc_NetrWkstaUserGetInfo)
X_SMBD_DCERPC_IMPL_TODO(wkssvc_NetrWkstaUserSetInfo)
X_SMBD_DCERPC_IMPL_TODO(wkssvc_NetWkstaTransportEnum)
X_SMBD_DCERPC_IMPL_TODO(wkssvc_NetrWkstaTransportAdd)
X_SMBD_DCERPC_IMPL_TODO(wkssvc_NetrWkstaTransportDel)
X_SMBD_DCERPC_IMPL_TODO(wkssvc_NetrUseAdd)
X_SMBD_DCERPC_IMPL_TODO(wkssvc_NetrUseGetInfo)
X_SMBD_DCERPC_IMPL_TODO(wkssvc_NetrUseDel)
X_SMBD_DCERPC_IMPL_TODO(wkssvc_NetrUseEnum)
X_SMBD_DCERPC_IMPL_TODO(wkssvc_NetrMessageBufferSend)
X_SMBD_DCERPC_IMPL_TODO(wkssvc_NetrWorkstationStatisticsGet)
X_SMBD_DCERPC_IMPL_TODO(wkssvc_NetrLogonDomainNameAdd)
X_SMBD_DCERPC_IMPL_TODO(wkssvc_NetrLogonDomainNameDel)
X_SMBD_DCERPC_IMPL_TODO(wkssvc_NetrJoinDomain)
X_SMBD_DCERPC_IMPL_TODO(wkssvc_NetrUnjoinDomain)
X_SMBD_DCERPC_IMPL_TODO(wkssvc_NetrRenameMachineInDomain)
X_SMBD_DCERPC_IMPL_TODO(wkssvc_NetrValidateName)
X_SMBD_DCERPC_IMPL_TODO(wkssvc_NetrGetJoinInformation)
X_SMBD_DCERPC_IMPL_TODO(wkssvc_NetrGetJoinableOus)
X_SMBD_DCERPC_IMPL_TODO(wkssvc_NetrJoinDomain2)
X_SMBD_DCERPC_IMPL_TODO(wkssvc_NetrUnjoinDomain2)
X_SMBD_DCERPC_IMPL_TODO(wkssvc_NetrRenameMachineInDomain2)
X_SMBD_DCERPC_IMPL_TODO(wkssvc_NetrValidateName2)
X_SMBD_DCERPC_IMPL_TODO(wkssvc_NetrGetJoinableOus2)
X_SMBD_DCERPC_IMPL_TODO(wkssvc_NetrAddAlternateComputerName)
X_SMBD_DCERPC_IMPL_TODO(wkssvc_NetrRemoveAlternateComputerName)
X_SMBD_DCERPC_IMPL_TODO(wkssvc_NetrSetPrimaryComputername)
X_SMBD_DCERPC_IMPL_TODO(wkssvc_NetrEnumerateComputerNames)


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
	"wkssvc",
	X_ARRAY_SIZE(wkssvc_fns),
	wkssvc_fns,
};


