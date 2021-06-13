
#include "smbd_dcerpc.hxx"
#include "include/librpc/srvsvc.hxx"

X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetCharDevEnum)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetCharDevGetInfo)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetCharDevControl)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetCharDevQEnum)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetCharDevQGetInfo)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetCharDevQSetInfo)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetCharDevQPurge)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetCharDevQPurgeSelf)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetConnEnum)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetFileEnum)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetFileGetInfo)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetFileClose)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetSessEnum)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetSessDel)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetShareAdd)

static uint32_t net_share_enum_all_1(x_smbd_conn_t *smbd_conn,
		std::shared_ptr<idl::srvsvc_NetShareCtr1> &ctr1)
{
	// TODO buffer size and resume handle
	ctr1->array = std::make_shared<std::vector<idl::srvsvc_NetShareInfo1>>();
	const std::shared_ptr<x_smbconf_t> smbconf = smbd_conn->get_smbconf();
	for (auto &it: smbconf->shares) {
		auto &share = it.second;
		idl::srvsvc_ShareType type =
			(share->type == TYPE_IPC ? idl::STYPE_IPC_HIDDEN : idl::STYPE_DISKTREE);
		idl::srvsvc_NetShareInfo1 info1{
			std::make_shared<std::u16string>(x_convert_utf8_to_utf16(share->name)),
			type,
			std::make_shared<std::u16string>(x_convert_utf8_to_utf16("no comment"))
		};

		ctr1->array->push_back(info1); /*
		ctr1->array->emplace_back(std::make_shared<std::u16string>(x_convert_utf8_to_utf16(share->name)),
			type,
			std::make_shared<std::u16string>(x_convert_utf8_to_utf16("no comment"))); */
	};
	return ctr1->array->size();
}

static bool x_smbd_dcerpc_impl_srvsvc_NetShareEnumAll(
		x_smbd_conn_t *smbd_conn,
		idl::srvsvc_NetShareEnumAll &arg)
{

	switch (arg.info_ctr.level) {
	case 1:
		arg.totalentries = net_share_enum_all_1(smbd_conn, arg.info_ctr.ctr.ctr1);
		arg.__result = WERR_OK;

	default:
		X_TODO;
		arg.__result = WERR_INVALID_LEVEL;
	}
	return true;
}

static bool x_smbd_dcerpc_impl_srvsvc_NetShareGetInfo(
		x_smbd_conn_t *smbd_conn,
		idl::srvsvc_NetShareGetInfo &arg)
{
	std::string share_name = x_convert_utf16_to_utf8(arg.share_name);
	auto smbshare = x_smbd_find_share(smbd_conn->smbd, share_name);
	if (!smbshare) {
		arg.__result = WERR_INVALID_NAME;
		return true;
	}

	switch (arg.level) {
	case 1: {
		auto &info1 = arg.info.info1;
		X_ASSERT(!info1);
		info1 = std::make_shared<idl::srvsvc_NetShareInfo1>();
		info1->name = std::make_shared<std::u16string>(arg.share_name);
		info1->type = (smbshare->type == TYPE_IPC) ? idl::STYPE_IPC_HIDDEN : idl::STYPE_DISKTREE;
		info1->comment = std::make_shared<std::u16string>();
		arg.__result = WERR_OK;
		}
		break;

	default:
		X_TODO;
		arg.__result = WERR_INVALID_LEVEL;
	}
	return true;
}

X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetShareSetInfo)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetShareDel)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetShareDelSticky)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetShareCheck)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetSrvGetInfo)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetSrvSetInfo)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetDiskEnum)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetServerStatisticsGet)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetTransportAdd)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetTransportEnum)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetTransportDel)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetRemoteTOD)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetSetServiceBits)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetPathType)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetPathCanonicalize)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetPathCompare)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetNameValidate)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NETRPRNAMECANONICALIZE)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetPRNameCompare)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetShareEnum)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetShareDelStart)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetShareDelCommit)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetGetFileSecurity)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetSetFileSecurity)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetServerTransportAddEx)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetServerSetServiceBitsEx)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NETRDFSGETVERSION)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NETRDFSCREATELOCALPARTITION)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NETRDFSDELETELOCALPARTITION)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NETRDFSSETLOCALVOLUMESTATE)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NETRDFSSETSERVERINFO)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NETRDFSCREATEEXITPOINT)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NETRDFSDELETEEXITPOINT)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NETRDFSMODIFYPREFIX)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NETRDFSFIXLOCALVOLUME)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NETRDFSMANAGERREPORTSITEINFO)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NETRSERVERTRANSPORTDELEX)


#define X_DCERPC_FUNCTION_DEF(x) X_SMBD_DCERPC_FUNCTION(x)
X_DCERPC_FUNCTION_ENUM_srvsvc
#undef X_DCERPC_FUNCTION_DEF

static const x_dcerpc_rpc_fn_t srvsvc_fns[] = {
#define X_DCERPC_FUNCTION_DEF(x) x_smbd_dcerpc_fn_##x,
X_DCERPC_FUNCTION_ENUM_srvsvc
#undef X_DCERPC_FUNCTION_DEF
};

const x_dcerpc_iface_t x_smbd_dcerpc_srvsvc = {
	{ NDR_SRVSVC_UUID, NDR_SRVSVC_VERSION },
	u"srvsvc",
	X_ARRAY_SIZE(srvsvc_fns),
	srvsvc_fns,
};


