
#include "smbd_dcerpc.hxx"
#include "smbd_ntacl.hxx"
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
	const std::shared_ptr<x_smbd_conf_t> smbd_conf = x_smbd_conf_get();
	for (auto &it: smbd_conf->shares) {
		auto &share = it.second;
		idl::srvsvc_ShareType type =
			(share->type == TYPE_IPC ? idl::STYPE_IPC_HIDDEN : idl::STYPE_DISKTREE);
		ctr1->array->push_back(idl::srvsvc_NetShareInfo1{
				std::make_shared<std::u16string>(x_convert_utf8_to_utf16(share->name)),
				type,
				std::make_shared<std::u16string>()});
	};
	return ctr1->array->size();
}

static bool x_smbd_dcerpc_impl_srvsvc_NetShareEnumAll(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::srvsvc_NetShareEnumAll &arg)
{

	switch (arg.info_ctr.level) {
	case 1:
		arg.totalentries = net_share_enum_all_1(smbd_sess->smbd_conn,
				arg.info_ctr.ctr.ctr1);
		arg.__result = WERR_OK;
		break;

	default:
		X_TODO;
		arg.__result = WERR_INVALID_LEVEL;
		break;
	}
	return true;
}

static uint32_t get_share_current_users(const x_smbd_share_t &smbshare)
{
	return 1; // TODO
}

template <typename Info>
static void fill_share_info1(Info &info, const std::u16string &share_name,
		x_smbd_share_t &smbshare)
{
	info.name = std::make_shared<std::u16string>(share_name);
	info.comment = std::make_shared<std::u16string>();
	if (smbshare.type == TYPE_IPC) {
		info.type = idl::STYPE_IPC_HIDDEN;
	} else {
		info.type = idl::STYPE_DISKTREE;
	}
}

static uint32_t get_max_users(const x_smbd_share_t &smbshare)
{
	return smbshare.max_connections ? smbshare.max_connections : (uint32_t)-1;
}

template <typename Info>
static void fill_share_info2(Info &info, const std::u16string &share_name,
		x_smbd_share_t &smbshare)
{
	info.name = std::make_shared<std::u16string>(share_name);
	info.comment = std::make_shared<std::u16string>();
	info.permissions = 0;
	info.current_users = get_share_current_users(smbshare);
	if (smbshare.type == TYPE_IPC) {
		info.type = idl::STYPE_IPC_HIDDEN;
		info.path = std::make_shared<std::u16string>(u"C:/tmp");
	} else {
		info.type = idl::STYPE_DISKTREE;
		info.path = std::make_shared<std::u16string>(u"C:/" + share_name);
	}
	info.max_users = get_max_users(smbshare);
	info.password = std::make_shared<std::u16string>();
}

static bool x_smbd_dcerpc_impl_srvsvc_NetShareGetInfo(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::srvsvc_NetShareGetInfo &arg)
{
	std::string share_name = x_convert_utf16_to_utf8(arg.share_name);
	auto smbshare = x_smbd_find_share(share_name);
	if (!smbshare) {
		arg.__result = WERR_INVALID_NAME;
		return true;
	}

	switch (arg.level) {
	case 0: {
		auto &info0 = arg.info.info0;
		X_ASSERT(!info0);
		info0 = std::make_shared<idl::srvsvc_NetShareInfo0>();
		info0->name = std::make_shared<std::u16string>(arg.share_name);
		arg.__result = WERR_OK;
		}
		break;

	case 1: {
		auto &info1 = arg.info.info1;
		X_ASSERT(!info1);
		info1 = std::make_shared<idl::srvsvc_NetShareInfo1>();
		fill_share_info1(*info1, arg.share_name, *smbshare);
		arg.__result = WERR_OK;
		}
		break;

	case 2: {
		auto &info2 = arg.info.info2;
		X_ASSERT(!info2);
		info2 = std::make_shared<idl::srvsvc_NetShareInfo2>();
		fill_share_info2(*info2, arg.share_name, *smbshare);
		arg.__result = WERR_OK;
		}
		break;

	case 501: {
		auto &info501 = arg.info.info501;
		X_ASSERT(!info501);
		info501 = std::make_shared<idl::srvsvc_NetShareInfo501>();
		fill_share_info1(*info501, arg.share_name, *smbshare);
		info501->csc_policy = 0; // TODO
		arg.__result = WERR_OK;
		}
		break;

	case 502: {
		auto &info502 = arg.info.info502;
		X_ASSERT(!info502);
		info502 = std::make_shared<idl::srvsvc_NetShareInfo502>();
		fill_share_info2(*info502, arg.share_name, *smbshare);
		info502->sd_buf.sd = get_share_security(share_name);
		arg.__result = WERR_OK;
		}
		break;

	case 1004: {
		auto &info1004 = arg.info.info1004;
		X_ASSERT(!info1004);
		info1004 = std::make_shared<idl::srvsvc_NetShareInfo1004>();
		info1004->comment = std::make_shared<std::u16string>();
		arg.__result = WERR_OK;
		}
		break;

	case 1005: {
		auto &info1005 = arg.info.info1005;
		X_ASSERT(!info1005);
		info1005 = std::make_shared<idl::srvsvc_NetShareInfo1005>();
		info1005->dfs_flags = idl::NetShareInfo1005Flags(0); // TODO DFS
		arg.__result = WERR_OK;
		}
		break;

	case 1006: {
		auto &info1006 = arg.info.info1006;
		X_ASSERT(!info1006);
		info1006 = std::make_shared<idl::srvsvc_NetShareInfo1006>();
		info1006->max_users = get_max_users(*smbshare);
		arg.__result = WERR_OK;
		}
		break;

	case 1007: {
		auto &info1007 = arg.info.info1007;
		X_ASSERT(!info1007);
		info1007 = std::make_shared<idl::srvsvc_NetShareInfo1007>();
		info1007->flags = 0;
		info1007->alternate_directory_name = std::make_shared<std::u16string>();
		arg.__result = WERR_OK;
		}
		break;

	case 1501: {
		auto &info1501 = arg.info.info1501;
		X_ASSERT(!info1501);
		info1501 = std::make_shared<idl::sec_desc_buf>();
		info1501->sd = get_share_security(share_name);
		arg.__result = WERR_OK;
		}
		break;

	default:
		arg.__result = WERR_INVALID_LEVEL;
	}
	return true;
}

X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetShareSetInfo)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetShareDel)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetShareDelSticky)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetShareCheck)

static bool x_smbd_dcerpc_impl_srvsvc_NetSrvGetInfo(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::srvsvc_NetSrvGetInfo &arg)
{
	const std::shared_ptr<x_smbd_conf_t> smbd_conf = x_smbd_conf_get();

	switch (arg.level) {
	case 101: {
		auto &info = arg.info.info101;
		X_ASSERT(!info);
		info = std::make_shared<idl::srvsvc_NetSrvInfo101>();
		info->platform_id = idl::PLATFORM_ID_NT;
		info->server_name = std::make_shared<std::u16string>(x_convert_utf8_to_utf16(smbd_conf->netbios_name));
		info->version_major = 0x06;
		info->version_minor = 0x01;
		info->server_type = smbd_conf->get_default_server_announce();
		info->comment = std::make_shared<std::u16string>();
		arg.__result = WERR_OK;
		}
		break;

	default:
		X_TODO;
		arg.__result = WERR_INVALID_LEVEL;
	}
	return true;
}

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
	{ idl::srvsvc_uuid, idl::srvsvc_version },
	"srvsvc",
	X_ARRAY_SIZE(srvsvc_fns),
	srvsvc_fns,
};


