
#include "smbd_dcerpc.hxx"
#include "smbd_ntacl.hxx"
#include "include/librpc/srvsvc.hxx"
#include "smbd_conf.hxx"
#include "smbd_dcerpc_srvsvc.hxx"

#if 0
	TODO check permission
	if (!nt_token_check_sid(&global_sid_Builtin_Administrators,
				session_info->security_token)) {
		DEBUG(1, ("Enumerating sessions only allowed for "
					"administrators\n"));
		return WERR_ACCESS_DENIED;
	}
#endif
#define SMBD_DCERPC_SRVSVC_CHECK_ACCESS(smbd_sess) do { } while (0)

static inline idl::srvsvc_ShareType get_share_type(const x_smbd_share_t &smbd_share)
{
	return (smbd_share.get_type() == X_SMB2_SHARE_TYPE_DISK ?
			idl::STYPE_DISKTREE : idl::STYPE_IPC_HIDDEN);
}

static uint32_t get_max_users(const x_smbd_share_t &smbd_share)
{
	return smbd_share.max_connections ? smbd_share.max_connections : (uint32_t)-1;
}

static uint32_t get_share_current_users(const x_smbd_share_t &smbd_share)
{
	return 1; // TODO
}

template <class Info, class Data>
Info x_smbd_net_get_info(const Data &data);

template <>
idl::srvsvc_NetShareInfo0 x_smbd_net_get_info<idl::srvsvc_NetShareInfo0>(const x_smbd_share_t &share)
{
	return idl::srvsvc_NetShareInfo0{
		std::make_shared<std::u16string>(x_convert_utf8_to_utf16_assert(share.name)),
	};
}

template <>
idl::srvsvc_NetShareInfo1 x_smbd_net_get_info<idl::srvsvc_NetShareInfo1>(const x_smbd_share_t &share)
{
	return idl::srvsvc_NetShareInfo1{
		std::make_shared<std::u16string>(x_convert_utf8_to_utf16_assert(share.name)),
		get_share_type(share),
		std::make_shared<std::u16string>() // comment
	};
}

template <>
idl::srvsvc_NetShareInfo2 x_smbd_net_get_info<idl::srvsvc_NetShareInfo2>(const x_smbd_share_t &share)
{
	return idl::srvsvc_NetShareInfo2{
		std::make_shared<std::u16string>(x_convert_utf8_to_utf16_assert(share.name)),
		get_share_type(share),
		std::make_shared<std::u16string>(),
		0, // permission
		get_max_users(share),
		get_share_current_users(share),
		std::make_shared<std::u16string>(x_convert_utf8_to_utf16_assert("C:\\" + share.name)),
		std::make_shared<std::u16string>(), // password
	};
}

template <>
idl::srvsvc_NetShareInfo501 x_smbd_net_get_info<idl::srvsvc_NetShareInfo501>(const x_smbd_share_t &share)
{
	return idl::srvsvc_NetShareInfo501{
		std::make_shared<std::u16string>(x_convert_utf8_to_utf16_assert(share.name)),
		get_share_type(share),
		std::make_shared<std::u16string>(), // comment
		0
	};
}

template <>
idl::srvsvc_NetShareInfo502 x_smbd_net_get_info<idl::srvsvc_NetShareInfo502>(const x_smbd_share_t &share)
{
	return idl::srvsvc_NetShareInfo502{
		std::make_shared<std::u16string>(x_convert_utf8_to_utf16_assert(share.name)),
		get_share_type(share),
		std::make_shared<std::u16string>(),
		0, // permission
		get_max_users(share),
		get_share_current_users(share),
		std::make_shared<std::u16string>(x_convert_utf8_to_utf16_assert("C:\\" + share.name)),
		std::make_shared<std::u16string>(), // password
		{ get_share_security(share.name) },
	};
}

template <>
idl::srvsvc_NetShareInfo1004 x_smbd_net_get_info<idl::srvsvc_NetShareInfo1004>(const x_smbd_share_t &share)
{
	return idl::srvsvc_NetShareInfo1004{
		std::make_shared<std::u16string>(), // comment
	};
}

template <>
idl::srvsvc_NetShareInfo1005 x_smbd_net_get_info<idl::srvsvc_NetShareInfo1005>(const x_smbd_share_t &share)
{
	return idl::srvsvc_NetShareInfo1005{
		idl::NetShareInfo1005Flags(0), // TODO DFS
	};
}

template <>
idl::srvsvc_NetShareInfo1006 x_smbd_net_get_info<idl::srvsvc_NetShareInfo1006>(const x_smbd_share_t &share)
{
	return idl::srvsvc_NetShareInfo1006{
		get_max_users(share),
	};
}

template <>
idl::srvsvc_NetShareInfo1007 x_smbd_net_get_info<idl::srvsvc_NetShareInfo1007>(const x_smbd_share_t &share)
{
	return idl::srvsvc_NetShareInfo1007{
		0, // flags,
		std::make_shared<std::u16string>(), // alternate_directory_name
	};
}

template <>
idl::sec_desc_buf x_smbd_net_get_info<idl::sec_desc_buf>(const x_smbd_share_t &share)
{
	return idl::sec_desc_buf{
		get_share_security(share.name),
	};
}

template <class Arg>
static WERROR x_smbd_net_enum(Arg &arg,
		std::vector<idl::srvsvc_NetShareInfo0> &array)
{
	const std::shared_ptr<x_smbd_conf_t> smbd_conf = x_smbd_conf_get();
	for (auto &it: smbd_conf->shares) {
		array.push_back(x_smbd_net_get_info<idl::srvsvc_NetShareInfo0>(*it.second));
	}
	return WERR_OK;
}

template <class Arg>
static WERROR x_smbd_net_enum(Arg &arg,
		std::vector<idl::srvsvc_NetShareInfo1> &array)
{
	const std::shared_ptr<x_smbd_conf_t> smbd_conf = x_smbd_conf_get();
	for (auto &it: smbd_conf->shares) {
		array.push_back(x_smbd_net_get_info<idl::srvsvc_NetShareInfo1>(*it.second));
	}
	return WERR_OK;
}

template <class Arg>
static WERROR x_smbd_net_enum(Arg &arg,
		std::vector<idl::srvsvc_NetShareInfo2> &array)
{
	const std::shared_ptr<x_smbd_conf_t> smbd_conf = x_smbd_conf_get();
	for (auto &it: smbd_conf->shares) {
		array.push_back(x_smbd_net_get_info<idl::srvsvc_NetShareInfo2>(*it.second));
	}
	return WERR_OK;
}

template <class Arg>
static WERROR x_smbd_net_enum(Arg &arg,
		std::vector<idl::srvsvc_NetShareInfo501> &array)
{
	const std::shared_ptr<x_smbd_conf_t> smbd_conf = x_smbd_conf_get();
	for (auto &it: smbd_conf->shares) {
		array.push_back(x_smbd_net_get_info<idl::srvsvc_NetShareInfo501>(*it.second));
	}
	return WERR_OK;
}

template <class Arg>
static WERROR x_smbd_net_enum(Arg &arg,
		std::vector<idl::srvsvc_NetShareInfo502> &array)
{
	const std::shared_ptr<x_smbd_conf_t> smbd_conf = x_smbd_conf_get();
	for (auto &it: smbd_conf->shares) {
		array.push_back(x_smbd_net_get_info<idl::srvsvc_NetShareInfo502>(*it.second));
	}
	return WERR_OK;
}


template <class Arg, class Info>
static void net_enum(Arg &arg, std::shared_ptr<std::vector<Info>> &array)
{
	array = std::make_shared<std::vector<Info>>();
	arg.__result = x_smbd_net_enum(arg, *array);
	arg.totalentries = x_convert_assert<uint32_t>(array->size());
}

template <class Arg, class Info, class Data>
static void net_get_info(Arg &arg, std::shared_ptr<Info> &info, const Data &data)
{
	info = std::make_shared<Info>(x_smbd_net_get_info<Info>(data));
	arg.__result = WERR_OK;
}


X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NetCharDevEnum)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NetCharDevGetInfo)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NetCharDevControl)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NetCharDevQEnum)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NetCharDevQGetInfo)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NetCharDevQSetInfo)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NetCharDevQPurge)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NetCharDevQPurgeSelf)

static bool x_smbd_dcerpc_impl_srvsvc_NetConnEnum(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::srvsvc_NetConnEnum &arg)
{
	SMBD_DCERPC_SRVSVC_CHECK_ACCESS(smbd_sess);

	auto &ctr = arg.info_ctr.ctr;
	switch (arg.info_ctr.level) {
	case 0:
		net_enum(arg, ctr.ctr0->array);
		break;

	case 1:
		net_enum(arg, ctr.ctr1->array);
		break;

	default:
		arg.__result = WERR_INVALID_LEVEL;
		break;
	}

	return true;
}

static bool x_smbd_dcerpc_impl_srvsvc_NetFileEnum(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::srvsvc_NetFileEnum &arg)
{
	SMBD_DCERPC_SRVSVC_CHECK_ACCESS(smbd_sess);

	auto &ctr = arg.info_ctr.ctr;
	switch (arg.info_ctr.level) {
	case 2:
		net_enum(arg, ctr.ctr2->array);
		break;

	case 3:
		net_enum(arg, ctr.ctr3->array);
		break;

	default:
		arg.__result = WERR_INVALID_LEVEL;
		break;
	}

	return true;
}

X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NetFileGetInfo)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetFileClose)

static bool x_smbd_dcerpc_impl_srvsvc_NetSessEnum(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::srvsvc_NetSessEnum &arg)
{
	SMBD_DCERPC_SRVSVC_CHECK_ACCESS(smbd_sess);

	auto &ctr = arg.info_ctr.ctr;
	switch (arg.info_ctr.level) {
	case 0:
		net_enum(arg, ctr.ctr0->array);
		break;

	case 1:
		net_enum(arg, ctr.ctr1->array);
		break;

	case 2:
		net_enum(arg, ctr.ctr2->array);
		break;

	case 10:
		net_enum(arg, ctr.ctr10->array);
		break;

	case 502:
		net_enum(arg, ctr.ctr502->array);
		break;

	default:
		arg.__result = WERR_INVALID_LEVEL;
		break;
	}

	return true;
}

static bool x_smbd_dcerpc_impl_srvsvc_NetSessDel(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::srvsvc_NetSessDel &arg)
{
	SMBD_DCERPC_SRVSVC_CHECK_ACCESS(smbd_sess);

	x_smbd_net_sess_del(arg.user.get(), arg.client.get());

	arg.__result = WERR_OK;
	return true;
}

X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NetShareAdd)

static bool x_smbd_dcerpc_impl_srvsvc_NetShareEnumAll(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::srvsvc_NetShareEnumAll &arg)
{
	auto &ctr = arg.info_ctr.ctr;
	switch (arg.info_ctr.level) {
	case 0:
		net_enum(arg, ctr.ctr0->array);
		break;

	case 1:
		net_enum(arg, ctr.ctr1->array);
		break;

	case 2:
		net_enum(arg, ctr.ctr2->array);
		break;

	case 501:
		net_enum(arg, ctr.ctr501->array);
		break;

	case 502:
		net_enum(arg, ctr.ctr502->array);
		break;

	default:
		arg.__result = WERR_INVALID_LEVEL;
		break;
	}
	return true;
}

static bool x_smbd_dcerpc_impl_srvsvc_NetShareGetInfo(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::srvsvc_NetShareGetInfo &arg)
{
	std::string share_name = x_convert_utf16_to_utf8_safe(arg.share_name, x_tolower);
	std::string volume;
	auto smbd_share = x_smbd_find_share(share_name, volume);
	if (!smbd_share || !volume.empty()) {
		arg.__result = WERR_INVALID_NAME;
		return true;
	}

	switch (arg.level) {
	case 0:
		net_get_info(arg, arg.info.info0, *smbd_share);
		break;

	case 1:
		net_get_info(arg, arg.info.info1, *smbd_share);
		break;

	case 2:
		net_get_info(arg, arg.info.info2, *smbd_share);
		break;

	case 501:
		net_get_info(arg, arg.info.info501, *smbd_share);
		break;

	case 502:
		net_get_info(arg, arg.info.info502, *smbd_share);
		break;

	case 1004:
		net_get_info(arg, arg.info.info1004, *smbd_share);
		break;

	case 1005:
		net_get_info(arg, arg.info.info1005, *smbd_share);
		break;

	case 1006:
		net_get_info(arg, arg.info.info1006, *smbd_share);
		break;

	case 1007:
		net_get_info(arg, arg.info.info1007, *smbd_share);
		break;

	case 1501:
		net_get_info(arg, arg.info.info1501, *smbd_share);
		break;

	default:
		arg.__result = WERR_INVALID_LEVEL;
	}
	return true;
}

X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NetShareSetInfo)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NetShareDel)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NetShareDelSticky)

static bool x_smbd_dcerpc_impl_srvsvc_NetShareCheck(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::srvsvc_NetShareCheck &arg)
{
	if (arg.device_name.size() == 0 || x_strcase_equal(arg.device_name,
				u"C:\\IPC$")) {
		arg.type = idl::STYPE_IPC;
	} else {
		arg.type = idl::STYPE_DISKTREE;
	}

	arg.__result = WERR_OK;
	return true;
}

template <>
idl::srvsvc_NetSrvInfo100 x_smbd_net_get_info<idl::srvsvc_NetSrvInfo100>(
		const x_smbd_conf_t &smbd_conf)
{
	return idl::srvsvc_NetSrvInfo100{
		idl::PLATFORM_ID_NT,
		std::make_shared<std::u16string>(x_convert_utf8_to_utf16_assert(smbd_conf.netbios_name)),
	};
}

template <>
idl::srvsvc_NetSrvInfo101 x_smbd_net_get_info<idl::srvsvc_NetSrvInfo101>(
		const x_smbd_conf_t &smbd_conf)
{
	return idl::srvsvc_NetSrvInfo101{
		idl::PLATFORM_ID_NT,
		std::make_shared<std::u16string>(x_convert_utf8_to_utf16_assert(smbd_conf.netbios_name)),
		0x06, // version_major
		0x01, // version_minor
		smbd_conf.get_default_server_announce(),
		std::make_shared<std::u16string>(), // commnet
	};
}

template <>
idl::srvsvc_NetSrvInfo102 x_smbd_net_get_info<idl::srvsvc_NetSrvInfo102>(
		const x_smbd_conf_t &smbd_conf)
{
	return idl::srvsvc_NetSrvInfo102{
		idl::PLATFORM_ID_NT,
		std::make_shared<std::u16string>(x_convert_utf8_to_utf16_assert(smbd_conf.netbios_name)),
		0x06, // version_major
		0x01, // version_minor
		smbd_conf.get_default_server_announce(),
		std::make_shared<std::u16string>(), // commnet
		/* copy the values from samba _srvsvc_NetSrvGetInfo */
		0xffffffff, // users
		0xf, // disc
		0, // hidden
		240, // announce
		3000, // anndelta
		100000, // licenses
		std::make_shared<std::u16string>(u"C:\\"),
	};
}

static bool x_smbd_dcerpc_impl_srvsvc_NetSrvGetInfo(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::srvsvc_NetSrvGetInfo &arg)
{
	const std::shared_ptr<x_smbd_conf_t> smbd_conf = x_smbd_conf_get();

	switch (arg.level) {
	case 100:
		net_get_info(arg, arg.info.info100, *smbd_conf);
		break;

	case 101:
		net_get_info(arg, arg.info.info101, *smbd_conf);
		break;

	case 102:
		net_get_info(arg, arg.info.info102, *smbd_conf);
		break;

	default:
		arg.__result = WERR_INVALID_LEVEL;
	}
	return true;
}

X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NetSrvSetInfo)

static bool x_smbd_dcerpc_impl_srvsvc_NetDiskEnum(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::srvsvc_NetDiskEnum &arg)
{
	auto &array = arg.info.disks;
	array = std::make_shared<std::vector<idl::srvsvc_NetDiskInfo0>>();
	array->push_back(idl::srvsvc_NetDiskInfo0{
			u"C:",
		});
	array->push_back(idl::srvsvc_NetDiskInfo0{
			u"",
		});
	arg.totalentries = 1;
	arg.__result = WERR_OK;
	return true;
}

X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NetServerStatisticsGet)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NetTransportAdd)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NetTransportEnum)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NetTransportDel)

static bool x_smbd_dcerpc_impl_srvsvc_NetRemoteTOD(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::srvsvc_NetRemoteTOD &arg)
{
	const time_t unixdate = time(NULL);
	struct tm gtm, *pgtm;
	struct tm ltm, *pltm;

	pgtm = gmtime_r(&unixdate, &gtm);
	X_ASSERT(pgtm == &gtm);
	pltm = localtime_r(&unixdate, &ltm);
	X_ASSERT(pltm == &ltm);

	auto info = std::make_shared<idl::srvsvc_NetRemoteTODInfo>();
	info->elapsed = x_convert<uint32_t>(unixdate);
	info->msecs = 0;	// TODO
	info->hours = gtm.tm_hour;
	info->mins = gtm.tm_min;
	info->secs = gtm.tm_sec;
	info->hunds = 0;	// TODO
	info->timezone = -x_convert<int>(ltm.tm_gmtoff / 60);
	info->tinterval = 10000;
	info->day = gtm.tm_mday;
	info->month = gtm.tm_mon + 1;
	info->year = 1900 + gtm.tm_year;
	info->weekday = gtm.tm_wday;

	arg.info = std::move(info);
	arg.__result = WERR_OK;

	return true;
}

X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NetSetServiceBits)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NetPathType)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NetPathCanonicalize)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NetPathCompare)

/* Characters we disallow in sharenames. */
#define INVALID_SHARENAME_CHARS u"%<>*?|/\\+=;:\","

static bool x_smbd_dcerpc_impl_srvsvc_NetNameValidate(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::srvsvc_NetNameValidate &arg)
{
	switch (arg.name_type) {
	case 0x9:
		arg.__result = x_str_validate(arg.name, INVALID_SHARENAME_CHARS)
			? WERR_OK : WERR_INVALID_NAME;
		break;

	default:
		arg.__result = WERR_INVALID_LEVEL;
	}

	return true;
}

X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NETRPRNAMECANONICALIZE)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NetPRNameCompare)

static bool x_smbd_dcerpc_impl_srvsvc_NetShareEnum(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::srvsvc_NetShareEnum &arg)
{
	auto &ctr = arg.info_ctr.ctr;
	switch (arg.info_ctr.level) {
	case 0:
		net_enum(arg, ctr.ctr0->array);
		break;

	case 1:
		net_enum(arg, ctr.ctr1->array);
		break;

	case 2:
		net_enum(arg, ctr.ctr2->array);
		break;

	case 502:
		net_enum(arg, ctr.ctr502->array);
		break;

	default:
		arg.__result = WERR_INVALID_LEVEL;
		break;
	}
	return true;
}

X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NetShareDelStart)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NetShareDelCommit)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetGetFileSecurity)
X_SMBD_DCERPC_IMPL_TODO(srvsvc_NetSetFileSecurity)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NetServerTransportAddEx)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NetServerSetServiceBitsEx)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NETRDFSGETVERSION)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NETRDFSCREATELOCALPARTITION)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NETRDFSDELETELOCALPARTITION)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NETRDFSSETLOCALVOLUMESTATE)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NETRDFSSETSERVERINFO)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NETRDFSCREATEEXITPOINT)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NETRDFSDELETEEXITPOINT)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NETRDFSMODIFYPREFIX)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NETRDFSFIXLOCALVOLUME)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NETRDFSMANAGERREPORTSITEINFO)
X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(srvsvc_NETRSERVERTRANSPORTDELEX)


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
	X_ARRAY_SIZE(srvsvc_fns),
	srvsvc_fns,
};


