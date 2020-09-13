
#ifndef __srvsvc__idl__hxx__
#define __srvsvc__idl__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/librpc/ndr_smb.hxx"

#include "include/librpc/misc.hxx"

namespace idl {

struct srvsvc_NetShareInfo0
{
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	x_ndr_off_t ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	std::shared_ptr<std::u16string> name;
};

template <> struct x_ndr_traits_t<srvsvc_NetShareInfo0> {
	using has_buffers = std::true_type;
	using ndr_type = x_ndr_type_struct;
};


struct srvsvc_NetShareCtr0
{
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	x_ndr_off_t ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	shared_vector<srvsvc_NetShareInfo0> array;
};

template <> struct x_ndr_traits_t<srvsvc_NetShareCtr0> {
	using has_buffers = std::true_type;
	using ndr_type = x_ndr_type_struct;
};


#define STYPE_TEMPORARY ( 0x40000000 )
#define STYPE_HIDDEN    ( 0x80000000 )
enum srvsvc_ShareType : uint32 {
	STYPE_DISKTREE = 0,
	STYPE_DISKTREE_TEMPORARY = STYPE_DISKTREE|STYPE_TEMPORARY,
	STYPE_DISKTREE_HIDDEN    = STYPE_DISKTREE|STYPE_HIDDEN,
	STYPE_PRINTQ   = 1,
	STYPE_PRINTQ_TEMPORARY = STYPE_PRINTQ|STYPE_TEMPORARY,
	STYPE_PRINTQ_HIDDEN    = STYPE_PRINTQ|STYPE_HIDDEN,
	STYPE_DEVICE   = 2,	/* Serial device */
	STYPE_DEVICE_TEMPORARY = STYPE_DEVICE|STYPE_TEMPORARY,
	STYPE_DEVICE_HIDDEN    = STYPE_DEVICE|STYPE_HIDDEN,
	STYPE_IPC      = 3,	/* Interprocess communication (IPC) */
	STYPE_IPC_TEMPORARY = STYPE_IPC|STYPE_TEMPORARY,
	STYPE_IPC_HIDDEN    = STYPE_IPC|STYPE_HIDDEN,
	STYPE_CLUSTER_FS		= 0x02000000,	/* A cluster share */
	STYPE_CLUSTER_FS_TEMPORARY	= STYPE_CLUSTER_FS|STYPE_TEMPORARY,
	STYPE_CLUSTER_FS_HIDDEN		= STYPE_CLUSTER_FS|STYPE_HIDDEN,
	STYPE_CLUSTER_SOFS		= 0x04000000,	/* A Scale-Out cluster share */
	STYPE_CLUSTER_SOFS_TEMPORARY	= STYPE_CLUSTER_SOFS|STYPE_TEMPORARY,
	STYPE_CLUSTER_SOFS_HIDDEN	= STYPE_CLUSTER_SOFS|STYPE_HIDDEN,
	STYPE_CLUSTER_DFS		= 0x08000000,	/* A DFS share in a cluster */
	STYPE_CLUSTER_DFS_TEMPORARY	= STYPE_CLUSTER_DFS|STYPE_TEMPORARY,
	STYPE_CLUSTER_DFS_HIDDEN	= STYPE_CLUSTER_DFS|STYPE_HIDDEN
}/* [v1_enum, public] */;

template <> struct x_ndr_traits_t<srvsvc_ShareType> {
	using has_buffers = std::false_type;
	using ndr_type = x_ndr_type_enum;
	using ndr_base_type = uint32;
	static const std::array<std::pair<uint32, const char *>, 21> value_name_map;
};

template <> inline x_ndr_off_t x_ndr_scalars<srvsvc_ShareType>(const srvsvc_ShareType &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	return x_ndr_push_uint32(__val, __ndr, __bpos, __epos, __flags);
}

template <> inline x_ndr_off_t x_ndr_scalars<srvsvc_ShareType>(srvsvc_ShareType &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	uint32_t v;
	X_NDR_SCALARS(v, __ndr, __bpos, __epos, __flags, __level);
	__val = srvsvc_ShareType(v);
	return __bpos;
}


struct srvsvc_NetShareInfo1
{
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	x_ndr_off_t ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	std::shared_ptr<std::u16string> name;
	srvsvc_ShareType type;
	std::shared_ptr<std::u16string> comment;
};

template <> struct x_ndr_traits_t<srvsvc_NetShareInfo1> {
	using has_buffers = std::true_type;
	using ndr_type = x_ndr_type_struct;
};


struct srvsvc_NetShareCtr1
{
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	x_ndr_off_t ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	shared_vector<srvsvc_NetShareInfo1> array;
};

template <> struct x_ndr_traits_t<srvsvc_NetShareCtr1> {
	using has_buffers = std::true_type;
	using ndr_type = x_ndr_type_struct;
};


union srvsvc_NetShareCtr
{
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	x_ndr_off_t ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
	srvsvc_NetShareCtr() { }
	~srvsvc_NetShareCtr() { }
	void __init(x_ndr_switch_t __level);
	void __init(x_ndr_switch_t __level, const srvsvc_NetShareCtr &__other);
	void __uninit(x_ndr_switch_t __level);

	std::shared_ptr<srvsvc_NetShareCtr0> ctr0;
	std::shared_ptr<srvsvc_NetShareCtr1> ctr1;
#if 0
	std::shared_ptr<srvsvc_NetShareCtr2> ctr2;
	std::shared_ptr<srvsvc_NetShareCtr501> ctr501;
	std::shared_ptr<srvsvc_NetShareCtr502> ctr502;
	std::shared_ptr<srvsvc_NetShareCtr1004> ctr1004;
	std::shared_ptr<srvsvc_NetShareCtr1005> ctr1005;
	std::shared_ptr<srvsvc_NetShareCtr1006> ctr1006;
	std::shared_ptr<srvsvc_NetShareCtr1007> ctr1007;
	std::shared_ptr<srvsvc_NetShareCtr1501> ctr1501;
#endif
#if 0
	PAC_INFO(x_ndr_switch_t __level) { __init(__level); }
	~PAC_INFO() { }
	void __init(x_ndr_switch_t __level);
	void __init(x_ndr_switch_t __level, const PAC_INFO &__other);
	void __uninit(x_ndr_switch_t __level);
	PAC_LOGON_INFO_CTR logon_info;/* [subcontext(0xFFFFFC01), case(PAC_TYPE_LOGON_INFO)] */
	// x_ndr_subndr_t<PAC_LOGON_INFO_CTR> logon_info;/* [subcontext(0xFFFFFC01), case(PAC_TYPE_LOGON_INFO)] */
	PAC_SIGNATURE_DATA srv_cksum;/* [case(PAC_TYPE_SRV_CHECKSUM)] */
	PAC_SIGNATURE_DATA kdc_cksum;/* [case(PAC_TYPE_KDC_CHECKSUM)] */
	PAC_LOGON_NAME logon_name;/* [case(PAC_TYPE_LOGON_NAME)] */
	PAC_CONSTRAINED_DELEGATION_CTR constrained_delegation;/* [subcontext(0xFFFFFC01), case(PAC_TYPE_CONSTRAINED_DELEGATION)] */
	// x_ndr_subndr_t<PAC_CONSTRAINED_DELEGATION_CTR> constrained_delegation;/* [subcontext(0xFFFFFC01), case(PAC_TYPE_CONSTRAINED_DELEGATION)] */
	DATA_BLOB_REM unknown;/* [subcontext(0), default] */
#endif
} /* [gensize, nodiscriminant, public] */;

template <> struct x_ndr_traits_t<srvsvc_NetShareCtr> {
	using has_buffers = std::false_type;
	using ndr_type = x_ndr_type_union;
};
#if 0
struct srvsvc_NetShareInfoCtr
{
	x_ndr_off_t ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	x_ndr_off_t ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;

	uint32 level;
	srvsvc_NetShareCtr ctr; /* [switch_is(level)] */
};

template <> struct x_ndr_traits_t<srvsvc_NetShareInfoCtr> {
	using has_buffers = std::true_type;
	using ndr_type = x_ndr_type_struct;
};
#endif
struct srvsvc_NetShareEnumAll
{
	~srvsvc_NetShareEnumAll() {
		ctr.__uninit(level);
	}
	x_ndr_off_t ndr_requ(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags);
	x_ndr_off_t ndr_resp(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags) const;

	std::shared_ptr<std::u16string> server_unc;
	uint32_t max_buffer;
	uint32 level{X_NDR_SWITCH_NONE};
	srvsvc_NetShareCtr ctr; /* [switch_is(level)] */
	// std::shared_ptr<srvsvc_NetShareInfoCtr> info_ctr;
	std::shared_ptr<uint32_t> resume_handle;
	uint32 totalentries;
};

};


#endif /* __srvsvc__idl__hxx__ */

