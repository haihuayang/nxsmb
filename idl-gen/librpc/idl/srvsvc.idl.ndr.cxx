
	
#include "include/librpc/srvsvc.hxx"
#include "include/librpc/ndr_smb.hxx"


namespace idl {

x_ndr_off_t srvsvc_NetShareInfo0::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS_UNIQUE_PTR(name, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t srvsvc_NetShareInfo0::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS_UNIQUE_PTR(name, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t srvsvc_NetShareInfo0::ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS_UNIQUE_SIZE_IS_LENGTH_IS__0(name, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}

x_ndr_off_t srvsvc_NetShareInfo0::ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS_UNIQUE_SIZE_IS_LENGTH_IS__0(name, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}

void srvsvc_NetShareInfo0::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(name, __ndr, __flags, X_NDR_SWITCH_NONE);
	(__ndr) << leave;
}


x_ndr_off_t srvsvc_NetShareCtr0::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_SAVE_POS(uint32, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS_UNIQUE_PTR(array, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t srvsvc_NetShareCtr0::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_SAVE_POS(uint32, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS_UNIQUE_PTR(array, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t srvsvc_NetShareCtr0::ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	x_ndr_off_t __pos_count = __ndr.load_pos();
	X_NDR_BUFFERS_UNIQUE_VECTOR(array, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE, uint32, __pos_count);
	return __bpos;
}

x_ndr_off_t srvsvc_NetShareCtr0::ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	x_ndr_off_t __pos_count = __ndr.load_pos();
	X_NDR_BUFFERS_UNIQUE_VECTOR(array, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE, uint32, __pos_count);
	return __bpos;
}

void srvsvc_NetShareCtr0::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(array, __ndr, __flags, X_NDR_SWITCH_NONE);
	(__ndr) << leave;
}


const std::array<std::pair<uint32, const char *>, 21> x_ndr_traits_t<srvsvc_ShareType>::value_name_map = { {
	{ STYPE_DISKTREE, "STYPE_DISKTREE" },
	{ STYPE_DISKTREE_TEMPORARY, "STYPE_DISKTREE_TEMPORARY" },
	{ STYPE_DISKTREE_HIDDEN, "STYPE_DISKTREE_HIDDEN" },
	{ STYPE_PRINTQ, "STYPE_PRINTQ" },
	{ STYPE_PRINTQ_TEMPORARY, "STYPE_PRINTQ_TEMPORARY" },
	{ STYPE_PRINTQ_HIDDEN, "STYPE_PRINTQ_HIDDEN" },
	{ STYPE_DEVICE, "STYPE_DEVICE" },
	{ STYPE_DEVICE_TEMPORARY, "STYPE_DEVICE_TEMPORARY" },
	{ STYPE_DEVICE_HIDDEN, "STYPE_DEVICE_HIDDEN" },
	{ STYPE_IPC, "STYPE_IPC" },
	{ STYPE_IPC_TEMPORARY, "STYPE_IPC_TEMPORARY" },
	{ STYPE_IPC_HIDDEN, "STYPE_IPC_HIDDEN" },
	{ STYPE_CLUSTER_FS, "STYPE_CLUSTER_FS" },
	{ STYPE_CLUSTER_FS_TEMPORARY, "STYPE_CLUSTER_FS_TEMPORARY" },
	{ STYPE_CLUSTER_FS_HIDDEN, "STYPE_CLUSTER_FS_HIDDEN" },
	{ STYPE_CLUSTER_SOFS, "STYPE_CLUSTER_SOFS" },
	{ STYPE_CLUSTER_SOFS_TEMPORARY, "STYPE_CLUSTER_SOFS_TEMPORARY" },
	{ STYPE_CLUSTER_SOFS_HIDDEN, "STYPE_CLUSTER_SOFS_HIDDEN" },
	{ STYPE_CLUSTER_DFS, "STYPE_CLUSTER_DFS" },
	{ STYPE_CLUSTER_DFS_TEMPORARY, "STYPE_CLUSTER_DFS_TEMPORARY" },
	{ STYPE_CLUSTER_DFS_HIDDEN, "STYPE_CLUSTER_DFS_HIDDEN" },
} };


x_ndr_off_t srvsvc_NetShareInfo1::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS_UNIQUE_PTR(name, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(type, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS_UNIQUE_PTR(comment, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t srvsvc_NetShareInfo1::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS_UNIQUE_PTR(name, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(type, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS_UNIQUE_PTR(comment, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t srvsvc_NetShareInfo1::ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS_UNIQUE_SIZE_IS_LENGTH_IS__0(name, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS_UNIQUE_SIZE_IS_LENGTH_IS__0(comment, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}

x_ndr_off_t srvsvc_NetShareInfo1::ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS_UNIQUE_SIZE_IS_LENGTH_IS__0(name, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS_UNIQUE_SIZE_IS_LENGTH_IS__0(comment, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}

void srvsvc_NetShareInfo1::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(name, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(type, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(comment, __ndr, __flags, X_NDR_SWITCH_NONE);
	(__ndr) << leave;
}


x_ndr_off_t srvsvc_NetShareCtr1::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_SAVE_POS(uint32, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS_UNIQUE_PTR(array, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t srvsvc_NetShareCtr1::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_SAVE_POS(uint32, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS_UNIQUE_PTR(array, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t srvsvc_NetShareCtr1::ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	x_ndr_off_t __pos_count = __ndr.load_pos();
	X_NDR_BUFFERS_UNIQUE_VECTOR(array, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE, uint32, __pos_count);
	return __bpos;
}

x_ndr_off_t srvsvc_NetShareCtr1::ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	x_ndr_off_t __pos_count = __ndr.load_pos();
	X_NDR_BUFFERS_UNIQUE_VECTOR(array, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE, uint32, __pos_count);
	return __bpos;
}

void srvsvc_NetShareCtr1::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(array, __ndr, __flags, X_NDR_SWITCH_NONE);
	(__ndr) << leave;
}


void srvsvc_NetShareCtr::__init(x_ndr_switch_t __level)
{
	switch (__level) {
		case 0: {
			ctr0 = std::make_shared<srvsvc_NetShareCtr0>();
		} break;
		case 1: {
			ctr1 = std::make_shared<srvsvc_NetShareCtr1>();
		} break;
		default:
			X_TODO;
	}
}

void srvsvc_NetShareCtr::__uninit(x_ndr_switch_t __level)
{
	switch (__level) {
		case 0: {
			destruct(ctr0);
		} break;
		case 1: {
			destruct(ctr1);
		} break;
		default:
			X_TODO;
	}
}

x_ndr_off_t srvsvc_NetShareCtr::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_UNION_ALIGN(5, __ndr, __bpos, __epos, __flags);
	switch (__level) {
		case 0: {
			X_NDR_SCALARS_UNIQUE_PTR(ctr0, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case 1: {
			X_NDR_SCALARS_UNIQUE_PTR(ctr1, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		default: {
			X_TODO;
		} break;
	}
	return __bpos;
}

x_ndr_off_t srvsvc_NetShareCtr::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_UNION_ALIGN(5, __ndr, __bpos, __epos, __flags);
	switch (__level) {
		case 0: {
			X_NDR_SCALARS_UNIQUE_PTR(ctr0, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case 1: {
			X_NDR_SCALARS_UNIQUE_PTR(ctr1, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		default: {
			X_TODO;
		} break;
	}
	return __bpos;
}

x_ndr_off_t srvsvc_NetShareCtr::ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_UNION_ALIGN(5, __ndr, __bpos, __epos, __flags);
	switch (__level) {
		case 0: {
			X_NDR_BUFFERS_UNIQUE_PTR(ctr0, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case 1: {
			X_NDR_BUFFERS_UNIQUE_PTR(ctr1, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		default: {
			X_TODO;
		} break;
	}
	return __bpos;
}

x_ndr_off_t srvsvc_NetShareCtr::ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_UNION_ALIGN(5, __ndr, __bpos, __epos, __flags);
	switch (__level) {
		case 0: {
			X_NDR_BUFFERS_UNIQUE_PTR(ctr0, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case 1: {
			X_NDR_BUFFERS_UNIQUE_PTR(ctr1, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		default: {
			X_TODO;
		} break;
	}
	return __bpos;
}

void srvsvc_NetShareCtr::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	switch (__level) {
		case 0: {
			X_NDR_OSTR(ctr0, __ndr, __flags, X_NDR_SWITCH_NONE);
		} break;
		case 1: {
			X_NDR_OSTR(ctr1, __ndr, __flags, X_NDR_SWITCH_NONE);
		} break;
		default: {
			X_TODO;
		} break;
	}
}

#if 0
x_ndr_off_t srvsvc_NetShareInfoCtr::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(level, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(ctr, __ndr, __bpos, __epos, __flags, level);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
}

x_ndr_off_t srvsvc_NetShareInfoCtr::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	x_ndr_off_t srvsvc_NetShareInfoCtr::ndr_buffers(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const;
	x_ndr_off_t srvsvc_NetShareInfoCtr::ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level);
	void srvsvc_NetShareInfoCtr::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const;
#endif
x_ndr_off_t srvsvc_NetShareEnumAll::ndr_requ(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags)
{
	X_NDR_SCALARS_UNIQUE_PTR(server_unc, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS_UNIQUE_SIZE_IS_LENGTH_IS__0(server_unc, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);

	X_NDR_SCALARS(level, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(level, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	ctr.__init(level);
	X_NDR_SCALARS(ctr, __ndr, __bpos, __epos, __flags, level);
	X_NDR_BUFFERS(ctr, __ndr, __bpos, __epos, __flags, level);
	X_NDR_SCALARS(max_buffer, __ndr, __bpos, __epos, __flags, level);
	X_NDR_SCALARS_UNIQUE_PTR(resume_handle, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS_UNIQUE_PTR(resume_handle, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);

	return __bpos;
}

x_ndr_off_t srvsvc_NetShareEnumAll::ndr_resp(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags) const
{
	X_NDR_SCALARS(level, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(level, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(ctr, __ndr, __bpos, __epos, __flags, level);
	X_NDR_BUFFERS(ctr, __ndr, __bpos, __epos, __flags, level);
	X_NDR_SCALARS(totalentries, __ndr, __bpos, __epos, __flags, level);
	X_NDR_SCALARS_UNIQUE_PTR(resume_handle, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS_UNIQUE_PTR(resume_handle, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);

	return __bpos;
}

}

