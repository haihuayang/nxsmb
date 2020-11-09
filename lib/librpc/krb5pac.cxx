
#include "include/librpc/krb5pac.hxx"

namespace idl {
#if 0
x_ndr_off_t PAC_INFO::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_UNION_ALIGN(4, __ndr, __bpos, __epos, __flags);
	switch (__level) {
		case PAC_TYPE_LOGON_INFO: {
			X_NDR_SCALARS(logon_info, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case PAC_TYPE_SRV_CHECKSUM: {
			X_NDR_SCALARS(srv_cksum, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case PAC_TYPE_KDC_CHECKSUM: {
			X_NDR_SCALARS(kdc_cksum, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case PAC_TYPE_LOGON_NAME: {
			X_NDR_SCALARS(logon_name, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case PAC_TYPE_CONSTRAINED_DELEGATION: {
			X_NDR_SCALARS(constrained_delegation, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		default: {
			X_NDR_SCALARS(unknown, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
	}
	return __bpos;
}

x_ndr_off_t PAC_INFO::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_UNION_ALIGN(4, __ndr, __bpos, __epos, __flags);
	switch (__level) {
		case PAC_TYPE_LOGON_INFO: {
			X_NDR_SCALARS(logon_info, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case PAC_TYPE_SRV_CHECKSUM: {
			X_NDR_SCALARS(srv_cksum, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case PAC_TYPE_KDC_CHECKSUM: {
			X_NDR_SCALARS(kdc_cksum, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case PAC_TYPE_LOGON_NAME: {
			X_NDR_SCALARS(logon_name, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case PAC_TYPE_CONSTRAINED_DELEGATION: {
			X_NDR_SCALARS(constrained_delegation, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		default: {
			X_NDR_SCALARS(unknown, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
	}
	return __bpos;
}
#endif
x_ndr_off_t ndr_traits_t<PAC_BUFFER>::scalars(
		const PAC_BUFFER &__val,
		x_ndr_push_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level) const
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS_DEFAULT(__val.type, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SAVE_POS(uint32, __ndr, __bpos, __epos, __flags);
	X_NDR_SAVE_POS(uint64, __ndr, __bpos, __epos, __flags);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t ndr_traits_t<PAC_BUFFER>::buffers(
		const PAC_BUFFER &__val,
		x_ndr_push_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level) const
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	x_ndr_off_t __pos_size = __ndr.load_pos();
	x_ndr_off_t __pos_info = __ndr.load_pos();
	X_NDR_BUFFERS_RELATIVE_PTR__1(ndr_traits_t<PAC_INFO>, __val.info, __ndr, __bpos, __epos,
			x_ndr_set_flags(__flags, LIBNDR_FLAG_ALIGN8), __val.type,
			ndr_traits_t<uint64>, __pos_info, ndr_traits_t<uint32>, __pos_size);
	return __bpos;
}

x_ndr_off_t ndr_traits_t<PAC_BUFFER>::scalars(
		PAC_BUFFER &__val,
		x_ndr_pull_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level) const
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS_DEFAULT(__val.type, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SAVE_POS(uint32, __ndr, __bpos, __epos, __flags);
	X_NDR_SAVE_POS(uint64, __ndr, __bpos, __epos, __flags);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t ndr_traits_t<PAC_BUFFER>::buffers(
		PAC_BUFFER &__val,
		x_ndr_pull_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level) const
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	x_ndr_off_t __pos_size = __ndr.load_pos();
	x_ndr_off_t __pos_info = __ndr.load_pos();
	X_NDR_BUFFERS_RELATIVE_PTR__1(ndr_traits_t<PAC_INFO>, __val.info, __ndr, __bpos, __epos,
			x_ndr_set_flags(__flags, LIBNDR_FLAG_ALIGN8), __val.type,
			ndr_traits_t<uint64>, __pos_info, ndr_traits_t<uint32>, __pos_size);
	return __bpos;
}

}

