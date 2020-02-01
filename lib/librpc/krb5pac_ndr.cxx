
#include "include/librpc/krb5pac_ndr.hxx"

namespace idl {

const std::array<std::pair<uint32, const char *>, 6> x_ndr_traits_t<PAC_TYPE>::value_name_map = { {
	{ PAC_TYPE_LOGON_INFO, "PAC_TYPE_LOGON_INFO" },
	{ PAC_TYPE_SRV_CHECKSUM, "PAC_TYPE_SRV_CHECKSUM" },
	{ PAC_TYPE_KDC_CHECKSUM, "PAC_TYPE_KDC_CHECKSUM" },
	{ PAC_TYPE_LOGON_NAME, "PAC_TYPE_LOGON_NAME" },
	{ PAC_TYPE_CONSTRAINED_DELEGATION, "PAC_TYPE_CONSTRAINED_DELEGATION" },
	{ PAC_TYPE_UNKNOWN_12, "PAC_TYPE_UNKNOWN_12" },
} };

x_ndr_off_t PAC_LOGON_NAME::ndr_scalars(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(logon_time, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(account_name, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t PAC_LOGON_NAME::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(logon_time, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(account_name, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

void PAC_LOGON_NAME::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(logon_time, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(account_name, __ndr, __flags, X_NDR_SWITCH_NONE);
	(__ndr) << leave;
}


x_ndr_off_t PAC_SIGNATURE_DATA::ndr_scalars(x_ndr_push_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level) const
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_PRINT_ARRAY_HEX);
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(type, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(signature, __ndr, __bpos, __epos, x_ndr_set_flags(__flags, LIBNDR_FLAG_REMAINING), X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	return __bpos;
}


x_ndr_off_t PAC_SIGNATURE_DATA::ndr_scalars(x_ndr_pull_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level)
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_PRINT_ARRAY_HEX);
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(type, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(signature, __ndr, __bpos, __epos, x_ndr_set_flags(__flags, LIBNDR_FLAG_REMAINING), X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

void PAC_SIGNATURE_DATA::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	__flags = x_ndr_set_flags(__flags, LIBNDR_PRINT_ARRAY_HEX);
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(type, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(signature, __ndr, __flags, X_NDR_SWITCH_NONE);
	(__ndr) << leave;
}

x_ndr_off_t PAC_LOGON_INFO::ndr_scalars(x_ndr_push_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level) const
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(info3, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(res_group_dom_sid, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(res_groups, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t PAC_LOGON_INFO::ndr_buffers(x_ndr_push_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_BUFFERS(info3, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(res_group_dom_sid, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(res_groups, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}

x_ndr_off_t PAC_LOGON_INFO::ndr_scalars(x_ndr_pull_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(info3, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(res_group_dom_sid, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(res_groups, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t PAC_LOGON_INFO::ndr_buffers(x_ndr_pull_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_BUFFERS(info3, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(res_group_dom_sid, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(res_groups, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}

void PAC_LOGON_INFO::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(info3, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(res_group_dom_sid, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(res_groups, __ndr, __flags, X_NDR_SWITCH_NONE);
	(__ndr) << leave;
}

#if 0
x_ndr_off_t x_ndr_ptr(x_ndr_ptr_t<PAC_LOGON_INFO> &__ptr, x_ndr_pull_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	__ptr.ptr_pos = __bpos;
	X_NDR_RESERVE(4, __ndr, __bpos, __epos, __flags); // TODO uint3264
	return __bpos;
}

x_ndr_off_t x_ndr_data(x_ndr_ptr_t<PAC_LOGON_INFO> &__ptr, x_ndr_pull_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	x_ndr_off_t ptr_pos = __ptr.ptr_pos;
	uint3264 ptr;
	X_NDR_DATA(ptr, __ndr, ptr_pos, __epos, __flags, X_NDR_SWITCH_NONE);

	if (ptr) {
		__ptr.val = std::make_shared<PAC_LOGON_INFO>();
		X_NDR_DATA(*__ptr.val, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	}
	return __bpos;
}
#endif
x_ndr_off_t PAC_CONSTRAINED_DELEGATION::ndr_scalars(x_ndr_push_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level) const
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(proxy_target, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(transited_services, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t PAC_CONSTRAINED_DELEGATION::ndr_buffers(x_ndr_push_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_BUFFERS(proxy_target, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(transited_services, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}

x_ndr_off_t PAC_CONSTRAINED_DELEGATION::ndr_scalars(x_ndr_pull_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(proxy_target, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(transited_services, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t PAC_CONSTRAINED_DELEGATION::ndr_buffers(x_ndr_pull_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_BUFFERS(proxy_target, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(transited_services, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}

void PAC_CONSTRAINED_DELEGATION::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(proxy_target, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(transited_services, __ndr, __flags, X_NDR_SWITCH_NONE);
	(__ndr) << leave;
}

#if 0
static x_ndr_off_t x_ndr_ptr(const x_ndr_ptr_t<PAC_CONSTRAINED_DELEGATION> &__ptr, x_ndr_push_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	__ptr.ptr_pos = __bpos;
	X_NDR_RESERVE(4, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

static x_ndr_off_t x_ndr_ptr(x_ndr_ptr_t<PAC_CONSTRAINED_DELEGATION> &__ptr, x_ndr_pull_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(4, __ndr, __bpos, __epos, __flags);
	__ptr.ptr_pos = __bpos;
	X_NDR_RESERVE(4, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

static x_ndr_off_t x_ndr_data(x_ndr_ptr_t<PAC_CONSTRAINED_DELEGATION> &__ptr, x_ndr_pull_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	x_ndr_off_t ptr_pos = __ptr.ptr_pos;
	uint3264 ptr_info;
	X_NDR_DATA(ptr_info, __ndr, ptr_pos, __epos, __flags, X_NDR_SWITCH_NONE);
	if (ptr_info) {
		__ptr.val = std::make_shared<PAC_CONSTRAINED_DELEGATION>();
		X_NDR_DATA(*__ptr.val, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	}
	return __bpos;
}

x_ndr_off_t PAC_CONSTRAINED_DELEGATION_CTR::push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	x_ndr_off_t __base = __bpos; (void)__base;
	x_ndr_off_t __ptr; (void)__ptr;
	X_NDR_DATA(info, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t PAC_CONSTRAINED_DELEGATION_CTR::ndr_scalars(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	ptr_pos = __bpos;
	X_NDR_SKIP(uint3264, __ndr, __bpos, __epos, __flags);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t PAC_CONSTRAINED_DELEGATION_CTR::ndr_buffers(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level)
{
	uint3264 ptr;
	X_NDR_SCALARS(ptr, __ndr, ptr_pos, __epos, __flags, X_NDR_SWITCH_NONE);
	if (ptr.val) {
		info = std::make_shared<PAC_CONSTRAINED_DELEGATION>();
		X_NDR_SCALARS(*info, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		X_NDR_BUFFERS(*info, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	}
	return __bpos;
}
#endif


void PAC_INFO::__init(x_ndr_switch_t __level)
{
	switch (__level) {
		case PAC_TYPE_LOGON_INFO: construct(logon_info); break;
		case PAC_TYPE_SRV_CHECKSUM: construct(srv_cksum); break;
		case PAC_TYPE_KDC_CHECKSUM: construct(kdc_cksum); break;
		case PAC_TYPE_LOGON_NAME: construct(logon_name); break;
		case PAC_TYPE_CONSTRAINED_DELEGATION: construct(constrained_delegation); break;
		default: construct(unknown); break;
	}
}

void PAC_INFO::__init(x_ndr_switch_t __level, const PAC_INFO &other)
{
	switch (__level) {
		case PAC_TYPE_LOGON_INFO: construct(logon_info, other.logon_info); break;
		case PAC_TYPE_SRV_CHECKSUM: construct(srv_cksum, other.srv_cksum); break;
		case PAC_TYPE_KDC_CHECKSUM: construct(kdc_cksum, other.kdc_cksum); break;
		case PAC_TYPE_LOGON_NAME: construct(logon_name, other.logon_name); break;
		case PAC_TYPE_CONSTRAINED_DELEGATION: construct(constrained_delegation, other.constrained_delegation); break;
		default: construct(unknown, other.unknown); break;
	}
}

void PAC_INFO::__uninit(x_ndr_switch_t __level)
{
	switch (__level) {
		case PAC_TYPE_LOGON_INFO: destruct(logon_info); break;
		case PAC_TYPE_SRV_CHECKSUM: destruct(srv_cksum); break;
		case PAC_TYPE_KDC_CHECKSUM: destruct(kdc_cksum); break;
		case PAC_TYPE_LOGON_NAME: destruct(logon_name); break;
		case PAC_TYPE_CONSTRAINED_DELEGATION: destruct(constrained_delegation); break;
		default: destruct(unknown); break;
	}
}
#if 0
x_ndr_off_t PAC_INFO::push(x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_UNION_ALIGN(5, __ndr, __bpos, __epos, __flags);
	switch (__level) {
		case PAC_TYPE_LOGON_INFO: {
			X_NDR_DATA(logon_info, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case PAC_TYPE_SRV_CHECKSUM: {
			X_NDR_DATA(srv_cksum, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case PAC_TYPE_KDC_CHECKSUM: {
			X_NDR_DATA(kdc_cksum, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case PAC_TYPE_LOGON_NAME: {
			X_NDR_DATA(logon_name, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		case PAC_TYPE_CONSTRAINED_DELEGATION: {
			X_NDR_DATA(constrained_delegation, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
		default: {
			X_NDR_DATA(unknown, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		} break;
	}
	return __bpos;
}

static x_ndr_off_t x_ndr_pull_subcontext(x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, ssize_t size_is)
{
	uint8_t version;
	uint8_t drep;
	uint16_t hdrlen;
	uint32_t filler;
	X_NDR_SCALARS(version, __ndr, __bpos, __epos, __base, 0, X_NDR_SWITCH_NONE);
	if (version != 1) {
		return -NDR_ERR_SUBCONTEXT;
	}
	X_NDR_SCALARS(drep, __ndr, __bpos, __epos, __base, 0, X_NDR_SWITCH_NONE);
	if (drep == 0x10) {
		force_le = true;
	} else if (drep == 0) {
		force_be = true;
	} else {
		return -NDR_ERR_SUBCONTEXT;
	}
	X_NDR_SCALARS(hdrlen, __ndr, __bpos, __epos, __base, 0, X_NDR_SWITCH_NONE);
	if (hdrlen != 8) {
		return -NDR_ERR_SUBCONTEXT;
	}
	X_NDR_SCALARS(filler, __ndr, __bpos, __epos, __base, 0, X_NDR_SWITCH_NONE);
	uint32_t content_size;
	X_NDR_SCALARS(content_size, __ndr, __bpos, __epos, __base, 0, X_NDR_SWITCH_NONE);
	if (size_is >= 0 && size_is != content_size) {
		return -NDR_ERR_SUBCONTEXT;
	}
	if (content_size % 8 != 0) {
		return -NDR_ERR_SUBCONTEXT;
	}
	X_NDR_SCALARS(filler, __ndr, __bpos, __epos, __base, 0, X_NDR_SWITCH_NONE);
	return __bpos;
}
#endif

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

void PAC_INFO::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	switch (__level) {
		case PAC_TYPE_LOGON_INFO: {
			X_NDR_OSTR(logon_info, __ndr, __flags, X_NDR_SWITCH_NONE);
		} break;
		case PAC_TYPE_SRV_CHECKSUM: {
			X_NDR_OSTR(srv_cksum, __ndr, __flags, X_NDR_SWITCH_NONE);
		} break;
		case PAC_TYPE_KDC_CHECKSUM: {
			X_NDR_OSTR(kdc_cksum, __ndr, __flags, X_NDR_SWITCH_NONE);
		} break;
		case PAC_TYPE_LOGON_NAME: {
			X_NDR_OSTR(logon_name, __ndr, __flags, X_NDR_SWITCH_NONE);
		} break;
		case PAC_TYPE_CONSTRAINED_DELEGATION: {
			X_NDR_OSTR(constrained_delegation, __ndr, __flags, X_NDR_SWITCH_NONE);
		} break;
		default: {
			X_NDR_OSTR(unknown, __ndr, __flags, X_NDR_SWITCH_NONE);
		} break;
	}
}

x_ndr_off_t PAC_BUFFER::ndr_scalars(x_ndr_push_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level) const
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(type, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(info, __ndr, __bpos, __epos, x_ndr_set_flags(__flags, LIBNDR_FLAG_ALIGN8), type);
	uint32_t pad = 0;
	X_NDR_SCALARS(pad, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t PAC_BUFFER::ndr_buffers(x_ndr_push_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level) const
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(8, __ndr, __bpos, __epos, __flags);
	X_NDR_BUFFERS(info, __ndr, __bpos, __epos, x_ndr_set_flags(__flags, LIBNDR_FLAG_ALIGN8), type);
	return __bpos;
}

x_ndr_off_t PAC_BUFFER::ndr_scalars(x_ndr_pull_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(type, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(info, __ndr, __bpos, __epos, x_ndr_set_flags(__flags, LIBNDR_FLAG_ALIGN8), type);
	uint32_t pad = 0;
	X_NDR_SCALARS(pad, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t PAC_BUFFER::ndr_buffers(x_ndr_pull_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(info, __ndr, __bpos, __epos, x_ndr_set_flags(__flags, LIBNDR_FLAG_ALIGN8), type);
	return __bpos;
}

void PAC_BUFFER::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(type, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(info, __ndr, __flags, type);
	(__ndr) << leave;
}


x_ndr_off_t PAC_DATA::ndr_scalars(x_ndr_push_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(uint32_t(get_size(buffers)), __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(version, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(buffers, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t PAC_DATA::ndr_buffers(x_ndr_push_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_BUFFERS(buffers, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}

x_ndr_off_t PAC_DATA::ndr_scalars(x_ndr_pull_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	uint32_t num_buffers;
	X_NDR_SCALARS(num_buffers, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(version, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	buffers.val.resize(num_buffers);
	X_NDR_SCALARS(buffers, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t PAC_DATA::ndr_buffers(x_ndr_pull_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_BUFFERS(buffers, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}

void PAC_DATA::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(version, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(buffers, __ndr, __flags, X_NDR_SWITCH_NONE);
	(__ndr) << leave;
}


x_ndr_off_t PAC_BUFFER_RAW::ndr_scalars(x_ndr_push_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level) const
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(type, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(info, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	uint32_t pad = 0;
	X_NDR_SCALARS(pad, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t PAC_BUFFER_RAW::ndr_buffers(x_ndr_push_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level) const
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(8, __ndr, __bpos, __epos, __flags);
	X_NDR_BUFFERS(info, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}

x_ndr_off_t PAC_BUFFER_RAW::ndr_scalars(x_ndr_pull_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(type, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(info, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	uint32_t pad = 0;
	X_NDR_SCALARS(pad, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t PAC_BUFFER_RAW::ndr_buffers(x_ndr_pull_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_BUFFERS(info, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}

void PAC_BUFFER_RAW::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(type, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(info, __ndr, __flags, X_NDR_SWITCH_NONE);
	(__ndr) << leave;
}


x_ndr_off_t PAC_DATA_RAW::ndr_scalars(x_ndr_push_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	X_NDR_SCALARS(uint32_t(get_size(buffers)), __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(version, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(buffers, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t PAC_DATA_RAW::ndr_buffers(x_ndr_push_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level) const
{
	X_NDR_BUFFERS(buffers, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}

x_ndr_off_t PAC_DATA_RAW::ndr_scalars(x_ndr_pull_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	uint32_t num_buffers;
	X_NDR_SCALARS(num_buffers, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(version, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	buffers.val.resize(num_buffers);
	X_NDR_SCALARS(buffers, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t PAC_DATA_RAW::ndr_buffers(x_ndr_pull_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level)
{
	X_NDR_BUFFERS(buffers, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}

void PAC_DATA_RAW::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	(__ndr) << enter;
	X_NDR_OSTR_NEXT(version, __ndr, __flags, X_NDR_SWITCH_NONE);
	X_NDR_OSTR_NEXT(buffers, __ndr, __flags, X_NDR_SWITCH_NONE);
	(__ndr) << leave;
}

}

