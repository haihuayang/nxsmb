
#include "include/librpc/ndr_lsa.hxx"

namespace idl {

x_ndr_off_t lsa_String::ndr_scalars(x_ndr_push_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level) const
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	uint16_t length = val ? val->val.size() * 2 : 0;
	X_NDR_SCALARS(length, __ndr, __bpos, __epos, __flags, __level);
	X_NDR_SCALARS(length, __ndr, __bpos, __epos, __flags, __level);
	uint3264 ptr{0};
	if (val) {
		ptr.val = __ndr.next_ptr();
	}
	X_NDR_SCALARS(ptr, __ndr, __bpos, __epos, __flags, __level);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t lsa_String::ndr_buffers(x_ndr_push_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level) const
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	if (val) {
		uint32_t size = val->val.size();
		X_NDR_SCALARS(uint3264{size}, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS(uint3264{0}, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS(uint3264{size}, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS(*val, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	}
	return __bpos;
}

x_ndr_off_t lsa_String::ndr_scalars(x_ndr_pull_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	__pos_ptr = __bpos;
	X_NDR_SKIP(uint16, __ndr, __bpos, __epos, __flags);
	X_NDR_SKIP(uint16, __ndr, __bpos, __epos, __flags);
	X_NDR_SKIP(uint3264, __ndr, __bpos, __epos, __flags);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t lsa_String::ndr_buffers(x_ndr_pull_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	uint16_t length, size;
	X_NDR_SCALARS(length, __ndr, __pos_ptr, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(size, __ndr, __pos_ptr, __epos, __flags, X_NDR_SWITCH_NONE);
	uint3264 ptr;
	X_NDR_SCALARS(ptr, __ndr, __pos_ptr, __epos, __flags, X_NDR_SWITCH_NONE);

	if (ptr.val) {
		if (length > size) {
			return -NDR_ERR_ARRAY_SIZE;
		}
		uint3264 array_size, array_offset, array_length;
		X_NDR_SCALARS(array_size, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS(array_offset, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS(array_length, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		if (array_length.val > array_size.val || array_offset.val != 0 || array_length.val * 2 != length) {
			return -NDR_ERR_ARRAY_SIZE;
		}
		__epos = X_NDR_CHECK_POS(__bpos + length, __bpos, __epos);
		val = std::make_shared<u16string>();
		X_NDR_SCALARS(*val, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	}
	return __bpos;
}

void lsa_String::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	x_ndr_ostr_u16string(val->val, __ndr, __flags, __level);
}

x_ndr_off_t lsa_StringLarge::ndr_scalars(x_ndr_push_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level) const
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	uint16_t length = val ? val->val.size() * 2 : 0;
	X_NDR_SCALARS(length, __ndr, __bpos, __epos, __flags, __level);
	X_NDR_SCALARS(uint16_t(length + 2), __ndr, __bpos, __epos, __flags, __level);
	uint3264 ptr{0};
	if (val) {
		ptr.val = __ndr.next_ptr();
	}
	X_NDR_SCALARS(ptr, __ndr, __bpos, __epos, __flags, __level);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t lsa_StringLarge::ndr_buffers(x_ndr_push_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level) const
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	if (val) {
		uint32_t size = val->val.size();
		X_NDR_SCALARS((uint3264{size + 1}), __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS(uint3264{0}, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS(uint3264{size}, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS(*val, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	}
	return __bpos;
}

x_ndr_off_t lsa_StringLarge::ndr_scalars(x_ndr_pull_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	__pos_ptr = __bpos;
	X_NDR_SKIP(uint16, __ndr, __bpos, __epos, __flags);
	X_NDR_SKIP(uint16, __ndr, __bpos, __epos, __flags);
	X_NDR_SKIP(uint3264, __ndr, __bpos, __epos, __flags);
	X_NDR_TRAILER_ALIGN(5, __ndr, __bpos, __epos, __flags);
	return __bpos;
}

x_ndr_off_t lsa_StringLarge::ndr_buffers(x_ndr_pull_t &__ndr,
		x_ndr_off_t __bpos, x_ndr_off_t __epos,
		uint32_t __flags, x_ndr_switch_t __level)
{
	X_ASSERT(__level == X_NDR_SWITCH_NONE);
	uint16_t length, size;
	X_NDR_SCALARS(length, __ndr, __pos_ptr, __epos, __flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS(size, __ndr, __pos_ptr, __epos, __flags, X_NDR_SWITCH_NONE);
	uint3264 ptr;
	X_NDR_SCALARS(ptr, __ndr, __pos_ptr, __epos, __flags, X_NDR_SWITCH_NONE);

	if (ptr.val) {
		if (length > size) {
			return -NDR_ERR_ARRAY_SIZE;
		}
		uint3264 array_size, array_offset, array_length;
		X_NDR_SCALARS(array_size, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS(array_offset, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS(array_length, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
		if (array_length.val > array_size.val || array_offset.val != 0 || array_length.val * 2 != length) {
			return -NDR_ERR_ARRAY_SIZE;
		}
		__epos = X_NDR_CHECK_POS(__bpos + length, __bpos, __epos);
		val = std::make_shared<u16string>();
		X_NDR_SCALARS(*val, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	}
	return __bpos;
}

void lsa_StringLarge::ostr(x_ndr_ostr_t &__ndr, uint32_t __flags, x_ndr_switch_t __level) const
{
	x_ndr_ostr_u16string(val->val, __ndr, __flags, __level);
}

}

