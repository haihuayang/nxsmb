
#include "include/librpc/lsa.hxx"

namespace idl {

template <typename T>
static x_ndr_off_t lsa_u16string_scalars(
		const std::shared_ptr<T> &val, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, ndr, bpos, epos, flags);
	uint16_t length = 0;
	if (val) {
		length = val->size() * 2;
	}
	X_NDR_SCALARS_DEFAULT(length, ndr, bpos, epos, flags, level);
	X_NDR_SCALARS_DEFAULT(length, ndr, bpos, epos, flags, level);
	uint3264 ptr{0};
	if (val) {
		ptr.val = ndr.next_ptr();
	}
	X_NDR_SCALARS_DEFAULT(ptr, ndr, bpos, epos, flags, level);
	X_NDR_TRAILER_ALIGN(5, ndr, bpos, epos, flags);
	return bpos;
}

template <typename T>
static x_ndr_off_t lsa_u16string_buffers(
		const std::shared_ptr<T> &val, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	if (val) {
		uint32_t size = val->size();
		X_NDR_SCALARS_DEFAULT(uint3264{size}, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS_DEFAULT(uint3264{0}, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS_DEFAULT(uint3264{size}, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS_CHARSET(*val, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	}
	return bpos;
}

template <typename T>
static x_ndr_off_t lsa_u16string_scalars(
		std::shared_ptr<T> &val, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, ndr, bpos, epos, flags);
	X_NDR_SKIP(uint16, ndr, bpos, epos, flags);
	X_NDR_SKIP(uint16, ndr, bpos, epos, flags);
	uint3264 ptr;
	X_NDR_SCALARS_DEFAULT(ptr, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (ptr.val) {
		val = std::make_shared<T>();
	}
	X_NDR_TRAILER_ALIGN(5, ndr, bpos, epos, flags);
	return bpos;
}

template <typename T>
static x_ndr_off_t lsa_u16string_buffers(
		std::shared_ptr<T> &val, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	if (val) {
		uint3264 array_size, array_offset, array_length;
		X_NDR_SCALARS_DEFAULT(array_size, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS_DEFAULT(array_offset, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS_DEFAULT(array_length, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		if (array_length.val > array_size.val || array_offset.val != 0) {
			return -NDR_ERR_ARRAY_SIZE;
		}
		epos = X_NDR_CHECK_POS(bpos + array_length.val * 2, bpos, epos);
		X_NDR_SCALARS_CHARSET(*val, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	}
	return bpos;
}

x_ndr_off_t ndr_traits_t<lsa_String>::scalars(
		const lsa_String &val, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	return lsa_u16string_scalars(val.string, ndr, bpos, epos, flags, level);
}

x_ndr_off_t ndr_traits_t<lsa_String>::buffers(
		const lsa_String &val, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	if (val.string) {
		bpos = x_ndr_scalars_size_length_string(*val.string, ndr, bpos, epos,
				flags|LIBNDR_FLAG_STR_NOTERM,
				str_size_noterm | str_length_noterm);
	}
	return bpos;
}

x_ndr_off_t ndr_traits_t<lsa_String>::scalars(
		lsa_String &val, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	return lsa_u16string_scalars(val.string, ndr, bpos, epos, flags, level);
}

x_ndr_off_t ndr_traits_t<lsa_String>::buffers(
		lsa_String &val, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	if (val.string) {
		bpos = x_ndr_scalars_size_length_string(*val.string, ndr, bpos, epos,
				flags|LIBNDR_FLAG_STR_NOTERM,
				str_size_noterm | str_length_noterm);
	}
	return bpos;
}


x_ndr_off_t ndr_traits_t<lsa_StringLarge>::scalars(
		const lsa_StringLarge &val, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, ndr, bpos, epos, flags);
	uint16_t length = 0;
	if (val.string) {
		length = val.string->size() * 2;
	}
	X_NDR_SCALARS_DEFAULT(length, ndr, bpos, epos, flags, level);
	X_NDR_SCALARS_DEFAULT(uint16_t(length + 2), ndr, bpos, epos, flags, level);
	uint3264 ptr{0};
	if (val.string) {
		ptr.val = ndr.next_ptr();
	}
	X_NDR_SCALARS_DEFAULT(ptr, ndr, bpos, epos, flags, level);
	X_NDR_TRAILER_ALIGN(5, ndr, bpos, epos, flags);
	return bpos;
}

x_ndr_off_t ndr_traits_t<lsa_StringLarge>::buffers(
		const lsa_StringLarge &val, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	if (val.string) {
		bpos = x_ndr_scalars_size_length_string(*val.string, ndr, bpos, epos,
				flags|LIBNDR_FLAG_STR_NOTERM,
				str_length_noterm);
	}
	return bpos;
}

x_ndr_off_t ndr_traits_t<lsa_StringLarge>::scalars(
		lsa_StringLarge &val, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, ndr, bpos, epos, flags);
	X_NDR_SKIP(uint16, ndr, bpos, epos, flags);
	X_NDR_SKIP(uint16, ndr, bpos, epos, flags);
	uint3264 ptr;
	X_NDR_SCALARS_DEFAULT(ptr, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (ptr.val) {
		val.string = std::make_shared<std::u16string>();
	}
	X_NDR_TRAILER_ALIGN(5, ndr, bpos, epos, flags);
	return bpos;
}

x_ndr_off_t ndr_traits_t<lsa_StringLarge>::buffers(
		lsa_StringLarge &val, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	if (val.string) {
		bpos = x_ndr_scalars_size_length_string(*val.string, ndr, bpos, epos,
				flags|LIBNDR_FLAG_STR_NOTERM,
				str_length_noterm);
	}
	return bpos;
}
#if 0
x_ndr_off_t ndr_traits_t<lsa_BinaryString>::scalars(
		const lsa_BinaryString &val, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	return lsa_u16string_scalars(val.array, ndr, bpos, epos, flags, level);
}

x_ndr_off_t ndr_traits_t<lsa_BinaryString>::buffers(
		const lsa_BinaryString &val, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	return lsa_u16string_buffers(val.array, ndr, bpos, epos, flags, level);
}

x_ndr_off_t ndr_traits_t<lsa_BinaryString>::scalars(
		lsa_BinaryString &val, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	return lsa_u16string_scalars(val.array, ndr, bpos, epos, flags, level);
}

x_ndr_off_t ndr_traits_t<lsa_BinaryString>::buffers(
		lsa_BinaryString &val, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	return lsa_u16string_buffers(val.array, ndr, bpos, epos, flags, level);
}
#endif

x_ndr_off_t ndr_traits_t<lsa_AsciiString>::scalars(
		const lsa_AsciiString &val, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	X_TODO;
	return bpos;
}

x_ndr_off_t ndr_traits_t<lsa_AsciiString>::buffers(
		const lsa_AsciiString &val, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	X_TODO;
	return bpos;
}

x_ndr_off_t ndr_traits_t<lsa_AsciiString>::scalars(
		lsa_AsciiString &val, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	X_TODO;
	return bpos;
}

x_ndr_off_t ndr_traits_t<lsa_AsciiString>::buffers(
		lsa_AsciiString &val, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	X_TODO;
	return bpos;
}


x_ndr_off_t ndr_traits_t<lsa_AsciiStringLarge>::scalars(
		const lsa_AsciiStringLarge &val, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	X_TODO;
	return bpos;
}

x_ndr_off_t ndr_traits_t<lsa_AsciiStringLarge>::buffers(
		const lsa_AsciiStringLarge &val, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	X_TODO;
	return bpos;
}

x_ndr_off_t ndr_traits_t<lsa_AsciiStringLarge>::scalars(
		lsa_AsciiStringLarge &val, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	X_TODO;
	return bpos;
}

x_ndr_off_t ndr_traits_t<lsa_AsciiStringLarge>::buffers(
		lsa_AsciiStringLarge &val, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	X_TODO;
	return bpos;
}





}

