#include "include/librpc/winreg.hxx"

namespace idl {

template <typename StrLength, typename StrSize>
static x_ndr_off_t ndr_u16string_scalars(const StrLength &sl, const StrSize &ss,
		const std::shared_ptr<u16string> &val, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, ndr, bpos, epos, flags);
	uint16_t length = x_convert<uint16_t>(sl(val) * 2);
	uint16_t size = x_convert<uint16_t>(ss(val) * 2);
	X_NDR_SCALARS_DEFAULT(length, ndr, bpos, epos, flags, level);
	X_NDR_SCALARS_DEFAULT(size, ndr, bpos, epos, flags, level);
	uint3264 ptr{0};
	if (val) {
		ptr.val = ndr.next_ptr();
	}
	X_NDR_SCALARS_DEFAULT(ptr, ndr, bpos, epos, flags, level);
	X_NDR_TRAILER_ALIGN(5, ndr, bpos, epos, flags);
	return bpos;
}

template <typename StrLength, typename StrSize>
static x_ndr_off_t ndr_u16string_buffers(const StrLength &sl, const StrSize &ss,
		const std::shared_ptr<u16string> &val, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	if (val) {
		uint32_t length = sl(val);
		uint32_t size = ss(val);
		X_NDR_SCALARS_DEFAULT(uint3264{length}, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS_DEFAULT(uint3264{0}, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS_DEFAULT(uint3264{size}, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS_CHARSET(*val, ndr, bpos, epos, flags | LIBNDR_FLAG_STR_NULLTERM, X_NDR_SWITCH_NONE);
	}
	return bpos;
}

template <typename StrLength, typename StrSize>
static x_ndr_off_t ndr_u16string_scalars(const StrLength &sl, const StrSize &ss,
		std::shared_ptr<u16string> &val, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	X_NDR_HEADER_ALIGN(5, ndr, bpos, epos, flags);
	X_NDR_SAVE_POS(uint16, ndr, bpos, epos, flags);
	X_NDR_SAVE_POS(uint16, ndr, bpos, epos, flags);
	X_NDR_SCALARS_UNIQUE_PTR(val, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(5, ndr, bpos, epos, flags);
	return bpos;
}

template <typename StrLength, typename StrSize>
static x_ndr_off_t ndr_u16string_buffers(const StrLength &sl, const StrSize &ss,
		std::shared_ptr<u16string> &val, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	uint3264 array_size{}, array_offset, array_length{};
	if (val) {
		X_NDR_SCALARS_DEFAULT(array_size, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS_DEFAULT(array_offset, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS_DEFAULT(array_length, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		if (array_length.val > array_size.val || array_offset.val != 0) {
			return -NDR_ERR_ARRAY_SIZE;
		}
		epos = X_NDR_CHECK_POS(bpos + array_length.val * 2, bpos, epos);
		X_NDR_SCALARS_CHARSET(*val, ndr, bpos, epos, flags | LIBNDR_FLAG_STR_NULLTERM, X_NDR_SWITCH_NONE);
	}
	x_ndr_off_t pos_1 = ndr.load_pos();
	x_ndr_off_t pos_2 = ndr.load_pos();
	uint16_t length, size;
	X_NDR_SCALARS_DEFAULT(length, ndr, pos_1, epos, flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS_DEFAULT(size, ndr, pos_2, epos, flags, X_NDR_SWITCH_NONE);
	/* TODO should it check lengths */
	if (length != array_length.val * 2 || length != array_size.val * 2) {
	}
	return bpos;
}


struct strlen_term
{
	uint16_t operator()(const std::shared_ptr<u16string> &s) const {
		return x_convert<uint16_t>(s ? s->length() + 1 : 0);
	}
};

struct strlen_term_null
{
	uint16_t operator()(const std::shared_ptr<u16string> &s) const {
		auto length = s ? s->length() + 1 : 0;
		if (length) {
			++length;
		}
		return x_convert<uint16_t>(length);
	}
};

x_ndr_off_t ndr_traits_t<winreg_String>::scalars(
		const winreg_String &val, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	return ndr_u16string_scalars(strlen_term(), strlen_term(),
			val.name, ndr, bpos, epos, flags, level);
}

x_ndr_off_t ndr_traits_t<winreg_String>::buffers(
		const winreg_String &val, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	return ndr_u16string_buffers(strlen_term(), strlen_term(),
			val.name, ndr, bpos, epos, flags, level);
}

x_ndr_off_t ndr_traits_t<winreg_String>::scalars(
		winreg_String &val, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	return ndr_u16string_scalars(strlen_term(), strlen_term(),
			val.name, ndr, bpos, epos, flags, level);
}

x_ndr_off_t ndr_traits_t<winreg_String>::buffers(
		winreg_String &val, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	return ndr_u16string_buffers(strlen_term(), strlen_term(),
			val.name, ndr, bpos, epos, flags, level);
}


x_ndr_off_t ndr_traits_t<winreg_ValNameBuf>::scalars(
		const winreg_ValNameBuf &val, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	return ndr_u16string_scalars(strlen_term(), strlen_term(),
			val.name, ndr, bpos, epos, flags, level);
}

x_ndr_off_t ndr_traits_t<winreg_ValNameBuf>::buffers(
		const winreg_ValNameBuf &val, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	return ndr_u16string_buffers(strlen_term(), strlen_term(),
			val.name, ndr, bpos, epos, flags, level);
}

x_ndr_off_t ndr_traits_t<winreg_ValNameBuf>::scalars(
		winreg_ValNameBuf &val, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	return ndr_u16string_scalars(strlen_term(), strlen_term(),
			val.name, ndr, bpos, epos, flags, level);
}

x_ndr_off_t ndr_traits_t<winreg_ValNameBuf>::buffers(
		winreg_ValNameBuf &val, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	return ndr_u16string_buffers(strlen_term(), strlen_term(),
			val.name, ndr, bpos, epos, flags, level);
}



x_ndr_off_t ndr_traits_t<winreg_StringBuf>::scalars(
		const winreg_StringBuf &val, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	return ndr_u16string_scalars(strlen_term_null(), strlen_term_null(),
			val.name, ndr, bpos, epos, flags, level);
}

x_ndr_off_t ndr_traits_t<winreg_StringBuf>::buffers(
		const winreg_StringBuf &val, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	return ndr_u16string_buffers(strlen_term_null(), strlen_term_null(),
			val.name, ndr, bpos, epos, flags, level);
}

x_ndr_off_t ndr_traits_t<winreg_StringBuf>::scalars(
		winreg_StringBuf &val, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	return ndr_u16string_scalars(strlen_term_null(), strlen_term_null(),
			val.name, ndr, bpos, epos, flags, level);
}

x_ndr_off_t ndr_traits_t<winreg_StringBuf>::buffers(
		winreg_StringBuf &val, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	return ndr_u16string_buffers(strlen_term_null(), strlen_term_null(),
			val.name, ndr, bpos, epos, flags, level);
}


x_ndr_off_t ndr_requ_traits_t<winreg_EnumValue>::scalars(const winreg_EnumValue &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_TODO;
	return __bpos;
}

x_ndr_off_t ndr_resp_traits_t<winreg_EnumValue>::scalars(const winreg_EnumValue &__val, x_ndr_push_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_TODO;
	X_NDR_SCALARS_DEFAULT(__val.__result, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}

x_ndr_off_t ndr_requ_traits_t<winreg_EnumValue>::scalars(winreg_EnumValue &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_TODO;
	return __bpos;
}

x_ndr_off_t ndr_resp_traits_t<winreg_EnumValue>::scalars(winreg_EnumValue &__val, x_ndr_pull_t &__ndr, x_ndr_off_t __bpos, x_ndr_off_t __epos, uint32_t __flags, x_ndr_switch_t __level) const
{
	X_TODO;
	X_NDR_SCALARS_DEFAULT(__val.__result, __ndr, __bpos, __epos, __flags, X_NDR_SWITCH_NONE);
	return __bpos;
}



x_ndr_off_t ndr_requ_traits_t<winreg_QueryValue>::scalars(
		const winreg_QueryValue &val,
		x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	X_NDR_SCALARS_DEFAULT(val.handle, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	X_NDR_CHECK(bpos = x_ndr_both(ndr_traits_t<winreg_String>(), val.value_name, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE));
	X_NDR_SCALARS_UNIQUE_PTR(val.type, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (val.type) {
		X_NDR_SCALARS_DEFAULT(*val.type, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	}
	X_NDR_SCALARS_UNIQUE_PTR(val.data, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (val.data) {
		X_NDR_SCALARS_DEFAULT(uint3264{val.data_size ? *val.data_size : 0},
				 ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS_DEFAULT(uint3264{0},
				 ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS_DEFAULT(uint3264{val.data_length ? *val.data_length : 0},
				 ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		for (auto &v: *val.data) {
			X_NDR_SCALARS_SIMPLE(ndr_traits_t<uint8>, v, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		}
	}
	X_NDR_SCALARS_UNIQUE_PTR(val.data_size, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (val.data_size) {
		X_NDR_SCALARS_DEFAULT(*val.data_size, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	}
	X_NDR_SCALARS_UNIQUE_PTR(val.data_length, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (val.data_length) {
		X_NDR_SCALARS_DEFAULT(*val.data_length, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	}

	return bpos;
}

x_ndr_off_t ndr_resp_traits_t<winreg_QueryValue>::scalars(const winreg_QueryValue &val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const
{
	X_NDR_SCALARS_UNIQUE_PTR(val.type, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (val.type) {
		X_NDR_SCALARS_DEFAULT(*val.type, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	}

	X_NDR_SCALARS_UNIQUE_PTR(val.data, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (val.data) {
		X_NDR_SCALARS_DEFAULT(uint3264{val.data_size ? *val.data_size : 0},
				 ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS_DEFAULT(uint3264{0},
				 ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS_DEFAULT(uint3264{val.data_length ? *val.data_length : 0},
				 ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		for (auto &v: *val.data) {
			X_NDR_SCALARS_SIMPLE(ndr_traits_t<uint8>, v, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		}
	}
	X_NDR_SCALARS_UNIQUE_PTR(val.data_size, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (val.data_size) {
		X_NDR_SCALARS_DEFAULT(*val.data_size, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	}
	X_NDR_SCALARS_UNIQUE_PTR(val.data_length, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (val.data_length) {
		X_NDR_SCALARS_DEFAULT(*val.data_length, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	}

	X_NDR_SCALARS_DEFAULT(val.__result, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	return bpos;
}

x_ndr_off_t ndr_requ_traits_t<winreg_QueryValue>::scalars(
		winreg_QueryValue &val,
		x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level) const
{
	X_NDR_SCALARS_DEFAULT(val.handle, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	X_NDR_CHECK(bpos = x_ndr_both(ndr_traits_t<winreg_String>(), val.value_name, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE));
	X_NDR_SCALARS_UNIQUE_PTR(val.type, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (val.type) {
		X_NDR_SCALARS_DEFAULT(*val.type, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	}
	X_NDR_SCALARS_UNIQUE_PTR(val.data, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (val.data) {
		uint3264 length, offset, size;
		X_NDR_SCALARS_DEFAULT(size, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS_DEFAULT(offset, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS_DEFAULT(length, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		if (offset.val != 0 || length.val > size.val) {
			return -NDR_ERR_ARRAY_SIZE;
		}
		if (size.val > 0x4000000) {
			return -NDR_ERR_RANGE;
		}
		val.data->resize(length.val);
		for (auto &v: *val.data) {
			X_NDR_SCALARS_SIMPLE(ndr_traits_t<uint8>, v, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		}
	}
	X_NDR_SCALARS_UNIQUE_PTR(val.data_size, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (val.data_size) {
		X_NDR_SCALARS_DEFAULT(*val.data_size, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	}
	X_NDR_SCALARS_UNIQUE_PTR(val.data_length, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (val.data_length) {
		X_NDR_SCALARS_DEFAULT(*val.data_length, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	}

	return bpos;
}

x_ndr_off_t ndr_resp_traits_t<winreg_QueryValue>::scalars(winreg_QueryValue &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const
{
	X_NDR_SCALARS_UNIQUE_PTR(val.type, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (val.type) {
		X_NDR_SCALARS_DEFAULT(*val.type, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	}

	X_NDR_SCALARS_UNIQUE_PTR(val.data, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (val.data) {
		X_NDR_SCALARS_DEFAULT(uint3264{val.data_size ? *val.data_size : 0},
				 ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS_DEFAULT(uint3264{0},
				 ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS_DEFAULT(uint3264{val.data_length ? *val.data_length : 0},
				 ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		for (auto &v: *val.data) {
			X_NDR_SCALARS_SIMPLE(ndr_traits_t<uint8>, v, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		}
	}
	X_NDR_SCALARS_UNIQUE_PTR(val.data_size, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (val.data_size) {
		X_NDR_SCALARS_DEFAULT(*val.data_size, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	}
	X_NDR_SCALARS_UNIQUE_PTR(val.data_length, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (val.data_length) {
		X_NDR_SCALARS_DEFAULT(*val.data_length, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	}

	X_NDR_SCALARS_DEFAULT(val.__result, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	return bpos;
}

}
