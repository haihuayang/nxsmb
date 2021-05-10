
#include "include/librpc/ndr.hxx"
#include "include/charset.hxx"
#include <assert.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <string>
#include <locale>
// #include <codecvt> TODO g++4.8.5 does not have this
#include <arpa/inet.h>

namespace idl {

static x_ndr_off_t push_u8string(const std::string &val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	bpos = x_ndr_push_bytes(val.data(), ndr, bpos, epos, val.size());
	if (bpos < 0) {
		return bpos;
	}
	if (!(flags & LIBNDR_FLAG_STR_NOTERM)) {
		X_NDR_SCALARS_DEFAULT(uint8(0), ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	}
	return bpos;
}

static x_ndr_off_t pull_u8string(std::string &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	size_t length = epos - bpos;
	if (!(flags & LIBNDR_FLAG_STR_NOTERM)) {
		if (length < 1) {
			return -NDR_ERR_LENGTH;
		}
		val.assign((const char *)(ndr.get_data() + bpos), (const char *)(ndr.get_data() + epos - 1)); 
		bpos = epos - 1;
		uint8_t eos;
		X_NDR_SCALARS_DEFAULT(eos, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		if (eos != 0) {
			return -NDR_ERR_ARRAY_SIZE;
		}
	} else {
		val.assign((const char16_t *)(ndr.get_data() + bpos), (const char16_t *)(ndr.get_data() + epos)); 
	}
	return epos;
}

static x_ndr_off_t push_u16string(const std::u16string &val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	X_ASSERT((flags & LIBNDR_FLAG_BIGENDIAN) == 0); // TODO
	bpos = x_ndr_push_bytes(val.data(), ndr, bpos, epos, val.size() * 2);
	if (bpos < 0) {
		return bpos;
	}
	if (!(flags & LIBNDR_FLAG_STR_NOTERM)) {
		X_NDR_SCALARS_DEFAULT(uint16(0), ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	}
	return bpos;
}

static x_ndr_off_t pull_u16string(std::u16string &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	X_ASSERT((flags & LIBNDR_FLAG_BIGENDIAN) == 0); // TODO
	size_t length = epos - bpos;
	if (length & 1) {
		return -NDR_ERR_LENGTH;
	}
	if (!(flags & LIBNDR_FLAG_STR_NOTERM)) {
		if (length < 2) {
			return -NDR_ERR_LENGTH;
		}
		val.assign((const char16_t *)(ndr.get_data() + bpos), (const char16_t *)(ndr.get_data() + epos - 2)); 
		bpos = epos - 2;
		uint16_t eos;
		X_NDR_SCALARS_DEFAULT(eos, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		if (eos != 0) {
			return -NDR_ERR_ARRAY_SIZE;
		}
	} else {
		val.assign((const char16_t *)(ndr.get_data() + bpos), (const char16_t *)(ndr.get_data() + epos)); 
	}
	return epos;
}

x_ndr_off_t x_ndr_scalars_u16string(const std::u16string &val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	if (flags & (LIBNDR_FLAG_STR_ASCII|LIBNDR_FLAG_STR_UTF8)) {
		return push_u8string(x_convert_utf16_to_utf8(val), ndr, bpos, epos, flags);
	} else {
		return push_u16string(val, ndr, bpos, epos, flags);
	}
}

x_ndr_off_t x_ndr_scalars_u16string(std::u16string &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	if (flags & (LIBNDR_FLAG_STR_ASCII|LIBNDR_FLAG_STR_UTF8)) {
		std::string tmp;
		bpos = pull_u8string(tmp, ndr, bpos, epos, flags);
		if (bpos < 0) {
			return bpos;
		}
		val = x_convert_utf8_to_utf16(tmp);
		return bpos;
	} else {
		return pull_u16string(val, ndr, bpos, epos, flags);
	}
}

void x_ndr_ostr_u16string(const std::u16string &val, x_ndr_ostr_t &ndr, uint32_t flags)
{
	ndr.os << "u\"" << x_convert_utf16_to_utf8(val) << '"';
}

x_ndr_off_t x_ndr_scalars_u8string(const std::string &val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	if (flags & (LIBNDR_FLAG_STR_ASCII|LIBNDR_FLAG_STR_UTF8)) {
		return push_u8string(val, ndr, bpos, epos, flags);
	} else {
		return push_u16string(x_convert_utf8_to_utf16(val), ndr, bpos, epos, flags);
	}
}

x_ndr_off_t x_ndr_scalars_u8string(std::string &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	if (flags & (LIBNDR_FLAG_STR_ASCII|LIBNDR_FLAG_STR_UTF8)) {
		return pull_u8string(val, ndr, bpos, epos, flags);
	} else {
		std::u16string tmp;
		bpos = pull_u16string(tmp, ndr, bpos, epos, flags);
		if (bpos < 0) {
			return bpos;
		}
		val = x_convert_utf16_to_utf8(tmp);
		return bpos;
	}
}

void x_ndr_ostr_u8string(const std::string &val, x_ndr_ostr_t &ndr, uint32_t flags)
{
	ndr.os << '"' << val << '"';
}

x_ndr_off_t x_ndr_scalars_size_length_string(const std::u16string &val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, uint32_t size_length_flags)
{
	size_t length = val.size();
	uint3264 tmp;
	tmp.val = length + (((size_length_flags & str_size_noterm) == 0) ? 1 : 0);
	X_NDR_SCALARS_DEFAULT(tmp, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS_DEFAULT(uint3264(0), ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	tmp.val = length + (((size_length_flags & str_length_noterm) == 0) ? 1 : 0);
	X_NDR_SCALARS_DEFAULT(tmp, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	return x_ndr_scalars_u16string(val, ndr, bpos, epos, flags);
}

x_ndr_off_t x_ndr_scalars_size_length_string(std::u16string &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, uint32_t size_length_flags)
{
	uint3264 size, offset, length;
	X_NDR_SCALARS_DEFAULT(size, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS_DEFAULT(offset, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS_DEFAULT(length, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (offset.val != 0) {
		return -NDR_ERR_LENGTH;
	}
	uint32_t len = length.val;
	if (len > size.val) {
		return -NDR_ERR_LENGTH;
	}

	epos = X_NDR_CHECK_POS(bpos + 2 * len, bpos, epos);
	return x_ndr_scalars_u16string(val, ndr, bpos, epos, flags);
}

} /* namespace idl */
