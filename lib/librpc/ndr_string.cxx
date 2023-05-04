
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

x_ndr_off_t x_ndr_scalars_string_intl(const std::string &val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, bool add_nul_empty)
{
	bpos = x_ndr_push_bytes(val.data(), ndr, bpos, epos, val.size());
	if (bpos < 0) {
		return bpos;
	}
	if ((add_nul_empty && val.size() == 0) || !(flags & LIBNDR_FLAG_STR_NOTERM)) {
		X_NDR_SCALARS_DEFAULT(uint8(0), ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	}
	return bpos;
}

x_ndr_off_t x_ndr_scalars_string_intl(std::string &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, bool add_nul_empty)
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
		const char *end = (const char *)(ndr.get_data() + epos);
		if (length > 0) {
			if (end[-1] == '\0') {
				--end;
			}
		}
		val.assign((const char *)(ndr.get_data() + bpos), end);
	}
	return epos;
}

x_ndr_off_t x_ndr_scalars_string_intl(const std::u16string &val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, bool add_nul_empty)
{
	X_ASSERT((flags & LIBNDR_FLAG_BIGENDIAN) == 0); // TODO
	bpos = x_ndr_push_bytes(val.data(), ndr, bpos, epos, val.size() * 2);
	if (bpos < 0) {
		return bpos;
	}
	if ((add_nul_empty && val.size() == 0) || !(flags & LIBNDR_FLAG_STR_NOTERM)) {
		X_NDR_SCALARS_DEFAULT(uint16(0), ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	}
	return bpos;
}

x_ndr_off_t x_ndr_scalars_string_intl(std::u16string &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, bool add_nul_empty)
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
		const char16_t *end = (const char16_t *)(ndr.get_data() + epos);
		if (length > 0) {
			if (end[-1] == 0) {
				--end;
			}
		}
		val.assign((const char16_t *)(ndr.get_data() + bpos), end);
	}
	return epos;
}

x_ndr_off_t x_ndr_scalars_string(const std::u16string &val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, bool add_nul_empty)
{
	if (flags & (LIBNDR_FLAG_STR_ASCII|LIBNDR_FLAG_STR_UTF8)) {
		std::string utf8_val;
		if (!x_str_convert(utf8_val, val)) {
			return -NDR_ERR_CHARCNV;
		}
		return x_ndr_scalars_string_intl(utf8_val, ndr, bpos, epos, flags, add_nul_empty);
	} else {
		return x_ndr_scalars_string_intl(val, ndr, bpos, epos, flags, add_nul_empty);
	}
}

x_ndr_off_t x_ndr_scalars_string(std::u16string &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, bool add_nul_empty)
{
	if (flags & (LIBNDR_FLAG_STR_ASCII|LIBNDR_FLAG_STR_UTF8)) {
		std::string tmp;
		bpos = x_ndr_scalars_string_intl(tmp, ndr, bpos, epos, flags, add_nul_empty);
		if (bpos < 0) {
			return bpos;
		}
		if (!x_str_convert(val, tmp)) {
			return -NDR_ERR_CHARCNV;
		}
		return bpos;
	} else {
		return x_ndr_scalars_string_intl(val, ndr, bpos, epos, flags, add_nul_empty);
	}
}

void x_ndr_ostr_string(const std::u16string &val, x_ndr_ostr_t &ndr, uint32_t flags)
{
	ndr.os << "u\"" << x_str_todebug(val) << '"';
}

x_ndr_off_t x_ndr_scalars_string(const std::string &val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, bool add_nul_empty)
{
	if (flags & (LIBNDR_FLAG_STR_ASCII|LIBNDR_FLAG_STR_UTF8)) {
		return x_ndr_scalars_string_intl(val, ndr, bpos, epos, flags, add_nul_empty);
	} else {
		std::u16string tmp;
		if (!x_str_convert(tmp, val)) {
			return -NDR_ERR_CHARCNV;
		}
		return x_ndr_scalars_string_intl(tmp, ndr, bpos, epos, flags, add_nul_empty);
	}
}

x_ndr_off_t x_ndr_scalars_string(std::string &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, bool add_nul_empty)
{
	if (flags & (LIBNDR_FLAG_STR_ASCII|LIBNDR_FLAG_STR_UTF8)) {
		return x_ndr_scalars_string_intl(val, ndr, bpos, epos, flags, add_nul_empty);
	} else {
		std::u16string tmp;
		bpos = x_ndr_scalars_string_intl(tmp, ndr, bpos, epos, flags, add_nul_empty);
		if (bpos < 0) {
			return bpos;
		}
		if (!x_str_convert(val, tmp)) {
			return -NDR_ERR_CHARCNV;
		}
		return bpos;
	}
}

void x_ndr_ostr_string(const std::string &val, x_ndr_ostr_t &ndr, uint32_t flags)
{
	ndr.os << '"' << val << '"';
}

x_ndr_off_t x_ndr_scalars_size_length_string(const std::u16string &val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, uint32_t size_length_flags)
{
	size_t length = val.size();
	uint3264 tmp;
	tmp.val = x_convert_assert<uint32_t>(length + (((size_length_flags & str_size_noterm) == 0) ? 1 : 0));
	X_NDR_SCALARS_DEFAULT(tmp, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	X_NDR_SCALARS_DEFAULT(uint3264(0), ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	tmp.val = x_convert_assert<uint32_t>(length + (((size_length_flags & str_length_noterm) == 0) ? 1 : 0));
	X_NDR_SCALARS_DEFAULT(tmp, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	return x_ndr_scalars_string(val, ndr, bpos, epos, flags, false);
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
	return x_ndr_scalars_string(val, ndr, bpos, epos, flags, false);
}

} /* namespace idl */
