
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

#if 0
x_ndr_off_t x_ndr_at(x_ndr_pull_t &ndr, string &str, uint32_t extra_flags, x_ndr_switch_t level, uint32_t off, uint32_t len)
{
	int do_convert = 1, chset = CH_UTF16;
	unsigned byte_mul = 2;
	unsigned c_len_term = 0;

	if (NDR_BE(ndr)) {
		X_ASSERT(false);
		chset = CH_UTF16BE;
	}

	if (flags & LIBNDR_FLAG_STR_ASCII) {
		chset = CH_DOS;
		byte_mul = 1;
		flags &= ~LIBNDR_FLAG_STR_ASCII;
	}

	if (flags & LIBNDR_FLAG_STR_UTF8) {
		chset = CH_UTF8;
		byte_mul = 1;
		flags &= ~LIBNDR_FLAG_STR_UTF8;
	}

	if (flags & LIBNDR_FLAG_STR_RAW8) {
		do_convert = 0;
		byte_mul = 1;
		flags &= ~LIBNDR_FLAG_STR_RAW8;
	}

	flags &= ~LIBNDR_FLAG_STR_CONFORMANT;
	if (flags & LIBNDR_FLAG_STR_CHARLEN) {
		c_len_term = 1;
		flags &= ~LIBNDR_FLAG_STR_CHARLEN;
	}

	switch (flags & LIBNDR_STRING_FLAGS) {
#if 0
	case LIBNDR_FLAG_STR_LEN4|LIBNDR_FLAG_STR_SIZE4:
	case LIBNDR_FLAG_STR_LEN4|LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_NOTERM:
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &len1));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &ofs));
		if (ofs != 0) {
			return ndr_pull_error(ndr, NDR_ERR_STRING, "non-zero array offset with string flags 0x%x\n",
					      ndr->flags & LIBNDR_STRING_FLAGS);
		}
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &len2));
		if (len2 > len1) {
			return ndr_pull_error(ndr, NDR_ERR_STRING,
					      "Bad string lengths len1=%u ofs=%u len2=%u\n",
					      len1, ofs, len2);
		} else if (len1 != len2) {
			DEBUG(6,("len1[%u] != len2[%u] '%s'\n", len1, len2, as));
		}
		conv_src_len = len2 + c_len_term;
		break;

	case LIBNDR_FLAG_STR_SIZE4:
	case LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_NOTERM:
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &len1));
		conv_src_len = len1 + c_len_term;
		break;

	case LIBNDR_FLAG_STR_LEN4:
	case LIBNDR_FLAG_STR_LEN4|LIBNDR_FLAG_STR_NOTERM:
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &ofs));
		if (ofs != 0) {
			return ndr_pull_error(ndr, NDR_ERR_STRING, "non-zero array offset with string flags 0x%x\n",
					      ndr->flags & LIBNDR_STRING_FLAGS);
		}
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &len1));
		conv_src_len = len1 + c_len_term;
		break;

	case LIBNDR_FLAG_STR_SIZE2:
	case LIBNDR_FLAG_STR_SIZE2|LIBNDR_FLAG_STR_NOTERM:
		NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &len3));
		conv_src_len = len3 + c_len_term;
		break;

	case LIBNDR_FLAG_STR_SIZE2|LIBNDR_FLAG_STR_NOTERM|LIBNDR_FLAG_STR_BYTESIZE:
		NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &len3));
		conv_src_len = len3;
		byte_mul = 1; /* the length is now absolute */
		break;

	case LIBNDR_FLAG_STR_NULLTERM:
		if (byte_mul == 1) {
			conv_src_len = ascii_len_n((const char *)(ndr->data+ndr->offset), ndr->data_size - ndr->offset);
		} else {
			conv_src_len = utf16_len_n(ndr->data+ndr->offset, ndr->data_size - ndr->offset);
		}
		byte_mul = 1; /* the length is now absolute */
		break;
#endif
	case LIBNDR_FLAG_STR_NOTERM:
		if (!(flags & LIBNDR_FLAG_REMAINING)) {
			return -NDR_ERR_STRING;
			// return ndr_pull_error(ndr, NDR_ERR_STRING, "Bad string flags 0x%x (missing NDR_REMAINING)\n", ndr->flags & LIBNDR_STRING_FLAGS);
		}
		// conv_src_len = ndr->data_size - ndr->offset;
		byte_mul = 1; /* the length is now absolute */
		break;

	default:
		X_TODO;
		// return ndr_pull_error(ndr, NDR_ERR_STRING, "Bad string flags 0x%x\n",
		//		      ndr->flags & LIBNDR_STRING_FLAGS);
	}

	// NDR_PULL_NEED_BYTES(ndr, len * byte_mul);
	if (len == 0) {
		val.val = "";
		converted_size = 0;
	} else if (!do_convert) {
		val.val = std::string((const char *)ndr.data + off, (const char *)ndr.data + off + len);
	} else if ((len % byte_mul) != 0) {
		return -NDR_ERR_STRING; // TODO which error code ?
	} else {
		std::u16string u16s{(const char16_t *)(ndr.data + off), (const char16_t *)(ndr.data + off + len)};
		std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> convert;
		val.val = convert.to_bytes(u16s);
	}
	return 0;
}
#endif

static x_ndr_off_t push_utf8(const std::string &val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos)
{
	x_ndr_off_t new_pos = bpos + val.size();
	if (new_pos < 0 || new_pos > epos) {
		return -NDR_ERR_LENGTH;
	}
	ndr.reserve(new_pos);
	memcpy(ndr.get_data() + bpos, val.data(), val.size());
	return new_pos;
}

static x_ndr_off_t pull_utf8(std::string &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos)
{
	val.assign((const char *)(ndr.get_data() + bpos), (const char *)(ndr.get_data() + epos));
	return epos;
}

x_ndr_off_t x_ndr_push_u16string(const std::u16string &str, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	X_ASSERT((flags & LIBNDR_FLAG_BIGENDIAN) == 0); // TODO
	return x_ndr_push_bytes(str.data(), ndr, bpos, epos, str.size() * 2);
}

x_ndr_off_t x_ndr_pull_u16string(std::u16string &str, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	X_ASSERT((flags & LIBNDR_FLAG_BIGENDIAN) == 0); // TODO
	x_ndr_off_t nepos = X_NDR_CHECK_POS(bpos + 2 * str.size(), bpos, epos);

	str.assign((const char16_t *)(ndr.get_data() + bpos), (const char16_t *)(ndr.get_data() + nepos));
	return nepos;
}

x_ndr_off_t x_ndr_pull_u16string_remain(std::u16string &str, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	X_ASSERT((flags & LIBNDR_FLAG_BIGENDIAN) == 0); // TODO
	size_t length = epos - bpos;
	if (length & 1) {
		return -NDR_ERR_LENGTH;
	}
	str.assign((const char16_t *)(ndr.get_data() + bpos), (const char16_t *)(ndr.get_data() + epos)); 
	return epos;
}

#if 0
x_ndr_off_t x_ndr_pull_u16string(std::u16string &str, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, size_t size)
{
	X_ASSERT((flags & LIBNDR_FLAG_BIGENDIAN) == 0); // TODO
	if ((size % 2) != 0) {
		return -NDR_ERR_LENGTH;
	}
	x_ndr_off_t new_epos = bpos + size;
	if (new_epos > epos || new_epos < bpos) {
		return -NDR_ERR_LENGTH;
	}
	str.assign((const char16_t *)(ndr.get_data() + bpos), (const char16_t *)(ndr.get_data() + new_epos));
	return new_epos;
}
#endif

void x_ndr_ostr_u16string(const std::u16string &str, x_ndr_ostr_t &ndr, uint32_t flags)
{
	ndr.os << "u\"" << x_convert_utf16_to_utf8(str) << '"';
}

#if 0
x_ndr_off_t u16string::ndr_scalars(x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	x_ndr_off_t new_pos = bpos + val.size() * 2;
	if (new_pos < 0 || new_pos > epos) {
		return -NDR_ERR_LENGTH;
	}
	ndr.reserve(new_pos);
	memcpy(ndr.get_data() + bpos, val.data(), val.size() * 2);
	return new_pos;
}

x_ndr_off_t u16string::ndr_scalars(x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	if (((epos - bpos) % 2) != 0) {
		return -NDR_ERR_STRING;
	}
	char16_t *beg = (char16_t *)(ndr.get_data() + bpos);
	char16_t *end = (char16_t *)(ndr.get_data() + epos);
	char16_t *p;
	for (p = beg; p < end && *p; ++p) {
	}
	val.assign(beg, p);
	// val.assign((const char16_t *)(ndr.get_data() + bpos), (const char16_t *)(ndr.get_data() + epos));
	return epos;
}

void u16string::ostr(x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	// TODO
	ndr.os << "u16string(" << val.size() << ")";
}

x_ndr_off_t sstring::ndr_scalars(x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	return push_utf8(val, ndr, bpos, epos);
}

x_ndr_off_t sstring::ndr_scalars(x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	return pull_utf8(val, ndr, bpos, epos);
}

void sstring::ostr(x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	ndr.os << '"' << val << '"';
}

x_ndr_off_t gstring::ndr_scalars(x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	if ((flags & LIBNDR_FLAG_STR_ASCII) != 0) {
		return push_utf8(val, ndr, bpos, epos);
	}
	std::u16string u16s = x_convert_utf8_to_utf16(val);

	x_ndr_off_t new_pos = bpos + u16s.size() * 2;
	if (new_pos < 0 || new_pos > epos) {
		return -NDR_ERR_LENGTH;
	}
	ndr.reserve(new_pos);
	memcpy(ndr.get_data() + bpos, u16s.data(), u16s.size() * 2);
	return new_pos;
}

x_ndr_off_t gstring::ndr_scalars(x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	if ((flags & LIBNDR_FLAG_STR_ASCII) != 0) {
		return pull_utf8(val, ndr, bpos, epos);
	}

	if (((epos - bpos) % 2) != 0) {
		return -NDR_ERR_STRING;
	}
	std::u16string u16s((const char16_t *)(ndr.get_data() + bpos), (const char16_t *)(ndr.get_data() + epos));
	val = x_convert_utf16_to_utf8(u16s);
	return epos;
}

void gstring::ostr(x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	ndr.os << '"' << val << '"';
}
#endif
x_ndr_off_t x_ndr_push_string(const std::string &str, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t extra_flags)
{
	x_ndr_off_t new_pos = bpos + str.size();
	if (new_pos > epos) {
		return -NDR_ERR_LENGTH;
	}
	ndr.reserve(new_pos);
	memcpy(ndr.get_data() + bpos, str.data(), str.size());
	return new_pos;
}

x_ndr_off_t x_ndr_pull_string(std::string &str, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t extra_flags)
{
	str = std::string(ndr.get_data() + bpos, ndr.get_data() + epos);
	return epos;
}

x_ndr_off_t x_ndr_push_gstring(const std::string &val, x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	if ((flags & LIBNDR_FLAG_STR_ASCII) != 0) {
		return push_utf8(val, ndr, bpos, epos);
	}
	return x_ndr_push_u16string(x_convert_utf8_to_utf16(val), ndr, bpos, epos, flags);
}

x_ndr_off_t x_ndr_pull_gstring(std::string &val, x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags)
{
	if ((flags & LIBNDR_FLAG_STR_ASCII) != 0) {
		return pull_utf8(val, ndr, bpos, epos);
	}

	std::u16string u16s;
	bpos = x_ndr_pull_u16string_remain(u16s, ndr, bpos, epos, flags);
	if (bpos < 0) {
		return bpos;
	}

	val = x_convert_utf16_to_utf8(u16s);
	return bpos;
}

void x_ndr_ostr_gstring(const std::string &val, x_ndr_ostr_t &ndr, uint32_t flags)
{
	ndr.os << '"' << val << '"';
}

} /* namespace idl */
