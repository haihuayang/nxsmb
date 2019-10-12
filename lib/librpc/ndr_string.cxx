
#include "include/librpc/ndr.hxx"
#include <assert.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
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
x_ndr_off_t nstring::push(x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const
{
	X_ASSERT(false);
	return bpos;
}

x_ndr_off_t nstring::pull(x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(false);
	return bpos;
}

x_ndr_off_t nstring_array::push(x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const
{
	X_ASSERT(false);
	return bpos;
}

x_ndr_off_t nstring_array::pull(x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(false);
	return bpos;
}

x_ndr_off_t DATA_BLOB::push(x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const
{
	X_ASSERT(false);
	return bpos;
}

x_ndr_off_t DATA_BLOB::pull(x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(false);
	return bpos;
}

x_ndr_off_t x_ndr_push_string(const std::string &str, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t extra_flags)
{
	if (bpos + str.size() > epos) {
		return -NDR_ERR_LENGTH;
	}
	ndr.data.resize(bpos + str.size());
	memcpy(ndr.data.data() + bpos, str.data(), str.size());
	return bpos + str.size();
}

x_ndr_off_t x_ndr_pull_string(std::string &str, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t extra_flags)
{
	str = std::string(ndr.data + bpos, ndr.data + epos);
	return epos;
}

} /* namespace idl */
