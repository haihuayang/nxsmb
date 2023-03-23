
#ifndef __charset__hxx__
#define __charset__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/xdefines.h"
#include "include/bits.hxx"
#include <string>
#include <stdint.h>
#include <string.h>

static const char32_t x_unicode_invalid = char32_t(-1);

extern const uint16_t x_lowcase_table[];
extern const uint16_t x_upcase_table[];

/**
 Convert a char32_t to upper case.
**/
static inline char32_t x_toupper(char32_t val)
{
	if (val >= 0x10000) {
		return val;
	}
	return x_upcase_table[val];
}

/**
 Convert a char32_t to lower case.
**/
static inline char32_t x_tolower(char32_t val)
{
	if (val >= 0x10000) {
		return val;
	}
	return x_lowcase_table[val];
}

struct x_identity_t
{
	char32_t operator()(char32_t v) const noexcept
	{
		return v;
	}
};

static inline std::pair<char32_t, const char16_t *> x_utf16_pull_unicode(
		const char16_t *str, const char16_t *end)
{
	char32_t uc0 = *str;
	if (uc0 >= 0xd800 && uc0 < 0xdc00) {
		if (str + 2 > end) {
			return {x_unicode_invalid, nullptr};
		}
		char32_t uc1 = str[1];
		if ((uc1 & 0xfc00) != 0xdc00) {
			return {x_unicode_invalid, nullptr};
		}
		uc0 = ((uc0 & 0x3ff) << 10) + (uc1 & 0x3ff) + 0x10000;
		return {uc0, str + 2};
	}
	return {uc0, str + 1};
}

static inline std::pair<char32_t, const char8_t *> x_utf8_pull_unicode(
		const char8_t *str, const char8_t *end)
{
	char32_t uc0 = *str;
	if ((uc0 & 0x80) == 0) {
		return {uc0, str + 1};
	}

	if ((uc0 & 0xe0) == 0xc0) {
		if (str + 2 > end) {
			return {x_unicode_invalid, nullptr};
		}
		char32_t uc1 = str[1];
		if ((uc1 & 0xc0) != 0x80) {
			return {x_unicode_invalid, nullptr};
		}

		uc0 = ((uc0 & 0x3f) << 6) | (uc1 & 0x3f);
		if (uc0 < 0x80) {
			return {x_unicode_invalid, nullptr};
		}
		return {uc0, str + 2};
	}

	if ((uc0 & 0xf0) == 0xe0) {
		if (str + 3 > end) {
			return {x_unicode_invalid, nullptr};
		}
		char32_t uc1 = str[1];
		if ((uc1 & 0xc0) != 0x80) {
			return {x_unicode_invalid, nullptr};
		}
		char32_t uc2 = str[2];
		if ((uc2 & 0xc0) != 0x80) {
			return {x_unicode_invalid, nullptr};
		}
		uc0 = ((uc0 & 0xf) << 12) | ((uc1 & 0x3f) << 6) | (uc2 & 0x3f);
		if (uc0 < 0x800) {
			return {x_unicode_invalid, nullptr};
		}
		return {uc0, str + 3};
	}

	if ((uc0 & 0xf8) == 0xf0) {
		if (str + 4 > end) {
			return {x_unicode_invalid, nullptr};
		}
		char32_t uc1 = str[1];
		if ((uc1 & 0xc0) != 0x80) {
			return {x_unicode_invalid, nullptr};
		}
		char32_t uc2 = str[2];
		if ((uc2 & 0xc0) != 0x80) {
			return {x_unicode_invalid, nullptr};
		}
		char32_t uc3 = str[3];
		if ((uc3 & 0xc0) != 0x80) {
			return {x_unicode_invalid, nullptr};
		}
		uc0 = ((uc0 & 0x7) << 18) | ((uc1 & 0x3f) << 12) |
			((uc2 & 0x3f) << 6) | (uc3 & 0x3f);
		if (uc0 < 0x10000) {
			return {x_unicode_invalid, nullptr};
		}
		return {uc0, str + 4};
	}

	/* not support 5 or 6 bytes */
	return {x_unicode_invalid, nullptr};
}

static inline int x_unicode_push_utf16(char32_t uc, std::u16string &str)
{
	if (uc > 0x10ffffu) {
		str.push_back(0xfffd);
	} else if (uc > 0xffff) {
		uc -= 0x10000u;
		str.push_back(x_convert<char16_t>((uc >> 10) + 0xd800));
		str.push_back(x_convert<char16_t>((uc & 0x3ff) + 0xdc00));
		return 2;
	} else if (uc >= 0xd800 && uc <= 0xdfff) {
		str.push_back(0xfffd);
	} else {
		str.push_back(x_convert<char16_t>(uc));
	}
	return 1;
}

static inline int x_unicode_push_utf8(char32_t uc, std::string &str)
{
	if (uc < 0x80) {
		str.push_back(x_convert<char>(uc));
		return 1;
	} else if (uc < 0x800) {
		char32_t c1 = uc & 0x3f;
		uc >>= 6;
		str.push_back(x_convert<char>(0xc0 | uc));
		str.push_back(x_convert<char>(0x80 | c1));
		return 2;
	} else if (uc < 0x10000) {
		char32_t c2 = (uc & 0x3f);
		uc >>= 6;
		char32_t c1 = (uc & 0x3f);
		uc >>= 6;
		char32_t c0 = (uc);
		str.push_back(x_convert<char>(0xe0 | c0));
		str.push_back(x_convert<char>(0x80 | c1));
		str.push_back(x_convert<char>(0x80 | c2));
		return 3;
	} else if (uc < 0x200000) {
		char32_t c3 = (uc & 0x3f);
		uc >>= 6;
		char32_t c2 = (uc & 0x3f);
		uc >>= 6;
		char32_t c1 = (uc & 0x3f);
		uc >>= 6;
		str.push_back(x_convert<char>(0xf0 | uc));
		str.push_back(x_convert<char>(0x80 | c1));
		str.push_back(x_convert<char>(0x80 | c2));
		str.push_back(x_convert<char>(0x80 | c3));
		return 4;
	} else if (uc < 0x4000000) {
		char32_t c4 = (uc & 0x3f);
		uc >>= 6;
		char32_t c3 = (uc & 0x3f);
		uc >>= 6;
		char32_t c2 = (uc & 0x3f);
		uc >>= 6;
		char32_t c1 = (uc & 0x3f);
		uc >>= 6;
		str.push_back(x_convert<char>(0xf8 | uc));
		str.push_back(x_convert<char>(0x80 | c1));
		str.push_back(x_convert<char>(0x80 | c2));
		str.push_back(x_convert<char>(0x80 | c3));
		str.push_back(x_convert<char>(0x80 | c4));
		return 5;
	} else if (uc < 0x80000000) {
		char32_t c5 = (uc & 0x3f);
		uc >>= 6;
		char32_t c4 = (uc & 0x3f);
		uc >>= 6;
		char32_t c3 = (uc & 0x3f);
		uc >>= 6;
		char32_t c2 = (uc & 0x3f);
		uc >>= 6;
		char32_t c1 = (uc & 0x3f);
		uc >>= 6;
		str.push_back(x_convert<char>(0xfc | uc));
		str.push_back(x_convert<char>(0x80 | c1));
		str.push_back(x_convert<char>(0x80 | c2));
		str.push_back(x_convert<char>(0x80 | c3));
		str.push_back(x_convert<char>(0x80 | c4));
		str.push_back(x_convert<char>(0x80 | c5));
		return 6;
	}
	X_ASSERT(false);
	return -1;
}

template <class UnaryOp = x_identity_t>
bool x_convert_utf16_to_utf8_new(const char16_t *begin, const char16_t *end,
		std::string &dst, UnaryOp op = {})
{
	size_t dst_orig_size = dst.size();
	while (begin != end) {
		auto [uc, next] = x_utf16_pull_unicode(begin, end);
		if (!next) {
			dst.resize(dst_orig_size);
			return false;
		}

		uc = op(uc);
		x_unicode_push_utf8(uc, dst);
		begin = next;
	}
	return true;
}

template <class UnaryOp = x_identity_t>
bool x_convert_utf16_to_utf8_new(const std::u16string &src,
		std::string &dst, UnaryOp op = {})
{
	const char16_t *begin = src.data();
	return x_convert_utf16_to_utf8_new(begin, begin + src.size(),
			dst, std::forward<UnaryOp>(op));
}

template <class UnaryOp = x_identity_t>
std::string x_convert_utf16_to_utf8_safe(const char16_t *begin, const char16_t *end,
		UnaryOp op = {})
{
	std::string ret;
	if (!x_convert_utf16_to_utf8_new(begin, end, ret, std::forward<UnaryOp>(op))) {
		ret = "[INVALID_UTF8]";
	}
	return ret;
}

template <class UnaryOp = x_identity_t>
std::string x_convert_utf16_to_utf8_safe(const std::u16string &src, UnaryOp op = {})
{
	std::string ret;
	if (!x_convert_utf16_to_utf8_new(src, ret, std::forward<UnaryOp>(op))) {
		ret = "[INVALID_UTF8]";
	}
	return ret;
}

template <class UnaryOp = x_identity_t>
std::string x_convert_utf16_to_utf8_assert(const std::u16string &src, UnaryOp op = {})
{
	std::string ret;
	const char16_t *begin = src.data();
	X_ASSERT(x_convert_utf16_to_utf8_new(begin, begin + src.size(),
				ret, std::forward<UnaryOp>(op)));
	return ret;
}

template <class UnaryOp = x_identity_t>
bool x_convert_utf8_to_utf16_new(const char8_t *begin, const char8_t *end,
		std::u16string &dst, UnaryOp op = {})
{
	size_t dst_orig_size = dst.size();
	while (begin != end) {
		auto [uc, next] = x_utf8_pull_unicode(begin, end);
		if (!next) {
			dst.resize(dst_orig_size);
			return false;
		}

		uc = op(uc);
		x_unicode_push_utf16(uc, dst);
		begin = next;
	}
	return true;
}

template <class UnaryOp = x_identity_t>
bool x_convert_utf8_to_utf16_new(const std::string src,
		std::u16string &dst, UnaryOp op = {})
{
	const char8_t *begin = (const char8_t *)src.data();
	return x_convert_utf8_to_utf16_new(begin, begin + src.size(),
			dst, std::forward<UnaryOp>(op));
}

template <class UnaryOp = x_identity_t>
std::u16string x_convert_utf8_to_utf16_assert(const std::string src,
		UnaryOp op = {})
{
	std::u16string ret;
	const char8_t *begin = (const char8_t *)src.data();
	X_ASSERT(x_convert_utf8_to_utf16_new(begin, begin + src.size(),
				ret, std::forward<UnaryOp>(op)));
	return ret;
}

static inline std::u16string x_utf16le_decode(const char16_t *begin,
		const char16_t *end)
{
	/* TODO big endian */
	return std::u16string(begin, end);
}

static inline char16_t *x_utf16le_encode(const std::u16string &s,
		void *ptr)
{
	/* TODO big endian */
	/* ptr has enough space, and alignment 2 bytes */
	X_ASSERT(long(ptr) % 2 == 0);
	char16_t *begin = (char16_t *)ptr;
	for (auto ch: s) {
		*begin++ = X_H2LE16(ch);
	}
	return begin;
}

static inline char16_t *x_utf16le_encode(const std::u16string &s,
		char16_t *begin, char16_t *end)
{
	/* TODO big endian */
	for (auto ch: s) {
		if (begin == end) {
			return nullptr;
		}
		*begin++ = X_H2LE16(ch);
	}
	return begin;
}

static inline char16_t *x_utf16le_encode(const char16_t *s,
		char16_t *begin, char16_t *end)
{
	/* TODO big endian */
	for ( ; *s; ++s) {
		if (begin == end) {
			return nullptr;
		}
		*begin++ = X_H2LE16(*s);
	}
	return begin;
}

static inline bool x_strcase_equal(const char16_t *s1, const char16_t *s2, size_t size)
{
	const char16_t *s1end = s1 + size;
	const char16_t *s2end = s2 + size;
	while (s1 != s1end) {
		auto [uc1, next1] = x_utf16_pull_unicode(s1, s1end);
		if (!next1) {
			/* not valid utf16, failback the byte compare */
			return memcmp(s1, s2, (s1end - s1) * sizeof(char16_t));
		}
		auto [uc2, next2] = x_utf16_pull_unicode(s2, s2end);
		if (!next2) {
			return false;
		}

		if (uc1 != uc2 && x_tolower(uc1) != x_tolower(uc2)) {
			return false;
		}
		s1 = next1;
		s2 = next2;
	}
	return true;
}

static inline bool x_strcase_equal(const std::u16string &s1, const std::u16string &s2)
{
	size_t size = s1.size();
	if (size != s2.size()) {
		return false;
	}
	return x_strcase_equal(s1.data(), s2.data(), size);
}

static inline bool x_strcase_equal(const char8_t *s1, const char8_t *s2, size_t size)
{
	const char8_t *s1end = s1 + size;
	const char8_t *s2end = s2 + size;
	while (s1 != s1end) {
		auto [uc1, next1] = x_utf8_pull_unicode(s1, s1end);
		if (!next1) {
			/* not valid utf8, failback the byte compare */
			return memcmp(s1, s2, (s1end - s1) * sizeof(char8_t));
		}
		auto [uc2, next2] = x_utf8_pull_unicode(s2, s2end);
		if (!next2) {
			return false;
		}

		if (uc1 != uc2 && x_tolower(uc1) != x_tolower(uc2)) {
			return false;
		}
		s1 = next1;
		s2 = next2;
	}
	return true;
}

static inline bool x_strcase_equal(const std::string &s1, const std::string &s2)
{
	size_t size = s1.size();
	if (size != s2.size()) {
		return false;
	}
	return x_strcase_equal((const char8_t *)s1.data(), (const char8_t *)s2.data(), size);
}

static inline std::string x_str_toupper(const std::string &s)
{
	std::string ret;
	ret.reserve(s.size());
	const char8_t *begin = (const char8_t *)s.data();
	const char8_t *end = begin + s.size();
	while (begin != end) {
		auto [uc, next] = x_utf8_pull_unicode(begin, end);
		if (!next) {
			/* not valid utf8, failback byte toupper */
			for ( ; begin != end; ++begin) {
				ret.push_back((char)std::toupper(*begin));
			}
			break;
		}

		uc = x_toupper(uc);
		x_unicode_push_utf8(uc, ret);
		begin = next;
	}
	return ret;
}

static inline bool x_str_has_wild(const std::u16string &s)
{
	for (auto c: s) {
		if (c == u'*' || c == u'?' || c == u'<' || c == u'>' || c == u'"') {
			return true;
		}
	}
	return false;
}

std::pair<bool, uint64_t> x_strcase_hash(const char16_t *begin, const char16_t *end);

static inline std::pair<bool, uint64_t> x_strcase_hash(const std::u16string &s)
{
	return x_strcase_hash(s.data(), s.data() + s.size());
}

/********************************************************************
 samba validate_net_name
 Check a string for any occurrences of a specified list of invalid
 characters.
********************************************************************/

static inline bool x_str_validate(const std::u16string &str,
		const char16_t *invalid_chars)
{
	for (auto ch: str) {
		for (auto p = invalid_chars; *p; ++p) {
			if (ch == *p) {
				return false;
			}
		}
	}
	return true;
}

#endif /* __charset__hxx__ */

