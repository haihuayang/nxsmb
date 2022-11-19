
#ifndef __charset__hxx__
#define __charset__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/xdefines.h"
#include "include/bits.hxx"
#include <string>
#include <stdint.h>

using x_codepoint_t = uint32_t;

extern const uint16_t x_lowcase_table[];
extern const uint16_t x_upcase_table[];

/**
 Convert a x_codepoint_t to upper case.
**/
static inline x_codepoint_t x_toupper(x_codepoint_t val)
{
	if (val >= 0x10000) {
		return val;
	}
	return x_upcase_table[val];
}

/**
 Convert a x_codepoint_t to lower case.
**/
static inline x_codepoint_t x_tolower(x_codepoint_t val)
{
	if (val >= 0x10000) {
		return val;
	}
	return x_lowcase_table[val];
}

template <class InputIt, class OutputIt>
OutputIt x_convert_utf16_to_utf8(InputIt begin, InputIt end, OutputIt oi)
{
	while (begin != end) {
		char16_t c = *begin;
		// TODO multibytes
		++oi = x_convert_assert<char>(c);
		++begin;
	}
	return oi;
}

template <class InputIt>
static inline std::string x_convert_utf16_to_utf8(InputIt begin, InputIt end)
{
	std::string ret;
	x_convert_utf16_to_utf8(begin, end, std::back_inserter(ret));
	return ret;
}

static inline std::string x_convert_utf16_to_utf8(const std::u16string &src)
{
	return x_convert_utf16_to_utf8(std::begin(src), std::end(src));
}


template <class InputIt, class OutputIt>
OutputIt x_convert_utf16_to_lower_utf8(InputIt begin, InputIt end, OutputIt oi)
{
	while (begin != end) {
		char16_t c = char16_t(x_tolower(*begin));
		// TODO multibytes
		++oi = x_convert_assert<char>(c);
		++begin;
	}
	return oi;
}

template <class InputIt>
std::string x_convert_utf16_to_lower_utf8(InputIt begin, InputIt end)
{
	std::string ret;
	x_convert_utf16_to_lower_utf8(begin, end, std::back_inserter(ret));
	return ret;
}

static inline std::string x_convert_utf16_to_lower_utf8(const std::u16string &src)
{
	return x_convert_utf16_to_lower_utf8(std::begin(src), std::end(src));
}


template <class InputIt, class OutputIt>
OutputIt x_convert_utf16_to_upper_utf8(InputIt begin, InputIt end, OutputIt oi)
{
	while (begin != end) {
		char16_t c = char16_t(x_toupper(*begin));
		// TODO multibytes
		++oi = x_convert_assert<char>(c);
		++begin;
	}
	return oi;
}

template <class InputIt>
std::string x_convert_utf16_to_upper_utf8(InputIt begin, InputIt end)
{
	std::string ret;
	x_convert_utf16_to_upper_utf8(begin, end, std::back_inserter(ret));
	return ret;
}

static inline std::string x_convert_utf16_to_upper_utf8(const std::u16string &src)
{
	return x_convert_utf16_to_upper_utf8(std::begin(src), std::end(src));
}


template <class InputIt, class OutputIt>
OutputIt x_convert_utf8_to_utf16(InputIt begin, InputIt end, OutputIt oi)
{
	for ( ; begin != end; ++begin) {
		unsigned char c = *begin;
		X_ASSERT(c < 0x80); // TODO
		*oi = c;
		++oi;
	}
	return oi;
}

template <class InputIt>
static inline std::u16string x_convert_utf8_to_utf16(InputIt begin, InputIt end)
{
	std::u16string ret;
	x_convert_utf8_to_utf16(begin, end, std::back_inserter(ret));
	return ret;
}

static inline std::u16string x_convert_utf8_to_utf16(const std::string &src)
{
	return x_convert_utf8_to_utf16(std::begin(src), std::end(src));
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

static inline bool x_strcase_equal(const std::u16string &s1, const std::u16string &s2)
{
	/* TODO case */
	return s1 == s2;
}

static inline bool x_strcase_equal(const std::string &s1, const std::string &s2)
{
	/* TODO case */
	return s1 == s2;
}

static inline std::string x_str_toupper(const std::string &s)
{
	/* TODO utf8 */
	std::string ret = s;
	for (auto &c: ret) {
		c = x_convert_assert<char>(std::toupper(c));
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

#endif /* __charset__hxx__ */

