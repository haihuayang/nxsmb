
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


#endif /* __charset__hxx__ */

