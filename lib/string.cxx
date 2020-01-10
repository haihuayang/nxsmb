
#include "include/xdefines.h"
#include "include/utils.hxx"

/* TODO not a real converter, maybe implement by iconv future */
std::u16string x_convert_utf8_to_utf16(const std::string &src)
{
#if 0
	std::wstring_convert<std::codecvt_utf8_utf16<char16_t>> converter;
	return converter.from_bytes(s);
#else
	/* TODO not a real convert */
	std::u16string ret;
	for (char c: src) {
		X_ASSERT((c & 0x80) == 0);
		ret.push_back(c);
	}
	return ret;
#endif
}

#if 0
std::string x_convert_utf16_to_utf8(const std::u16string &src)
{
#if 0
	std::wstring_convert<std::codecvt_utf8_utf16<char16_t>> converter;
	return converter.from_bytes(s);
#else
	/* TODO not a real convert */
	std::string ret;
	x_convert_utf16_to_utf8(std::begin(src), std::end(src), std::back_inserter(ret));
	return ret;
#endif
}
#endif

