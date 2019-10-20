
#include "include/utils.hxx"

std::u16string u16string_from_utf8(const char *s)
{
#if 0
	std::wstring_convert<std::codecvt_utf8_utf16<char16_t>> converter;
	return converter.from_bytes(s);
#else
	/* TODO not a real convert */
	std::u16string ret;
	if (s) {
		for ( ; *s; ++s) {
			ret.push_back(*s);
		}
	}
	return ret;
#endif
}


