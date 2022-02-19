
#include <regex>
#include "include/charset.hxx"
#include <iostream>

int main(int argc, char *const argv[])
{
	auto args = argv + 1;
	auto options = std::regex_constants::basic;
	std::regex_constants::match_flag_type flags = std::regex_constants::match_default;
	if (strcmp(args[0], "-i") == 0) {
		options |= std::regex_constants::icase;
		++args;
	}
#if 0
	std::u16string pattern = x_convert_utf8_to_utf16(argv[1]);

	std::basic_regex<char16_t> re(pattern);

	for (int i = 2; i < argc; ++i) {
		std::u16string text = x_convert_utf8_to_utf16(argv[i]);
		if (std::regex_search(text, re)) {
			std::cout << "matched " << argv[i] << std::endl;
		} else {
			std::cout << "not matched " << argv[i] << std::endl;
		}
	}
#else
	std::string pattern = *args++;

	std::regex re(pattern, options);

	for (; *args; ++args) {
		std::string text = *args;
		if (std::regex_match(text, re)) {
			std::cout << "matched " << *args << std::endl;
		} else {
			std::cout << "not matched " << *args << std::endl;
		}
	}
#endif
	return 0;
}

