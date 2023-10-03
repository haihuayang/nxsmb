
#include "include/charset.hxx"
#include <iostream>
#include <stdlib.h>

static void output(const std::string &str)
{
	std::cout << "'" << str << "'" << std::endl;
	for (auto ch: str) {
		char buf[8];
		snprintf(buf, sizeof buf, "%02x", uint8_t(ch));
		std::cout << buf;
	}
	std::cout << std::endl;
}

int main(int argc, char **argv)
{
	unsigned long code = strtoul(argv[1], nullptr, 0);
	std::string str;
	x_str_push_unicode(str, (char32_t)code);
	output(str);
	return 0;
}

