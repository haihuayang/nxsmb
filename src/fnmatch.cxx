
#include "misc.hxx"
#include <regex>

struct x_fnmatch_t
{
	x_fnmatch_t(const std::string &r, std::regex::flag_type flags): re(r, flags) { }
	std::regex re;
};

bool x_fnmatch_match(const x_fnmatch_t &fnmatch, const char *name)
{
	return std::regex_match(name, fnmatch.re);
}

x_fnmatch_t *x_fnmatch_create(const std::u16string &pattern, bool icase)
{
	/* std::basic_regex not support char16_t, convert to ut8
	 */
	if (pattern.length() == 0 || pattern == u"*") {
		return nullptr;
	}
	bool has_wildcard = false;
	auto options = std::regex_constants::basic;
	if (icase) {
		options |= std::regex_constants::icase;
	}

	const std::u16string escapes = u".^$+|[](){}\\";
	std::string u8 = "^";
	// TODO not support <>"
	for (auto c: pattern) {
		if (c == u'*') {
			has_wildcard = true;
			u8.push_back('.');
			u8.push_back('*');
		} else if (c == u'?') {
			has_wildcard = true;
			u8.push_back('.');
		} else if (escapes.find(c) != std::u16string::npos) {
			u8.push_back('\\');
			// TODO multibytes
			u8.push_back(x_convert_assert<char>(c));
		} else {
			if (!x_convert_utf16_to_utf8_new(&c, &c + 1, u8)) {
				X_TODO;
				return nullptr;
			}
		}
	}

	u8.push_back('$');

	(void)has_wildcard; // TODO not used for now
	return new x_fnmatch_t(u8, options);
}

void x_fnmatch_destroy(x_fnmatch_t *fnmatch)
{
	delete fnmatch;
}

