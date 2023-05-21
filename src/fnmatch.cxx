/*
   Unix SMB/CIFS implementation.
   filename matching routine
   Copyright (C) Andrew Tridgell 1992-2004

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
   This module was originally based on fnmatch.c copyright by the Free
   Software Foundation. It bears little (if any) resemblence to that
   code now
*/

/**
 * @file
 * @brief MS-style Filename matching
 */

#include "misc.hxx"

struct x_fnmatch_t
{
	x_fnmatch_t(std::u32string &&p, bool has_wild, bool i)
		: pattern(p), has_wild(has_wild), icase(i)
	{
	}
	std::u32string pattern;
	bool has_wild;
	bool icase;
};

static int null_match(const char32_t *p)
{
	for (;*p;p++) {
		if (*p != U'*' &&
		    *p != U'<' &&
		    *p != U'"' &&
		    *p != U'>') return -1;
	}
	return 0;
}

/*
  the max_n structure is purely for efficiency, it doesn't contribute
  to the matching algorithm except by ensuring that the algorithm does
  not grow exponentially
*/
struct max_n {
	const char32_t *predot;
	const char32_t *postdot;
};


/*
  p and n are the pattern and string being matched. The max_n array is
  an optimisation only. The ldot pointer is NULL if the string does
  not contain a '.', otherwise it points at the last dot in 'n'.
*/
static int ms_fnmatch_core(const char32_t *p, const char32_t *n,
			   struct max_n *max_n, const char32_t *ldot,
			   bool is_case_sensitive)
{
	while (*p) {
		char32_t c = *p++;

		switch (c) {
		case U'*':
			/* a '*' matches zero or more characters of any type */
			if (max_n != NULL && max_n->predot &&
			    max_n->predot <= n) {
				return null_match(p);
			}
			for (const char32_t *nn = n; *nn; ++nn) {
				if (ms_fnmatch_core(p, nn, max_n+1, ldot, is_case_sensitive) == 0) {
					return 0;
				}
			}
			if (max_n != NULL && (!max_n->predot ||
			    max_n->predot > n)) {
				max_n->predot = n;
			}
			return null_match(p);

		case U'<':
			/* a '<' matches zero or more characters of
			   any type, but stops matching at the last
			   '.' in the string. */
			if (max_n != NULL && max_n->predot &&
			    max_n->predot <= n) {
				return null_match(p);
			}
			if (max_n != NULL && max_n->postdot &&
			    max_n->postdot <= n && n <= ldot) {
				return -1;
			}
			for (const char32_t *nn = n; *nn; ++nn) {
				if (ms_fnmatch_core(p, nn, max_n+1, ldot, is_case_sensitive) == 0) {
					return 0;
				}
				if (nn == ldot) {
					if (ms_fnmatch_core(p, nn + 1, max_n+1, ldot, is_case_sensitive) == 0) {
						return 0;
					}
					if (max_n != NULL) {
						if (!max_n->postdot ||
						    max_n->postdot > n) {
							max_n->postdot = n;
						}
					}
					return -1;
				}
			}
			if (max_n != NULL && (!max_n->predot ||
			    max_n->predot > n)) {
				max_n->predot = n;
			}
			return null_match(p);

		case U'?':
			/* a '?' matches any single character */
			if (! *n) {
				return -1;
			}
			++n;
			break;

		case U'>':
			/* a '?' matches any single character, but
			   treats '.' specially */
			if (n[0] == '.') {
				if (! n[1] && null_match(p) == 0) {
					return 0;
				}
				break;
			}
			if (! *n) return null_match(p);
			++n;
			break;

		case U'"':
			/* a bit like a soft '.' */
			if (*n == 0 && null_match(p) == 0) {
				return 0;
			}
			if (*n != '.') return -1;
			++n;
			break;

		default:
			if (c != *n) {
				return -1;
			}
			++n;
			break;
		}
	}

	if (! *n) {
		return 0;
	}

	return -1;
}

/* samba ms_fnmatch_protocol */
bool x_fnmatch_match(const x_fnmatch_t &fnmatch, const char *name)
{
	if (strcmp(name, "..") == 0) {
		++name;
	}

	std::u32string n;
	if (fnmatch.icase) {
		if (!x_str_convert(n, std::string_view(name), x_tolower_t())) {
			return false;
		}
	} else {
		if (!x_str_convert(n, std::string_view(name))) {
			return false;
		}
	}

	if (!fnmatch.has_wild) {
		return fnmatch.pattern == n;
	}

	size_t count = 0;
	for (auto ch: fnmatch.pattern) {
		if (ch == U'*' || ch == U'<') {
			count++;
		}
	}

	const char32_t *ldot;
	auto ldot_pos = n.rfind(U'.');
	if (ldot_pos == n.npos) {
		ldot = 0;
	} else {
		ldot = n.data() + ldot_pos;
	}

	/* If the pattern includes '*' or '<' */
	int ret;
	if (count > 0) {
		struct max_n max_n[count];
		memset(max_n, 0, sizeof(struct max_n) * count);

		ret = ms_fnmatch_core(fnmatch.pattern.c_str(), n.c_str(), max_n, ldot,
				fnmatch.icase);
	} else {
		ret = ms_fnmatch_core(fnmatch.pattern.c_str(), n.c_str(), NULL, ldot,
				fnmatch.icase);
	}

	return ret == 0;
}

static const std::u32string wildcards = U"<>*?\"";
x_fnmatch_t *x_fnmatch_create(const std::u16string &pattern, bool icase)
{
	if (pattern.size() == 0 || (pattern.size() == 1 && pattern[0] == u'*')) {
		return nullptr;
	}
	std::u32string p;
	bool ret;
	if (icase) {
		ret = x_str_convert(p, pattern, x_tolower_t());
	} else {
		ret = x_str_convert(p, pattern);
	}
	X_TODO_ASSERT(ret);

	bool has_wild = false;
	for (auto c: p) {
		if (wildcards.find(c) != std::u32string::npos) {
			has_wild = true;
			break;
		}
	}
	return new x_fnmatch_t(std::move(p), has_wild, icase);
}

#if 0
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
	for (char16_t c: pattern) {
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
			if (!x_str_convert(u8, (const char16_t *)&c, (const char16_t *)&c + 1)) {
				X_TODO;
				return nullptr;
			}
		}
	}

	u8.push_back('$');

	(void)has_wildcard; // TODO not used for now
	return new x_fnmatch_t(u8, options);
}
#endif

void x_fnmatch_destroy(x_fnmatch_t *fnmatch)
{
	delete fnmatch;
}

