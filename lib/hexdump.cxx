
#include "include/utils.hxx"
#include <functional>

static void x_hex_dump(const void *data, size_t length,
		std::function<bool(const char *)> &&cbfunc)
{
	size_t i = 0;
	const uint8_t *d = (const uint8_t *)data;
	char tmp[80];
	char *p = tmp;
	for (i = 0; length; --length, ++d) {
		sprintf(p, "%02x ", *d);
		if (i == 15) {
			if (cbfunc(tmp)) {
				return;
			}
			i = 0;
			p = tmp;
		} else {
			++i;
			p += 3;
		}
	}

	if (i != 0) {
		cbfunc(tmp);
	}
}

std::string x_hex_dump(const void *data, size_t length, const char *prefix)
{
	std::string ret;
	x_hex_dump(data, length, [&ret,prefix](const char *str) {
			ret += prefix;
			ret += str;
			ret += '\n';
			return false;
		});
	return ret;
}

