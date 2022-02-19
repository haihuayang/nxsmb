
typedef void x_hex_dump_func(void *cbdata, const char *line);

void x_hex_dump(const void *data, size_t length,
		x_hex_dump_func cbfunc, void *cbdata)
{
	size_t i = 0;
	const uint8_t *d = data;
	char tmp[80];
	char *p = tmp;
	for (i = 0; length; --length, ++d) {
		sprintf(p, "%02x ", *d);
		if (i == 15) {
			cbfunc(cbdata, tmp);
			i = 0;
			p = tmp;
		} else {
			++i;
			p += 3;
		}
	}

	if (i != 0) {
		cbfunc(cbdata, tmp);
	}
}

