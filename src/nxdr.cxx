
#include "nxdr.hxx"
#include "include/charset.hxx"

bool x_nxdr_utf16string_l2_le(x_nxdr_push_t &nxdr, const std::u16string &val)
{
	uint16_t length = x_convert_assert<uint16_t>(val.length() * 2);
	if (!x_nxdr_uint16(nxdr, length)) {
		return false;
	}
	for (auto ch: val) {
		if (!x_nxdr_uint16(nxdr, ch)) {
			return false;
		}
	}
	return true;
}

bool x_nxdr_utf16string_l2_le(x_nxdr_pull_t &nxdr, std::u16string &val)
{
	uint16_t length;
	if (!x_nxdr_uint16(nxdr, length)) {
		return false;
	}
	if (length % 2 != 0) {
		return false;
	}
	std::u16string tmp;
	tmp.reserve(length / 2);
	for (uint16_t i = 0; i < length / 2; ++i) {
		uint16_t ch;
		if (!x_nxdr_uint16(nxdr, ch)) {
			return false;
		}
		tmp.push_back(ch);
	}
	std::swap(val, tmp);
	return true;
}

