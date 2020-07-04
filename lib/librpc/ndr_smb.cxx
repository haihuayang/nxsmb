
#include "include/librpc/ndr_smb.hxx"

namespace idl {

std::ostream &operator<<(std::ostream &os, NTTIME v)
{
	if (v.val > (0x7ffffffful << 32)) {
		return os << "NEVER";
	}

	time_t sec = v.val / (1000 * 1000 * 10) - NTTIME::TIME_FIXUP_CONSTANT;
	uint32_t remain = v.val % (1000 * 1000 * 10);
	struct tm tm;
	localtime_r(&sec, &tm);

	char buf1[32];
	strftime(buf1, sizeof buf1, "%Y-%m-%d %H:%M:%S", &tm);

	char buf2[16];
	snprintf(buf2, sizeof buf2, ".%07u ", remain);

	return os << buf1 << buf2;
}

}
