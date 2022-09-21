
#include "util_io.hxx"

/* sys_valid_io_range */
bool valid_io_range(uint64_t offset, uint64_t length)
{
	if (offset > INT64_MAX) {
		return false;
	}

	if (length > UINT32_MAX) {
		return false;
	}

	uint64_t last_byte_ofs = (uint64_t)offset + (uint64_t)length;
	if (last_byte_ofs > INT64_MAX) {
		return false;
	}

	return true;
}


