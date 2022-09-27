
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

/* vfs_valid_pwrite_range */
bool valid_write_range(uint64_t offset, uint64_t length)
{
	/*
	 * See MAXFILESIZE in [MS-FSA] 2.1.5.3 Server Requests a Write
	 */
	static const uint64_t maxfilesize = 0xfffffff0000;

	if (!valid_io_range(offset, length)) {
		return false;
	}

	if (length == 0) {
		return true;
	}

	uint64_t last_byte_ofs = offset + length;
	if (last_byte_ofs > maxfilesize) {
		return false;
	}

	return true;
}



