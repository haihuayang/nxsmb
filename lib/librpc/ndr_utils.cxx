
#include "include/librpc/ndr.hxx"
#include <assert.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <arpa/inet.h>

namespace idl {

x_ndr_ostr_t &next(x_ndr_ostr_t &ndr)
{
	ndr.newline = true;
	return ndr;
}

x_ndr_ostr_t &leave(x_ndr_ostr_t &ndr)
{
	X_ASSERT(ndr.depth > 0);
	--ndr.depth;
	ndr.newline = true;
	return ndr;
}

x_ndr_ostr_t &enter(x_ndr_ostr_t &ndr)
{
	++ndr.depth;
	ndr.newline = true;
	return ndr;
}

template <>
std::ostream &operator<<(std::ostream &os, x_hex_t<uint32_t> v)
{
	char buf[16];
	snprintf(buf, sizeof buf, "0x%08x", v.v);
	return os << buf;
}

template <>
std::ostream &operator<<(std::ostream &os, x_hex_t<uint64_t> v)
{
	char buf[24];
	snprintf(buf, sizeof buf, "0x%016lx", v.v);
	return os << buf;
}

template <>
std::ostream &operator<<(std::ostream &os, x_hex_t<uint16_t> v)
{
	char buf[16];
	snprintf(buf, sizeof buf, "0x%04x", v.v);
	return os << buf;
}

template <>
std::ostream &operator<<(std::ostream &os, x_hex_t<uint8_t> v)
{
	char buf[16];
	snprintf(buf, sizeof buf, "0x%02x", v.v);
	return os << buf;
}

void x_ndr_ostr_uint8_array(const uint8_t *v, x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level, size_t count)
{
	char buf[4];
	for (size_t i = 0; i < count; ++i) {
		snprintf(buf, 4, "%02x", v[i]);
		ndr.os << buf;
	}
}

#if 0
x_ndr_off_t blob_t::ndr_scalars(x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	// TODO should align? X_NDR_ALIGN(4, ndr, bpos, epos, flags);

	ndr.reserve(bpos + val.size());
	memcpy(ndr.get_data() + bpos, val.data(), val.size());
	return bpos + val.size();
}

x_ndr_off_t blob_t::ndr_scalars(x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	// TODO should align? X_NDR_ALIGN(4, ndr, bpos, epos, flags);
	val.assign(ndr.get_data() + bpos, ndr.get_data() + epos);
	return epos;
}

void blob_t::ostr(x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	ndr.os << "blob(" << val.size() << ')';
}
#endif
x_ndr_off_t DATA_BLOB::ndr_scalars(x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
#if 0
	uint32_t alignment = 1;
	if (flags & LIBNDR_FLAG_ALIGN8) {
		alignment = 8;
	} else if (flags & LIBNDR_FLAG_ALIGN4) {
		alignment = 4;
	} else if (flags & LIBNDR_FLAG_ALIGN2) {
		alignment = 2;
	}
#endif
	return x_ndr_push_bytes(val.data(), ndr, bpos, epos, val.size());
}

x_ndr_off_t DATA_BLOB::ndr_scalars(x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	val.resize(epos - bpos);
	return x_ndr_pull_bytes(val.data(), ndr, bpos, epos);
}

void DATA_BLOB::ostr(x_ndr_ostr_t &ndr, uint32_t flags, x_ndr_switch_t level) const
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	ndr.os << "DATA_BLOB(" << val.size() << ')';
}

}

