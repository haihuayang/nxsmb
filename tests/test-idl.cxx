
#include <cassert>
#include <cstring>
#include <string>
// #include "librpc/idl/ntlmssp.h"
#include "include/ndr.hxx"

namespace idl {

struct test_marshall_size {
	x_ndr_off_t push(x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t extra_flags, x_ndr_switch_t level) const;
	x_ndr_off_t pull(x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t extra_flags, x_ndr_switch_t level);
	x_ndr_off_t ostr(x_ndr_ostr_t &ndr, uint32_t flags, const char *name, x_ndr_switch_t level) const;
	uint32 type;
	uint32 level;
	uint32 data;
} /* [public] */;

x_ndr_off_t test_marshall_size::push(x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t extra_flags, x_ndr_switch_t level) const
{
	// std::array<size_t, 1> marshall_size_ptrs;
	// x_ndr_off_t base = bpos = X_NDR_HEADER_ALIGN(4, ndr, bpos, epos, extra_flags);
	x_ndr_off_t base = bpos;
	X_NDR_ALIGN(4, ndr, bpos, epos, extra_flags);
	X_NDR_DATA(this->type, ndr, bpos, epos, extra_flags, X_NDR_SWITCH_NONE);
	X_NDR_ALIGN(4, ndr, bpos, epos, extra_flags);
	X_NDR_DATA(this->level, ndr, bpos, epos, extra_flags, X_NDR_SWITCH_NONE);
	X_NDR_ALIGN(4, ndr, bpos, epos, extra_flags);
	x_ndr_off_t ptr = bpos;
	X_NDR_HOLE(4, ndr, bpos, epos, extra_flags);
	X_NDR_DATA(this->data, ndr, bpos, epos, extra_flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(4, ndr, bpos, epos, extra_flags);
	X_NDR_DATA(uint32(bpos - base), ndr, ptr, epos, 0, X_NDR_SWITCH_NONE);
	return bpos;
}

x_ndr_off_t test_marshall_size::pull(x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t extra_flags, x_ndr_switch_t level)
{
	x_ndr_off_t base = bpos;
	X_NDR_ALIGN(4, ndr, bpos, epos, extra_flags);
	X_NDR_DATA(this->type, ndr, bpos, epos, extra_flags, X_NDR_SWITCH_NONE);
	X_NDR_ALIGN(4, ndr, bpos, epos, extra_flags);
	X_NDR_DATA(this->level, ndr, bpos, epos, extra_flags, X_NDR_SWITCH_NONE);
	X_NDR_ALIGN(4, ndr, bpos, epos, extra_flags);
	uint32 _marshall_size;
	X_NDR_DATA(_marshall_size, ndr, bpos, epos, extra_flags, X_NDR_SWITCH_NONE);
	X_NDR_SET_EPOS(_marshall_size, base, bpos, epos);
	X_NDR_DATA(this->data, ndr, bpos, epos, extra_flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(4, ndr, bpos, epos, extra_flags);
	return bpos;
}

struct test_relative_ptr {
	x_ndr_off_t push(x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t extra_flags, x_ndr_switch_t level) const;
	x_ndr_off_t pull(x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t extra_flags, x_ndr_switch_t level);
	x_ndr_off_t ostr(x_ndr_ostr_t &ndr, uint32_t flags, const char *name, x_ndr_switch_t level) const;
	uint32 type;
	std::string name;
	uint32 data;
};

x_ndr_off_t test_relative_ptr::push(x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t extra_flags, x_ndr_switch_t level) const
{
	// std::array<size_t, 1> relative_ptr_ptrs;
	// bpos = X_NDR_HEADER_ALIGN(4, ndr, bpos, epos, extra_flags);
	X_NDR_ALIGN(4, ndr, bpos, epos, extra_flags);
	X_NDR_DATA(this->type, ndr, bpos, epos, extra_flags, X_NDR_SWITCH_NONE);
	X_NDR_ALIGN(4, ndr, bpos, epos, extra_flags);
	x_ndr_off_t ptr = bpos;
	X_NDR_HOLE(8, ndr, bpos, epos, extra_flags);
	X_NDR_DATA(this->data, ndr, bpos, epos, extra_flags, X_NDR_SWITCH_NONE);
	X_NDR_TRAILER_ALIGN(4, ndr, bpos, epos, extra_flags);
	size_t ptr_pos = bpos;
	X_NDR_DATA(this->name, ndr, bpos, epos, extra_flags, X_NDR_SWITCH_NONE);
	size_t size = bpos - ptr_pos;
	X_NDR_DATA(uint32(size), ndr, ptr, epos, 0, X_NDR_SWITCH_NONE);
	// X_NDR_DATA(uint32(size), ndr, ptr, epos, 0, X_NDR_SWITCH_NONE);
	X_NDR_DATA(uint32(ptr_pos), ndr, ptr, epos, 0, X_NDR_SWITCH_NONE);
	return bpos;
}

x_ndr_off_t test_relative_ptr::pull(x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t extra_flags, x_ndr_switch_t level)
{
	// x_ndr_off_t base = bpos = X_NDR_HEADER_ALIGN(4, ndr, bpos, epos, extra_flags);
	X_NDR_ALIGN(4, ndr, bpos, epos, extra_flags);
	x_ndr_off_t base = bpos;
	X_NDR_DATA(this->type, ndr, bpos, epos, extra_flags, X_NDR_SWITCH_NONE);
	uint32 length, offset;
	X_NDR_DATA(length, ndr, bpos, epos, extra_flags, X_NDR_SWITCH_NONE);
	// X_NDR_DATA(maxlen, ndr, bpos, epos, extra_flags, X_NDR_SWITCH_NONE);
	X_NDR_DATA(offset, ndr, bpos, epos, extra_flags, X_NDR_SWITCH_NONE);
	X_NDR_DATA(this->data, ndr, bpos, epos, extra_flags, X_NDR_SWITCH_NONE);
	x_ndr_off_t ret = bpos;
	bpos = base + offset;
	X_NDR_DATA(this->name, ndr, bpos, bpos + length, extra_flags, X_NDR_SWITCH_NONE);
	ret = std::max(ret, bpos);
	return ret;
}

}

static void test_idl1()
{
	idl::test_marshall_size msg;
	msg.type = 1;
	msg.level = 2;
	msg.data = 0xabcdef01u;

	std::vector<uint8_t> data;
	idl::x_ndr_off_t ret = idl::x_ndr_push(msg, data);
	assert(ret > 0);

	idl::test_marshall_size msg1;
	ret = idl::x_ndr_pull(msg1, data.data(), data.size());
	assert(ret > 0);
}

static void test_idl2()
{
	idl::test_relative_ptr msg;
	msg.type = 1;
	msg.name = "hello";
	msg.data = 0xabcdef01u;

	std::vector<uint8_t> data;
	idl::x_ndr_off_t ret = idl::x_ndr_push(msg, data);
	assert(ret > 0);

	idl::test_relative_ptr msg1;
	ret = idl::x_ndr_pull(msg1, data.data(), data.size());
	assert(ret > 0);
}

int main(int argc, char  **argv)
{
	test_idl1();
	test_idl2();
	return 0;
}

