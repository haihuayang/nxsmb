
#include <cassert>
#include <cstring>
#include <iostream>
#include "include/librpc/ntlmssp_ndr.hxx"
#include "common.h"

static const uint8_t negotiate_data[] = {
	0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x37, 0x12, 0x08, 0xe0,
	0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00,
	0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f,
};


static const uint8_t challenge_data[] = {
	0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
	0x02, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0c, 0x00,
	0x38, 0x00, 0x00, 0x00, 0x15, 0x02, 0x89, 0xe2,
	0x1f, 0xf5, 0x71, 0x23, 0x34, 0xc6, 0xc0, 0x90,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x6a, 0x00, 0x6a, 0x00, 0x44, 0x00, 0x00, 0x00,
	0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f,
	0x43, 0x00, 0x48, 0x00, 0x49, 0x00, 0x4c, 0x00,
	0x44, 0x00, 0x32, 0x00, 0x02, 0x00, 0x0c, 0x00,
	0x43, 0x00, 0x48, 0x00, 0x49, 0x00, 0x4c, 0x00,
	0x44, 0x00, 0x32, 0x00, 0x01, 0x00, 0x0c, 0x00,
	0x48, 0x00, 0x48, 0x00, 0x33, 0x00, 0x35, 0x00,
	0x30, 0x00, 0x53, 0x00, 0x04, 0x00, 0x02, 0x00,
	0x00, 0x00, 0x03, 0x00, 0x30, 0x00, 0x6e, 0x00,
	0x74, 0x00, 0x6e, 0x00, 0x78, 0x00, 0x2d, 0x00,
	0x31, 0x00, 0x30, 0x00, 0x2d, 0x00, 0x35, 0x00,
	0x33, 0x00, 0x2d, 0x00, 0x37, 0x00, 0x31, 0x00,
       	0x2d, 0x00, 0x31, 0x00, 0x33, 0x00, 0x32, 0x00,
	0x2d, 0x00, 0x61, 0x00, 0x2d, 0x00, 0x66, 0x00,
       	0x73, 0x00, 0x76, 0x00, 0x6d, 0x00, 0x07, 0x00,
	0x08, 0x00, 0x8c, 0x5f, 0x0e, 0x0d, 0x06, 0xb8,
       	0xd4, 0x01, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t authenticate_data[] = {
	0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
	0x03, 0x00, 0x00, 0x00, 0x18, 0x00, 0x18, 0x00,
	0x58, 0x00, 0x00, 0x00, 0x96, 0x00, 0x96, 0x00,
	0x70, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0c, 0x00,
	0x06, 0x01, 0x00, 0x00, 0x04, 0x00, 0x04, 0x00,
	0x12, 0x01, 0x00, 0x00, 0x0e, 0x00, 0x0e, 0x00,
	0x16, 0x01, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00,
	0x24, 0x01, 0x00, 0x00, 0x35, 0x02, 0x89, 0xe0,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xfc, 0x3e, 0xc5, 0x17, 0xa0, 0xd1, 0xa6, 0x61,
	0x9f, 0x02, 0xec, 0x70, 0xa9, 0xb6, 0xb6, 0x19,
	0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x8c, 0x5f, 0x0e, 0x0d, 0x06, 0xb8, 0xd4, 0x01,
	0x3f, 0xed, 0x1e, 0xf8, 0x54, 0x26, 0x5b, 0xe8,
	0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x0c, 0x00,
	0x43, 0x00, 0x48, 0x00, 0x49, 0x00, 0x4c, 0x00,
	0x44, 0x00, 0x32, 0x00, 0x01, 0x00, 0x0c, 0x00,
	0x48, 0x00, 0x48, 0x00, 0x33, 0x00, 0x35, 0x00,
	0x30, 0x00, 0x53, 0x00, 0x04, 0x00, 0x02, 0x00,
	0x00, 0x00, 0x03, 0x00, 0x30, 0x00, 0x6e, 0x00,
	0x74, 0x00, 0x6e, 0x00, 0x78, 0x00, 0x2d, 0x00,
	0x31, 0x00, 0x30, 0x00, 0x2d, 0x00, 0x35, 0x00,
	0x33, 0x00, 0x2d, 0x00, 0x37, 0x00, 0x31, 0x00,
	0x2d, 0x00, 0x31, 0x00, 0x33, 0x00, 0x32, 0x00,
	0x2d, 0x00, 0x61, 0x00, 0x2d, 0x00, 0x66, 0x00,
	0x73, 0x00, 0x76, 0x00, 0x6d, 0x00, 0x07, 0x00,
	0x08, 0x00, 0x8c, 0x5f, 0x0e, 0x0d, 0x06, 0xb8,
	0xd4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x43, 0x00,
	0x48, 0x00, 0x49, 0x00, 0x4c, 0x00, 0x44, 0x00,
	0x32, 0x00, 0x75, 0x00, 0x31, 0x00, 0x68, 0x00,
	0x68, 0x00, 0x2d, 0x00, 0x74, 0x00, 0x65, 0x00,
	0x73, 0x00, 0x74, 0x00, 0xd4, 0x5d, 0x2e, 0xc2,
	0x5b, 0x7c, 0x54, 0x80, 0xa4, 0x9d, 0xee, 0x04,
	0x16, 0x6b, 0xd4, 0x48, 
};
#if 0
template <class T>
static void verify(const uint8_t *data, size_t size, bool verify)
{
	T msg;
	idl::x_ndr_off_t ret = idl::x_ndr_pull(msg, data, size);
	assert(ret == long(size));

	idl::x_ndr_ostr(msg, std::cout, 8, 3);

	std::vector<uint8_t> out;
	ret = idl::x_ndr_push(msg, out);

	if (verify) {
		assert(ret == long(size));
		assert(memcmp(out.data(), data, size) == 0);
	}
}
#endif
static void test_ntlmssp()
{
	verify<idl::NEGOTIATE_MESSAGE>(negotiate_data, sizeof negotiate_data, false); // data has version, although flag does not mark
	verify<idl::CHALLENGE_MESSAGE>(challenge_data, sizeof challenge_data, true);
	verify<idl::AUTHENTICATE_MESSAGE>(authenticate_data, sizeof authenticate_data, false); // data has version, although flag does not mark, mic is present
}

int main(int argc, char  **argv)
{
	test_ntlmssp();
	return 0;
}

