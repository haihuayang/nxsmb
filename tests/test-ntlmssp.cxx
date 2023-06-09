
#include <cassert>
#include <cstring>
#include <iostream>
#include "include/librpc/ntlmssp.hxx"
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

static const uint8_t anonymous_authenticate_data[] = {
	0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
	0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x58, 0x00, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00,
	0x58, 0x00, 0x00, 0x00, 0x15, 0x8a, 0x00, 0x62,
	0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f,
	0x23, 0x03, 0x65, 0xd1, 0x0f, 0xa3, 0xd2, 0x92,
	0x71, 0x4d, 0xe6, 0xeb, 0x7b, 0xc5, 0x55, 0xf5,
	0xd3, 0xcf, 0xde, 0x4c, 0x93, 0x52, 0x39, 0x32,
	0x3f, 0x66, 0x14, 0xbc, 0xf0, 0x21, 0xf4, 0x57,
};

#define VERIFY(t, data, compare) \
	verify<t>(data, sizeof data, compare)

static void test_ntlmssp()
{
	// data has version, although flag does not mark
	VERIFY(idl::NEGOTIATE_MESSAGE, negotiate_data, false);

	VERIFY(idl::CHALLENGE_MESSAGE, challenge_data, true);

	// data has version, although flag does not mark, mic is present
	VERIFY(idl::AUTHENTICATE_MESSAGE, authenticate_data, false);

	// we output 0 offset if field is null, so encoded data is not exact same
	VERIFY(idl::AUTHENTICATE_MESSAGE, anonymous_authenticate_data, false);
}

int main(int argc, char  **argv)
{
	test_ntlmssp();
	return 0;
}

