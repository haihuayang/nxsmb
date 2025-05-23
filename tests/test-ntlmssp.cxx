
#include <cassert>
#include <cstring>
#include <iostream>
#include "include/librpc/ntlmssp.hxx"
#include "include/ntlmssp.hxx"
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
	0x45, 0xa5, 0x70, 0x17, 0xd1, 0x1c, 0x0c, 0x56,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x9e, 0x00, 0x9e, 0x00, 0x44, 0x00, 0x00, 0x00,
	0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f,
	0x43, 0x00, 0x48, 0x00, 0x49, 0x00, 0x4c, 0x00,
	0x44, 0x00, 0x34, 0x00, 0x02, 0x00, 0x0c, 0x00,
	0x43, 0x00, 0x48, 0x00, 0x49, 0x00, 0x4c, 0x00,
	0x44, 0x00, 0x34, 0x00, 0x01, 0x00, 0x0c, 0x00,
	0x48, 0x00, 0x48, 0x00, 0x44, 0x00, 0x4b, 0x00,
	0x53, 0x00, 0x36, 0x00, 0x04, 0x00, 0x2c, 0x00,
	0x63, 0x00, 0x68, 0x00, 0x69, 0x00, 0x6c, 0x00,
	0x64, 0x00, 0x34, 0x00, 0x2e, 0x00, 0x61, 0x00,
	0x66, 0x00, 0x73, 0x00, 0x2e, 0x00, 0x6d, 0x00,
	0x69, 0x00, 0x6e, 0x00, 0x65, 0x00, 0x72, 0x00,
	0x76, 0x00, 0x61, 0x00, 0x2e, 0x00, 0x63, 0x00,
	0x6f, 0x00, 0x6d, 0x00, 0x03, 0x00, 0x3a, 0x00,
	0x68, 0x00, 0x68, 0x00, 0x64, 0x00, 0x6b, 0x00,
	0x73, 0x00, 0x36, 0x00, 0x2e, 0x00, 0x63, 0x00,
	0x68, 0x00, 0x69, 0x00, 0x6c, 0x00, 0x64, 0x00,
	0x34, 0x00, 0x2e, 0x00, 0x61, 0x00, 0x66, 0x00,
	0x73, 0x00, 0x2e, 0x00, 0x6d, 0x00, 0x69, 0x00,
	0x6e, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00,
	0x61, 0x00, 0x2e, 0x00, 0x63, 0x00, 0x6f, 0x00,
	0x6d, 0x00, 0x07, 0x00, 0x08, 0x00, 0x14, 0xd5,
	0x77, 0x90, 0x01, 0x63, 0xda, 0x01, 0x00, 0x00,
	0x00, 0x00,
};

static const uint8_t authenticate_data[] = {
	0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
	0x03, 0x00, 0x00, 0x00, 0x18, 0x00, 0x18, 0x00,
	0x58, 0x00, 0x00, 0x00, 0xca, 0x00, 0xca, 0x00,
	0x70, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0c, 0x00,
	0x3a, 0x01, 0x00, 0x00, 0x04, 0x00, 0x04, 0x00,
	0x46, 0x01, 0x00, 0x00, 0x0c, 0x00, 0x0c, 0x00,
	0x4a, 0x01, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00,
	0x56, 0x01, 0x00, 0x00, 0x15, 0x02, 0x89, 0xe0,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x18, 0x77, 0x30, 0xcc, 0x0c, 0xb8, 0xc6, 0x37,
	0x13, 0xac, 0xa6, 0x6d, 0x8e, 0xce, 0xf7, 0x75,
	0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x14, 0xd5, 0x77, 0x90, 0x01, 0x63, 0xda, 0x01,
	0xc3, 0xad, 0xb9, 0xb2, 0x00, 0x25, 0xd8, 0xc9,
	0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x0c, 0x00,
	0x43, 0x00, 0x48, 0x00, 0x49, 0x00, 0x4c, 0x00,
	0x44, 0x00, 0x34, 0x00, 0x01, 0x00, 0x0c, 0x00,
	0x48, 0x00, 0x48, 0x00, 0x44, 0x00, 0x4b, 0x00,
	0x53, 0x00, 0x36, 0x00, 0x04, 0x00, 0x2c, 0x00,
	0x63, 0x00, 0x68, 0x00, 0x69, 0x00, 0x6c, 0x00,
	0x64, 0x00, 0x34, 0x00, 0x2e, 0x00, 0x61, 0x00,
	0x66, 0x00, 0x73, 0x00, 0x2e, 0x00, 0x6d, 0x00,
	0x69, 0x00, 0x6e, 0x00, 0x65, 0x00, 0x72, 0x00,
	0x76, 0x00, 0x61, 0x00, 0x2e, 0x00, 0x63, 0x00,
	0x6f, 0x00, 0x6d, 0x00, 0x03, 0x00, 0x3a, 0x00,
	0x68, 0x00, 0x68, 0x00, 0x64, 0x00, 0x6b, 0x00,
	0x73, 0x00, 0x36, 0x00, 0x2e, 0x00, 0x63, 0x00,
	0x68, 0x00, 0x69, 0x00, 0x6c, 0x00, 0x64, 0x00,
	0x34, 0x00, 0x2e, 0x00, 0x61, 0x00, 0x66, 0x00,
	0x73, 0x00, 0x2e, 0x00, 0x6d, 0x00, 0x69, 0x00,
	0x6e, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00,
	0x61, 0x00, 0x2e, 0x00, 0x63, 0x00, 0x6f, 0x00,
	0x6d, 0x00, 0x07, 0x00, 0x08, 0x00, 0x14, 0xd5,
	0x77, 0x90, 0x01, 0x63, 0xda, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x43, 0x00, 0x48, 0x00, 0x49, 0x00,
	0x4c, 0x00, 0x44, 0x00, 0x34, 0x00, 0x75, 0x00,
	0x32, 0x00, 0x68, 0x00, 0x68, 0x00, 0x64, 0x00,
	0x6b, 0x00, 0x63, 0x00, 0x31, 0x00, 0x07, 0x4d,
	0xc9, 0x1f, 0x68, 0xea, 0xc6, 0x04, 0xab, 0xf8,
	0x8c, 0x89, 0xbe, 0xd0, 0x4d, 0x64,
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

static void test_ntlmssp_ndr()
{
	// data has version, although flag does not mark
	VERIFY(idl::NEGOTIATE_MESSAGE, negotiate_data, false);

	VERIFY(idl::CHALLENGE_MESSAGE, challenge_data, true);

	// data has version, although flag does not mark, mic is present
	VERIFY(idl::AUTHENTICATE_MESSAGE, authenticate_data, false);

	// we output 0 offset if field is null, so encoded data is not exact same
	VERIFY(idl::AUTHENTICATE_MESSAGE, anonymous_authenticate_data, false);
}

static void test_ntlmssp_process()
{
	std::vector<uint8_t> out;
	uint8_t client_challenge[] = {
		0xc3, 0xad, 0xb9, 0xb2, 0x00, 0x25, 0xd8, 0xc9,
	};
	uint8_t exported_session_key[] = {
		0x89, 0xb2, 0x2b, 0x58, 0xf9, 0x0a, 0x00, 0xdf,
		0xa8, 0x76, 0xaa, 0x86, 0xcc, 0xf6, 0xa7, 0xc2,
	};
	int err = x_ntlmssp_client_authenticate(out, challenge_data, sizeof challenge_data,
			client_challenge, exported_session_key,
			"u2", "nutanix/4u", "CHILD4", "hhdkc1");
	X_ASSERT(err == 0);
	X_ASSERT(out.size() == sizeof(authenticate_data));
	X_ASSERT(memcmp(out.data(), authenticate_data, out.size()) == 0);
}

int main(int argc, char  **argv)
{
	test_ntlmssp_ndr();
	test_ntlmssp_process();
	return 0;
}

