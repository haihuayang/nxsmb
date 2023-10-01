
#include <assert.h>
#include <cstring>
#include "include/librpc/srvsvc.hxx"
#include "include/librpc/lsa.hxx"
#include "include/librpc/winreg.hxx"
#include "common.h"

static const uint8_t srvsvc_NetShareEnumAll_requ[] = {
	0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
	0x68, 0x00, 0x68, 0x00, 0x6e, 0x00, 0x78, 0x00,
	0x73, 0x00, 0x6d, 0x00, 0x62, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x04, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
	0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t srvsvc_NetDiskEnum_requ[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
	0x00, 0x00, 0x00, 0x00,
};

static const uint8_t srvsvc_NetShareEnumAll_requ64[] = {
	0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x68, 0x00, 0x68, 0x00, 0x70, 0x00, 0x65, 0x00,
	0x72, 0x00, 0x66, 0x00, 0x31, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t lsa_LookupSids2_requ64[] = {
	0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
	0x15, 0x00, 0x00, 0x00, 0x0e, 0x7b, 0x02, 0xd1,
	0xbc, 0xd8, 0x64, 0xae, 0x1c, 0xd9, 0x21, 0x6d,
	0xf4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
	0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00,
	0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
	0x20, 0x00, 0x00, 0x00, 0x21, 0x02, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
};

static const uint8_t winreg_OpenKey_requ[] = {
	0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x5a, 0x00, 0x5a, 0x00,
	0x00, 0x00, 0x02, 0x00, 0x2d, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x2d, 0x00, 0x00, 0x00,
	0x53, 0x00, 0x4f, 0x00, 0x46, 0x00, 0x54, 0x00,
	0x57, 0x00, 0x41, 0x00, 0x52, 0x00, 0x45, 0x00,
	0x5c, 0x00, 0x4d, 0x00, 0x49, 0x00, 0x43, 0x00,
	0x52, 0x00, 0x4f, 0x00, 0x53, 0x00, 0x4f, 0x00,
	0x46, 0x00, 0x54, 0x00, 0x5c, 0x00, 0x57, 0x00,
	0x49, 0x00, 0x4e, 0x00, 0x44, 0x00, 0x4f, 0x00,
	0x57, 0x00, 0x53, 0x00, 0x20, 0x00, 0x4e, 0x00,
	0x54, 0x00, 0x5c, 0x00, 0x43, 0x00, 0x55, 0x00,
	0x52, 0x00, 0x52, 0x00, 0x45, 0x00, 0x4e, 0x00,
	0x54, 0x00, 0x56, 0x00, 0x45, 0x00, 0x52, 0x00,
	0x53, 0x00, 0x49, 0x00, 0x4f, 0x00, 0x4e, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x02,
};

static const uint8_t winreg_QueryMultipleValues_requ[] = {
	0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x04, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x1e, 0x00, 0x1e, 0x00, 0x08, 0x00, 0x02, 0x00,
	0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x0f, 0x00, 0x00, 0x00, 0x43, 0x00, 0x75, 0x00,
	0x72, 0x00, 0x72, 0x00, 0x65, 0x00, 0x6e, 0x00,
	0x74, 0x00, 0x56, 0x00, 0x65, 0x00, 0x72, 0x00,
	0x73, 0x00, 0x69, 0x00, 0x6f, 0x00, 0x6e, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x16, 0x00, 0x16, 0x00,
	0x0c, 0x00, 0x02, 0x00, 0x0b, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00,
	0x53, 0x00, 0x79, 0x00, 0x73, 0x00, 0x74, 0x00,
	0x65, 0x00, 0x6d, 0x00, 0x52, 0x00, 0x6f, 0x00,
	0x6f, 0x00, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
};

static const uint8_t winreg_EnumKey_requ[] = {
	0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x04,
	0x04, 0x00, 0x02, 0x00, 0x00, 0x02, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
};

template <class T>
void verify_requ(const uint8_t *data, size_t size, bool verify, uint32_t ndr_flags)
{
	T val;
	idl::x_ndr_off_t ret = idl::x_ndr_requ_pull(val, data, size, ndr_flags);
	assert(ret > 0);
	//idl::x_ndr_output(val, std::cout, 8, 3);

	assert((size_t)ret == size);

	std::vector<uint8_t> out;
	ret = idl::x_ndr_requ_push(val, out, ndr_flags);

	assert(ret > 0);
	assert((size_t)ret == size);

	if (verify) {
		assert(memcmp(out.data(), data, size) == 0);
	}
}

static void test_ndr()
{
	/* TODO not verify data, because it specify the size for string */
	verify_requ<idl::winreg_EnumKey>(winreg_EnumKey_requ,
			sizeof winreg_EnumKey_requ, false, 0);

	verify_requ<idl::winreg_QueryMultipleValues>(winreg_QueryMultipleValues_requ,
			sizeof winreg_QueryMultipleValues_requ, true, 0);

	verify_requ<idl::winreg_OpenKey>(winreg_OpenKey_requ,
			sizeof winreg_OpenKey_requ, true, 0);

	verify_requ<idl::lsa_LookupSids2>(lsa_LookupSids2_requ64,
			sizeof lsa_LookupSids2_requ64, false, LIBNDR_FLAG_NDR64);

	verify_requ<idl::srvsvc_NetShareEnumAll>(srvsvc_NetShareEnumAll_requ,
			sizeof srvsvc_NetShareEnumAll_requ, true, 0);
	verify_requ<idl::srvsvc_NetDiskEnum>(srvsvc_NetDiskEnum_requ,
			sizeof srvsvc_NetDiskEnum_requ, true, 0);
	/* unique ptr value could be different in 64bit, so disable verify data */
	verify_requ<idl::srvsvc_NetShareEnumAll>(srvsvc_NetShareEnumAll_requ64,
			sizeof srvsvc_NetShareEnumAll_requ64, false, LIBNDR_FLAG_NDR64);
}

int main(int argc, char  **argv)
{
	test_ndr();
	return 0;
}

