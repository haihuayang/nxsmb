
#include "include/librpc/ndr_ntlmssp.hxx"
#include "librpc/idl/ntlmssp.h"

namespace idl {

uint32_t x_ndr_ntlmssp_negotiated_string_flags(uint32_t negotiate_flags)
{
	uint32_t flags = LIBNDR_FLAG_STR_NOTERM |
			 LIBNDR_FLAG_STR_CHARLEN |
			 LIBNDR_FLAG_REMAINING;

	if (!(negotiate_flags & NTLMSSP_NEGOTIATE_UNICODE)) {
		flags |= LIBNDR_FLAG_STR_ASCII;
	}

	return flags;
}

}
