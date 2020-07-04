
#ifndef __librpc__ntlmssp__hxx__
#define __librpc__ntlmssp__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "librpc/idl/ntlmssp.idl.hxx"

namespace idl {

static inline uint32_t x_ndr_ntlmssp_negotiated_string_flags(uint32_t negotiate_flags)
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

#endif /* __librpc__ntlmssp__hxx__ */

