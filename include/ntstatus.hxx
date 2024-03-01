
#ifndef __ntstatus__hxx__
#define __ntstatus__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include <stdint.h>

#ifdef X_ERROR_CODE_DEF
#undef X_ERROR_CODE_DEF
#endif
#if 0
#define X_ERROR_CODE_DEF(n, c) NT_STATUS_##n = (c),
enum
{
#include "include/libsmb/ntstatus_gen.h"
};
#endif

struct NTSTATUS
{
	bool operator==(NTSTATUS o) const { return v == o.v; }
	bool operator!=(NTSTATUS o) const { return v != o.v; }
	inline bool ok() const { return v == 0; }
	uint32_t v;
};

#define X_ERROR_CODE_DEF(n, c) const NTSTATUS NT_STATUS_##n = {c};
#include "include/libsmb/ntstatus_gen.h"

#define NT_STATUS_V(x) (x).v

#define NT_STATUS_OK NT_STATUS_SUCCESS
/* I use NT_STATUS_FOOBAR when I have no idea what error code to use -
 * this means we need a torture test */
#define NT_STATUS_FOOBAR NT_STATUS_UNSUCCESSFUL
const NTSTATUS NT_STATUS_SMB_NO_PREAUTH_INTEGRITY_HASH_OVERLAP = {0xC05D0000};

static inline bool NT_STATUS_IS_OK(NTSTATUS x)
{
	return NT_STATUS_V(x) == 0;
}

static inline bool NT_STATUS_EQUAL(NTSTATUS x, NTSTATUS y)
{
	return NT_STATUS_V(x) == NT_STATUS_V(y);
}

const char *x_ntstatus_str(NTSTATUS status);

#endif /* __ntstatus__hxx__ */

