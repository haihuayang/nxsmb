
#ifndef __werror__hxx__
#define __werror__hxx__

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

struct WERROR
{
	uint32_t v;
};

#define X_ERROR_CODE_DEF(n, c) const WERROR WERR_##n = {c};
#include "include/libsmb/werror_gen.h"

#define W_ERROR_V(x) (x).v

#define WERR_OK WERR_SUCCESS

static inline bool W_ERROR_IS_OK(WERROR x)
{
	return W_ERROR_V(x) == 0;
}

static inline bool W_ERROR_EQUAL(WERROR x, WERROR y)
{
	return W_ERROR_V(x) == W_ERROR_V(y);
}

#endif /* __werror__hxx__ */

