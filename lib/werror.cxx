
#include "include/werror.hxx"

#ifdef X_ERROR_CODE_DEF
#undef X_ERROR_CODE_DEF
#endif
#define X_ERROR_CODE_DEF(n, c) { c, "WERR_"#n },

static const struct
{
	uint32_t code;
	const char *errstr;
} werr_codes[] = {
#include "include/libsmb/werror_gen.h"
};
