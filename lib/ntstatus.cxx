
#include "include/ntstatus.hxx"

#ifdef X_ERROR_CODE_DEF
#undef X_ERROR_CODE_DEF
#endif
#define X_ERROR_CODE_DEF(n, c) { c, "STATUS_"#n },

static const struct
{
	uint32_t code;
	const char *errstr;
} nt_err_codes[] = {
#include "include/libsmb/ntstatus_gen.h"
};
