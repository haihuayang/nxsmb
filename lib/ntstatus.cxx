
#include "include/ntstatus.hxx"
#include <stdio.h>

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

static __thread char ntstatus_str[24];
const char *x_ntstatus_str(NTSTATUS status)
{
	for (auto &desc: nt_err_codes) {
		if (desc.code == NT_STATUS_V(status)) {
			return desc.errstr;
		}
	}
	snprintf(ntstatus_str, sizeof(ntstatus_str),
			"STATUS_0x%x",  NT_STATUS_V(status));
	return ntstatus_str;
}
