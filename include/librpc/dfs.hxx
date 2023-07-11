
#ifndef __librpc__dfs__hxx__
#define __librpc__dfs__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/librpc/ndr.hxx"
#include <string.h>
#include "librpc/idl/dfs.idl.hxx"

namespace idl {
#if 0
static inline bool operator==(const GUID &id1, const GUID &id2)
{
	return memcmp(&id1, &id2, sizeof(GUID)) == 0;
}

void x_ndr_ostr(const GUID &v, x_ndr_ostr_t &os, uint32_t flags, x_ndr_switch_t level);

static inline bool operator==(const ndr_syntax_id &id1, const ndr_syntax_id &id2)
{
	return id1.uuid == id2.uuid && id1.if_version == id2.if_version;
}

void x_ndr_ostr(const ndr_syntax_id &v, x_ndr_ostr_t &os, uint32_t flags, x_ndr_switch_t level);

static inline bool operator==(const policy_handle &v1, const policy_handle &v2)
{
	return v1.handle_type == v2.handle_type && v1.uuid == v2.uuid;
}
#endif
}

#endif /* __librpc__dfs__hxx__ */

