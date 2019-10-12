
#include "include/librpc/ndr.hxx"
#include <assert.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <arpa/inet.h>

namespace idl {

x_ndr_off_t blob_t::push(x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level) const
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	X_NDR_ALIGN(4, ndr, bpos, epos, flags);

	ndr.data.resize(bpos + val.size());
	memcpy(ndr.data.data() + bpos, val.data(), val.size());
	return bpos + val.size();
}

x_ndr_off_t blob_t::pull(x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos, uint32_t flags, x_ndr_switch_t level)
{
	X_ASSERT(level == X_NDR_SWITCH_NONE);
	X_NDR_ALIGN(4, ndr, bpos, epos, flags);
	val.assign(ndr.data + bpos, ndr.data + epos);
	return epos;
}

}

