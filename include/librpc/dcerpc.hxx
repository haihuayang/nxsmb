
#ifndef __librpc__dcerpc__hxx__
#define __librpc__dcerpc__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/librpc/ndr_smb.hxx"

namespace idl {
//extern const uint8_t DCERPC_SEC_VT_MAGIC[8];
//const uint8_t DCERPC_SEC_VT_MAGIC[] = {0x8a,0xe3,0x13,0x71,0x02,0xf4,0x36,0x71};
#define DCERPC_SEC_VT_MAGIC {0x8a,0xe3,0x13,0x71,0x02,0xf4,0x36,0x71}
}

#include "librpc/idl/dcerpc.idl.hxx"


#endif /* __librpc__dcerpc__hxx__ */

