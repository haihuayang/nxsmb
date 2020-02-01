
#ifndef __svc_wkssvc__hxx__
#define __svc_wkssvc__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "dcerpc_x.hxx"
#include "wkssvc_ndr.hxx"

idl::wkssvc_NetWkstaGetInfo_t *wkssvc_NetWkstaGetInfo_create();
void wkssvc_NetWkstaGetInfo_destroy(idl::wkssvc_NetWkstaGetInfo_t *);
bool wkssvc_NetWkstaGetInfo_decode_arg(idl::wkssvc_NetWkstaGetInfo_t *);
bool wkssvc_NetWkstaGetInfo_encode_res(idl::wkssvc_NetWkstaGetInfo_t *);
static WERROR wkssvc_NetWkstaGetInfo_process(x_named_pipe_t *named_pipe,
		idl::wkssvc_NetWkstaGetInfo_t *r);

struct x_dcerpc_gen_t x_dcerpc_wkssvc[] = {
	{
		(x_dcerpc_create_fn)svc_NetWkstaGetInfo_create,
		(x_dcerpc_destroy_fn)wkssvc_NetWkstaGetInfo_decode_arg,
		(x_dcerpc_decode_arg_fn)wkssvc_NetWkstaGetInfo_decode_arg,
		(x_dcerpc_encode_res_fn)wkssvc_NetWkstaGetInfo_encode_res,
		(x_dcerpc_process_fn)wkssvc_NetWkstaGetInfo_prcess,
	},
};


#endif /* __svc_wkssvc__hxx__ */

