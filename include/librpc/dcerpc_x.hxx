
#ifndef __dcerpc_x__hxx__
#define __dcerpc_x__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "dcerpc.hxx"

typedef void *x_dcerpc_arg_res_t;
typedef x_dcerpc_arg_res_t (*x_dcerpc_create_fn)();
typedef void (*x_dcerpc_destroy_fn)(x_dcerpc_arg_res_t);
typedef bool (*x_dcerpc_decode_arg_fn)(x_dcerpc_arg_res_t, idl::dcerpc_request &requ);
typedef bool (*x_dcerpc_encode_res_fn)(const x_dcerpc_arg_res_t arg_res, WERROR ret,
		std::vector<uint8_t> &output);
typedef WERROR (*x_dcerpc_process_fn)(void *pipe, void *arg_res);

struct x_dcerpc_gen_t 
{
	x_dcerpc_create_fn create;
	x_dcerpc_destroy_fn destroy;
	x_dcerpc_decode_arg_fn decode_arg;
	x_dcerpc_encode_res_fn encode_res;
	x_dcerpc_process_fn process;
};

#endif /* __dcerpc_x__hxx__ */

