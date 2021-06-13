
#ifndef __smbd_dcerpc__hxx__
#define __smbd_dcerpc__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "smbd.hxx"
#include "include/librpc/dcerpc.hxx"

typedef idl::dcerpc_nca_status (*x_dcerpc_rpc_fn_t)(
		x_smbd_conn_t *smbd_conn,
		idl::dcerpc_request request,
		uint8_t &resp_type,
		std::vector<uint8_t> &body_output,
		uint32_t ndr_flags);


struct x_dcerpc_iface_t {
	idl::ndr_syntax_id syntax_id;
	std::u16string iface_name;
	uint32_t n_cmd;
	const x_dcerpc_rpc_fn_t *cmds;
};

idl::dcerpc_nca_status x_smbd_dcerpc_fault(
		uint8_t &resp_type,
		std::vector<uint8_t> &body_output,
		uint32_t ndr_flags);

#define X_SMBD_DCERPC_FUNCTION(Arg) \
static idl::dcerpc_nca_status x_smbd_dcerpc_fn_##Arg( \
		x_smbd_conn_t *smbd_conn, \
		idl::dcerpc_request request, \
		uint8_t &resp_type, \
		std::vector<uint8_t> &body_output, \
		uint32_t ndr_flags) \
{ \
	idl::Arg arg; \
	idl::x_ndr_off_t ret = idl::x_ndr_requ_pull(arg, \
			request.stub_and_verifier.val.data(), \
			request.stub_and_verifier.val.size(), \
			ndr_flags); \
	if (ret < 0) { \
		return idl::DCERPC_NCA_S_PROTO_ERROR; \
	} \
	X_DEVEL_ASSERT(ret == (long)request.stub_and_verifier.val.size()); \
	if (x_smbd_dcerpc_impl_##Arg(smbd_conn, arg)) { \
		ret = idl::x_ndr_resp_push(arg, body_output, ndr_flags); \
		X_ASSERT(ret > 0); \
		resp_type = idl::DCERPC_PKT_RESPONSE; \
		return idl::dcerpc_nca_status(0); \
	} else { \
		return x_smbd_dcerpc_fault(resp_type, body_output, ndr_flags); \
	} \
}

extern const x_dcerpc_iface_t x_smbd_dcerpc_srvsvc;

#define X_SMBD_DCERPC_IMPL_TODO(Arg) \
static bool x_smbd_dcerpc_impl_##Arg(x_smbd_conn_t *smbd_conn, idl::Arg &arg) \
{ \
	return false; \
}

#endif /* __smbd_dcerpc__hxx__ */

