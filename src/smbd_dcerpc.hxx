
#ifndef __smbd_dcerpc__hxx__
#define __smbd_dcerpc__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "smbd.hxx"
#include "include/librpc/dcerpc.hxx"

struct x_dcerpc_handle_t
{
	idl::policy_handle wire_handle;
	uint32_t access_granted;
	std::shared_ptr<void> data;
};

struct x_dcerpc_pipe_t {
	std::vector<x_dcerpc_handle_t> handles;
};

typedef idl::dcerpc_nca_status (*x_dcerpc_rpc_fn_t)(
		x_dcerpc_pipe_t &rpc_pipe,
		const std::shared_ptr<x_smbd_user_t> &smbd_user,
		idl::dcerpc_request request,
		uint8_t &resp_type,
		std::vector<uint8_t> &body_output,
		uint32_t ndr_flags);


struct x_dcerpc_iface_t {
	idl::ndr_syntax_id syntax_id;
	uint32_t n_cmd;
	const x_dcerpc_rpc_fn_t *cmds;
};

idl::dcerpc_nca_status x_smbd_dcerpc_fault(
		uint8_t &resp_type,
		std::vector<uint8_t> &body_output,
		uint32_t ndr_flags);

#define X_SMBD_DCERPC_NCA_STATUS_OK (idl::dcerpc_nca_status(0))

#define X_SMBD_DCERPC_FUNCTION(Arg) \
static idl::dcerpc_nca_status x_smbd_dcerpc_fn_##Arg( \
		x_dcerpc_pipe_t &rpc_pipe, \
		const std::shared_ptr<x_smbd_user_t> &smbd_user, \
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
	idl::dcerpc_nca_status status = x_smbd_dcerpc_impl_##Arg(rpc_pipe, smbd_user, arg); \
	if (status == X_SMBD_DCERPC_NCA_STATUS_OK) { \
		ret = idl::x_ndr_resp_push(arg, body_output, ndr_flags); \
		X_ASSERT(ret > 0); \
		resp_type = idl::DCERPC_PKT_RESPONSE; \
	} \
	return status; \
}

#define X_SMBD_DCERPC_IFACE_ENUM \
	X_SMBD_DCERPC_IFACE_DECL(srvsvc) \
	X_SMBD_DCERPC_IFACE_DECL(wkssvc) \
	X_SMBD_DCERPC_IFACE_DECL(dssetup) \
	X_SMBD_DCERPC_IFACE_DECL(lsarpc) \
	X_SMBD_DCERPC_IFACE_DECL(winreg) \

#define X_SMBD_DCERPC_IFACE_DECL(x) extern const x_dcerpc_iface_t x_smbd_dcerpc_##x;
X_SMBD_DCERPC_IFACE_ENUM
#undef X_SMBD_DCERPC_IFACE_DECL

bool x_smbd_dcerpc_is_admin(const std::shared_ptr<x_smbd_user_t> &smbd_user);

#define X_SMBD_DCERPC_CHECK_ADMIN_ACCESS(smbd_user, arg) do { \
	if (!x_smbd_dcerpc_is_admin(smbd_user)) { \
		arg.__result = WERR_ACCESS_DENIED; \
		return X_SMBD_DCERPC_NCA_STATUS_OK; \
	} \
} while (0)

bool x_smbd_dcerpc_create_handle(x_dcerpc_pipe_t &rpc_pipe,
		idl::policy_handle &wire_handle,
		const std::shared_ptr<void> &data);

bool x_smbd_dcerpc_close_handle(x_dcerpc_pipe_t &rpc_pipe,
		idl::policy_handle &handle);

std::pair<bool, std::shared_ptr<void>> x_smbd_dcerpc_find_handle(
		x_dcerpc_pipe_t &rpc_pipe, const idl::policy_handle &handle);

#define X_SMBD_DCERPC_IMPL_TODO(Arg) \
static idl::dcerpc_nca_status x_smbd_dcerpc_impl_##Arg(x_dcerpc_pipe_t &rpc_pipe, const std::shared_ptr<x_smbd_user_t> &smbd_user, idl::Arg &arg) \
{ \
	X_TODO; \
	return idl::DCERPC_NCA_S_FAULT_UNSPEC; \
}

#define X_SMBD_DCERPC_IMPL_NOT_SUPPORTED(Arg) \
static idl::dcerpc_nca_status x_smbd_dcerpc_impl_##Arg(x_dcerpc_pipe_t &rpc_pipe, const std::shared_ptr<x_smbd_user_t> &smbd_user, idl::Arg &arg) \
{ \
	(arg).__result = WERR_NOT_SUPPORTED; \
	return X_SMBD_DCERPC_NCA_STATUS_OK; \
}

#define X_SMBD_DCERPC_IMPL_NT_NOT_SUPPORTED(Arg) \
static idl::dcerpc_nca_status x_smbd_dcerpc_impl_##Arg(x_dcerpc_pipe_t &rpc_pipe, const std::shared_ptr<x_smbd_user_t> &smbd_user, idl::Arg &arg) \
{ \
	(arg).__result = NT_STATUS_NOT_SUPPORTED; \
	return X_SMBD_DCERPC_NCA_STATUS_OK; \
}

#endif /* __smbd_dcerpc__hxx__ */

