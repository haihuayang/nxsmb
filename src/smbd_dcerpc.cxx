
#include "smbd_dcerpc.hxx"

idl::dcerpc_nca_status x_smbd_dcerpc_fault(
		uint8_t &resp_type,
		std::vector<uint8_t> &body_output,
		uint32_t ndr_flags)
{
	idl::dcerpc_fault fault;
	fault.alloc_hint = 0;
	fault.context_id = 0;
	fault.cancel_count = 0;
	fault.status = idl::DCERPC_NCA_S_OP_RNG_ERROR;
	x_ndr_push(fault, body_output, ndr_flags);
	resp_type = idl::DCERPC_PKT_FAULT;
	return idl::dcerpc_nca_status(0);
}

