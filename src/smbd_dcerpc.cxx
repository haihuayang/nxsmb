
#include "smbd_dcerpc.hxx"

#ifndef MAX_OPEN_POLS
#define MAX_OPEN_POLS 2048
#endif


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

bool x_smbd_dcerpc_is_admin(const std::shared_ptr<x_smbd_user_t> &smbd_user)
{
	if (smbd_user->uid == idl::DOMAIN_RID_ADMINS) {
		return true;
	}
	if (smbd_user->gid == idl::DOMAIN_RID_ADMINS) {
		return true;
	}
	for (auto &ra: smbd_user->group_rids) {
		if (ra.rid == idl::DOMAIN_RID_ADMINS) {
			return true;
		}
	}
	return false;
}

static std::atomic<uint64_t> pol_hnd{0};
static std::atomic<uint64_t> pol_hnd_random{0}; // TODO samba use time(), and pid()

bool x_smbd_dcerpc_create_handle(x_dcerpc_pipe_t &rpc_pipe,
		idl::policy_handle &wire_handle,
		const std::shared_ptr<void> &data)
{
	if (rpc_pipe.handles.size() >= MAX_OPEN_POLS) {
		return false;
	}

	x_dcerpc_handle_t handle;
	handle.wire_handle.handle_type = 0;
	*(uint64_t *)&handle.wire_handle.uuid = ++pol_hnd;
	*((uint64_t *)&handle.wire_handle.uuid + 1) = ++pol_hnd_random;
	handle.data = data;
	rpc_pipe.handles.push_back(handle);

	wire_handle = handle.wire_handle;
	return true;
}

static auto find_handle(x_dcerpc_pipe_t &rpc_pipe, const idl::policy_handle &handle)
{
	auto it = std::begin(rpc_pipe.handles);
	for ( ; it != std::end(rpc_pipe.handles); ++it) {
		if (it->wire_handle == handle) {
			break;
		}
	}
	return it;
}

std::pair<bool, std::shared_ptr<void>> x_smbd_dcerpc_find_handle(
		x_dcerpc_pipe_t &rpc_pipe, const idl::policy_handle &handle)
{
	auto it = std::begin(rpc_pipe.handles);
	for ( ; it != std::end(rpc_pipe.handles); ++it) {
		if (it->wire_handle == handle) {
			return {true, it->data};
		}
	}
	return {false, nullptr};
}

bool x_smbd_dcerpc_close_handle(x_dcerpc_pipe_t &rpc_pipe,
		idl::policy_handle &handle)
{
	auto it = find_handle(rpc_pipe, handle);
	if (it == std::end(rpc_pipe.handles)) {
		return false;
	}

	rpc_pipe.handles.erase(it);
	return true;
}


