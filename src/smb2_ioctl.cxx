
#include "smbd.hxx"
#include "include/charset.hxx"
#include "smbd_open.hxx"
#include "smb2.hxx"
#include "smbd_conf.hxx"
#include "smbd_share.hxx"
#include "smb2_ioctl.hxx"
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>

struct x_smb2_in_ioctl_t
{
	uint16_t struct_size;
	uint16_t reserved0;
	uint32_t ctl_code;
	uint64_t file_id_persistent;
	uint64_t file_id_volatile;
	uint32_t input_offset;
	uint32_t input_length;
	uint32_t max_input_length;
	uint32_t output_offset;
	uint32_t output_length;
	uint32_t max_output_length;
	uint32_t flags;
	uint32_t reserved1;
};

static bool decode_in_ioctl(x_smb2_state_ioctl_t &state,
		x_buf_t *in_buf, uint32_t in_offset, uint32_t in_len)
{
	const uint8_t *in_hdr = in_buf->data + in_offset;
	const x_smb2_in_ioctl_t *in_ioctl = (const x_smb2_in_ioctl_t *)(in_hdr + sizeof(x_smb2_header_t));
	uint32_t in_input_offset = X_LE2H16(in_ioctl->input_offset);
	uint32_t in_input_length = X_LE2H32(in_ioctl->input_length);

	if (!x_check_range<uint32_t>(in_input_offset, in_input_length,
				sizeof(x_smb2_header_t) + sizeof(x_smb2_in_ioctl_t), in_len)) {
		return false;
	}

	state.ctl_code = X_LE2H32(in_ioctl->ctl_code);
	state.in_file_id_persistent = X_LE2H64(in_ioctl->file_id_persistent);
	state.in_file_id_volatile = X_LE2H64(in_ioctl->file_id_volatile);
	state.in_max_input_length = X_LE2H32(in_ioctl->max_input_length);
	state.in_max_output_length = X_LE2H32(in_ioctl->max_output_length);
	state.in_flags = X_LE2H32(in_ioctl->flags);

	if (in_input_length > 0) {
		state.in_buf = x_buf_get(in_buf);
		state.in_buf_offset = in_offset + in_input_offset;
		state.in_buf_length = in_input_length;
	}
	return true;
}

struct x_smb2_out_ioctl_t
{
	uint16_t struct_size;
	uint16_t reserved0;
	uint32_t ctl_code;
	uint64_t file_id_persistent;
	uint64_t file_id_volatile;
	uint32_t input_offset;
	uint32_t input_length;
	uint32_t output_offset;
	uint32_t output_length;
	uint64_t reserved1;
};

static void encode_out_ioctl(const x_smb2_state_ioctl_t &state,
		uint8_t *out_hdr)
{
	x_smb2_out_ioctl_t *out_ioctl = (x_smb2_out_ioctl_t *)(out_hdr + sizeof(x_smb2_header_t));
	out_ioctl->struct_size = X_H2LE16(sizeof(x_smb2_out_ioctl_t) + 1);

	out_ioctl->reserved0 = 0;
	out_ioctl->ctl_code = X_H2LE32(state.ctl_code);
	out_ioctl->file_id_persistent = X_H2LE64(state.in_file_id_persistent);
	out_ioctl->file_id_volatile = X_H2LE64(state.in_file_id_volatile);
	out_ioctl->input_offset = X_H2LE32(sizeof(x_smb2_header_t) + sizeof(x_smb2_out_ioctl_t));
	out_ioctl->input_length = 0;
	out_ioctl->output_offset = X_H2LE32(sizeof(x_smb2_header_t) + sizeof(x_smb2_out_ioctl_t));
	out_ioctl->output_length = X_H2LE32(state.out_buf_length);
	out_ioctl->reserved1 = 0;
}

static void x_smb2_reply_ioctl(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		NTSTATUS status,
		x_smb2_state_ioctl_t &state)
{
	X_LOG_OP("%ld IOCTL SUCCESS", smbd_requ->in_smb2_hdr.mid);

	x_bufref_t *bufref = x_bufref_alloc(sizeof(x_smb2_out_ioctl_t));
	if (state.out_buf_length) {
		bufref->next = new x_bufref_t(state.out_buf, 0, state.out_buf_length);
		state.out_buf = nullptr;
	}

	uint8_t *out_hdr = bufref->get_data();
	encode_out_ioctl(state, out_hdr);

	x_smb2_reply(smbd_conn, smbd_requ, bufref,
			bufref->next ? bufref->next : bufref, status, 
			sizeof(x_smb2_header_t) + sizeof(x_smb2_out_ioctl_t) + state.out_buf_length);
}


static inline bool file_id_is_nul(const x_smb2_state_ioctl_t &state)
{
	/*
	 * Some SMB2 specific CtlCodes like FSCTL_DFS_GET_REFERRALS or
	 * FSCTL_PIPE_WAIT does not take a file handle.
	 *
	 * If FileId in the SMB2 Header of the request is not
	 * 0xFFFFFFFFFFFFFFFF, then the server MUST fail the request
	 * with STATUS_INVALID_PARAMETER.
	 */
	return x_smb2_file_id_is_nul(state.in_file_id_persistent,
			state.in_file_id_volatile);
}
#if 0
static int parse_dfs_path(const std::string &in_file_name,
		std::string &host, std::string &share, std::string &relpath)
{
	// TODO NT_STATUS_ILLEGAL_CHARACTER
	const char *str = in_file_name.c_str();
	const char *sep = strchr(str, '\\');
	if (!sep) {
		return -EINVAL;
	}
	host = std::string(str, sep);
	str = sep + 1;
	sep = strchr(str, '\\');
	if (!sep) {
		share = str;
		return x_convert_assert<unsigned int>(in_file_name.length());
	} else {
		share = std::string(str, sep);
		relpath = sep + 1;
		return x_convert_assert<int>(sep - in_file_name.c_str());
	}
}

struct x_referral_t
{
	// uint32_t proximity;
	uint16_t server_type = 0;
	uint16_t flags = 0;
	uint32_t ttl;
	std::u16string path;
	std::u16string node;
};

#define DFS_HEADER_FLAG_REFERAL_SVR ( 0x00000001 )
#define DFS_HEADER_FLAG_STORAGE_SVR ( 0x00000002 )
#define DFS_HEADER_FLAG_TARGET_BCK ( 0x00000004 )

#define DFS_SERVER_ROOT 1

#define DFS_FLAG_REFERRAL_FIRST_TARGET_SET 0x0004

struct x_dfs_referral_resp_t
{
	uint16_t path_consumed;
	uint32_t header_flags;
	std::vector<x_referral_t> referrals;
};
#endif
static idl::x_ndr_off_t push_referral_v3(const x_referral_t &referral, idl::x_ndr_push_t &ndr,
		idl::x_ndr_off_t bpos, idl::x_ndr_off_t epos, uint32_t ndr_flags)
{
	idl::x_ndr_off_t base_pos = bpos;
	bpos = X_NDR_CHECK(idl::x_ndr_push_uint16(4, ndr, bpos, epos, ndr_flags)); // TODO version to be max_referral_level
	idl::x_ndr_off_t size_pos = bpos;
	bpos = X_NDR_CHECK(idl::x_ndr_push_uint16(0, ndr, bpos, epos, ndr_flags));
	bpos = X_NDR_CHECK(idl::x_ndr_push_uint16(referral.server_type, ndr, bpos, epos, ndr_flags));
	bpos = X_NDR_CHECK(idl::x_ndr_push_uint16(referral.flags, ndr, bpos, epos, ndr_flags));
	bpos = X_NDR_CHECK(idl::x_ndr_push_uint32(referral.ttl, ndr, bpos, epos, ndr_flags));
	idl::x_ndr_off_t path_pos = bpos;
	bpos = X_NDR_CHECK(idl::x_ndr_push_uint16(0, ndr, bpos, epos, ndr_flags));
	bpos = X_NDR_CHECK(idl::x_ndr_push_uint16(0, ndr, bpos, epos, ndr_flags));
	bpos = X_NDR_CHECK(idl::x_ndr_push_uint16(0, ndr, bpos, epos, ndr_flags));
	const uint8_t zeroes[16] = {0, };
	bpos = X_NDR_CHECK(idl::x_ndr_push_bytes(zeroes, ndr, bpos, epos, 16));

	uint16_t size = x_convert_assert<uint16_t>(bpos - base_pos);
	idl::x_ndr_push_uint16(size, ndr, size_pos, epos, ndr_flags);
	for (uint32_t i = 0; i < 2; ++i) {
		path_pos = idl::x_ndr_push_uint16(x_convert_assert<uint16_t>(bpos - base_pos), ndr, path_pos, epos, ndr_flags);
		bpos = X_NDR_CHECK(idl::x_ndr_scalars_string(referral.path, ndr, bpos, epos, ndr_flags, false));
	}

	path_pos = idl::x_ndr_push_uint16(x_convert_assert<uint16_t>(bpos - base_pos), ndr, path_pos, epos, ndr_flags);
	bpos = X_NDR_CHECK(idl::x_ndr_scalars_string(referral.node, ndr, bpos, epos, ndr_flags, false));

	return bpos;
}

static idl::x_ndr_off_t push_dfs_referral_resp(const x_dfs_referral_resp_t &resp,
		idl::x_ndr_push_t &ndr, idl::x_ndr_off_t bpos, idl::x_ndr_off_t epos,
		uint32_t flags)
{
	bpos = X_NDR_CHECK(idl::x_ndr_push_uint16(resp.path_consumed, ndr, bpos, epos, flags));
	bpos = X_NDR_CHECK(idl::x_ndr_push_uint16(x_convert_assert<uint16_t>(resp.referrals.size()), ndr, bpos, epos, flags));
	bpos = X_NDR_CHECK(idl::x_ndr_push_uint32(resp.header_flags, ndr, bpos, epos, flags));
	for (const auto& ref: resp.referrals) {
		bpos = X_NDR_CHECK(push_referral_v3(ref, ndr, bpos, epos, idl::x_ndr_set_flags(flags, LIBNDR_FLAG_NOALIGN)));
	}
	return bpos;
}

static NTSTATUS push_ref_resp(const x_dfs_referral_resp_t &resp, size_t in_max_output,
		x_buf_t *&out_buf, uint32_t &out_buf_length)
{
	idl::x_ndr_push_buff_t ndr_data{};
	idl::x_ndr_push_t ndr{ndr_data, 0};
	idl::x_ndr_off_t ndr_ret = push_dfs_referral_resp(resp, ndr, 0, in_max_output, 0);
	if (ndr_ret < 0) {
		return NT_STATUS_BUFFER_OVERFLOW;
	}
	out_buf = x_buf_alloc(ndr_data.data.size());
	memcpy(out_buf->data, ndr_data.data.data(), ndr_data.data.size());
	out_buf_length = x_convert_assert<uint32_t>(ndr_data.data.size());
	return NT_STATUS_OK;
}

static NTSTATUS fsctl_dfs_get_refers_internal(
		x_smbd_conn_t *smbd_conn,
		x_smb2_state_ioctl_t &state,
		uint16_t in_max_referral_level,
		const uint8_t *in_file_name_data,
		uint32_t in_file_name_size)
{
	if (in_file_name_size % 2 != 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	const char16_t *in_file_name_begin = (const char16_t *)(in_file_name_data);
	const char16_t *in_file_name_end = (const char16_t *)(in_file_name_data + in_file_name_size);
	/* trim back 0 */
	for (; in_file_name_end > in_file_name_begin; --in_file_name_end) {
		if (in_file_name_end[-1] != char16_t(0)) {
			break;
		}
	}
	
	const char16_t *in_server_begin = x_skip_sep(in_file_name_begin, in_file_name_end, u'\\');
	const char16_t *in_server_end = x_next_sep(in_server_begin, in_file_name_end, u'\\');

	if (in_server_end == in_file_name_end) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	/* TODO check server name */

	const char16_t *in_share_begin = in_server_end + 1;
	const char16_t *in_share_end = x_next_sep(in_share_begin, in_file_name_end, u'\\');

	if (in_share_end == in_share_begin) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	auto [smbd_share, smbd_volume] = x_smbd_resolve_share(in_share_begin, in_share_end);
	if (!smbd_share) {
		// TODO find_service user_share
		return NT_STATUS_NOT_FOUND;
	}

	x_dfs_referral_resp_t dfs_referral_resp;
	NTSTATUS status = smbd_share->get_dfs_referral(dfs_referral_resp,
			in_file_name_begin, in_file_name_end,
			in_server_begin, in_server_end,
			in_share_begin, in_share_end);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	return push_ref_resp(dfs_referral_resp, state.in_max_output_length, state.out_buf, state.out_buf_length);
}

/* FSCTL_DFS_GET_REFERRALS_EX References: [MS-DFSC]: 2.2.3
 */
	/* TODO should check IPC ?
	if (smbd_tcon->smbshare->type != TYPE_IPC) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}
	if (!smbd_conf->host_msdfs) {
		return NT_STATUS_FS_DRIVER_REQUIRED;
	}
	*/
static NTSTATUS x_smb2_fsctl_dfs_get_referrals(
		x_smbd_conn_t *smbd_conn,
		x_smb2_state_ioctl_t &state)
{
	if (!file_id_is_nul(state)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (state.in_buf_length < (2 + 2)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	const uint8_t *in_data = state.in_buf->data + state.in_buf_offset;
	uint16_t in_max_referral_level = x_get_le16(in_data);

	return fsctl_dfs_get_refers_internal(smbd_conn, state,
			in_max_referral_level,
			in_data + 2, state.in_buf_length - 2);
}

struct x_smb2_in_refers_ex_t
{
	uint16_t max_referral_level;
	uint16_t request_flags;
	uint32_t request_size;
};

static NTSTATUS x_smb2_fsctl_dfs_get_referrals_ex(
		x_smbd_conn_t *smbd_conn,
		x_smb2_state_ioctl_t &state)
{
	if (!file_id_is_nul(state)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (state.in_buf_length < sizeof(x_smb2_in_refers_ex_t) + 2) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	const uint8_t *in_data = state.in_buf->data + state.in_buf_offset;
	x_smb2_in_refers_ex_t in_refers_ex;
	memcpy(&in_refers_ex, in_data, sizeof(in_refers_ex));

	in_refers_ex.max_referral_level = X_LE2H16(in_refers_ex.max_referral_level);
	in_refers_ex.request_size = X_LE2H16(in_refers_ex.request_size);

	if (in_refers_ex.request_size < 2) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (in_refers_ex.request_size > state.in_buf_length - sizeof(x_smb2_in_refers_ex_t)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	uint16_t in_file_name_size = x_get_le16(in_data + sizeof(in_refers_ex));
	/* Skip check site_name here since referrals are not site dependent */
	if (in_file_name_size > in_refers_ex.request_size - 2) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return fsctl_dfs_get_refers_internal(smbd_conn, state,
			in_refers_ex.max_referral_level,
			in_data + sizeof(x_smb2_in_refers_ex_t) + 2,
			in_file_name_size);
}

static NTSTATUS x_smb2_fsctl_pipe_wait(
		x_smbd_conn_t *smbd_conn,
		x_smb2_state_ioctl_t &state)
{
	if (!file_id_is_nul(state)) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	return NT_STATUS_FS_DRIVER_REQUIRED; // TODO
}

static NTSTATUS x_smb2_fsctl_validate_negotiate_info_224(
		x_smbd_conn_t *smbd_conn,
		x_smb2_state_ioctl_t &state)
{
	if (!file_id_is_nul(state)) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	X_TODO;
	return NT_STATUS_INTERNAL_ERROR;
}

struct x_smb2_fsctl_validate_negotiate_info_in_t
{
	uint32_t capabilities;
	x_smb2_uuid_bytes_t client_guid;
	uint16_t security_mode;
	uint16_t num_dialects;
};

struct x_smb2_fsctl_validate_negotiate_info_out_t
{
	uint32_t capabilities;
	x_smb2_uuid_bytes_t server_guid;
	uint16_t security_mode;
	uint16_t dialect;
};

static NTSTATUS x_smb2_fsctl_validate_negotiate_info(
		x_smbd_conn_t *smbd_conn,
		x_smb2_state_ioctl_t &state)
{
	if (!file_id_is_nul(state)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	uint32_t in_input_size = state.in_buf_length;

	if (in_input_size < sizeof(x_smb2_fsctl_validate_negotiate_info_in_t)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (state.in_max_output_length < sizeof(x_smb2_fsctl_validate_negotiate_info_out_t)) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	x_smb2_fsctl_validate_negotiate_info_state_t fsctl_state;
	const x_smb2_fsctl_validate_negotiate_info_in_t *in = (x_smb2_fsctl_validate_negotiate_info_in_t *)(state.in_buf->data + state.in_buf_offset);

	fsctl_state.in_capabilities = X_LE2H32(in->capabilities);
	fsctl_state.in_guid.from_bytes(in->client_guid);
	fsctl_state.in_security_mode = X_LE2H16(in->security_mode);
	uint16_t in_num_dialects = X_LE2H16(in->num_dialects);
	if (in_input_size < (sizeof(x_smb2_fsctl_validate_negotiate_info_in_t)
				+ in_num_dialects * 2)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (x_smbd_conn_get_dialect(smbd_conn) >= X_SMB2_DIALECT_311) {
		return X_NT_STATUS_INTERNAL_TERMINATE;
	}

	const uint16_t *in_dialects = (const uint16_t *)(in + 1);

	fsctl_state.in_dialects.resize(in_num_dialects);
	for (uint16_t i = 0; i < in_num_dialects; ++i, ++in_dialects) {
		fsctl_state.in_dialects[i] = X_LE2H16(*in_dialects);
	}

	NTSTATUS status = x_smbd_conn_validate_negotiate_info(smbd_conn, fsctl_state);
	if (NT_STATUS_IS_OK(status)) {
		state.out_buf = x_buf_alloc(sizeof(x_smb2_fsctl_validate_negotiate_info_out_t));
		x_smb2_fsctl_validate_negotiate_info_out_t *out = (x_smb2_fsctl_validate_negotiate_info_out_t *)state.out_buf->data;
		out->capabilities = X_H2LE32(fsctl_state.out_capabilities);
		memcpy(&out->server_guid, &fsctl_state.out_guid, sizeof(out->server_guid));
		out->security_mode = X_H2LE16(fsctl_state.out_security_mode);
		out->dialect = X_H2LE16(fsctl_state.out_dialect);
		state.out_buf_length = sizeof(x_smb2_fsctl_validate_negotiate_info_out_t);
	}

	return status;
}

struct fsctl_net_iface_info_t
{
	uint32_t next;
	uint32_t ifindex;
	uint32_t capability;
	uint32_t rss_queue;
	uint64_t linkspeed;
	struct sockaddr_storage sockaddr;
};

enum {
	FSCTL_NET_IFACE_AF_INET6=(int)(0x0017),
};

static NTSTATUS x_smb2_fsctl_query_network_interface_info(
		x_smbd_conn_t *smbd_conn,
		x_smbd_tcon_t *smbd_tcon,
		x_smb2_state_ioctl_t &state)
{
	if (!file_id_is_nul(state)) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	if (!(x_smbd_conn_get_capabilities(smbd_conn) & X_SMB2_CAP_MULTI_CHANNEL)) {
		if (x_smbd_tcon_get_share(smbd_tcon)->get_type() == X_SMB2_SHARE_TYPE_PIPE) {
			return NT_STATUS_FS_DRIVER_REQUIRED;
		} else {
			return NT_STATUS_INVALID_DEVICE_REQUEST;
		}
	}

	const x_smbd_conf_t &smbd_conf = x_smbd_conf_get_curr();

	const auto &local_ifaces = *smbd_conf.local_ifaces;
	if (state.in_max_output_length < sizeof(fsctl_net_iface_info_t) * local_ifaces.size()) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	state.out_buf = x_buf_alloc(sizeof(fsctl_net_iface_info_t) * local_ifaces.size());
	uint8_t *p = state.out_buf->data;
	fsctl_net_iface_info_t *last_info = nullptr;
	fsctl_net_iface_info_t *info = (fsctl_net_iface_info_t *)p;
	for (auto &iface: local_ifaces) {
		if (last_info) {
			last_info->next = X_H2LE32(sizeof(fsctl_net_iface_info_t));
		}
		info->next = 0;
		info->ifindex = X_H2LE32(iface.if_index);
		info->capability = X_H2LE32(iface.capability);
		info->rss_queue = 0; // samba always set to 0
		info->linkspeed = X_H2LE64(iface.linkspeed);
		info->sockaddr = iface.ip;
		if (iface.ip.ss_family == AF_INET6) {
			info->sockaddr.ss_family = FSCTL_NET_IFACE_AF_INET6;
		}
		last_info = info;
		++info;
	}
	state.out_buf_length = x_convert_assert<uint32_t>(sizeof(fsctl_net_iface_info_t) * local_ifaces.size());

	return NT_STATUS_OK;
}

static void ioctl_async_done(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		NTSTATUS status)
{
	X_LOG_DBG("status=0x%x", status.v);
	auto state = smbd_requ->release_state<x_smb2_state_ioctl_t>();
	if (!smbd_conn) {
		return;
	}
	if (NT_STATUS_IS_OK(status) || state->out_buf_length) {
		x_smb2_reply_ioctl(smbd_conn, smbd_requ, status, *state);
		status = NT_STATUS_OK;
	}
	x_smbd_conn_requ_done(smbd_conn, smbd_requ, status);
}

static NTSTATUS x_smb2_ioctl_query_allocated_ranges(
		x_smbd_requ_t *smbd_requ,
		x_smb2_state_ioctl_t &state)
{
	/* TODO check tcon writable */

	auto smbd_open = smbd_requ->smbd_open;
	if (!smbd_open->check_access_any(idl::SEC_FILE_READ_DATA)) {
		X_LOG_NOTICE("query_allocated_ranges invalid access 0x%x",
				smbd_open->open_state.access_mask);
		return NT_STATUS_ACCESS_DENIED;
	}

	if (state.in_buf_length < sizeof(x_smb2_file_range_t)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	const x_smb2_file_range_t *in_qar =
		(const x_smb2_file_range_t *)(state.in_buf->data + state.in_buf_offset);
	uint64_t in_qar_off = X_LE2H64(in_qar->offset);
	uint64_t in_qar_len = X_LE2H64(in_qar->length);

	auto [object_meta, stream_meta] = x_smbd_open_op_get_meta(smbd_open);
	if (in_qar_len == 0 || stream_meta->end_of_file == 0 ||
			in_qar_off >= stream_meta->end_of_file) {
		/* zero length range or after EOF, no ranges to return */
		return NT_STATUS_OK;
	}

	uint64_t in_qar_end = in_qar_off + in_qar_len;
	if (in_qar_end < in_qar_off) {
		/* integer overflow */
		return NT_STATUS_INVALID_PARAMETER;
	}

	uint64_t max_off = std::min(stream_meta->end_of_file, in_qar_end);
	std::vector<x_smb2_file_range_t> ranges;
	if (!(object_meta->file_attributes & X_SMB2_FILE_ATTRIBUTE_SPARSE)) {
		ranges.push_back({in_qar_off, max_off - in_qar_off});
	} else {
		NTSTATUS status = x_smbd_object_query_allocated_ranges(
				smbd_open->smbd_object,
				smbd_open->smbd_stream,
				ranges,
				in_qar_off, max_off);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	size_t out_size = sizeof(x_smb2_file_range_t) * ranges.size();
	if (out_size > state.in_max_output_length) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	state.out_buf = x_buf_alloc(out_size);
	uint8_t *p = state.out_buf->data;
	x_smb2_file_range_t *out_range = (x_smb2_file_range_t *)p;
	for (auto &r: ranges) {
		out_range->offset = X_H2LE64(r.offset);
		out_range->length = X_H2LE64(r.length);
		++out_range;
	}
	state.out_buf_length = x_convert_assert<uint32_t>(out_size);
	return NT_STATUS_OK;
}

static NTSTATUS x_smb2_ioctl_set_sparse(
		x_smbd_requ_t *smbd_requ,
		x_smb2_state_ioctl_t &state)
{
	/* TODO check tcon writable */

	auto smbd_open = smbd_requ->smbd_open;
	if (!smbd_open->check_access_any(idl::SEC_FILE_WRITE_DATA |
				idl::SEC_FILE_WRITE_ATTRIBUTE |
				idl::SEC_FILE_APPEND_DATA)) {
		X_LOG_NOTICE("set_sparse invalid access 0x%x",
				smbd_open->open_state.access_mask);
		return NT_STATUS_ACCESS_DENIED;
	}

	auto smbd_object = smbd_open->smbd_object;
	if (x_smbd_object_is_dir(smbd_object)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	uint32_t set = (state.in_buf_length == 0 ||
			state.in_buf->data[state.in_buf_offset] != 0) ?
		X_SMB2_FILE_ATTRIBUTE_SPARSE : 0;

	bool modified = false;
	NTSTATUS status = x_smbd_object_set_attribute(smbd_object,
			smbd_open->smbd_stream,
			X_SMB2_FILE_ATTRIBUTE_SPARSE, set, modified);

	if (modified) {
#if 0
		windows server seems not send notify when it change
		std::vector<x_smb2_change_t> changes;
		changes.push_back(x_smb2_change_t{NOTIFY_ACTION_MODIFIED,
				FILE_NOTIFY_CHANGE_ATTRIBUTES,
				smbd_open->open_state.parent_lease_key,
				smbd_open->open_state.client_guid,
				smbd_object->path, {}});
		x_smbd_notify_change(smbd_object->smbd_volume, changes);
#endif
	}

	return status;
}

struct x_smb2_file_range2_t
{
	uint64_t begin_offset;
	uint64_t end_offset;
};

static NTSTATUS x_smb2_ioctl_set_zero_data(
		x_smbd_requ_t *smbd_requ,
		x_smb2_state_ioctl_t &state)
{
	/* TODO check tcon writable */
	auto smbd_open = smbd_requ->smbd_open;
	if (!smbd_open->check_access_any(idl::SEC_FILE_WRITE_DATA)) {
		X_LOG_NOTICE("set_sparse invalid access 0x%x",
				smbd_open->open_state.access_mask);
		return NT_STATUS_ACCESS_DENIED;
	}

	if (state.in_buf_length < sizeof(x_smb2_file_range2_t)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	const x_smb2_file_range2_t *in_range =
		(const x_smb2_file_range2_t *)(state.in_buf->data + state.in_buf_offset);
	uint64_t in_begin_offset = X_LE2H64(in_range->begin_offset);
	uint64_t in_end_offset = X_LE2H64(in_range->end_offset);

	if (in_begin_offset > in_end_offset) {
		return NT_STATUS_INVALID_PARAMETER;
	} else if (in_begin_offset == in_end_offset) {
		return NT_STATUS_OK;
	}

	return x_smbd_object_set_zero_data(smbd_open,
			in_begin_offset, in_end_offset);
}

static NTSTATUS x_smb2_ioctl_get_compression(
		x_smbd_requ_t *smbd_requ,
		x_smb2_state_ioctl_t &state)
{
	if (state.in_max_output_length < 2) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}
	state.out_buf = x_buf_alloc(2);
	state.out_buf_length = 2;
	uint16_t *data = (uint16_t *)state.out_buf->data;
	*data = 0; // TODO not support compression yet
	return NT_STATUS_OK;
}

static NTSTATUS x_smb2_ioctl_set_compression(
		x_smbd_requ_t *smbd_requ,
		x_smb2_state_ioctl_t &state)
{
	if (state.in_buf_length < 2) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	const uint8_t *in_data = state.in_buf->data + state.in_buf_offset;
	uint16_t compression_format = x_get_le16(in_data);
	return compression_format == 0 ? NT_STATUS_OK : NT_STATUS_NOT_SUPPORTED;
}

static NTSTATUS x_smbd_open_ioctl(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_ioctl_t> &state)
{
	smbd_requ->async_done_fn = ioctl_async_done;
	switch (state->ctl_code) {
	/*
	 * [MS-SMB2] 2.2.31
	 * FSCTL_SRV_COPYCHUNK is issued when a handle has
	 * FILE_READ_DATA and FILE_WRITE_DATA access to the file;
	 * FSCTL_SRV_COPYCHUNK_WRITE is issued when a handle only has
	 * FILE_WRITE_DATA access.
	 */
	case X_SMB2_FSCTL_SRV_COPYCHUNK_WRITE: /* FALL THROUGH */
	case X_SMB2_FSCTL_SRV_COPYCHUNK:
		return x_smb2_ioctl_copychunk(smbd_conn, smbd_requ, state);
	case X_SMB2_FSCTL_SRV_REQUEST_RESUME_KEY:
		return x_smb2_ioctl_request_resume_key(smbd_requ, *state);
	case X_SMB2_FSCTL_SET_SPARSE:
		return x_smb2_ioctl_set_sparse(smbd_requ, *state);
	case X_SMB2_FSCTL_SET_ZERO_DATA:
		return x_smb2_ioctl_set_zero_data(smbd_requ, *state);
	case X_SMB2_FSCTL_QUERY_ALLOCATED_RANGES:
		return x_smb2_ioctl_query_allocated_ranges(smbd_requ, *state);
	case X_SMB2_FSCTL_GET_COMPRESSION:
		return x_smb2_ioctl_get_compression(smbd_requ, *state);
	case X_SMB2_FSCTL_SET_COMPRESSION:
		return x_smb2_ioctl_set_compression(smbd_requ, *state);
	default:
		return x_smbd_open_op_ioctl(smbd_requ->smbd_open,
				smbd_requ, state);
	}
}

NTSTATUS x_smb2_process_ioctl(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	if (smbd_requ->in_requ_len < sizeof(x_smb2_header_t) + sizeof(x_smb2_in_ioctl_t)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	auto state = std::make_unique<x_smb2_state_ioctl_t>();
	if (!decode_in_ioctl(*state, smbd_requ->in_buf, smbd_requ->in_offset, smbd_requ->in_requ_len)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	X_LOG_OP("%ld IOCTL 0x%lx, 0x%lx", smbd_requ->in_smb2_hdr.mid,
			state->in_file_id_persistent, state->in_file_id_volatile);

	if (state->in_flags != X_SMB2_IOCTL_FLAG_IS_FSCTL) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_NOT_SUPPORTED);
	}

	NTSTATUS status;
	switch (state->ctl_code) {
	default:
		status = x_smbd_requ_init_open(smbd_requ,
				state->in_file_id_persistent,
				state->in_file_id_volatile,
				true);
		if (!NT_STATUS_IS_OK(status)) {
			RETURN_OP_STATUS(smbd_requ, status);
		}

		status = x_smbd_open_ioctl(smbd_conn, smbd_requ, state);
		break;
	case X_SMB2_FSCTL_DFS_GET_REFERRALS:
		status = x_smb2_fsctl_dfs_get_referrals(smbd_conn, *state);
		break;
	case X_SMB2_FSCTL_DFS_GET_REFERRALS_EX:
		status = x_smb2_fsctl_dfs_get_referrals_ex(smbd_conn, *state);
		break;
	case X_SMB2_FSCTL_PIPE_WAIT:
		status = x_smb2_fsctl_pipe_wait(smbd_conn, *state);
		break;
	case X_SMB2_FSCTL_VALIDATE_NEGOTIATE_INFO_224:
		status = x_smb2_fsctl_validate_negotiate_info_224(smbd_conn, *state);
		break;
	case X_SMB2_FSCTL_VALIDATE_NEGOTIATE_INFO:
		status = x_smb2_fsctl_validate_negotiate_info(smbd_conn, *state);
		break;
	case X_SMB2_FSCTL_QUERY_NETWORK_INTERFACE_INFO:
		status = x_smb2_fsctl_query_network_interface_info(smbd_conn,
				smbd_requ->smbd_tcon, *state);
		break;
	}

	if (NT_STATUS_IS_OK(status) || (state && state->out_buf_length)) {
		x_smb2_reply_ioctl(smbd_conn, smbd_requ, status, *state);
		return NT_STATUS_OK;
	}
	return status;
}

enum {
	X_FSCTL_SMBTORTURE_FORCE_UNACKED_TIMEOUT = 0x83848003,
};

NTSTATUS x_smb2_process_ioctl_torture(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ)
{
	if (smbd_requ->in_requ_len < sizeof(x_smb2_header_t) + sizeof(x_smb2_in_ioctl_t)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	auto state = std::make_unique<x_smb2_state_ioctl_t>();
	if (!decode_in_ioctl(*state, smbd_requ->in_buf, smbd_requ->in_offset, smbd_requ->in_requ_len)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	X_LOG_OP("%ld IOCTL 0x%lx, 0x%lx", smbd_requ->in_smb2_hdr.mid,
			state->in_file_id_persistent, state->in_file_id_volatile);

	switch (state->ctl_code) {
	case X_FSCTL_SMBTORTURE_FORCE_UNACKED_TIMEOUT:
		state->out_buf_length = 0;
		x_smb2_reply_ioctl(smbd_conn, smbd_requ, NT_STATUS_OK, *state);
		return NT_STATUS_OK;
	}
	return NT_STATUS_INVALID_PARAMETER;
}

