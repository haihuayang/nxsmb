
#include "smb2_ioctl.hxx"
#include "smbd_open.hxx"

enum {
	COPYCHUNK_MAX_CHUNKS = 256,
	COPYCHUNK_MAX_CHUNK_LEN = 1024 * 1024,
	COPYCHUNK_MAX_TOTAL_LEN = 16 * 1024 * 1024,
};

struct x_smb2_copychunk_t
{
	uint64_t source_offset;
	uint64_t target_offset;
	uint32_t length;
	uint32_t unused;
};

struct x_smb2_fsctl_srv_copychunk_in_t
{
	uint64_t file_id_persistent, file_id_volatile;
	uint64_t unused1;
	uint32_t chunk_count;
	uint32_t unused2;
	x_smb2_copychunk_t chunks[];
};

struct x_smb2_fsctl_srv_copychunk_out_t
{
	uint32_t chunks_written;
	uint32_t chunk_bytes_written;
	uint32_t total_bytes_writen;
};

struct x_smbd_requ_copychunk_t : x_smbd_requ_ioctl_t
{
	x_smbd_requ_copychunk_t(x_smbd_conn_t *smbd_conn, x_in_buf_t &in_buf,
			uint32_t in_msgsize, bool encrypted,
			x_smbd_requ_state_ioctl_t &state,
			uint64_t src_id_persistent, uint64_t src_id_volatile,
			std::vector<x_smb2_copychunk_t> &chunks)
		: x_smbd_requ_ioctl_t(smbd_conn, in_buf, in_msgsize, encrypted, state)
		, src_id_persistent(src_id_persistent), src_id_volatile(src_id_volatile)
		, chunks(std::move(chunks))
	{
		/* wait 1 second to send interim response */
		interim_timeout_ns = X_NSEC_PER_SEC;
	}

	NTSTATUS process(void *ctx_conn) override;
	NTSTATUS cancelled(void *ctx_conn, int reason) override
	{
		return NT_STATUS_CANCELLED;
	}

	const uint64_t src_id_persistent, src_id_volatile;
	const std::vector<x_smb2_copychunk_t> chunks;
};

struct copychunk_job_t
{
	static x_job_t::retval_t func(x_job_t *job, void *data)
	{
		auto copychunk_job = X_CONTAINER_OF(job, copychunk_job_t, base);

		auto nxfsd_requ = std::exchange(copychunk_job->nxfsd_requ, nullptr);
		auto requ = dynamic_cast<x_smbd_requ_copychunk_t *>(nxfsd_requ);
		/* TODO set processing to avoid cancel */

		NTSTATUS status = NT_STATUS_OK;
		uint32_t total_count = 0;
		uint32_t chunks_written = 0;
		for (auto &chunk : requ->chunks) {
			/* do sync read write because we have in async job */
			/* TODO use copy_file_range to avoid copying */
			x_smbd_requ_state_read_t read_state;
			read_state.in_flags = 0;
			read_state.in_length = chunk.length;
			read_state.in_offset = chunk.source_offset;
			read_state.in_minimum_count = 0;
			status = x_smbd_open_op_read(copychunk_job->src_open, nullptr,
					read_state, true);
			if (!status.ok()) {
				break;
			}

			x_smbd_requ_state_write_t write_state;
			write_state.in_offset = chunk.target_offset;
			write_state.in_flags = 0;
			write_state.in_buf.buf = std::exchange(read_state.out_buf, nullptr);
			write_state.in_buf.offset = 0;
			write_state.in_buf.length = read_state.out_buf_length;
			status = x_smbd_open_op_write(nxfsd_requ->smbd_open, nullptr,
					write_state);
			if (!NT_STATUS_IS_OK(status)) {
				break;
			}
			total_count += read_state.out_buf_length;
			++chunks_written;
		}

		requ->state.out_buf = x_buf_alloc(sizeof(x_smb2_fsctl_srv_copychunk_out_t));
		auto out = (x_smb2_fsctl_srv_copychunk_out_t *)requ->state.out_buf->data;
		out->chunks_written = X_H2LE32(chunks_written);
		out->chunk_bytes_written = 0;
		out->total_bytes_writen = X_H2LE32(total_count);
		requ->state.out_buf_length = x_convert_assert<uint32_t>(sizeof(x_smb2_fsctl_srv_copychunk_out_t));
		X_NXFSD_REQU_POST_DONE(nxfsd_requ, status);

		delete copychunk_job;
		return x_job_t::JOB_DONE;
	}

	copychunk_job_t(x_nxfsd_requ_t *nxfsd_requ, x_smbd_open_t *src_open)
		: base(func), nxfsd_requ(nxfsd_requ), src_open(src_open)
	{
	}

	~copychunk_job_t()
	{
		X_ASSERT(!nxfsd_requ);
		x_ref_dec(src_open);
	}
	x_job_t base;
	x_nxfsd_requ_t *nxfsd_requ;
	x_smbd_open_t *const src_open;
};

struct x_smbd_requ_copychunk_invalid_t : x_smbd_requ_ioctl_t
{
	using x_smbd_requ_ioctl_t::x_smbd_requ_ioctl_t;

	NTSTATUS process(void *ctx_conn) override
	{
		state.out_buf = x_buf_alloc(sizeof(x_smb2_fsctl_srv_copychunk_out_t));
		x_smb2_fsctl_srv_copychunk_out_t *out = (x_smb2_fsctl_srv_copychunk_out_t *)state.out_buf->data;
		out->chunks_written = X_H2LE32(COPYCHUNK_MAX_CHUNKS);
		out->chunk_bytes_written = X_H2LE32(COPYCHUNK_MAX_CHUNK_LEN);
		out->total_bytes_writen = X_H2LE32(COPYCHUNK_MAX_TOTAL_LEN);
		state.out_buf_length = x_convert_assert<uint32_t>(sizeof(x_smb2_fsctl_srv_copychunk_out_t));
		return NT_STATUS_INVALID_PARAMETER;
	}
};

static NTSTATUS copychunk_invalid_limit(x_smbd_conn_t *smbd_conn, x_smbd_requ_t **p_smbd_requ,
		x_in_buf_t &in_buf, uint32_t in_msgsize,
		bool encrypted, x_smbd_requ_state_ioctl_t &state)
{
	*p_smbd_requ = new x_smbd_requ_copychunk_invalid_t(smbd_conn, in_buf,
			in_msgsize, encrypted, state);
	return NT_STATUS_OK;
}

NTSTATUS x_smbd_parse_ioctl_copychunk(x_smbd_conn_t *smbd_conn, x_smbd_requ_t **p_smbd_requ,
		x_in_buf_t &in_buf, uint32_t in_msgsize,
		bool encrypted, x_smbd_requ_state_ioctl_t &state)
{
	auto in_smb2_hdr = (const x_smb2_header_t *)(in_buf.get_data());
	if (state.in_input_length < sizeof(x_smb2_fsctl_srv_copychunk_in_t)) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}
	if (state.in_max_output_length < sizeof(x_smb2_fsctl_srv_copychunk_out_t)) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}

	auto in = (const x_smb2_fsctl_srv_copychunk_in_t *)(
			(const uint8_t *)in_smb2_hdr + state.in_input_offset);
	uint32_t chunk_count = X_LE2H32(in->chunk_count);
	/*
	 * [MS-SMB2] 3.3.5.15.6 Handling a Server-Side Data Copy Request
	 * Send and invalid parameter response if:
	 * - The ChunkCount value is greater than
	 *   ServerSideCopyMaxNumberofChunks
	 */
	if (chunk_count > COPYCHUNK_MAX_CHUNKS) {
		return copychunk_invalid_limit(smbd_conn, p_smbd_requ, in_buf,
				in_msgsize, encrypted, state);
	}
	if (in->unused1 != 0) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_OBJECT_NAME_NOT_FOUND);
	}

	std::vector<x_smb2_copychunk_t> chunks;
	const x_smb2_copychunk_t *chunk = in->chunks;
	uint64_t total_asked = 0;
	for (uint32_t i = 0; i < chunk_count; ++i, ++chunk) {
		uint32_t length = X_LE2H32(chunk->length);
		if (length == 0 || length > COPYCHUNK_MAX_CHUNK_LEN) {
			return copychunk_invalid_limit(smbd_conn, p_smbd_requ, in_buf,
					in_msgsize, encrypted, state);
		}

		total_asked += length;
		chunks.push_back({X_LE2H64(chunk->source_offset),
				X_LE2H64(chunk->target_offset),
				X_LE2H32(chunk->length), 0});
	}

	if (total_asked > COPYCHUNK_MAX_TOTAL_LEN) {
		return copychunk_invalid_limit(smbd_conn, p_smbd_requ, in_buf,
				in_msgsize, encrypted, state);
	}

	*p_smbd_requ = new x_smbd_requ_copychunk_t(smbd_conn, in_buf,
			in_msgsize, encrypted,
			state,
			X_LE2H64(in->file_id_persistent),
			X_LE2H64(in->file_id_volatile),
			chunks);
	return NT_STATUS_OK;
}

static NTSTATUS copychunk_check_access(uint32_t fsctl,
		const x_smbd_open_t *src_open,
		const x_smbd_open_t *dst_open)
{
	if (!x_smbd_tcon_same_sess(src_open->smbd_tcon, dst_open->smbd_tcon)) {
		X_LOG(SMB, NOTICE, "copy chunk handles not in the same session");
		return NT_STATUS_ACCESS_DENIED;
	}

	/* TODO check closing, we do not need it for now */

	if (src_open->smbd_object->type == x_smbd_object_t::type_dir && !src_open->smbd_stream) {
		X_LOG(SMB, NOTICE, "copy chunk src not regular file or data stream");
		return NT_STATUS_ACCESS_DENIED;
	}

	if (dst_open->smbd_object->type == x_smbd_object_t::type_dir && !dst_open->smbd_stream) {
		X_LOG(SMB, NOTICE, "copy chunk dst not regular file or data stream");
		return NT_STATUS_ACCESS_DENIED;
	}

	/* TODO is IPC tcon allowed? */


	/*
	 * [MS-SMB2] 3.3.5.15.6 Handling a Server-Side Data Copy Request
	 * The server MUST fail the request with STATUS_ACCESS_DENIED if any of
	 * the following are true:
	 * - The Open.GrantedAccess of the destination file does not include
	 *   FILE_WRITE_DATA or FILE_APPEND_DATA.
	 *
	 * A non writable dst handle also doesn't make sense for other fsctls.
	 */
	if (!dst_open->check_access_any(idl::SEC_FILE_WRITE_DATA | idl::SEC_FILE_APPEND_DATA)) {
		X_LOG(SMB, NOTICE, "copy chunk dst not writable");
		return NT_STATUS_ACCESS_DENIED;
	}
	/*
	 * - The Open.GrantedAccess of the destination file does not include
	 *   FILE_READ_DATA, and the CtlCode is FSCTL_SRV_COPYCHUNK.
	 */
	if (fsctl == X_SMB2_FSCTL_SRV_COPYCHUNK && !dst_open->check_access_any(idl::SEC_FILE_READ_DATA)) {
		X_LOG(SMB, NOTICE, "copy chunk dst not readable");
		return NT_STATUS_ACCESS_DENIED;
	}
	/*
	 * - The Open.GrantedAccess of the source file does not include
	 *   FILE_READ_DATA access.
	 */
	if (!src_open->check_access_any(idl::SEC_FILE_READ_DATA |
				idl::SEC_FILE_EXECUTE)) {
		X_LOG(SMB, NOTICE, "copy chunk src not readable");
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_OK;
}

NTSTATUS x_smbd_requ_copychunk_t::process(void *ctx_conn)
{
	NTSTATUS status = x_smbd_requ_init_open(this,
			state.in_file_id_persistent, state.in_file_id_volatile,
			true);
	if (!status.ok()) {
		return status;
	}

	x_smbd_open_t *src_open = x_smbd_open_lookup(src_id_persistent,
			src_id_volatile, nullptr);

	if (!src_open) {
		X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_OBJECT_NAME_NOT_FOUND);
	}

	/* vfs_offload_token_check_handles */
	status = copychunk_check_access(state.in_ctl_code, src_open,
			this->smbd_open);
	if (!NT_STATUS_IS_OK(status)) {
		x_ref_dec(src_open);
		return status;
	}

	this->incref();
	copychunk_job_t *copychunk_job = new copychunk_job_t(this,
			src_open);
	x_smbd_schedule_async(&copychunk_job->base);
	return NT_STATUS_PENDING;
}


