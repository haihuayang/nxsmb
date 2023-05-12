
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


struct copychunk_evt_t
{
	static void func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user)
	{
		copychunk_evt_t *evt = X_CONTAINER_OF(fdevt_user, copychunk_evt_t, base);
		x_smbd_requ_t *smbd_requ = evt->smbd_requ;
		X_LOG_DBG("evt=%p, requ=%p, smbd_conn=%p", evt, smbd_requ, smbd_conn);
		x_smbd_requ_async_done(smbd_conn, smbd_requ, evt->status);
		delete evt;
	}

	copychunk_evt_t(x_smbd_requ_t *r, NTSTATUS s)
		: base(func), smbd_requ(r), status(s)
	{
	}

	~copychunk_evt_t()
	{
		x_smbd_ref_dec(smbd_requ);
	}

	x_fdevt_user_t base;
	x_smbd_requ_t * const smbd_requ;
	NTSTATUS const status;
};

struct copychunk_job_t
{
	copychunk_job_t(x_smbd_requ_t *smbd_requ, x_smbd_open_t *src_open,
			std::vector<x_smb2_copychunk_t> &&chunks);
	~copychunk_job_t()
	{
		X_ASSERT(!smbd_requ);
		x_smbd_ref_dec(src_open);
	}
	x_job_t base;
	x_smbd_requ_t *smbd_requ;
	x_smbd_open_t *const src_open;
	const std::vector<x_smb2_copychunk_t> chunks;
};

static x_job_t::retval_t copychunk_job_run(x_job_t *job)
{
	copychunk_job_t *copychunk_job = X_CONTAINER_OF(job, copychunk_job_t, base);

	x_smbd_requ_t *smbd_requ = copychunk_job->smbd_requ;
	copychunk_job->smbd_requ = nullptr;

	auto state = smbd_requ->get_requ_state<x_smb2_state_ioctl_t>();

	NTSTATUS status = NT_STATUS_OK;
	uint32_t total_count = 0;
	for (auto &chunk : copychunk_job->chunks) {
		/* do sync read write because we have in async job */
		/* TODO use copy_file_range to avoid copying */
		auto read_state = std::make_unique<x_smb2_state_read_t>();
		read_state->in_flags = 0;
		read_state->in_length = chunk.length;
		read_state->in_offset = chunk.source_offset;
		read_state->in_minimum_count = 0;
		status = x_smbd_open_op_read(copychunk_job->src_open, nullptr,
				read_state);
		if (!NT_STATUS_IS_OK(status)) {
			X_TODO;
			break;
		}

		auto write_state = std::make_unique<x_smb2_state_write_t>();
		write_state->in_offset = chunk.target_offset;
		write_state->in_flags = 0;
		write_state->in_buf = read_state->out_buf;
		read_state->out_buf = nullptr;
		write_state->in_buf_offset = 0;
		write_state->in_buf_length = read_state->out_buf_length;
		status = x_smbd_open_op_write(smbd_requ->smbd_open, nullptr,
				write_state);
		if (!NT_STATUS_IS_OK(status)) {
			X_TODO;
			break;
		}
		total_count += read_state->out_buf_length;
	}

	/* TODO handle io failure */
	state->out_buf = x_buf_alloc(sizeof(x_smb2_fsctl_srv_copychunk_out_t));
	x_smb2_fsctl_srv_copychunk_out_t *out = (x_smb2_fsctl_srv_copychunk_out_t *)state->out_buf->data;
	out->chunks_written = X_H2LE32(x_convert_assert<uint32_t>(copychunk_job->chunks.size()));
	out->chunk_bytes_written = 0;
	out->total_bytes_writen = X_H2LE32(total_count);
	state->out_buf_length = x_convert_assert<uint32_t>(sizeof(x_smb2_fsctl_srv_copychunk_out_t));

	X_SMBD_CHAN_POST_USER(smbd_requ->smbd_chan,
			new copychunk_evt_t(smbd_requ, status));
	return x_job_t::JOB_DONE;
}

static void copychunk_job_done(x_job_t *job)
{
	copychunk_job_t *copychunk_job = X_CONTAINER_OF(job, copychunk_job_t, base);
	X_ASSERT(!copychunk_job->smbd_requ);
	delete copychunk_job;
}

static const x_job_ops_t copychunk_job_ops = {
	copychunk_job_run,
	copychunk_job_done,
};

inline copychunk_job_t::copychunk_job_t(x_smbd_requ_t *smbd_requ, x_smbd_open_t *src_open,
			std::vector<x_smb2_copychunk_t> &&chunks)
	: smbd_requ(smbd_requ), src_open(src_open), chunks(chunks)
{
	base.ops = &copychunk_job_ops;
}

static void copychunk_cancel(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	x_smbd_conn_post_cancel(smbd_conn, smbd_requ, NT_STATUS_CANCELLED);
}

static NTSTATUS copychunk_invalid_limit(x_smb2_state_ioctl_t &state)
{
	state.out_buf = x_buf_alloc(sizeof(x_smb2_fsctl_srv_copychunk_out_t));
	x_smb2_fsctl_srv_copychunk_out_t *out = (x_smb2_fsctl_srv_copychunk_out_t *)state.out_buf->data;
	out->chunks_written = X_H2LE32(COPYCHUNK_MAX_CHUNKS);
	out->chunk_bytes_written = X_H2LE32(COPYCHUNK_MAX_CHUNK_LEN);
	out->total_bytes_writen = X_H2LE32(COPYCHUNK_MAX_TOTAL_LEN);
	state.out_buf_length = x_convert_assert<uint32_t>(sizeof(x_smb2_fsctl_srv_copychunk_out_t));
	return NT_STATUS_INVALID_PARAMETER;
}

static NTSTATUS copychunk_check_access(uint32_t fsctl,
		const x_smbd_open_t *src_open,
		const x_smbd_open_t *dst_open)
{
	if (!x_smbd_tcon_same_sess(src_open->smbd_tcon, dst_open->smbd_tcon)) {
		X_LOG_NOTICE("copy chunk handles not in the same session");
		return NT_STATUS_ACCESS_DENIED;
	}

	/* TODO check closing, we do not need it for now */

	if (src_open->smbd_object->type == x_smbd_object_t::type_dir && !src_open->smbd_stream) {
		X_LOG_NOTICE("copy chunk src not regular file or data stream");
		return NT_STATUS_ACCESS_DENIED;
	}

	if (dst_open->smbd_object->type == x_smbd_object_t::type_dir && !dst_open->smbd_stream) {
		X_LOG_NOTICE("copy chunk dst not regular file or data stream");
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
	if (!dst_open->check_access(idl::SEC_FILE_WRITE_DATA | idl::SEC_FILE_APPEND_DATA)) {
		X_LOG_NOTICE("copy chunk dst not writable");
		return NT_STATUS_ACCESS_DENIED;
	}
	/*
	 * - The Open.GrantedAccess of the destination file does not include
	 *   FILE_READ_DATA, and the CtlCode is FSCTL_SRV_COPYCHUNK.
	 */
	if (fsctl == X_SMB2_FSCTL_SRV_COPYCHUNK && !dst_open->check_access(idl::SEC_FILE_READ_DATA)) {
		X_LOG_NOTICE("copy chunk dst not readable");
		return NT_STATUS_ACCESS_DENIED;
	}
	/*
	 * - The Open.GrantedAccess of the source file does not include
	 *   FILE_READ_DATA access.
	 */
	if (!src_open->check_access(idl::SEC_FILE_READ_DATA)) {
		X_LOG_NOTICE("copy chunk src not readable");
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_OK;
}

NTSTATUS x_smb2_ioctl_copychunk(
		x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_ioctl_t> &state)
{
	if (state->in_buf_length < sizeof(x_smb2_fsctl_srv_copychunk_in_t)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}
	if (state->in_max_output_length < sizeof(x_smb2_fsctl_srv_copychunk_out_t)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}
	const x_smb2_fsctl_srv_copychunk_in_t *in = (x_smb2_fsctl_srv_copychunk_in_t *)(
			state->in_buf->data + state->in_buf_offset);
	uint32_t chunk_count = X_LE2H32(in->chunk_count);
	/*
	 * [MS-SMB2] 3.3.5.15.6 Handling a Server-Side Data Copy Request
	 * Send and invalid parameter response if:
	 * - The ChunkCount value is greater than
	 *   ServerSideCopyMaxNumberofChunks
	 */
	if (chunk_count > COPYCHUNK_MAX_CHUNKS) {
		return copychunk_invalid_limit(*state);
	}
	if (sizeof(x_smb2_fsctl_srv_copychunk_in_t) + chunk_count * sizeof(x_smb2_copychunk_t) >
			state->in_buf_length) {
		return copychunk_invalid_limit(*state);
	}
	if (in->unused1 != 0) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_OBJECT_NAME_NOT_FOUND);
	}

	std::vector<x_smb2_copychunk_t> chunks;
	const x_smb2_copychunk_t *chunk = in->chunks;
	uint64_t total_asked = 0;
	for (uint32_t i = 0; i < chunk_count; ++i, ++chunk) {
		uint32_t length = X_LE2H32(chunk->length);
		if (length == 0 || length > COPYCHUNK_MAX_CHUNK_LEN) {
			return copychunk_invalid_limit(*state);
		}

		total_asked += length;
		chunks.push_back({X_LE2H64(chunk->source_offset),
				X_LE2H64(chunk->target_offset),
				X_LE2H32(chunk->length), 0});
	}

	if (total_asked > COPYCHUNK_MAX_TOTAL_LEN) {
		return copychunk_invalid_limit(*state);
	}

	uint64_t src_id_persistent = X_LE2H64(in->file_id_persistent);
	uint64_t src_id_volatile = X_LE2H64(in->file_id_volatile);

	x_smbd_open_t *src_open = x_smbd_open_lookup(src_id_persistent,
			src_id_volatile, nullptr);

	if (!src_open) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_OBJECT_NAME_NOT_FOUND);
	}

	/* vfs_offload_token_check_handles */
	NTSTATUS status = copychunk_check_access(state->ctl_code, src_open, smbd_requ->smbd_open);
	if (!NT_STATUS_IS_OK(status)) {
		x_smbd_ref_dec(src_open);
		return status;
	}

	copychunk_job_t *copychunk_job = new copychunk_job_t(x_smbd_ref_inc(smbd_requ),
			src_open, std::move(chunks));
	smbd_requ->save_requ_state(state);
	x_smbd_requ_async_insert(smbd_requ, copychunk_cancel);
	x_smbd_schedule_async(&copychunk_job->base);
	return NT_STATUS_PENDING;
}

NTSTATUS x_smb2_ioctl_request_resume_key(
		x_smbd_requ_t *smbd_requ,
		x_smb2_state_ioctl_t &state)
{
	if (state.in_max_output_length < 32) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}
	state.out_buf = x_buf_alloc(32);
	state.out_buf_length = 32;
	uint64_t *data = (uint64_t *)state.out_buf->data;
	auto [ persistent_id, volatile_id ] = x_smbd_open_get_id(smbd_requ->smbd_open);
	*data++ = X_H2LE64(persistent_id);
	*data++ = X_H2LE64(volatile_id);
	*data++ = 0;
	*data++ = 0;
	return NT_STATUS_OK;
}


