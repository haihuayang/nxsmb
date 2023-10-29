
#include "smbd.hxx"
#include "smbd_open.hxx"
#include "smbd_ntacl.hxx"
#include "smbd_stats.hxx"
#include "smbd_conf.hxx"

enum {
	X_SMB2_FIND_REQU_BODY_LEN = 0x20,
	X_SMB2_FIND_RESP_BODY_LEN = 0x08,
};

struct x_smb2_in_qdir_t
{
	uint16_t struct_size;
	uint8_t info_level;
	uint8_t flags;
	uint32_t file_index;
	uint64_t file_id_persistent;
	uint64_t file_id_volatile;
	uint16_t name_offset;
	uint16_t name_length;
	uint32_t output_buffer_length;
};

static bool decode_in_qdir(x_smbd_requ_state_qdir_t &state,
		const uint8_t *in_hdr, uint32_t in_len)
{
	const x_smb2_in_qdir_t *in_qdir = (const x_smb2_in_qdir_t *)(in_hdr + sizeof(x_smb2_header_t));

	uint16_t in_name_offset             = X_LE2H16(in_qdir->name_offset);
	uint16_t in_name_length             = X_LE2H16(in_qdir->name_length);

	if (in_name_length % 2 != 0 || !x_check_range<uint32_t>(in_name_offset, in_name_length, 
				sizeof(x_smb2_header_t) + sizeof(x_smb2_in_qdir_t), in_len)) {
		return false;
	}

	state.in_info_level = x_smb2_info_level_t(X_LE2H8(in_qdir->info_level));
	state.in_flags = X_LE2H8(in_qdir->flags);
	state.in_file_index = X_LE2H32(in_qdir->file_index);
	state.in_file_id_persistent = X_LE2H64(in_qdir->file_id_persistent);
	state.in_file_id_volatile = X_LE2H64(in_qdir->file_id_volatile);
	state.in_output_buffer_length = X_LE2H32(in_qdir->output_buffer_length);

	state.in_name.assign((char16_t *)(in_hdr + in_name_offset),
			(char16_t *)(in_hdr + in_name_offset + in_name_length));

	return true;
}

struct x_smb2_out_qdir_t
{
	uint16_t struct_size;
	uint16_t offset;
	uint32_t length;
};

static void encode_out_qdir(const x_smbd_requ_state_qdir_t &state,
		uint8_t *out_hdr)
{
	x_smb2_out_qdir_t *out_qdir = (x_smb2_out_qdir_t *)(out_hdr + sizeof(x_smb2_header_t));

	out_qdir->struct_size = X_H2LE16(sizeof(x_smb2_out_qdir_t) + 1);
	out_qdir->offset = X_H2LE16(sizeof(x_smb2_header_t) + sizeof(x_smb2_out_qdir_t));
	out_qdir->length = X_H2LE32(x_convert_assert<uint32_t>(state.out_buf_length));
}

static void x_smb2_reply_qdir(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		x_smbd_requ_state_qdir_t &state)
{
	x_bufref_t *bufref = x_bufref_alloc(sizeof(x_smb2_out_qdir_t));
	if (state.out_buf_length) {
		bufref->next = new x_bufref_t(state.out_buf, 0, state.out_buf_length);
		state.out_buf = nullptr;
	}

	uint8_t *out_hdr = bufref->get_data();
	encode_out_qdir(state, out_hdr);

	x_smb2_reply(smbd_conn, smbd_requ, bufref,
			bufref->next ? bufref->next : bufref, NT_STATUS_OK, 
			sizeof(x_smb2_header_t) + sizeof(x_smb2_out_qdir_t) + state.out_buf_length);
}


void x_smbd_requ_state_qdir_t::async_done(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		NTSTATUS status)
{
	X_SMBD_REQU_LOG(OP, smbd_requ, " %s", x_ntstatus_str(status));
	if (!smbd_conn) {
		return;
	}
	if (NT_STATUS_IS_OK(status)) {
		x_smb2_reply_qdir(smbd_conn, smbd_requ, *this);
	}
	x_smbd_conn_requ_done(smbd_conn, smbd_requ, status);
}

static bool smbd_qdir_queue_req(x_smbd_qdir_t *smbd_qdir, x_smbd_requ_t *smbd_requ)
{
	auto &requ_list = smbd_qdir->requ_list;
	x_smbd_ref_inc(smbd_requ);
	for (auto curr_requ = requ_list.get_back(); curr_requ;
			curr_requ = requ_list.prev(curr_requ)) {
		X_ASSERT(smbd_requ->compound_id != curr_requ->compound_id);
		if (smbd_requ->compound_id > curr_requ->compound_id) {
			requ_list.insert_after(smbd_requ, curr_requ);
			return false;
		}
	}

	requ_list.push_front(smbd_requ);
	return smbd_qdir->compound_id_blocking == smbd_requ->compound_id;
}

#define DIR_READ_ACCESS_MASK (idl::SEC_FILE_READ_DATA| \
		idl::SEC_FILE_READ_EA| \
		idl::SEC_FILE_READ_ATTRIBUTE| \
		idl::SEC_STD_READ_CONTROL)

static NTSTATUS smbd_qdir_process_requ(x_smbd_qdir_t *smbd_qdir, x_smbd_requ_t *smbd_requ)
{
	if (smbd_qdir->delay_ms) {
		usleep(smbd_qdir->delay_ms * 1000);
	}
	auto state = smbd_requ->get_requ_state<x_smbd_requ_state_qdir_t>();
	if (smbd_qdir->total_count == 0 ||
			(state->in_flags & (X_SMB2_CONTINUE_FLAG_REOPEN |
					    X_SMB2_CONTINUE_FLAG_RESTART))) {
		smbd_qdir->error_status = NT_STATUS_OK;
		if (smbd_qdir->fnmatch) {
			x_fnmatch_destroy(smbd_qdir->fnmatch);
		}
		smbd_qdir->fnmatch = x_fnmatch_create(state->in_name, true);
		smbd_qdir->ops->rewind(smbd_qdir);

	} else if (!NT_STATUS_IS_OK(smbd_qdir->error_status)) {
		return smbd_qdir->error_status;
	}

	state->out_buf = x_buf_alloc(state->in_output_buffer_length);
	if (!state->out_buf) {
		return NT_STATUS_NO_MEMORY;
	}

	uint32_t max_count = 0x7fffffffu;
	if (state->in_flags & X_SMB2_CONTINUE_FLAG_SINGLE) {
		max_count = 1;
	}
	std::shared_ptr<idl::security_descriptor> psd, *ppsd = nullptr;
	std::shared_ptr<x_smbd_user_t> smbd_user;
	if (x_smbd_tcon_get_abe(smbd_requ->smbd_tcon)) {
		ppsd = &psd;
		smbd_user = x_smbd_sess_get_user(smbd_requ->smbd_sess);
	}

	uint32_t num = 0, matched_count = 0;

	x_smb2_chain_marshall_t marshall{state->out_buf->data,
		state->out_buf->data + state->out_buf->size, 8};
	while (num < max_count) {
		x_smbd_object_meta_t object_meta;
		x_smbd_stream_meta_t stream_meta;
		std::u16string ent_name;
		x_smbd_qdir_pos_t qdir_pos;
		if (!smbd_qdir->ops->get_entry(smbd_qdir, qdir_pos,
					ent_name,
					object_meta, stream_meta, ppsd)) {
			break;
		}
		if (psd) {
			uint32_t access = se_calculate_maximal_access(*psd, *smbd_user);
			psd = nullptr;
			if ((access & DIR_READ_ACCESS_MASK) != DIR_READ_ACCESS_MASK) {
				X_LOG(SMB, DBG, "entry '%s' skip by ABE",
						x_str_todebug(ent_name).c_str());
				continue;
			}
		}

		++matched_count;
		if (x_smbd_marshall_dir_entry(marshall, object_meta, stream_meta,
					ent_name, state->in_info_level)) {
			++num;
		} else {
			x_smbd_qdir_unget_entry(smbd_qdir, qdir_pos);
			max_count = num;
		}
	}

	if (num > 0) {
		smbd_qdir->total_count += num;
		state->out_buf_length = marshall.get_size();
		return NT_STATUS_OK;
	}
	
	x_buf_release(state->out_buf);
	state->out_buf = nullptr;
	if (matched_count > 0) {
		return NT_STATUS_INFO_LENGTH_MISMATCH;
	} else {
		return smbd_qdir->error_status = (smbd_qdir->total_count == 0 ?
				NT_STATUS_NO_SUCH_FILE : NT_STATUS_NO_MORE_FILES);
	}
}

struct smbd_qdir_evt_t
{
	static void func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user)
	{
		smbd_qdir_evt_t *evt = X_CONTAINER_OF(fdevt_user, smbd_qdir_evt_t, base);
		x_smbd_requ_t *smbd_requ = evt->smbd_requ;
		X_LOG(SMB, DBG, "evt=%p, requ=%p, smbd_conn=%p", evt, smbd_requ, smbd_conn);
		x_smbd_requ_async_done(smbd_conn, smbd_requ, evt->status);
		delete evt;
	}

	smbd_qdir_evt_t(x_smbd_requ_t *r, NTSTATUS s)
		: base(func), smbd_requ(r), status(s)
	{
	}
	~smbd_qdir_evt_t()
	{
		x_smbd_ref_dec(smbd_requ);
	}
	x_fdevt_user_t base;
	x_smbd_requ_t * const smbd_requ;
	NTSTATUS const status;
};

static x_job_t::retval_t smbd_qdir_job_run(x_job_t *job, void *sche)
{
	x_smbd_qdir_t *smbd_qdir = X_CONTAINER_OF(job, x_smbd_qdir_t, base);
	x_smbd_object_t *smbd_object = smbd_qdir->smbd_open->smbd_object;
	{
		auto lock = std::unique_lock(smbd_object->mutex);
		for (;;) {
			x_smbd_requ_t *smbd_requ = smbd_qdir->requ_list.get_front();
			if (!smbd_requ) {
				break;
			}
			if (smbd_qdir->compound_id_blocking != 0 &&
					smbd_qdir->compound_id_blocking != smbd_requ->compound_id) {
				break;
			}
			smbd_qdir->requ_list.remove(smbd_requ);
			lock.unlock();

			if (!smbd_qdir->closed) {
				NTSTATUS status = smbd_qdir_process_requ(smbd_qdir, smbd_requ);
				X_SMBD_CHAN_POST_USER(smbd_requ->smbd_chan,
						new smbd_qdir_evt_t(smbd_requ, status));
			} else {
				X_SMBD_CHAN_POST_USER(smbd_requ->smbd_chan,
						new smbd_qdir_evt_t(smbd_requ, NT_STATUS_FILE_CLOSED));
			}
			lock.lock();
		}
		if (!smbd_qdir->closed) {
			return  x_job_t::JOB_BLOCKED;
		}
	}
	smbd_qdir->ops->destroy(smbd_qdir);
	return x_job_t::JOB_DONE;
}

x_smbd_qdir_t::x_smbd_qdir_t(x_smbd_open_t *smbd_open, const x_smbd_qdir_ops_t *ops)
	: base(smbd_qdir_job_run), ops(ops), smbd_open(x_smbd_ref_inc(smbd_open))
	, delay_ms(x_smbd_conf_get_curr().my_dev_delay_qdir_ms)
{
	X_SMBD_COUNTER_INC_CREATE(qdir, 1);
}

x_smbd_qdir_t::~x_smbd_qdir_t()
{
	X_ASSERT(!requ_list.get_front());
	if (fnmatch) {
		x_fnmatch_destroy(fnmatch);
	}
	x_smbd_ref_dec(smbd_open);
	X_SMBD_COUNTER_INC_DELETE(qdir, 1);
}

static void smbd_qdir_cancel(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	x_smbd_open_t *smbd_open = smbd_requ->smbd_open;
	{
		auto lock = std::lock_guard(smbd_open->smbd_object->mutex);
		x_smbd_qdir_t *smbd_qdir = smbd_requ->smbd_open->smbd_qdir;
		if (!smbd_qdir) {
			/* smbd_qdir is closed, do nothing */
			return;
		}
		/* TODO check if processing the requ, if so, cannot remove it */
		smbd_qdir->requ_list.remove(smbd_requ);
	}
	x_smbd_conn_post_cancel(smbd_conn, smbd_requ, NT_STATUS_CANCELLED);
}

NTSTATUS x_smb2_process_query_directory(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	if (smbd_requ->in_requ_len < sizeof(x_smb2_header_t) + sizeof(x_smb2_in_qdir_t)) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	const uint8_t *in_hdr = smbd_requ->get_in_data();

	auto state = std::make_unique<x_smbd_requ_state_qdir_t>();
	if (!decode_in_qdir(*state, in_hdr, smbd_requ->in_requ_len)) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	X_SMBD_REQU_LOG(OP, smbd_requ,  " open=0x%lx,0x%lx",
			state->in_file_id_persistent, state->in_file_id_volatile);

	if (state->in_output_buffer_length > x_smbd_conn_get_negprot(smbd_conn).max_trans_size) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	if (!x_smbd_requ_verify_creditcharge(smbd_requ,
				state->in_output_buffer_length)) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	switch (state->in_info_level) {
	case x_smb2_info_level_t::FILE_ID_BOTH_DIR_INFORMATION:
	case x_smb2_info_level_t::FILE_ID_FULL_DIR_INFORMATION:
	case x_smb2_info_level_t::FILE_DIRECTORY_INFORMATION:
	case x_smb2_info_level_t::FILE_BOTH_DIR_INFORMATION:
	case x_smb2_info_level_t::FILE_FULL_DIRECTORY_INFORMATION:
	case x_smb2_info_level_t::FILE_NAMES_INFORMATION:
		break;
	default:
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	if (state->in_output_buffer_length < 4) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INFO_LENGTH_MISMATCH);
	}

	NTSTATUS status = x_smbd_requ_init_open(smbd_requ,
			state->in_file_id_persistent,
			state->in_file_id_volatile,
			false);
	if (!NT_STATUS_IS_OK(status)) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, status);
	}

	auto smbd_open = smbd_requ->smbd_open;
	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	if (smbd_open->smbd_stream || !x_smbd_object_is_dir(smbd_object)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	auto op_fn = smbd_object->smbd_volume->ops->qdir_create;
	if (!op_fn) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}

	{
		auto lock = std::lock_guard(smbd_object->mutex);
		if (!smbd_open->smbd_qdir) {
			smbd_open->smbd_qdir = x_smbd_qdir_create(smbd_open);
			if (!smbd_open->smbd_qdir) {
				return NT_STATUS_INSUFFICIENT_RESOURCES;
			}
		}

		smbd_requ->save_requ_state(state);
		x_smbd_requ_async_insert(smbd_requ, smbd_qdir_cancel,
				X_NSEC_PER_SEC);

		smbd_qdir_queue_req(smbd_open->smbd_qdir, smbd_requ);
		/* TODO 
			if (smbd_requ->smbd_qdir_waiting) {
				X_ASSERT(smbd_open->smbd_qdir->compound_id_blocking
						== smbd_requ->compound_id);
			} else if (smbd_requ->is_compound_followed()) {
				X_ASSERT(smbd_open->smbd_qdir->compound_id_blocking == 0);
				smbd_requ->smbd_qdir_waiting = smbd_open->smbd_qdir;
			}
			*/
		x_smbd_schedule_async(&smbd_open->smbd_qdir->base);
	}

	X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_PENDING);
}

/* caller hold smbd_object's mutex */
void x_smbd_qdir_close(x_smbd_qdir_t *smbd_qdir)
{
	smbd_qdir->closed = true;
	x_smbd_schedule_async(&smbd_qdir->base);
}

