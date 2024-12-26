
#include "smbd.hxx"
#include "smbd_open.hxx"
#include "smbd_ntacl.hxx"
#include "nxfsd_stats.hxx"
#include "smbd_conf.hxx"

struct x_smbd_requ_state_qdir_t
{
	x_smb2_info_level_t in_info_level;
	uint8_t in_flags;
	uint32_t in_file_index;
	uint32_t in_output_buffer_length;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	std::u16string in_name;
	x_buf_t *out_buf{};
	uint32_t out_buf_length{0};
};

struct x_smbd_requ_qdir_t : x_smbd_requ_t
{
	x_smbd_requ_qdir_t(x_smbd_conn_t *smbd_conn, x_in_buf_t &in_buf,
			uint32_t in_msgsize, bool encrypted,
			x_smbd_requ_state_qdir_t &state)
		: x_smbd_requ_t(smbd_conn, in_buf, in_msgsize, encrypted)
		, state(std::move(state))
	{
		/* wait 1 second to send interim response */
		interim_timeout_ns = X_NSEC_PER_SEC;
	}

	std::tuple<bool, bool, bool> get_properties() const override
	{
		return { true, true, false };
	}
	NTSTATUS process(void *ctx_conn) override;
	NTSTATUS done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status) override;
	NTSTATUS cancelled(void *ctx_conn, int reason) override;

	x_smbd_requ_state_qdir_t state;
};

static void encode_out_qdir(const x_smbd_requ_state_qdir_t &state,
		uint8_t *out_hdr)
{
	x_smb2_qdir_resp_t *out_qdir = (x_smb2_qdir_resp_t *)(out_hdr + sizeof(x_smb2_header_t));

	out_qdir->struct_size = X_H2LE16(sizeof(x_smb2_qdir_resp_t) + 1);
	out_qdir->offset = X_H2LE16(sizeof(x_smb2_header_t) + sizeof(x_smb2_qdir_resp_t));
	out_qdir->length = X_H2LE32(x_convert_assert<uint32_t>(state.out_buf_length));
}

static void x_smb2_reply_qdir(x_smbd_requ_t *smbd_requ,
		x_smbd_requ_state_qdir_t &state)
{
	auto &out_buf = smbd_requ->get_requ_out_buf();
	out_buf.head = out_buf.tail = x_smb2_bufref_alloc(sizeof(x_smb2_qdir_resp_t));
	out_buf.length = out_buf.head->length;

	if (state.out_buf_length) {
		out_buf.head->next = out_buf.tail = new x_bufref_t(state.out_buf, 0, state.out_buf_length);
		state.out_buf = nullptr;
		out_buf.length += state.out_buf_length;
	}

	uint8_t *out_hdr = out_buf.head->get_data();
	encode_out_qdir(state, out_hdr);
}


static bool smbd_qdir_queue_req(x_smbd_qdir_t *smbd_qdir, x_smbd_requ_t *smbd_requ)
{
	auto &requ_list = smbd_qdir->requ_list;
	smbd_requ->incref();
	for (auto curr_requ = requ_list.get_back(); curr_requ;
			curr_requ = requ_list.prev(curr_requ)) {
		auto curr_smbd_requ = dynamic_cast<x_smbd_requ_t *>(curr_requ);
		X_ASSERT(smbd_requ->compound_id != curr_smbd_requ->compound_id);
		if (smbd_requ->compound_id > curr_smbd_requ->compound_id) {
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

static NTSTATUS smbd_qdir_process_requ(x_smbd_qdir_t *smbd_qdir,
		x_smbd_requ_qdir_t *requ, bool new_requ)
{
	if (smbd_qdir->delay_ms) {
		usleep(smbd_qdir->delay_ms * 1000);
	}
	auto &state = requ->state;
	if (new_requ) {
		X_ASSERT(!state.out_buf);

		if (smbd_qdir->total_count == 0 ||
				(state.in_flags & (X_SMB2_CONTINUE_FLAG_REOPEN |
						    X_SMB2_CONTINUE_FLAG_RESTART))) {
			smbd_qdir->error_status = NT_STATUS_OK;
			if (smbd_qdir->fnmatch) {
				x_fnmatch_destroy(smbd_qdir->fnmatch);
			}
			smbd_qdir->fnmatch = x_fnmatch_create(state.in_name, true);
			smbd_qdir->ops->rewind(smbd_qdir);

		} else if (!NT_STATUS_IS_OK(smbd_qdir->error_status)) {
			return smbd_qdir->error_status;
		}

		state.out_buf = x_buf_alloc(state.in_output_buffer_length);
		if (!state.out_buf) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	uint32_t max_count = 0x7fffffffu;
	if (state.in_flags & X_SMB2_CONTINUE_FLAG_SINGLE) {
		max_count = 1;
	}
	std::shared_ptr<idl::security_descriptor> psd, *ppsd = nullptr;
	if (smbd_qdir->smbd_user) {
		ppsd = &psd;
	}

	uint32_t num = 0, matched_count = 0; // TODO should be stored in smbd_qdir
	NTSTATUS status = NT_STATUS_OK;

	x_smb2_chain_marshall_t marshall{state.out_buf->data,
		state.out_buf->data + state.out_buf->size, 8};
	while (num < max_count) {
		x_smbd_object_meta_t object_meta;
		x_smbd_stream_meta_t stream_meta;
		std::u16string ent_name;
		status = smbd_qdir->ops->get_entry(requ, smbd_qdir,
					ent_name,
					object_meta, stream_meta, ppsd);
		if (status == NT_STATUS_NO_MORE_FILES) {
			if (smbd_qdir->total_count + num == 0) {
				status = NT_STATUS_NO_SUCH_FILE;
			}
			break;
		} if (status == X_NT_STATUS_INTERNAL_BLOCKED) {
			return status;
		} else if (!NT_STATUS_IS_OK(status)) {
			break;
		}
		
		if (psd) {
			uint32_t access = se_calculate_maximal_access(*psd,
					*smbd_qdir->smbd_user);
			psd = nullptr;
			if ((access & DIR_READ_ACCESS_MASK) != DIR_READ_ACCESS_MASK) {
				X_LOG(SMB, DBG, "entry '%s' skip by ABE",
						x_str_todebug(ent_name).c_str());
				continue;
			}
		}

		++matched_count;
		if (x_smbd_marshall_dir_entry(marshall, object_meta, stream_meta,
					ent_name, state.in_info_level)) {
			++num;
		} else {
			smbd_qdir->ops->unget_entry(smbd_qdir);
			max_count = num;
		}
	}

	smbd_qdir->error_status = status;
	if (num > 0) {
		smbd_qdir->total_count += num;
		state.out_buf_length = marshall.get_size();
		return NT_STATUS_OK;
	}
	
	x_buf_release(state.out_buf);
	state.out_buf = nullptr;
	if (matched_count > 0) {
		return NT_STATUS_INFO_LENGTH_MISMATCH;
	}
	return smbd_qdir->error_status;
}

static x_job_t::retval_t smbd_qdir_job_run(x_job_t *job, void *sche)
{
	x_smbd_qdir_t *smbd_qdir = X_CONTAINER_OF(job, x_smbd_qdir_t, base);
	x_smbd_object_t *smbd_object = smbd_qdir->smbd_open->smbd_object;
	{
		auto lock = std::unique_lock(smbd_object->mutex);
		for (;;) {
			x_nxfsd_requ_t *nxfsd_requ = smbd_qdir->curr_requ;
			bool new_requ = false;
			if (!nxfsd_requ) {
				nxfsd_requ = smbd_qdir->requ_list.get_front();
				if (!nxfsd_requ) {
					break;
				}
				auto smbd_requ = dynamic_cast<x_smbd_requ_t *>(nxfsd_requ);
				if (smbd_qdir->compound_id_blocking != 0 &&
						smbd_qdir->compound_id_blocking != smbd_requ->compound_id) {
					break;
				}
				smbd_qdir->requ_list.remove(nxfsd_requ);
				smbd_qdir->curr_requ = nxfsd_requ;
				new_requ = true;
			}

			lock.unlock();

			if (nxfsd_requ->set_processing()) {
				auto requ = dynamic_cast<x_smbd_requ_qdir_t *>(nxfsd_requ);
				NTSTATUS status = NT_STATUS_FILE_CLOSED;
				if (!smbd_qdir->closed) {
					status = smbd_qdir_process_requ(smbd_qdir, requ, new_requ);
				}

				if (status == X_NT_STATUS_INTERNAL_BLOCKED) {
					return x_job_t::JOB_BLOCKED;
				} else {
					smbd_qdir->curr_requ = nullptr;
				}
				x_nxfsd_requ_post_done(nxfsd_requ, status);
			} else {
				/* already cancelled */
				smbd_qdir->curr_requ = nullptr;
				nxfsd_requ->decref();
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

x_smbd_qdir_t::x_smbd_qdir_t(x_smbd_open_t *smbd_open, const x_smbd_qdir_ops_t *ops,
		const std::shared_ptr<x_smbd_user_t> &smbd_user)
	: base(smbd_qdir_job_run), ops(ops), smbd_open(x_ref_inc(smbd_open))
	, delay_ms(x_smbd_conf_get_curr().my_dev_delay_qdir_ms)
	, smbd_user(smbd_user)
{
	X_NXFSD_COUNTER_INC_CREATE(smbd_qdir, 1);
}

x_smbd_qdir_t::~x_smbd_qdir_t()
{
	X_ASSERT(!requ_list.get_front());
	if (fnmatch) {
		x_fnmatch_destroy(fnmatch);
	}
	x_ref_dec(smbd_open);
	X_NXFSD_COUNTER_INC_DELETE(smbd_qdir, 1);
}

NTSTATUS x_smbd_requ_qdir_t::process(void *ctx_conn)
{
	X_SMBD_REQU_LOG(OP, this, " open=0x%lx,0x%lx",
			state.in_file_id_persistent, state.in_file_id_volatile);

	if (!x_smbd_requ_verify_creditcharge(this,
				state.in_output_buffer_length)) {
		X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_INVALID_PARAMETER);
	}

	NTSTATUS status = x_smbd_requ_init_open(this,
			state.in_file_id_persistent,
			state.in_file_id_volatile,
			false);
	if (!status.ok()) {
		X_SMBD_REQU_RETURN_STATUS(this, status);
	}

	x_smbd_object_t *smbd_object = smbd_open->smbd_object;
	if (smbd_open->smbd_stream || !x_smbd_object_is_dir(smbd_object)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	auto op_fn = smbd_object->smbd_volume->ops->qdir_create;
	if (!op_fn) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}

	std::shared_ptr<x_smbd_user_t> smbd_user;
	if (x_smbd_tcon_get_abe(this->smbd_tcon)) {
		smbd_user = x_smbd_sess_get_user(this->smbd_sess);
	}

	{
		auto lock = std::lock_guard(smbd_object->mutex);
		if (!smbd_open->smbd_qdir) {
			smbd_open->smbd_qdir = x_smbd_qdir_create(smbd_open, smbd_user);
			if (!smbd_open->smbd_qdir) {
				X_NXFSD_COUNTER_INC(smbd_fail_alloc_qdir, 1);
				return NT_STATUS_INSUFFICIENT_RESOURCES;
			}
		}

		smbd_qdir_queue_req(smbd_open->smbd_qdir, this);
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

	X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_PENDING);
}

NTSTATUS x_smbd_requ_qdir_t::done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status)
{
	X_SMBD_REQU_LOG(OP, this, " %s", x_ntstatus_str(status));
	if (status.ok()) {
		x_smb2_reply_qdir(this, this->state);
	}
	return status;
}

NTSTATUS x_smbd_requ_qdir_t::cancelled(void *ctx_conn, int reason)
{
	/* TODO we let the async job to cleanup for now, otherwise there is a race */
	return NT_STATUS_CANCELLED;
}

NTSTATUS x_smb2_parse_QUERY_DIRECTORY(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t **p_smbd_requ,
		x_in_buf_t &in_buf, uint32_t in_msgsize,
		bool encrypted)
{
	auto in_smb2_hdr = (const x_smb2_header_t *)(in_buf.get_data());

	if (in_buf.length < sizeof(x_smb2_header_t) + sizeof(x_smb2_qdir_requ_t)) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}

	auto in_body = (const x_smb2_qdir_requ_t *)(in_smb2_hdr + 1);

	uint16_t in_name_offset             = X_LE2H16(in_body->name_offset);
	uint16_t in_name_length             = X_LE2H16(in_body->name_length);

	if (in_name_length % 2 != 0 || !x_check_range<uint32_t>(in_name_offset, in_name_length, 
				sizeof(x_smb2_header_t) + sizeof(x_smb2_qdir_requ_t),
				in_buf.length)) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}

	auto in_output_buffer_length = X_LE2H32(in_body->output_buffer_length);
	if (in_output_buffer_length > x_smbd_conn_get_negprot(smbd_conn).max_trans_size) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}
	if (in_output_buffer_length < 4) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INFO_LENGTH_MISMATCH);
	}

	x_smbd_requ_state_qdir_t state;

	state.in_info_level = x_smb2_info_level_t(X_LE2H8(in_body->info_level));
	switch (state.in_info_level) {
	case x_smb2_info_level_t::FILE_ID_BOTH_DIR_INFORMATION:
	case x_smb2_info_level_t::FILE_ID_FULL_DIR_INFORMATION:
	case x_smb2_info_level_t::FILE_DIRECTORY_INFORMATION:
	case x_smb2_info_level_t::FILE_BOTH_DIR_INFORMATION:
	case x_smb2_info_level_t::FILE_FULL_DIRECTORY_INFORMATION:
	case x_smb2_info_level_t::FILE_NAMES_INFORMATION:
		break;
	default:
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INFO_LENGTH_MISMATCH);
	}

	state.in_flags = X_LE2H8(in_body->flags);
	state.in_file_index = X_LE2H32(in_body->file_index);
	state.in_file_id_persistent = X_LE2H64(in_body->file_id_persistent);
	state.in_file_id_volatile = X_LE2H64(in_body->file_id_volatile);
	state.in_output_buffer_length = in_output_buffer_length;
	auto in_name_ptr = (const uint8_t *)in_smb2_hdr + in_name_offset;
	state.in_name = x_utf16le_decode((char16_t *)(in_name_ptr),
			(char16_t *)(in_name_ptr + in_name_length));

	*p_smbd_requ = new x_smbd_requ_qdir_t(smbd_conn, in_buf,
			in_msgsize, encrypted,
			state);
	return NT_STATUS_OK;
}

/* caller hold smbd_object's mutex */
void x_smbd_qdir_close(x_smbd_qdir_t *smbd_qdir)
{
	smbd_qdir->closed = true;
	x_smbd_schedule_async(&smbd_qdir->base);
}

