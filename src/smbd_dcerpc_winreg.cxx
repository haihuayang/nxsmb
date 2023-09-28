
#include "smbd_dcerpc.hxx"
#include "smbd_ntacl.hxx"
#include "include/librpc/winreg.hxx"
#include "smbd_conf.hxx"
#include "smbd_registry.hxx"
//#include "smbd_dcerpc_winreg.hxx"


X_SMBD_DCERPC_IMPL_TODO(winreg_OpenHKCR)
X_SMBD_DCERPC_IMPL_TODO(winreg_OpenHKCU)

static idl::dcerpc_nca_status x_smbd_dcerpc_impl_winreg_OpenHKLM(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::winreg_OpenHKLM &arg)
{
	/* TODO check arg.access_mask */
	auto data = std::make_shared<std::u16string>(u"HKLM");
	if (!x_smbd_dcerpc_create_handle(rpc_pipe, arg.handle,
				data)) {
		// samba return NOT_FOUND for any error
		arg.__result = WERR_FILE_NOT_FOUND;
		return X_SMBD_DCERPC_NCA_STATUS_OK;
	}

	arg.__result = WERR_OK;
	return X_SMBD_DCERPC_NCA_STATUS_OK;
}

static idl::dcerpc_nca_status x_smbd_dcerpc_impl_winreg_OpenHKPD(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::winreg_OpenHKPD &arg)
{
	/* TODO check arg.access_mask */
	auto data = std::make_shared<std::u16string>(u"HKPD");
	if (!x_smbd_dcerpc_create_handle(rpc_pipe, arg.handle,
				data)) {
		// samba return NOT_FOUND for any error
		arg.__result = WERR_FILE_NOT_FOUND;
		return X_SMBD_DCERPC_NCA_STATUS_OK;
	}

	arg.__result = WERR_OK;
	return X_SMBD_DCERPC_NCA_STATUS_OK;
}

X_SMBD_DCERPC_IMPL_TODO(winreg_OpenHKU)

static idl::dcerpc_nca_status x_smbd_dcerpc_impl_winreg_CloseKey(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::winreg_CloseKey &arg)
{
	if (x_smbd_dcerpc_close_handle(rpc_pipe, arg.handle)) {
		arg.__result = WERR_OK;
	} else {
		arg.__result = WERR_INVALID_HANDLE;
	}
	return X_SMBD_DCERPC_NCA_STATUS_OK;

}

static idl::dcerpc_nca_status x_smbd_dcerpc_impl_winreg_CreateKey(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::winreg_CreateKey &arg)
{
	X_TODO;
	arg.__result = WERR_FILE_NOT_FOUND;
	return X_SMBD_DCERPC_NCA_STATUS_OK;
}

static idl::dcerpc_nca_status x_smbd_dcerpc_impl_winreg_DeleteKey(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::winreg_DeleteKey &arg)
{
	arg.__result = WERR_FILE_NOT_FOUND;
	return X_SMBD_DCERPC_NCA_STATUS_OK;
}

X_SMBD_DCERPC_IMPL_TODO(winreg_DeleteValue)
X_SMBD_DCERPC_IMPL_TODO(winreg_EnumKey)
X_SMBD_DCERPC_IMPL_TODO(winreg_EnumValue)
X_SMBD_DCERPC_IMPL_TODO(winreg_FlushKey)
X_SMBD_DCERPC_IMPL_TODO(winreg_GetKeySecurity)
X_SMBD_DCERPC_IMPL_TODO(winreg_LoadKey)
X_SMBD_DCERPC_IMPL_TODO(winreg_NotifyChangeKeyValue)

static idl::dcerpc_nca_status x_smbd_dcerpc_impl_winreg_OpenKey(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::winreg_OpenKey &arg)
{
	auto [ found, data ] = x_smbd_dcerpc_find_handle(rpc_pipe,
			arg.parent_handle);
	if (!found) {
		arg.__result = WERR_INVALID_HANDLE;
		return X_SMBD_DCERPC_NCA_STATUS_OK;
	}

	auto parent_name = std::static_pointer_cast<std::u16string>(data);
	X_LOG_DBG("winreg_OpenKey parent '%s' key '%s'",
			x_str_todebug(*parent_name).c_str(),
			x_str_todebug(*arg.keyname.name).c_str());

	std::u16string full_path;
	full_path.reserve(parent_name->length() + 1 + arg.keyname.name->length() + 1);
	full_path.assign(*parent_name);
	full_path.push_back(u'\\');

	const char16_t *begin = arg.keyname.name->data();
	const char16_t *end = begin + arg.keyname.name->length();

	for ( ; begin != end; ++begin) {
		if (*begin != u'\\') {
			break;
		}
	}

	if (!x_str_convert(full_path, begin, end, x_toupper_t())) {
		arg.__result = WERR_FILE_NOT_FOUND;
		return X_SMBD_DCERPC_NCA_STATUS_OK;
	}
	if (full_path[full_path.length() - 1] == u'\\') {
		full_path.pop_back();
	}

	if (!x_smbd_registry_find_key(full_path)) {
		arg.__result = WERR_FILE_NOT_FOUND;
		return X_SMBD_DCERPC_NCA_STATUS_OK;
	}

	auto full_path_ptr = std::make_shared<std::u16string>(std::move(full_path));
	if (!x_smbd_dcerpc_create_handle(rpc_pipe, arg.handle,
				full_path_ptr)) {
		// samba return NOT_FOUND for any error
		arg.__result = WERR_FILE_NOT_FOUND;
		return X_SMBD_DCERPC_NCA_STATUS_OK;
	}

	arg.__result = WERR_OK;
	return X_SMBD_DCERPC_NCA_STATUS_OK;
}

X_SMBD_DCERPC_IMPL_TODO(winreg_QueryInfoKey)

static idl::dcerpc_nca_status x_smbd_dcerpc_impl_winreg_QueryValue(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::winreg_QueryValue &arg)
{
	auto [ found, data ] = x_smbd_dcerpc_find_handle(rpc_pipe,
			arg.handle);
	if (!found) {
		arg.__result = WERR_INVALID_HANDLE;
		return X_SMBD_DCERPC_NCA_STATUS_OK;
	}

	if (!arg.value_name.name) {
		arg.__result = WERR_INVALID_PARAMETER;
		return X_SMBD_DCERPC_NCA_STATUS_OK;
	}

	if (!arg.data_length || !arg.type || !arg.data_size) {
		arg.__result = WERR_INVALID_PARAMETER;
		return X_SMBD_DCERPC_NCA_STATUS_OK;
	}

	auto name = std::static_pointer_cast<std::u16string>(data);

	const x_smbd_registry_key_t *reg_key = x_smbd_registry_find_key(*name);
	X_ASSERT(reg_key);

	const x_smbd_registry_value_t *reg_val = x_smbd_registry_find_value(
			reg_key, *arg.value_name.name);

	if (!reg_val) {
		arg.__result = WERR_FILE_NOT_FOUND;
		return X_SMBD_DCERPC_NCA_STATUS_OK;
	}

	arg.type = std::make_shared<idl::winreg_Type>(reg_val->type);

	if (*arg.data_size < reg_val->value.size()) {
		*arg.data_size = x_convert<uint32_t>(reg_val->value.size());
		if (arg.data) {
			arg.__result = WERR_MORE_DATA;
		} else {
			arg.__result = WERR_OK;
		}
	} else {
		arg.data = std::make_shared<std::vector<uint8_t>>(reg_val->value);
		arg.data_length = std::make_shared<uint32_t>(reg_val->value.size());
		arg.data_size = std::make_shared<uint32_t>(reg_val->value.size());
		arg.__result = WERR_OK;
	}
	return X_SMBD_DCERPC_NCA_STATUS_OK;
}

X_SMBD_DCERPC_IMPL_TODO(winreg_ReplaceKey)
X_SMBD_DCERPC_IMPL_TODO(winreg_RestoreKey)
X_SMBD_DCERPC_IMPL_TODO(winreg_SaveKey)
X_SMBD_DCERPC_IMPL_TODO(winreg_SetKeySecurity)
X_SMBD_DCERPC_IMPL_TODO(winreg_SetValue)
X_SMBD_DCERPC_IMPL_TODO(winreg_UnLoadKey)
X_SMBD_DCERPC_IMPL_TODO(winreg_InitiateSystemShutdown)
X_SMBD_DCERPC_IMPL_TODO(winreg_AbortSystemShutdown)

static idl::dcerpc_nca_status x_smbd_dcerpc_impl_winreg_GetVersion(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::winreg_GetVersion &arg)
{
	arg.version = 0x00000005; /* Windows 2000 registry API version */
	arg.__result = WERR_OK;
	return X_SMBD_DCERPC_NCA_STATUS_OK;
}

X_SMBD_DCERPC_IMPL_TODO(winreg_OpenHKCC)
X_SMBD_DCERPC_IMPL_TODO(winreg_OpenHKDD)

static WERROR __winreg_QueryMultipleValues(
		x_dcerpc_pipe_t &rpc_pipe,
		const idl::policy_handle &key_handle,
		const std::vector<idl::QueryMultipleValue> &values_in,
		std::vector<idl::QueryMultipleValue> &values_out_,
		std::shared_ptr<std::vector<uint8_t>> &out_buf_,
		uint32_t offered, uint32_t &needed)
{
	auto [ found, data ] = x_smbd_dcerpc_find_handle(rpc_pipe,
			key_handle);
	if (!found) {
		return WERR_INVALID_HANDLE;
	}

	auto name = std::static_pointer_cast<std::u16string>(data);
	const x_smbd_registry_key_t *reg_key = x_smbd_registry_find_key(*name);
	X_ASSERT(reg_key);

	std::vector<uint8_t> out_buf;
	out_buf.reserve(1024);
	std::vector<idl::QueryMultipleValue> values_out;
	values_out.reserve(values_in.size());
	bool not_found = false;
	for (auto &value_in: values_in) {
		const x_smbd_registry_value_t *reg_val = nullptr;
		if (value_in.ve_valuename && value_in.ve_valuename->name) {
			reg_val = x_smbd_registry_find_value(
					reg_key, *value_in.ve_valuename->name);
		}

		if (!reg_val) {
			values_out.push_back({value_in.ve_valuename,
					0, x_convert<uint32_t>(out_buf.size()),
					idl::REG_NONE});
			not_found = true;
		} else {
			values_out.push_back({value_in.ve_valuename, 
					x_convert<uint32_t>(reg_val->value.size() * 2),
					x_convert<uint32_t>(out_buf.size()),
					reg_val->type});
			out_buf.insert(out_buf.end(), reg_val->value.begin(), reg_val->value.end());
		}
	}

	std::swap(values_out_, values_out);

	needed = x_convert<uint32_t>(out_buf.size());
	if (not_found) {
		return WERR_FILE_NOT_FOUND;
	}
	if (offered < needed) {
		return WERR_MORE_DATA;
	}

	if (out_buf_) {
		std::swap(*out_buf_, out_buf);
	}
	if (not_found) {
		return WERR_FILE_NOT_FOUND;
	}
	return WERR_OK;
}

static idl::dcerpc_nca_status x_smbd_dcerpc_impl_winreg_QueryMultipleValues(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::winreg_QueryMultipleValues &arg)
{
	uint32_t needed = 0;
	arg.__result = __winreg_QueryMultipleValues(rpc_pipe, arg.key_handle,
			arg.values_in, arg.values_out,
			arg.buffer,
			x_convert<uint32_t>(arg.buffer ? arg.buffer->size() : 0),
			needed);
	return X_SMBD_DCERPC_NCA_STATUS_OK;
}

X_SMBD_DCERPC_IMPL_TODO(winreg_InitiateSystemShutdownEx)
X_SMBD_DCERPC_IMPL_TODO(winreg_SaveKeyEx)
X_SMBD_DCERPC_IMPL_TODO(winreg_OpenHKPT)
X_SMBD_DCERPC_IMPL_TODO(winreg_OpenHKPN)

static idl::dcerpc_nca_status x_smbd_dcerpc_impl_winreg_QueryMultipleValues2(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::winreg_QueryMultipleValues2 &arg)
{
	arg.__result = __winreg_QueryMultipleValues(rpc_pipe, arg.key_handle,
			arg.values_in, arg.values_out,
			arg.buffer, arg.offered, arg.needed);
	return X_SMBD_DCERPC_NCA_STATUS_OK;
}

X_SMBD_DCERPC_IMPL_TODO(winreg_DeleteKeyEx)

#define X_DCERPC_FUNCTION_DEF(x) X_SMBD_DCERPC_FUNCTION(x)
X_DCERPC_FUNCTION_ENUM_winreg
#undef X_DCERPC_FUNCTION_DEF

static const x_dcerpc_rpc_fn_t winreg_fns[] = {
#define X_DCERPC_FUNCTION_DEF(x) x_smbd_dcerpc_fn_##x,
X_DCERPC_FUNCTION_ENUM_winreg
#undef X_DCERPC_FUNCTION_DEF
};

const x_dcerpc_iface_t x_smbd_dcerpc_winreg = {
	{ idl::winreg_uuid, idl::winreg_version },
	X_ARRAY_SIZE(winreg_fns),
	winreg_fns,
};


