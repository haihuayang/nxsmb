
#include "smbd_dcerpc.hxx"
#include "smbd_ntacl.hxx"
#include "include/librpc/winreg.hxx"
#include "smbd_conf.hxx"
#include "smbd_registry.hxx"

static bool normalize_reg_path(std::u16string &name,
		const std::u16string &src)
{
	const char16_t *begin = src.data();
	const char16_t *end = begin + src.length();

	for ( ; begin != end; ++begin) {
		if (*begin != u'\\') {
			break;
		}
	}

	if (!x_str_convert(name, begin, end, x_toupper_t())) {
		return false;
	}

	if (name[name.length() - 1] == u'\\') {
		name.pop_back();
	}
	return true;
}

static std::shared_ptr<x_smbd_registry_key_t> find_handle(
		x_dcerpc_pipe_t &rpc_pipe, const idl::policy_handle &handle)
{
	auto [ found, data ] = x_smbd_dcerpc_find_handle(rpc_pipe,
			handle);
	if (found) {
		return std::static_pointer_cast<x_smbd_registry_key_t>(data);
	}
	return nullptr;
}

static WERROR open_top_key(x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::policy_handle &wire_handle,
		const std::u16string &name)
{
	/* TODO check arg.access_mask */
	std::shared_ptr<x_smbd_registry_key_t> key =
		x_smbd_registry_open_key(nullptr, name);
	if (!key) {
		return WERR_FILE_NOT_FOUND;
	}

	if (!x_smbd_dcerpc_create_handle(rpc_pipe, wire_handle,
				key)) {
		// samba return NOT_FOUND for any error
		return WERR_FILE_NOT_FOUND;
	}

	return WERR_OK;
}


#define X_SMBD_WINREG_IMPL_NOT_SUPPORTED_FAULT(Arg) \
static idl::dcerpc_nca_status x_smbd_dcerpc_impl_##Arg( \
		x_dcerpc_pipe_t &rpc_pipe, \
		x_smbd_sess_t *smbd_sess, \
		idl::Arg &arg) \
{ \
	arg.__result = WERR_NOT_SUPPORTED; \
	return idl::DCERPC_NCA_S_OP_RNG_ERROR; \
}


X_SMBD_DCERPC_IMPL_TODO(winreg_OpenHKCR)
X_SMBD_DCERPC_IMPL_TODO(winreg_OpenHKCU)

static idl::dcerpc_nca_status x_smbd_dcerpc_impl_winreg_OpenHKLM(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::winreg_OpenHKLM &arg)
{
	arg.__result = open_top_key(rpc_pipe, smbd_sess, arg.handle, u"HKLM");
	return X_SMBD_DCERPC_NCA_STATUS_OK;
}

static idl::dcerpc_nca_status x_smbd_dcerpc_impl_winreg_OpenHKPD(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::winreg_OpenHKPD &arg)
{
	X_TODO;
#if 0
	/* TODO check arg.access_mask */
	auto data = std::make_shared<std::u16string>(u"HKPD");
	if (!x_smbd_dcerpc_create_handle(rpc_pipe, arg.handle,
				data)) {
		// samba return NOT_FOUND for any error
		arg.__result = WERR_FILE_NOT_FOUND;
		return X_SMBD_DCERPC_NCA_STATUS_OK;
	}
#endif
	arg.__result = WERR_OK;
	return X_SMBD_DCERPC_NCA_STATUS_OK;
}

static idl::dcerpc_nca_status x_smbd_dcerpc_impl_winreg_OpenHKU(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::winreg_OpenHKU &arg)
{
	arg.__result = open_top_key(rpc_pipe, smbd_sess, arg.handle, u"HKU");
	return X_SMBD_DCERPC_NCA_STATUS_OK;
}

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
	std::shared_ptr<x_smbd_registry_key_t> parent_key = find_handle(
			rpc_pipe, arg.handle);
	if (!parent_key) {
		arg.__result = WERR_INVALID_HANDLE;
		return X_SMBD_DCERPC_NCA_STATUS_OK;
	}

	std::u16string name;
	if (!normalize_reg_path(name, *arg.name.name)) {
		arg.__result = WERR_FILE_NOT_FOUND;
		return X_SMBD_DCERPC_NCA_STATUS_OK;
	}

	auto [key, werr] = x_smbd_registry_create_key(*parent_key, name,
			arg.options);
	if (!key) {
		X_ASSERT(!W_ERROR_IS_OK(werr));
		arg.__result = werr;
		return X_SMBD_DCERPC_NCA_STATUS_OK;
	}

	arg.action_taken = std::make_shared<idl::winreg_CreateAction>(
			W_ERROR_EQUAL(werr, WERR_ALREADY_EXISTS)
			? idl::REG_OPENED_EXISTING_KEY :
			idl::REG_CREATED_NEW_KEY);

	if (!x_smbd_dcerpc_create_handle(rpc_pipe, arg.new_handle,
				key)) {
		// samba return NOT_FOUND for any error
		arg.__result = WERR_FILE_NOT_FOUND;
		return X_SMBD_DCERPC_NCA_STATUS_OK;
	}

	arg.__result = WERR_OK;
	return X_SMBD_DCERPC_NCA_STATUS_OK;
}

static idl::dcerpc_nca_status x_smbd_dcerpc_impl_winreg_DeleteKey(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::winreg_DeleteKey &arg)
{
	std::shared_ptr<x_smbd_registry_key_t> parent_key = find_handle(
			rpc_pipe, arg.handle);
	if (!parent_key) {
		arg.__result = WERR_INVALID_HANDLE;
		return X_SMBD_DCERPC_NCA_STATUS_OK;
	}

	std::u16string name;
	if (!normalize_reg_path(name, *arg.key.name)) {
		arg.__result = WERR_FILE_NOT_FOUND;
		return X_SMBD_DCERPC_NCA_STATUS_OK;
	}

	bool ret = x_smbd_registry_delete_key(parent_key.get(), name);

	if (!ret) {
		arg.__result = WERR_FILE_NOT_FOUND;
	} else {
		arg.__result = WERR_OK;
	}
	return X_SMBD_DCERPC_NCA_STATUS_OK;
}

static idl::dcerpc_nca_status x_smbd_dcerpc_impl_winreg_DeleteValue(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::winreg_DeleteValue &arg)
{
	std::shared_ptr<x_smbd_registry_key_t> key = find_handle(
			rpc_pipe, arg.handle);
	if (!key) {
		arg.__result = WERR_INVALID_HANDLE;
		return X_SMBD_DCERPC_NCA_STATUS_OK;
	}

	bool ret = x_smbd_registry_delete_value(*key, *arg.value.name);
	if (!ret) {
		arg.__result = WERR_FILE_NOT_FOUND;
	} else {
		arg.__result = WERR_OK;
	}
	return X_SMBD_DCERPC_NCA_STATUS_OK;
}

static idl::dcerpc_nca_status x_smbd_dcerpc_impl_winreg_EnumKey(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::winreg_EnumKey &arg)
{
	std::shared_ptr<x_smbd_registry_key_t> key = find_handle(
			rpc_pipe, arg.handle);
	if (!key) {
		arg.__result = WERR_INVALID_HANDLE;
		return X_SMBD_DCERPC_NCA_STATUS_OK;
	}

	std::u16string name;
	idl::NTTIME last_changed_time;
	bool ret = x_smbd_registry_enum_key(*key,
			arg.enum_index,
			name, last_changed_time);
	if (!ret) {
		arg.__result = WERR_NO_MORE_ITEMS;
	} else {
		arg.name.name = std::make_shared<std::u16string>(std::move(name));
		arg.last_changed_time =  std::make_shared<idl::NTTIME>(last_changed_time);
		arg.__result = WERR_OK;
	}
	return X_SMBD_DCERPC_NCA_STATUS_OK;
}

static idl::dcerpc_nca_status x_smbd_dcerpc_impl_winreg_EnumValue(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::winreg_EnumValue &arg)
{
	std::shared_ptr<x_smbd_registry_key_t> key = find_handle(
			rpc_pipe, arg.handle);
	if (!key) {
		arg.__result = WERR_INVALID_HANDLE;
		return X_SMBD_DCERPC_NCA_STATUS_OK;
	}

	x_smbd_registry_value_t reg_val;
	if (!x_smbd_registry_enum_value(*key, arg.enum_index, reg_val)) {
		arg.__result = WERR_NO_MORE_ITEMS;
	} else {
		arg.name.name = std::make_shared<std::u16string>(std::move(reg_val.name));
		arg.type = std::make_shared<idl::winreg_Type>(reg_val.type);
		arg.size = arg.length = std::make_shared<uint32_t>(reg_val.value.size());
		arg.value = std::make_shared<std::vector<uint8_t>>(std::move(reg_val.value));
		arg.__result = WERR_OK;
	}
	return X_SMBD_DCERPC_NCA_STATUS_OK;
}

static idl::dcerpc_nca_status x_smbd_dcerpc_impl_winreg_FlushKey(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::winreg_FlushKey &arg)
{
	arg.__result = WERR_OK;
	return X_SMBD_DCERPC_NCA_STATUS_OK;
}

static idl::dcerpc_nca_status x_smbd_dcerpc_impl_winreg_GetKeySecurity(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::winreg_GetKeySecurity &arg)
{
	std::shared_ptr<x_smbd_registry_key_t> key = find_handle(
			rpc_pipe, arg.handle);
	if (!key) {
		arg.__result = WERR_INVALID_HANDLE;
		return X_SMBD_DCERPC_NCA_STATUS_OK;
	}

	std::vector<uint8_t> secdata;
	x_smbd_registry_get_security(*key, secdata);
	arg.sd.data = std::make_shared<std::vector<uint8_t>>(std::move(secdata));
	arg.__result = WERR_OK;
	return X_SMBD_DCERPC_NCA_STATUS_OK;
}

X_SMBD_WINREG_IMPL_NOT_SUPPORTED_FAULT(winreg_LoadKey)

static idl::dcerpc_nca_status x_smbd_dcerpc_impl_winreg_NotifyChangeKeyValue(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::winreg_NotifyChangeKeyValue &arg)
{
	arg.__result = WERR_NOT_SUPPORTED;
	return X_SMBD_DCERPC_NCA_STATUS_OK;
}

static idl::dcerpc_nca_status x_smbd_dcerpc_impl_winreg_OpenKey(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::winreg_OpenKey &arg)
{
	std::shared_ptr<x_smbd_registry_key_t> parent_key = find_handle(
			rpc_pipe, arg.parent_handle);
	if (!parent_key) {
		arg.__result = WERR_INVALID_HANDLE;
		return X_SMBD_DCERPC_NCA_STATUS_OK;
	}

	X_LOG_DBG("winreg_OpenKey parent '%s' key '%s'",
			x_str_todebug(x_smbd_registry_key_get_name(*parent_key)).c_str(),
			x_str_todebug(*arg.keyname.name).c_str());

	std::u16string name;
	if (!normalize_reg_path(name, *arg.keyname.name)) {
		arg.__result = WERR_FILE_NOT_FOUND;
		return X_SMBD_DCERPC_NCA_STATUS_OK;
	}

	std::shared_ptr<x_smbd_registry_key_t> key = x_smbd_registry_open_key(
			parent_key.get(), name);
	if (!key) {
		arg.__result = WERR_FILE_NOT_FOUND;
		return X_SMBD_DCERPC_NCA_STATUS_OK;
	}

	if (!x_smbd_dcerpc_create_handle(rpc_pipe, arg.handle,
				key)) {
		// samba return NOT_FOUND for any error
		arg.__result = WERR_FILE_NOT_FOUND;
		return X_SMBD_DCERPC_NCA_STATUS_OK;
	}

	arg.__result = WERR_OK;
	return X_SMBD_DCERPC_NCA_STATUS_OK;
}

static idl::dcerpc_nca_status x_smbd_dcerpc_impl_winreg_QueryInfoKey(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::winreg_QueryInfoKey &arg)
{
	std::shared_ptr<x_smbd_registry_key_t> key = find_handle(
			rpc_pipe, arg.handle);
	if (!key) {
		arg.__result = WERR_INVALID_HANDLE;
		return X_SMBD_DCERPC_NCA_STATUS_OK;
	}

	bool ret = x_smbd_registry_query_key(*key,
			arg.num_subkeys, arg.max_subkeylen,
			arg.max_classlen,
			arg.num_values, arg.max_valnamelen, arg.max_valbufsize,
			arg.secdescsize, arg.last_changed_time);
	X_ASSERT(ret);
	arg.__result = WERR_OK;
	return X_SMBD_DCERPC_NCA_STATUS_OK;
}

static idl::dcerpc_nca_status x_smbd_dcerpc_impl_winreg_QueryValue(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::winreg_QueryValue &arg)
{
	std::shared_ptr<x_smbd_registry_key_t> key = find_handle(
			rpc_pipe, arg.handle);
	if (!key) {
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

	const x_smbd_registry_value_t *reg_val = x_smbd_registry_find_value(
			*key, *arg.value_name.name);

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

X_SMBD_WINREG_IMPL_NOT_SUPPORTED_FAULT(winreg_ReplaceKey)

static idl::dcerpc_nca_status x_smbd_dcerpc_impl_winreg_RestoreKey(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::winreg_RestoreKey &arg)
{
	std::shared_ptr<x_smbd_registry_key_t> key = find_handle(
			rpc_pipe, arg.handle);
	if (!key) {
		arg.__result = WERR_INVALID_HANDLE;
		return X_SMBD_DCERPC_NCA_STATUS_OK;
	}

	arg.__result = WERR_BAD_PATHNAME;
	return X_SMBD_DCERPC_NCA_STATUS_OK;
}

static idl::dcerpc_nca_status x_smbd_dcerpc_impl_winreg_SaveKey(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::winreg_SaveKey &arg)
{
	std::shared_ptr<x_smbd_registry_key_t> key = find_handle(
			rpc_pipe, arg.handle);
	if (!key) {
		arg.__result = WERR_INVALID_HANDLE;
		return X_SMBD_DCERPC_NCA_STATUS_OK;
	}

	arg.__result = WERR_BAD_PATHNAME;
	return X_SMBD_DCERPC_NCA_STATUS_OK;
}

X_SMBD_DCERPC_IMPL_TODO(winreg_SetKeySecurity)

static idl::dcerpc_nca_status x_smbd_dcerpc_impl_winreg_SetValue(
		x_dcerpc_pipe_t &rpc_pipe,
		x_smbd_sess_t *smbd_sess,
		idl::winreg_SetValue &arg)
{
	std::shared_ptr<x_smbd_registry_key_t> key = find_handle(
			rpc_pipe, arg.handle);
	if (!key) {
		arg.__result = WERR_INVALID_HANDLE;
		return X_SMBD_DCERPC_NCA_STATUS_OK;
	}

	x_smbd_registry_set_value(*key, *arg.name.name, arg.type,
			arg.data);
	arg.__result = WERR_OK;
	return X_SMBD_DCERPC_NCA_STATUS_OK;
}

X_SMBD_WINREG_IMPL_NOT_SUPPORTED_FAULT(winreg_UnLoadKey)

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
	std::shared_ptr<x_smbd_registry_key_t> reg_key = find_handle(
			rpc_pipe, key_handle);
	if (!reg_key) {
		return WERR_INVALID_HANDLE;
	}

	std::vector<uint8_t> out_buf;
	out_buf.reserve(1024);
	std::vector<idl::QueryMultipleValue> values_out;
	values_out.reserve(values_in.size());
	bool not_found = false;
	for (auto &value_in: values_in) {
		const x_smbd_registry_value_t *reg_val = nullptr;
		if (value_in.ve_valuename && value_in.ve_valuename->name) {
			reg_val = x_smbd_registry_find_value(
					*reg_key, *value_in.ve_valuename->name);
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
X_SMBD_WINREG_IMPL_NOT_SUPPORTED_FAULT(winreg_SaveKeyEx)
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

X_SMBD_WINREG_IMPL_NOT_SUPPORTED_FAULT(winreg_DeleteKeyEx)

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


