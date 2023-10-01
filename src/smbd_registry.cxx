
#include "smbd_registry.hxx"
#include "include/librpc/security.hxx"
#include "include/librpc/winreg.hxx"
#include "smbd_ntacl.hxx"
#include "util_sid.hxx"

struct x_smbd_registry_key_t
{
	x_smbd_registry_key_t(std::u16string &&name, uint32_t options)
		: name(name), options(options) { }
	const std::u16string name;
	const uint32_t options;
	std::vector<std::shared_ptr<x_smbd_registry_key_t>> subkeys;
	std::vector<x_smbd_registry_value_t> values;
};


static x_smbd_registry_key_t g_smbd_registry_root{u"", 0};
static std::shared_ptr<idl::security_descriptor> g_default_sd;
static std::vector<uint8_t> g_default_sd_data;


const std::u16string &x_smbd_registry_key_get_name(const x_smbd_registry_key_t &key)
{
	return key.name;
}

const x_smbd_registry_value_t *x_smbd_registry_find_value(
		const x_smbd_registry_key_t &key, const std::u16string &name)
{
	for (auto &val: key.values) {
		if (x_strcase_equal(val.name, name)) {
			return &val;
		}
	}
	return nullptr;
}

bool x_smbd_registry_query_key(const x_smbd_registry_key_t &key,
		uint32_t &num_subkeys, uint32_t &max_subkeylen,
		uint32_t &max_classlen,
		uint32_t &num_values, uint32_t &max_value_name_len,
		uint32_t &max_value_buf_size, uint32_t &secdescsize,
		idl::NTTIME &last_changed_time)
{
	size_t max_name_len = 0;
	for (auto &subkey : key.subkeys) {
		max_name_len = std::max(max_name_len, subkey->name.size() * 2);
	}

	num_subkeys = x_convert_assert<uint32_t>(key.subkeys.size());
	max_subkeylen = x_convert_assert<uint32_t>(max_name_len);
	max_classlen = 0; /* Class length? */

	max_name_len = 0;
	size_t max_buf_len = 0;
	for (auto &value : key.values) {
		max_name_len = std::max(max_name_len, value.name.size() * 2);
		max_buf_len = std::max(max_buf_len, value.value.size());
	}

	num_values = x_convert_assert<uint32_t>(key.values.size());
	max_value_name_len = x_convert_assert<uint32_t>(max_name_len);

	secdescsize = x_convert_assert<uint32_t>(g_default_sd_data.size());
	last_changed_time.val = 0;
	return true;
}

bool x_smbd_registry_enum_key(const x_smbd_registry_key_t &key,
		uint32_t idx,
		std::u16string &name,
		idl::NTTIME &last_changed_time)
{
	if (idx >= key.subkeys.size()) {
		return false;
	}

	name = key.subkeys[idx]->name;
	last_changed_time.val = 0;
	return true;
}

bool x_smbd_registry_enum_value(const x_smbd_registry_key_t &key,
		uint32_t idx,
		x_smbd_registry_value_t &value)
{
	if (idx >= key.values.size()) {
		return false;
	}

	value = key.values[idx];
	return true;
}

void x_smbd_registry_set_value(x_smbd_registry_key_t &key,
		const std::u16string &name,
		idl::winreg_Type type,
		const std::vector<uint8_t> &value)
{
	for (auto &val: key.values) {
		if (x_strcase_equal(val.name, name)) {
			val.type = type;
			val.value = value;
			return;
		}
	}
	key.values.push_back({name, type, value});
}

void x_smbd_registry_get_security(const x_smbd_registry_key_t &key,
		std::vector<uint8_t> &data)
{
	data = g_default_sd_data;
}

static x_smbd_registry_value_t regval_compose(const std::u16string &name,
		idl::winreg_Type type,
		const std::u16string value)
{
	uint8_t *b = (uint8_t *)value.data();
	uint8_t *e = b + (2 * value.length() + 1);
	return x_smbd_registry_value_t{name, type, {b, e}};
}

static std::pair<std::shared_ptr<x_smbd_registry_key_t>, WERROR> create_subkey(
		x_smbd_registry_key_t *parent, std::u16string name,
		uint32_t options)
{
	for (auto &subkey : parent->subkeys) {
		if (subkey->name == name) {
			return { subkey, WERR_ALREADY_EXISTS };
		}
	}

	if ((parent->options & idl::REG_OPTION_VOLATILE) && !(options & idl::REG_OPTION_VOLATILE)) {
		return { nullptr, WERR_CHILD_MUST_BE_VOLATILE };
	}

	auto key = std::make_shared<x_smbd_registry_key_t>(std::move(name), options);
	parent->subkeys.push_back(key);
	return { key, WERR_SUCCESS };
}

static std::pair<std::shared_ptr<x_smbd_registry_key_t>, WERROR> create_subkey_path(
		x_smbd_registry_key_t *parent, const std::u16string &path,
		uint32_t options)
{
	std::u16string::size_type pos, last_pos = 0;
	for (;;) {
		pos = path.find(u'\\', last_pos);
		if (pos == std::u16string::npos) {
			break;
		}
		auto [key, _] = create_subkey(parent,
				path.substr(last_pos, pos - last_pos), options);
		X_ASSERT(key);

		parent = key.get();
		last_pos = pos + 1;
	}

	return create_subkey(parent, path.substr(last_pos), options);
}

std::shared_ptr<x_smbd_registry_key_t> x_smbd_registry_open_key(
		const x_smbd_registry_key_t *parent,
		const std::u16string &path)
{
	std::shared_ptr<x_smbd_registry_key_t> tmp;
	if (!parent) {
		parent = &g_smbd_registry_root;
	}
	std::u16string::size_type pos, last_pos = 0;
	for (;;) {
		pos = path.find(u'\\', last_pos);
		if (pos == std::u16string::npos) {
			break;
		}
		bool found = false;
		size_t count = pos - last_pos;
		for (auto &subkey : parent->subkeys) {
			if (subkey->name.length() == count &&
					subkey->name.compare(0, count,
						path, last_pos, count) == 0) {
				tmp = subkey;
				found = true;
			}
		}

		if (!found) {
			return nullptr;
		}
		parent = tmp.get();
		last_pos = pos + 1;
	}

	for (auto &subkey : parent->subkeys) {
		if (subkey->name.compare(path.data() + last_pos) == 0) {
			return subkey;
		}
	}
	return nullptr;
}

std::pair<std::shared_ptr<x_smbd_registry_key_t>, WERROR> x_smbd_registry_create_key(
		x_smbd_registry_key_t &parent,
		const std::u16string &path,
		uint32_t options)
{
	return create_subkey_path(&parent, path, options);
}

bool x_smbd_registry_delete_key(x_smbd_registry_key_t *parent,
		const std::u16string &path)
{
	X_ASSERT(parent);
	std::shared_ptr<x_smbd_registry_key_t> tmp;
	std::u16string::size_type pos, last_pos = 0;
	for (;;) {
		pos = path.find(u'\\', last_pos);
		if (pos == std::u16string::npos) {
			break;
		}
		bool found = false;
		size_t count = pos - last_pos;
		for (auto &subkey : parent->subkeys) {
			if (subkey->name.length() == count &&
					subkey->name.compare(0, count,
						path, last_pos, count) == 0) {
				tmp = subkey;
				found = true;
			}
		}

		if (!found) {
			return false;
		}
		parent = tmp.get();
		last_pos = pos + 1;
	}

	auto it = parent->subkeys.begin();
	for ( ; it != parent->subkeys.end(); ++it) {
		if ((*it)->name.compare(path.data() + last_pos) == 0) {
			parent->subkeys.erase(it);
			return true;
		}
	}
	return false;
}

bool x_smbd_registry_delete_value(x_smbd_registry_key_t &key,
		const std::u16string &name)
{
	// TODO check access
	auto it = key.values.begin();
	for ( ; it != key.values.end(); ++it) {
		if (x_strcase_equal(it->name, name)) {
			key.values.erase(it);
			return true;
		}
	}
	return false;
}

static int create_default_sd()
{
	auto psd = std::make_shared<idl::security_descriptor>();
	psd->owner_sid = std::make_shared<idl::dom_sid>(global_sid_Builtin_Administrators);
	psd->group_sid = std::make_shared<idl::dom_sid>(global_sid_System);
	psd->dacl = std::make_shared<idl::security_acl>();
	psd->dacl->revision = idl::security_acl_revision(idl::NT4_ACL_REVISION);
	append_ace(psd->dacl->aces, 
			idl::SEC_ACE_TYPE_ACCESS_ALLOWED,
			idl::security_ace_flags(0),
			idl::REG_KEY_READ,
			global_sid_World);
	append_ace(psd->dacl->aces, 
			idl::SEC_ACE_TYPE_ACCESS_ALLOWED,
			idl::security_ace_flags(0),
			idl::REG_KEY_ALL,
			global_sid_Builtin_Administrators);
	append_ace(psd->dacl->aces, 
			idl::SEC_ACE_TYPE_ACCESS_ALLOWED,
			idl::security_ace_flags(0),
			idl::REG_KEY_ALL,
			global_sid_System);
	psd->revision = idl::SECURITY_DESCRIPTOR_REVISION_1;
	psd->type = idl::security_descriptor_type(idl::SEC_DESC_SELF_RELATIVE);

	std::vector<uint8_t> out;
	idl::x_ndr_off_t ret = idl::x_ndr_push(*psd, out, 0);

	X_ASSERT(ret > 0);

	g_default_sd = psd;
	std::swap(out, g_default_sd_data);

	return 0;
}

#define KEY_CURRENT_VERSION_NORM u"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION"

int x_smbd_registry_init()
{
	create_default_sd();

	auto [key, werr] = create_subkey_path(&g_smbd_registry_root,
			KEY_CURRENT_VERSION_NORM, 0);
	X_ASSERT(W_ERROR_IS_OK(werr));
	key->values.push_back(regval_compose(u"SystemRoot",
				idl::REG_SZ, u"c:\\Windows"));
	key->values.push_back(regval_compose(u"CurrentVersion",
				idl::REG_SZ, u"6.1"));
	create_subkey_path(&g_smbd_registry_root, u"HKU", 0);
	create_subkey_path(&g_smbd_registry_root, u"HKCU", 0);
	create_subkey_path(&g_smbd_registry_root, u"HKCR", 0);
	return 0;
}
