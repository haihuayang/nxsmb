
#include "smbd_registry.hxx"


static std::vector<x_smbd_registry_key_t> g_smbd_registry;

const x_smbd_registry_key_t *x_smbd_registry_find_key(const std::u16string &name)
{
	for (auto &key: g_smbd_registry) {
		if (name == key.name) {
			return &key;
		}
	}
	return nullptr;
}

const x_smbd_registry_value_t *x_smbd_registry_find_value(
		const x_smbd_registry_key_t *key, const std::u16string &name)
{
	for (auto &val: key->values) {
		if (x_strcase_equal(val.name, name)) {
			return &val;
		}
	}
	return nullptr;
}

static x_smbd_registry_value_t regval_compose(const std::u16string &name,
		idl::winreg_Type type,
		const std::u16string value)
{
	uint8_t *b = (uint8_t *)value.data();
	uint8_t *e = b + (2 * value.length() + 1);
	return x_smbd_registry_value_t{name, type, {b, e}};
}

#define KEY_CURRENT_VERSION_NORM u"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION"

int x_smbd_registry_init()
{
	std::vector<x_smbd_registry_value_t> current_version_values;
	current_version_values.push_back(regval_compose(u"SystemRoot",
				idl::REG_SZ, u"c:\\Windows"));
	current_version_values.push_back(regval_compose(u"CurrentVersion",
				idl::REG_SZ, u"6.1"));

	g_smbd_registry.push_back({KEY_CURRENT_VERSION_NORM,
			std::move(current_version_values)});
	return 0;
}
