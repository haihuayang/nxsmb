
#include "smbd_registry.hxx"

struct x_smbd_registry_key_t
{
	x_smbd_registry_key_t(std::u16string &&name) : name(name) { }
	const std::u16string name;
	std::vector<std::shared_ptr<x_smbd_registry_key_t>> subkeys;
	std::vector<x_smbd_registry_value_t> values;
};


static x_smbd_registry_key_t g_smbd_registry_root{u""};


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

static x_smbd_registry_value_t regval_compose(const std::u16string &name,
		idl::winreg_Type type,
		const std::u16string value)
{
	uint8_t *b = (uint8_t *)value.data();
	uint8_t *e = b + (2 * value.length() + 1);
	return x_smbd_registry_value_t{name, type, {b, e}};
}

static std::pair<std::shared_ptr<x_smbd_registry_key_t>, bool> create_subkey(
		x_smbd_registry_key_t *parent, std::u16string name)
{
	for (auto &subkey : parent->subkeys) {
		if (subkey->name == name) {
			return { subkey, true };
		}
	}

	auto key = std::make_shared<x_smbd_registry_key_t>(std::move(name));
	parent->subkeys.push_back(key);
	return { key, false };
}

static std::pair<std::shared_ptr<x_smbd_registry_key_t>, bool> create_subkey_path(
		x_smbd_registry_key_t *parent, const std::u16string &path)
{
	std::u16string::size_type pos, last_pos = 0;
	for (;;) {
		pos = path.find(u'\\', last_pos);
		if (pos == std::u16string::npos) {
			break;
		}
		auto [key, _] = create_subkey(parent, path.substr(last_pos, pos - last_pos));
		X_ASSERT(key);

		parent = key.get();
		last_pos = pos + 1;
	}

	return create_subkey(parent, path.substr(last_pos));
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

std::pair<std::shared_ptr<x_smbd_registry_key_t>, bool> x_smbd_registry_create_key(
		x_smbd_registry_key_t *parent,
		const std::u16string &path)
{
	X_ASSERT(parent);
	return create_subkey_path(parent, path);
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

#define KEY_CURRENT_VERSION_NORM u"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION"

int x_smbd_registry_init()
{
	auto [key, exist] = create_subkey_path(&g_smbd_registry_root, KEY_CURRENT_VERSION_NORM);
	X_ASSERT(!exist);
	key->values.push_back(regval_compose(u"SystemRoot",
				idl::REG_SZ, u"c:\\Windows"));
	key->values.push_back(regval_compose(u"CurrentVersion",
				idl::REG_SZ, u"6.1"));
	return 0;
}
