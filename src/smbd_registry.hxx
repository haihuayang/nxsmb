
#ifndef __smbd_registry__hxx__
#define __smbd_registry__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/librpc/misc.hxx"

struct x_smbd_registry_value_t
{
	std::u16string name;
	idl::winreg_Type type;
	std::vector<uint8_t> value;
};

struct x_smbd_registry_key_t;

const std::u16string &x_smbd_registry_key_get_name(const x_smbd_registry_key_t &key);

std::shared_ptr<x_smbd_registry_key_t> x_smbd_registry_open_key(
		const x_smbd_registry_key_t *parent_key,
		const std::u16string &path);

std::pair<std::shared_ptr<x_smbd_registry_key_t>, bool> x_smbd_registry_create_key(
		x_smbd_registry_key_t *parent,
		const std::u16string &path);

bool x_smbd_registry_delete_key(x_smbd_registry_key_t *parent,
		const std::u16string &path);

const x_smbd_registry_value_t *x_smbd_registry_find_value(
		const x_smbd_registry_key_t &key, const std::u16string &name);

int x_smbd_registry_init();

#endif /* __smbd_registry__hxx__ */

