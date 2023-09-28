
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

struct x_smbd_registry_key_t
{
	const std::u16string name;
	const std::vector<x_smbd_registry_value_t> values;
};

const x_smbd_registry_key_t *x_smbd_registry_find_key(const std::u16string &name);

const x_smbd_registry_value_t *x_smbd_registry_find_value(
		const x_smbd_registry_key_t *key, const std::u16string &name);

int x_smbd_registry_init();

#endif /* __smbd_registry__hxx__ */

