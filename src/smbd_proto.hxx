
#ifndef __smbd_proto__hxx__
#define __smbd_proto__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include <stdint.h>

enum class x_smbd_dhmode_t : uint8_t {
	NONE,
	DURABLE,
	PERSISTENT,
	MAX,
};

extern const char x_smbd_dhmode_names[];

static inline char x_smbd_dhmode_to_name(x_smbd_dhmode_t dhmode)
{
	if (dhmode >= x_smbd_dhmode_t::MAX) {
		return 'X';
	} else {
		return x_smbd_dhmode_names[(unsigned int)dhmode];
	}
}

#endif /* __smbd_proto__hxx__ */

