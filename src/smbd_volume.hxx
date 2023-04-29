
#ifndef __smbd_volume__hxx__
#define __smbd_volume__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/xdefines.h"
#include <stdint.h>

int x_smbd_volume_read_id(int vol_fd, uint16_t &vol_id);
int x_smbd_volume_set_id(int vol_fd, uint16_t vol_id);

#endif /* __smbd_volume__hxx__ */

