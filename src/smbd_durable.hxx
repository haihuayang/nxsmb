
#ifndef __smbd_durable__hxx__
#define __smbd_durable__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/xdefines.h"
#include <stdint.h>

struct x_smbd_durable_db_t;

x_smbd_durable_db_t *x_smbd_durable_db_init(int fd,
		uint32_t capacity, uint32_t reserved);

int x_smbd_durable_db_save(x_smbd_durable_db_t *db,
		const void *data, uint32_t length,
		uint16_t volume_id,
		uint64_t &id);

int x_smbd_durable_db_set_timeout(x_smbd_durable_db_t *db,
		uint64_t id, uint32_t timeout);

x_smbd_durable_db_t *x_smbd_durable_db_open(int fd);

void x_smbd_durable_db_close(x_smbd_durable_db_t *durable_db);

struct x_smbd_durable_db_visitor_t
{
	virtual bool operator()(uint64_t id, uint32_t timeout,
			void *record, size_t size) = 0;
};

void x_smbd_durable_db_traverse(x_smbd_durable_db_t *durable_db,
		x_smbd_durable_db_visitor_t &visitor);

void *x_smbd_durable_db_lookup(x_smbd_durable_db_t *durable_db,
		uint64_t id);

#endif /* __smbd_durable__hxx__ */

