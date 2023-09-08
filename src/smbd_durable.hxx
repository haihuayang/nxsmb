
#ifndef __smbd_durable__hxx__
#define __smbd_durable__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/xdefines.h"
#include "smbd.hxx"
#include <stdint.h>

struct x_smbd_durable_db_t;

x_smbd_durable_db_t *x_smbd_durable_db_init(int fd,
		uint32_t capacity);

int x_smbd_durable_db_allocate_id(x_smbd_durable_db_t *db, uint64_t *p_id);

x_smbd_durable_t *x_smbd_durable_lookup(x_smbd_durable_db_t *durable_db,
		uint64_t id_persistent);

int x_smbd_durable_save(x_smbd_durable_db_t *db,
		uint64_t id_volatile,
		const x_smbd_open_state_t &open_state,
		const x_smbd_file_handle_t &file_handle);

int x_smbd_durable_remove(x_smbd_durable_db_t *db, uint64_t id_persistent);

int x_smbd_durable_disconnect(x_smbd_durable_db_t *db, uint64_t id_persistent);

x_smbd_durable_db_t *x_smbd_durable_db_open(int fd);

void x_smbd_durable_db_close(x_smbd_durable_db_t *durable_db);

void x_smbd_durable_db_restore(std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		x_smbd_durable_db_t *durable_db,
		NTSTATUS (*restore_fn)(std::shared_ptr<x_smbd_volume_t> &smbd_volume,
			x_smbd_durable_t &durable, uint64_t timeout_msec));

struct x_smbd_durable_db_visitor_t
{
	virtual bool operator()(const x_smbd_durable_t &durable) = 0;
};

void x_smbd_durable_db_traverse(x_smbd_durable_db_t *durable_db,
		x_smbd_durable_db_visitor_t &visitor);

#endif /* __smbd_durable__hxx__ */

