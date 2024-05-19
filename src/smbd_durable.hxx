
#ifndef __smbd_durable__hxx__
#define __smbd_durable__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/xdefines.h"
#include "smbd.hxx"
#include <stdint.h>

enum {
	X_SMBD_DURABLE_DB_VERSION_1 = 1,
	X_SMBD_DURABLE_MAX_RECORD_SIZE = 1024 * 1024,
};

#define X_SMBD_DURABLE_LOG "durable.log"
#define X_SMBD_DURABLE_LOG_MERGED X_SMBD_DURABLE_LOG "-merged"
#define X_SMBD_DURABLE_LOG_TMP X_SMBD_DURABLE_LOG "-tmp"

struct x_smbd_durable_db_t;

x_smbd_durable_db_t *x_smbd_durable_db_init(int dir_fd, uint32_t capacity,
		uint32_t max_record_per_file);

int x_smbd_durable_db_allocate_id(x_smbd_durable_db_t *db,
		uint64_t *p_id_persistent, uint64_t id_volatile);

uint64_t x_smbd_durable_lookup(x_smbd_durable_db_t *durable_db,
		uint64_t id_persistent);

int x_smbd_durable_update_flags(x_smbd_durable_db_t *db,
		uint64_t id_persistent,
		uint32_t flags);

int x_smbd_durable_update_locks(x_smbd_durable_db_t *db,
		uint64_t id_persistent,
		const std::vector<x_smb2_lock_element_t> &locks);

int x_smbd_durable_save(x_smbd_durable_db_t *db,
		uint64_t id_persistent,
		uint64_t id_volatile,
		const x_smbd_open_state_t &open_state,
		const x_smbd_lease_data_t &lease_data,
		const x_smbd_file_handle_t &file_handle);

int x_smbd_durable_remove(x_smbd_durable_db_t *db, uint64_t id_persistent);

int x_smbd_durable_disconnect(x_smbd_durable_db_t *db, uint64_t id_persistent);

x_smbd_durable_db_t *x_smbd_durable_db_open(int fd);

void x_smbd_durable_db_release(x_smbd_durable_db_t *durable_db);

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

ssize_t x_smbd_durable_log_read_file(int dir_fd, const char *name,
		bool is_merged, uint64_t &skip_idx,
		std::map<uint64_t, std::unique_ptr<x_smbd_durable_t>> &durables);

ssize_t x_smbd_durable_log_read(int dir_fd, uint64_t max_file_no,
		uint64_t &next_file_no,
		std::map<uint64_t, std::unique_ptr<x_smbd_durable_t>> &durables,
		std::vector<std::string> &files);
#if 0
bool x_smbd_durable_log_output(int fd, x_smbd_durable_record_t *rec,
		uint32_t type, uint32_t size,
		uint64_t id_persistent);
#endif
int x_smbd_durable_log_durable(int fd,
		uint64_t id_persistent,
		uint64_t disconnect_msec,
		uint64_t id_volatile,
		const x_smbd_open_state_t &open_state,
		const x_smbd_lease_data_t &lease_data,
		const x_smbd_file_handle_t &file_handle);

int x_smbd_durable_log_close(int fd, uint64_t id_persistent);

int x_smbd_durable_log_disconnect(int fd, uint64_t id_persistent, uint64_t disconnect_msec);

int x_smbd_durable_log_flags(int fd, uint64_t id_persistent, uint32_t flags);

int x_smbd_durable_log_locks(int fd, uint64_t id_persistent,
		const std::vector<x_smb2_lock_element_t> &locks);

void x_smbd_durable_log_init_header(int fd, uint64_t next_file_no);

#endif /* __smbd_durable__hxx__ */

