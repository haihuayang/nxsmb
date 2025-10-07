
#ifndef __smbd_durable__hxx__
#define __smbd_durable__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/xdefines.h"
#include "smbd.hxx"
#include <stdint.h>

#define X_SMBD_DURABLE_DIR "smbd-durable"

struct x_smbd_durable_db_t;

x_smbd_durable_db_t *x_smbd_durable_db_init(int dir_fd, uint32_t capacity,
		uint32_t max_record_per_file);

int x_smbd_durable_db_allocate_id(x_smbd_durable_db_t *db,
		uint64_t *p_id_persistent, uint64_t id_volatile);

uint64_t x_smbd_durable_lookup(x_smbd_durable_db_t *durable_db,
		uint64_t id_persistent);

int x_smbd_durable_update_flags(x_smbd_durable_db_t *db,
		bool sync,
		uint64_t id_persistent,
		uint32_t flags);

int x_smbd_durable_update_locks(x_smbd_durable_db_t *db,
		bool sync,
		uint64_t id_persistent,
		const std::vector<x_smb2_lock_element_t> &locks);

int x_smbd_durable_save(x_smbd_durable_db_t *db,
		uint64_t id_persistent,
		uint64_t id_volatile,
		const x_smbd_open_state_t &open_state,
		const x_smbd_lease_data_t &lease_data,
		const x_smbd_file_handle_t &file_handle);

int x_smbd_durable_remove(x_smbd_durable_db_t *db, bool sync, uint64_t id_persistent);

int x_smbd_durable_disconnect(x_smbd_durable_db_t *db, bool sync, uint64_t id_persistent);

int x_smbd_durable_reconnect(x_smbd_durable_db_t *db, bool sync, uint64_t id_persistent);

void x_smbd_durable_db_release(x_smbd_durable_db_t *durable_db);

void x_smbd_durable_db_restore(
		std::shared_ptr<x_smbd_share_t> &smbd_share,
		std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		x_smbd_durable_db_t *durable_db,
		NTSTATUS (*restore_fn)(
			std::shared_ptr<x_smbd_share_t> &smbd_share,
			std::shared_ptr<x_smbd_volume_t> &smbd_volume,
			uint64_t id_persistent,
			x_smbd_durable_t &durable, uint64_t timeout_msec));

ssize_t x_smbd_durable_log_read_file(int dir_fd, const char *name,
		bool is_merged, uint64_t &skip_idx,
		std::map<uint64_t, std::unique_ptr<x_smbd_durable_t>> &durables);

ssize_t x_smbd_durable_log_read(int dir_fd, uint64_t max_file_no,
		uint64_t &next_file_no,
		std::map<uint64_t, std::unique_ptr<x_smbd_durable_t>> &durables,
		std::vector<std::string> &files);

struct x_smbd_durable_update_t
{
	enum {
		type_update_flags,
		type_update_locks,
		type_disconnect,
		type_reconnect,
		type_max,
	};
	uint32_t type;
	uint32_t flags;
	uint64_t disconnect_msec;
	std::vector<x_smb2_lock_element_t> locks;
};

struct x_smbd_durable_log_visitor_t {
	virtual ~x_smbd_durable_log_visitor_t() = default;
	virtual bool initiate(uint64_t id, x_smbd_durable_t &durable) = 0;
	virtual bool update(uint64_t id, x_smbd_durable_update_t &update) = 0;
	virtual bool finalize(uint64_t id) = 0;
};

ssize_t x_smbd_durable_log_read(int dirfd,
		x_smbd_durable_log_visitor_t &visitor);

ssize_t x_smbd_durable_log_read_file(int dir_fd, const char *name,
		bool is_merged,
		x_smbd_durable_log_visitor_t &visitor);

/* smbd_durable private */
enum {
	X_SMBD_DURABLE_MAX_RECORD_SIZE = 1024 * 1024 - 1024,
};

union x_smbd_durable_update_record_t
{
	uint32_t type;
	struct {
		uint32_t type;
		uint32_t flags;
	} update_flags;
	struct {
		uint32_t type;
		uint32_t num_lock;
		x_smb2_lock_element_t locks[0];
	} update_locks;
	struct {
		uint32_t type;
		uint32_t unused;
		uint64_t disconnect_msec;
	} disconnect;
	struct {
		uint32_t type;
		uint32_t unused;
	} reconnect;
};

std::unique_ptr<x_smbd_durable_t> x_smbd_durable_parse(
		const void *data, size_t size);

ssize_t x_smbd_durable_encode(void *p, size_t buf_size,
		uint64_t disconnect_msec,
		uint64_t id_volatile,
		const x_smbd_open_state_t &open_state,
		const x_smbd_lease_data_t &lease_data,
		const x_smbd_file_handle_t &file_handle);

#endif /* __smbd_durable__hxx__ */

