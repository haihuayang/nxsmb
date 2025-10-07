
#include "include/bits.hxx"
#include "include/utils.hxx"
#include "include/iuflog.hxx"
#include "nxfsd.hxx"
#include "smbd_durable.hxx"
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <string.h>
#include <atomic>

struct x_smbd_durable_slot_t
{
	std::atomic<uint64_t> id_volatile;
};

struct x_smbd_durable_db_t
{
	x_smbd_durable_db_t(int fd, uint32_t capacity, uint32_t max_record_per_file);

	~x_smbd_durable_db_t()
	{
		x_iuflog_release(log);
	}

	x_iuflog_t *log;

	std::atomic<int64_t> num_durable;
	std::vector<x_smbd_durable_slot_t> slots;
};


static inline uint64_t get_epoch_msec()
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
};

static inline uint32_t get_durable_slot(uint64_t id_persistent)
{
	return x_convert<uint32_t>(id_persistent);
}

int x_smbd_durable_db_allocate_id(x_smbd_durable_db_t *db,
		uint64_t *p_id_persistent, uint64_t id_volatile)
{
	X_ASSERT(id_volatile != 0);
	if (db->num_durable.load(std::memory_order_relaxed) >=
			int64_t(db->slots.size() / 2)) {
		return -ENOSPC;
	}
	uint64_t slot_id;
	uint64_t rval;
	std::uniform_int_distribution<uint64_t> distrib(0ul, (1ul << 48) - 1);

	for (uint32_t i = 0; ; ++i) {
		rval = distrib(rand_engine);
		slot_id = rval % db->slots.size();
		auto &slot = db->slots[slot_id];

		uint64_t old_val = 0ul;
		if (std::atomic_compare_exchange_weak_explicit(
					&slot.id_volatile,
					&old_val, id_volatile,
					std::memory_order_relaxed,
					std::memory_order_relaxed)) {
			break;
		}
	}
	X_ASSERT(db->num_durable.fetch_add(1, std::memory_order_relaxed) >= 0);
	uint64_t id = (rval & (0xffff00000000)) | slot_id;
	*p_id_persistent = id;
	return 0;
}

int x_smbd_durable_remove(x_smbd_durable_db_t *db, bool sync, uint64_t id_persistent)
{
	X_LOG(SMB, DBG, "id_persistent=0x%lx", id_persistent);
	uint32_t slot_id = get_durable_slot(id_persistent);

	X_ASSERT(slot_id < db->slots.size());
	uint64_t id_volatile = db->slots[slot_id].id_volatile.exchange(0, std::memory_order_relaxed);
	X_ASSERT(id_volatile != 0);

	X_ASSERT(db->num_durable.fetch_sub(1, std::memory_order_relaxed) > 0);

	return x_iuflog_finalize(db->log, sync, id_persistent);
}

struct smbd_durable_disconnect_t
{
	x_iuflog_state_t base;
	const uint64_t disconnect_msec;
};

static ssize_t smbd_durable_disconnect_op_encode(
		const x_iuflog_state_t *state, void *buf, size_t size)
{
	const auto *disconnect_state = X_CONTAINER_OF(
			state, smbd_durable_disconnect_t, base);
	if (size < sizeof(x_smbd_durable_update_record_t::disconnect)) {
		return -ENOSPC;
	}

	auto *record = (x_smbd_durable_update_record_t *)buf;
	record->type = X_H2LE32(x_smbd_durable_update_t::type_disconnect);
	record->disconnect.unused = 0;
	record->disconnect.disconnect_msec = X_H2LE64(disconnect_state->disconnect_msec);
	return sizeof(x_smbd_durable_update_record_t::disconnect);
}

struct x_iuflog_state_ops_t smbd_durable_disconnect_ops = {
	nullptr,
	smbd_durable_disconnect_op_encode,
	nullptr,
};

int x_smbd_durable_disconnect(x_smbd_durable_db_t *db, bool sync, uint64_t id_persistent)
{
	X_LOG(SMB, DBG, "id_persistent=0x%lx", id_persistent);
	uint32_t slot_id = get_durable_slot(id_persistent);

	X_ASSERT(slot_id < db->slots.size());

	smbd_durable_disconnect_t state{&smbd_durable_disconnect_ops, get_epoch_msec()};
	return x_iuflog_update(db->log, sync, id_persistent, &state.base);
}

struct smbd_durable_reconnect_t
{
	x_iuflog_state_t base;
	// TODO lease state
};

static ssize_t smbd_durable_reconnect_op_encode(
		const x_iuflog_state_t *state, void *buf, size_t size)
{
	const auto *reconnect_state = X_CONTAINER_OF(
			state, smbd_durable_reconnect_t, base);
	if (size < sizeof(x_smbd_durable_update_record_t::reconnect)) {
		return -ENOSPC;
	}

	(void)reconnect_state;
	auto *record = (x_smbd_durable_update_record_t *)buf;
	record->type = X_H2LE32(x_smbd_durable_update_t::type_reconnect);
	record->reconnect.unused = 0;
	return sizeof(x_smbd_durable_update_record_t::reconnect);
}

struct x_iuflog_state_ops_t smbd_durable_reconnect_ops = {
	nullptr,
	smbd_durable_reconnect_op_encode,
	nullptr,
};

int x_smbd_durable_reconnect(x_smbd_durable_db_t *db, bool sync, uint64_t id_persistent)
{
	X_LOG(SMB, DBG, "id_persistent=0x%lx", id_persistent);
	uint32_t slot_id = get_durable_slot(id_persistent);

	X_ASSERT(slot_id < db->slots.size());

	smbd_durable_reconnect_t state{&smbd_durable_reconnect_ops};
	return x_iuflog_update(db->log, sync, id_persistent, &state.base);
}

struct smbd_durable_update_flags_t
{
	x_iuflog_state_t base;
	const uint32_t flags;
};

static ssize_t smbd_durable_update_flags_op_encode(
		const x_iuflog_state_t *state, void *buf, size_t size)
{
	const auto *update_flags_state = X_CONTAINER_OF(
			state, smbd_durable_update_flags_t, base);
	if (size < sizeof(x_smbd_durable_update_record_t::update_flags)) {
		return -ENOSPC;
	}

	auto *record = (x_smbd_durable_update_record_t *)buf;
	record->type = X_H2LE32(x_smbd_durable_update_t::type_update_flags);
	record->update_flags.flags = X_H2LE32(update_flags_state->flags);
	return sizeof(x_smbd_durable_update_record_t::update_flags);
}

struct x_iuflog_state_ops_t smbd_durable_update_flags_ops = {
	nullptr,
	smbd_durable_update_flags_op_encode,
	nullptr,
};

int x_smbd_durable_update_flags(x_smbd_durable_db_t *db,
		bool sync,
		uint64_t id_persistent,
		uint32_t flags)
{
	X_LOG(SMB, DBG, "id_persistent=0x%lx", id_persistent);

	smbd_durable_update_flags_t state{&smbd_durable_update_flags_ops, flags};
	return x_iuflog_update(db->log, sync, id_persistent, &state.base);
}


struct smbd_durable_update_locks_t
{
	x_iuflog_state_t base;
	const std::vector<x_smb2_lock_element_t> &locks;
};

static ssize_t smbd_durable_update_locks_op_encode(
		const x_iuflog_state_t *state, void *buf, size_t size)
{
	const auto *update_locks_state = X_CONTAINER_OF(
			state, smbd_durable_update_locks_t, base);
	if (size < sizeof(x_smbd_durable_update_record_t::update_locks) +
			update_locks_state->locks.size() * sizeof(x_smb2_lock_element_t)) {
		return -ENOSPC;
	}

	auto *record = (x_smbd_durable_update_record_t *)buf;
	record->type = X_H2LE32(x_smbd_durable_update_t::type_update_locks);
	record->update_locks.num_lock = X_H2LE32(x_convert_assert<uint32_t>(update_locks_state->locks.size()));
	auto plock = record->update_locks.locks;
	for (auto &lock : update_locks_state->locks) {
		plock->offset = X_H2LE64(lock.offset);
		plock->length = X_H2LE64(lock.length);
		plock->flags = X_H2LE32(lock.flags);
		plock->unused = 0;
		++plock;
	}
	return sizeof(x_smbd_durable_update_record_t::update_locks) +
		update_locks_state->locks.size() * sizeof(x_smb2_lock_element_t);
}

struct x_iuflog_state_ops_t smbd_durable_update_locks_ops = {
	nullptr,
	smbd_durable_update_locks_op_encode,
	nullptr,
};

int x_smbd_durable_update_locks(x_smbd_durable_db_t *db,
		bool sync,
		uint64_t id_persistent,
		const std::vector<x_smb2_lock_element_t> &locks)
{
	X_LOG(SMB, DBG, "id_persistent=0x%lx", id_persistent);

	smbd_durable_update_locks_t state{&smbd_durable_update_locks_ops, locks};
	return x_iuflog_update(db->log, sync, id_persistent, &state.base);
}

struct smbd_durable_save_t
{
	x_iuflog_state_t base;

	const uint64_t epoch;
	const uint64_t id_volatile;
	const x_smbd_open_state_t & open_state;
	const x_smbd_lease_data_t & lease_data;
	const x_smbd_file_handle_t & file_handle;
};

static ssize_t smbd_durable_save_op_encode(
		const x_iuflog_state_t *state, void *buf, size_t size)
{
	const auto *save_state = X_CONTAINER_OF(
			state, smbd_durable_save_t, base);

	return x_smbd_durable_encode(buf, size,
		save_state->epoch,
		save_state->id_volatile,
		save_state->open_state,
		save_state->lease_data,
		save_state->file_handle);
}

struct x_iuflog_state_ops_t smbd_durable_save_ops = {
	nullptr,
	smbd_durable_save_op_encode,
	nullptr,
};

int x_smbd_durable_save(x_smbd_durable_db_t *db,
		uint64_t id_persistent,
		uint64_t id_volatile,
		const x_smbd_open_state_t &open_state,
		const x_smbd_lease_data_t &lease_data,
		const x_smbd_file_handle_t &file_handle)
{
	X_LOG(SMB, DBG, "id_persistent=0x%lx", id_persistent);

	smbd_durable_save_t durable_save{
			&smbd_durable_save_ops,
			uint64_t(-1),
			id_volatile,
			open_state, lease_data, file_handle};
	return x_iuflog_initiate(db->log,
			open_state.dhmode == x_smbd_dhmode_t::PERSISTENT,
			id_persistent,
			&durable_save.base);
}

struct smbd_durable_load_t
{
	x_iuflog_state_t base;
	x_smbd_durable_t durable;
};

static void smbd_durable_load_op_release(x_iuflog_state_t *state)
{
	auto *load_state = X_CONTAINER_OF(
			state, smbd_durable_load_t, base);
	delete load_state;
}

static ssize_t smbd_durable_load_op_encode(
		const x_iuflog_state_t *state, void *buf, size_t size)
{
	const auto *load_state = X_CONTAINER_OF(
			state, smbd_durable_load_t, base);
	const auto &smbd_durable = load_state->durable;

	return x_smbd_durable_encode(buf, size,
		smbd_durable.disconnect_msec,
		smbd_durable.id_volatile,
		smbd_durable.open_state,
		smbd_durable.lease_data,
		smbd_durable.file_handle);
}

#define REPORT_ERR(fmt, ...) X_LOG(SMB, ERR, fmt, ##__VA_ARGS__)
static int smbd_durable_load_op_update(x_iuflog_state_t *state,
		const void *buf, size_t size)
{
	auto *load_state = X_CONTAINER_OF(
			state, smbd_durable_load_t, base);
	auto &smbd_durable = load_state->durable;

	auto *record = (x_smbd_durable_update_record_t *)buf;
	if (size < sizeof(record->type)) {
		return -EINVAL;
	}

	uint32_t type = X_LE2H32(record->type);
	if (type == x_smbd_durable_update_t::type_update_flags) {
		if (size != sizeof(x_smbd_durable_update_record_t::update_flags)) {
			REPORT_ERR("invalid type_update_flags record size %lu", size);
			return -EINVAL;
		}
		uint32_t flags = X_LE2H32(record->update_flags.flags);
		smbd_durable.open_state.flags = flags;

	} else if (type == x_smbd_durable_update_t::type_update_locks) {
		if (size < sizeof(x_smbd_durable_update_record_t::update_locks)) {
			REPORT_ERR("invalid type_update_locks record size %lu", size);
			return -EINVAL;
		}
		uint32_t num_lock = X_LE2H32(record->update_locks.num_lock);
		if (size != sizeof(x_smbd_durable_update_record_t::update_locks)
				+ num_lock * sizeof(x_smb2_lock_element_t)) {
			REPORT_ERR("invalid type_update_locks record size %lu", size);
			return -EINVAL;
		}

		const auto *ptr = record->update_locks.locks;
		std::vector<x_smb2_lock_element_t> locks(num_lock);
		for (uint32_t i = 0; i < num_lock; ++i) {
			auto &lock = locks[i];
			lock.offset = X_LE2H64(ptr[i].offset);
			lock.length = X_LE2H64(ptr[i].length);
			lock.flags = X_LE2H32(ptr[i].flags);
		}

		std::swap(smbd_durable.open_state.locks, locks);
	} else if (type == x_smbd_durable_update_t::type_disconnect) {
		if (size != sizeof(x_smbd_durable_update_record_t::disconnect)) {
			REPORT_ERR("invalid type_disconnect record size %lu", size);
			return -EINVAL;
		}

		uint64_t disconnect_msec = X_LE2H64(record->disconnect.disconnect_msec);
		smbd_durable.disconnect_msec = disconnect_msec;

	} else if (type == x_smbd_durable_update_t::type_reconnect) {
		if (size != sizeof(x_smbd_durable_update_record_t::reconnect)) {
			REPORT_ERR("invalid type_reconnect record size %lu", size);
			return -EINVAL;
		}

		smbd_durable.disconnect_msec = uint64_t(-1);

	} else {
		REPORT_ERR("invalid record type %u", type);
		return -EINVAL;
	}
	return 0;
}

struct x_iuflog_state_ops_t smbd_durable_load_ops = {
	smbd_durable_load_op_release,
	smbd_durable_load_op_encode,
	smbd_durable_load_op_update,
};

static x_iuflog_state_t *smbd_durable_parse_state(
		uint64_t id, const void *data, size_t size)
{
	auto durable = x_smbd_durable_parse(data, size);
	if (!durable) {
		return nullptr;
	}
	auto *ret =  new smbd_durable_load_t{
		&smbd_durable_load_ops, *durable};
	return ret ? &ret->base : nullptr;
}

x_smbd_durable_db_t *x_smbd_durable_db_init(int dir_fd, uint32_t capacity,
		uint32_t max_record_per_file)
{
	x_smbd_durable_db_t *db = new x_smbd_durable_db_t(dir_fd, capacity,
			max_record_per_file);
	X_ASSERT(db);
	return db;
}

uint64_t x_smbd_durable_lookup(x_smbd_durable_db_t *db,
		uint64_t id_persistent)
{
	uint32_t slot_id = get_durable_slot(id_persistent);
	if (slot_id >= db->slots.size()) {
		return 0;
	}

	return db->slots[slot_id].id_volatile.load(std::memory_order_relaxed);
}

static int smbd_durable_restore(uint64_t id, x_iuflog_state_t *state,
		x_smbd_durable_db_t * durable_db,
		uint64_t epoch,
		std::shared_ptr<x_smbd_share_t> &smbd_share,
		std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		NTSTATUS (*restore_fn)(
			std::shared_ptr<x_smbd_share_t> &smbd_share,
			std::shared_ptr<x_smbd_volume_t> &smbd_volume,
			uint64_t id_persistent,
			x_smbd_durable_t &durable, uint64_t timeout_msec))
{
	auto *durable_state = X_CONTAINER_OF(
			state, smbd_durable_load_t, base);
	auto &durable = durable_state->durable;

	uint64_t timeout_msec;
	uint64_t disconnect_msec = durable.disconnect_msec;
	if (disconnect_msec == (uint64_t)-1) {
		disconnect_msec = epoch;
		timeout_msec = durable.open_state.durable_timeout_msec;
		durable.disconnect_msec = disconnect_msec;
	} else {
		uint64_t expired_msec = durable.disconnect_msec +
			durable.open_state.durable_timeout_msec;
		if (expired_msec < epoch) {
			return -ETIMEDOUT;
		}
		timeout_msec = expired_msec - epoch;
	}
	uint64_t slot_id = get_durable_slot(id);
	if (slot_id >= durable_db->slots.size()) {
		X_LOG(SMB, ERR, "invalid id_persistent 0x%lx",
				id);
		return -EINVAL;
	}
	NTSTATUS status = restore_fn(smbd_share,
			smbd_volume,
			id, durable, timeout_msec);
	if (!NT_STATUS_IS_OK(status)) {
		X_LOG(SMB, WARN, "failed to restore open %lx:%lx",
				id,
				durable.id_volatile);
		return -EINVAL;
	}
	X_LOG(SMB, DBG, "restored open %lx:%lx",
			id,
			durable.id_volatile);

	durable_db->num_durable.fetch_add(1, std::memory_order_relaxed);
	durable_db->slots[slot_id].id_volatile.store(durable.id_volatile, std::memory_order_relaxed);
	return 0;
}

void x_smbd_durable_db_restore(
		std::shared_ptr<x_smbd_share_t> &smbd_share,
		std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		x_smbd_durable_db_t *durable_db,
		NTSTATUS (*restore_fn)(
			std::shared_ptr<x_smbd_share_t> &smbd_share,
			std::shared_ptr<x_smbd_volume_t> &smbd_volume,
			uint64_t id_persistent,
			x_smbd_durable_t &durable, uint64_t timeout_msec))
{
	x_iuflog_restore(durable_db->log, [&](uint64_t id, x_iuflog_state_t *state) {
			return smbd_durable_restore(id, state,
				durable_db,
				get_epoch_msec(),
				smbd_share,
				smbd_volume,
				restore_fn);
		});
}

x_smbd_durable_db_t::x_smbd_durable_db_t(int fd, uint32_t capacity,
		uint32_t max_record_per_file)
	: log(x_iuflog_open(x_nxfsd_get_async_tpool(),
				fd,
				smbd_durable_parse_state,
				X_SMBD_DURABLE_MAX_RECORD_SIZE,
				max_record_per_file,
				4))
	, slots(capacity << 1)
{
}

void x_smbd_durable_db_release(x_smbd_durable_db_t *durable_db)
{
	delete durable_db;
}


