
#include "include/bits.hxx"
#include "smbd_durable.hxx"
#include <sys/mman.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <string.h>
#include <atomic>
#include <stdlib.h>

#define PAGE_SIZE 4096
#define ALIGN(s, a) (((s) + (a) - 1) & ~(a))

enum {
	X_SMBD_DURABLE_DB_VERSION_1 = 1,
	X_SMBD_DURABLE_DB_RECORD_SIZE = 512, // >= sizeof(x_smbd_durable_t)
	X_SMBD_DURABLE_TORELANT = 10,
};

static const char magic[8] = "DURABLE";

struct x_smbd_durable_db_header_t
{
	uint8_t magic[8];
	uint32_t version;
	uint32_t record_size;
	uint32_t capacity;
	uint32_t reserved;
};

union x_smbd_durable_marker_t
{
	uint64_t val;
	struct {
		uint32_t expired;
		uint16_t gen;
		uint16_t unused;
	};
};

static inline uint64_t get_record_offset(uint32_t reserved)
{
	return PAGE_SIZE + ALIGN(reserved * sizeof(uint64_t), PAGE_SIZE);
}

struct x_smbd_durable_db_t
{
	x_smbd_durable_db_t(int fd, uint32_t capacity, uint32_t reserved,
			void *ptr, uint64_t msize)
		: fd(fd), capacity(capacity), reserved(reserved)
		, map_ptr(ptr), map_size(msize)
		, markers((x_smbd_durable_marker_t *)((char *)map_ptr + PAGE_SIZE))
		, records((char *)ptr + get_record_offset(reserved))

	{
	}

	~x_smbd_durable_db_t()
	{
		X_ASSERT(munmap(map_ptr, map_size) == 0);
		X_ASSERT(close(fd) == 0);
	}

	const int fd;
	std::atomic<uint32_t> count{};
	const uint32_t capacity;
	const uint32_t reserved;
	void *const map_ptr;
	const uint64_t map_size;
	x_smbd_durable_marker_t *const markers;
	char *  const records;
};

static inline size_t smbd_durable_mapsize(uint32_t record_size, uint64_t reserved)
{
	size_t record_offset = get_record_offset(record_size);
	return record_offset + record_size * reserved;
}

static inline uint32_t get_epoch()
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return x_convert_assert<uint32_t>(ts.tv_sec);
};

/* persistent_id 
   16bits volume_id + 32bits db_index + generation */
/* 16bits generation + type + 32bits epoch */
int x_smbd_durable_db_save(x_smbd_durable_db_t *db,
		const void *data, uint32_t length,
		uint16_t volume_id,
		uint64_t &id)
{
	X_ASSERT(length <= X_SMBD_DURABLE_DB_RECORD_SIZE);
	uint32_t epoch = get_epoch();
	if (db->count > db->capacity / 2) {
		return -ENOSPC;
	}
	uint32_t slot;
	x_smbd_durable_marker_t old_marker;
	x_smbd_durable_marker_t new_marker;
	new_marker.expired = epoch + X_SMBD_DURABLE_TORELANT;
	new_marker.unused = 0;
	for (;;) {
		slot = (uint32_t)rand() % db->capacity;
		old_marker.val = __atomic_load_n(&db->markers[slot].val, __ATOMIC_ACQUIRE);
		if (old_marker.expired < epoch) {
			new_marker.gen = x_convert<uint16_t>(old_marker.gen + 1);
			if (new_marker.gen == 0) {
				new_marker.gen = 1;
			}
		}
			
		if (__atomic_compare_exchange_n(&db->markers[slot].val, &old_marker.val,
					new_marker.val,
					true, __ATOMIC_RELEASE, __ATOMIC_ACQUIRE)) {
			break;
		}
	}
	
	void *record = db->records + X_SMBD_DURABLE_DB_RECORD_SIZE * slot;
	memcpy(record, data, length);
	msync(record, length, MS_SYNC);

	uint64_t orig_val = new_marker.val;
	new_marker.expired = 0xffffffffu;
	X_ASSERT(orig_val == __atomic_exchange_n(&db->markers[slot].val, new_marker.val, __ATOMIC_ACQ_REL));
	msync(&db->markers[slot], sizeof(x_smbd_durable_marker_t), MS_SYNC);
	id = (uint64_t(volume_id) << 48) | (uint64_t(new_marker.gen) << 32) | slot;
	X_LOG_DBG("volume=0x%x id=0x%lx", volume_id, id);
	++db->count;
	return 0;
}

static inline uint32_t get_durable_slot(uint64_t id)
{
	return x_convert<uint32_t>(id);
}

int x_smbd_durable_db_set_timeout(x_smbd_durable_db_t *db,
		uint64_t id, uint32_t timeout)
{
	X_LOG_DBG("id=0x%lx, timeout=%d", id, timeout);
	uint32_t slot = get_durable_slot(id);
	if (slot >= db->capacity) {
		return -ENOENT;
	}

	uint32_t expired;
	if (timeout == 0) {
		expired = 0;
	} else if (timeout == 0xffffffffu) {
		expired = 0xffffffffu;
	} else {
		expired = get_epoch() + timeout;
	}

	x_smbd_durable_marker_t old_marker, new_marker;
	old_marker.val = __atomic_load_n(&db->markers[slot].val, __ATOMIC_ACQUIRE);
	new_marker.val = old_marker.val;
	new_marker.expired = expired;

	X_ASSERT(__atomic_compare_exchange_n(&db->markers[slot].val, &old_marker.val,
				new_marker.val,
				true, __ATOMIC_RELEASE, __ATOMIC_ACQUIRE));
	return 0;
}

static bool smbd_durable_db_check(const x_smbd_durable_db_header_t *db_header,
		int64_t db_size)
{
	if (memcmp(db_header->magic, magic, sizeof magic) != 0) {
		X_LOG_ERR("Invalid durable.db, wrong magic");
		return false;
	}
	
	if (db_header->version != X_SMBD_DURABLE_DB_VERSION_1) {
		X_LOG_ERR("Not support durable.db version %d", db_header->version);
		return false;
	}
	
	if (db_header->record_size != X_SMBD_DURABLE_DB_RECORD_SIZE) {
		X_LOG_ERR("Invalid durable.db, record_size = %u",
				db_header->record_size);
		return false;
	}
	
	if (db_size < (long)smbd_durable_mapsize(db_header->record_size, db_header->reserved)) {
		X_LOG_ERR("Invalid durable.db, size not match");
		return false;
	}
	return true;
}

x_smbd_durable_db_t *x_smbd_durable_db_open(int fd)
{
	struct stat st;
	int err = fstat(fd, &st);
	X_ASSERT(err == 0);

	if (st.st_size < PAGE_SIZE) {
		X_LOG_ERR("Invalid durable.db");
		return nullptr;
	}

	void *ptr = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	X_ASSERT(ptr);
	x_smbd_durable_db_header_t *db_header = (x_smbd_durable_db_header_t *)ptr;

	if (!smbd_durable_db_check(db_header, st.st_size)) {
		munmap(ptr, st.st_size);
		return nullptr;
	}

	x_smbd_durable_db_t *db = new x_smbd_durable_db_t(fd,
			db_header->capacity, db_header->reserved,
			ptr, st.st_size);
	return db;
}

x_smbd_durable_db_t *x_smbd_durable_db_init(int fd,
		uint32_t capacity, uint32_t reserved)
{
	X_ASSERT(capacity <= reserved);

	struct stat st;
	int err = fstat(fd, &st);
	X_ASSERT(err == 0);
	bool reinitialize = true;
	if (st.st_size == 0) {
		/* new file */
		X_LOG_NOTICE("new durable.db");
	} else if (st.st_size < PAGE_SIZE) {
		X_LOG_ERR("Invalid durable.db");
	} else {
		void *ptr = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		X_ASSERT(ptr);
		x_smbd_durable_db_header_t *db_header = (x_smbd_durable_db_header_t *)ptr;
		if (!smbd_durable_db_check(db_header, st.st_size)) {
		} else if (db_header->reserved < capacity) {
			/* TODO upgrade db */
			X_LOG_WARN("durable.db size not enought");
		} else {
			X_LOG_NOTICE("can reuse durable.db");
			reinitialize = false;
		}
		munmap(ptr, PAGE_SIZE);
	}

	void *ptr;
	x_smbd_durable_db_header_t *db_header;
	size_t mmap_size;
	if (reinitialize) {
		if (st.st_size == 0) {
			X_ASSERT(ftruncate(fd, 0) == 0);
		}
		mmap_size = smbd_durable_mapsize(X_SMBD_DURABLE_DB_RECORD_SIZE,
				reserved);
		X_ASSERT(ftruncate(fd, mmap_size) == 0);
		ptr = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		X_ASSERT(ptr);
		db_header = (x_smbd_durable_db_header_t *)ptr;
		memcpy(db_header->magic, magic, 8);
		db_header->version = X_SMBD_DURABLE_DB_VERSION_1;
		db_header->record_size = X_SMBD_DURABLE_DB_RECORD_SIZE;
		db_header->reserved = reserved;
		db_header->capacity = capacity;
	} else {
		mmap_size = st.st_size;
		ptr = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		X_ASSERT(ptr);
		db_header = (x_smbd_durable_db_header_t *)ptr;
		db_header->capacity = capacity;
		/* TODO restore durable opens */
	}
	msync(db_header, sizeof *db_header, MS_SYNC);

	x_smbd_durable_db_t *db = new x_smbd_durable_db_t(fd, capacity, reserved,
			ptr, mmap_size);
	return db;
}

void x_smbd_durable_db_traverse(x_smbd_durable_db_t *durable_db,
		x_smbd_durable_db_visitor_t &visitor)
{
	uint32_t epoch = get_epoch();
	for (uint32_t i = 0; i < durable_db->capacity; ++i) {
		const x_smbd_durable_marker_t marker = durable_db->markers[i];
		if (marker.expired >= epoch) {
			uint64_t id = (uint64_t(marker.gen) << 32) | i;
			uint32_t timeout = marker.expired == 0xffffffffu ?
				0xffffffffu : marker.expired - epoch;
			if (visitor(id, timeout, durable_db->records +
						(X_SMBD_DURABLE_DB_RECORD_SIZE * i),
						X_SMBD_DURABLE_DB_RECORD_SIZE)) {
				break;
			}
		}
	}
}

void *x_smbd_durable_db_lookup(x_smbd_durable_db_t *durable_db,
		uint64_t id)
{
	uint32_t slot = get_durable_slot(id);
	if (slot >= durable_db->capacity) {
		return nullptr;
	}
	
	uint32_t epoch = get_epoch();
	const x_smbd_durable_marker_t marker = durable_db->markers[slot];
	if (marker.expired < epoch) {
		return nullptr;
	}

	return  durable_db->records + (X_SMBD_DURABLE_DB_RECORD_SIZE * slot);
}

#if 0
void x_smbd_durable_db_restore(x_smbd_durable_db_t *durable_db,
		x_smbd_durable_db_visitor_t &visitor)
{
	uint32_t epoch = get_epoch();
	for (uint32_t i = 0; i < durable_db->capacity; ++i) {
		x_smbd_durable_marker_t marker = durable_db->markers[i];
		if (marker.expired > epoch) {
			void *record = durable_db->records +
				(X_SMBD_DURABLE_DB_RECORD_SIZE * i);
			x_smbd_durable_t *smbd_durable = record;
			uint32_t timeout_msec = smbd_durable->timeout_msec;
			
			uint64_t id = (uint64_t(marker.gen) << 32) | i;
			uint32_t timeout = marker.expired == 0xffffffffu ?
				0xffffffffu : marker.expired - epoch;

			x_smbd_open_t *smbd_open;
			NTSTATUS status = smbd_volume->open_by_handle(
					smbd_open, smbd_volume,
					smbd_durable

			if (visitor(id, timeout, durable_db->records +
						(X_SMBD_DURABLE_DB_RECORD_SIZE * i),
						X_SMBD_DURABLE_DB_RECORD_SIZE)) {
				break;
			}
		}
	}
}
#endif
void x_smbd_durable_db_close(x_smbd_durable_db_t *durable_db)
{
	delete durable_db;
}


