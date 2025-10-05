
#ifndef __include__iuflog__hxx__
#define __include__iuflog__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/xdefines.h"
#include "include/threadpool.hxx"
#include <functional>
#include <stdint.h>

enum class x_iuflog_record_type_t {
	initiate,
	update,
	finalize,
	max,
};

struct x_iuflog_t;

struct x_iuflog_state_t;
struct x_iuflog_state_ops_t
{
	void (*release)(x_iuflog_state_t *state);
	ssize_t (*encode)(const x_iuflog_state_t *state, void *buf, size_t size);
	int (*update)(x_iuflog_state_t *state, const void *buf, size_t size);
};

struct x_iuflog_state_t
{
	const x_iuflog_state_ops_t *ops;
};

using x_iuflog_parse_fn = std::function<x_iuflog_state_t *(uint64_t id,
		const void *data, size_t size)>;

x_iuflog_t *x_iuflog_open(
		x_threadpool_t *threadpool,
		int dir_fd,
		x_iuflog_parse_fn parse_state,
		uint32_t max_record_size,
		uint32_t max_record_per_file,
		uint32_t merge_threshold);

void x_iuflog_release(x_iuflog_t *log);

int x_iuflog_initiate(x_iuflog_t *log,
		bool sync, uint64_t id,
		const x_iuflog_state_t *state);

int x_iuflog_update(x_iuflog_t *log,
		bool sync, uint64_t id,
		const x_iuflog_state_t *state);

int x_iuflog_finalize(x_iuflog_t *log,
		bool sync, uint64_t id);

void x_iuflog_restore(x_iuflog_t *log,
		const std::function<int(uint64_t, x_iuflog_state_t *)> &restorer);

ssize_t x_iuflog_read_file(int dir_fd, const char *name,
		uint32_t max_record_size,
		bool is_merged,
		const std::function<int(uint64_t, x_iuflog_record_type_t type,
			const void *data, size_t size)> &visitor);

ssize_t x_iuflog_read(int dir_fd,
		uint32_t max_record_size,
		const std::function<int(uint64_t, x_iuflog_record_type_t type,
			const void *data, size_t size)> &visitor);

#endif /* __include__iuflog__hxx__ */

