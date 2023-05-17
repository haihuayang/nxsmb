
#include "include/utils.hxx"
#include <stdio.h>

thread_local x_trace_t g_trace;

static thread_local char x_trace_buffer[4096];

const char *x_trace_string()
{
	auto depth = g_trace.depth;
	size_t max = sizeof x_trace_buffer - 1;
	char *p = x_trace_buffer;
	while (depth-- > 0) {
		size_t len = snprintf(p, max, "\n\t%s", g_trace.stack[depth]);
		if (len >= max) {
			break;
		}
		p += len;
		max -= len;
	}
	*p = '\0';
	return x_trace_buffer;
}

