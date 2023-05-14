/* ==========================================================================
 * timeout.h - Tickless hierarchical timing wheel.
 * --------------------------------------------------------------------------
 * Copyright (c) 2013, 2014  William Ahern
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to permit
 * persons to whom the Software is furnished to do so, subject to the
 * following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
 * NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
 * USE OR OTHER DEALINGS IN THE SOFTWARE.
 * ==========================================================================
 */
#ifndef __timeout__hxx__
#define __timeout__hxx__

#include "list.hxx"

#include <inttypes.h>   /* PRIu64 PRIx64 PRIX64 uint64_t */


#if !defined TIMEOUT_PUBLIC
#define TIMEOUT_PUBLIC
#endif


/*
 * I N T E G E R  T Y P E  I N T E R F A C E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define TIMEOUT_C(n) UINT64_C(n)
#define TIMEOUT_PRIu PRIu64
#define TIMEOUT_PRIx PRIx64
#define TIMEOUT_PRIX PRIX64

typedef uint64_t timeout_t;


/*
 * C A L L B A C K  I N T E R F A C E
 *
 * Callback function parameters unspecified to make embedding into existing
 * applications easier.
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#ifndef TIMEOUT_CB_OVERRIDE
struct timeout_cb {
	void (*fn)();
	void *arg;
}; /* struct timeout_cb */
#endif

/*
 * T I M E O U T  I N T E R F A C E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define TIMEOUT_ABS 0x02 /* treat timeout values as absolute */

#define TIMEOUT_INITIALIZER(flags) { (flags) }

#define timeout_setcb(to, fn, arg) do { \
	(to)->callback.fn = (fn);       \
	(to)->callback.arg = (arg);     \
} while (0)

struct x_timer_t {
	int flags;
	unsigned int bucket;
	/* index to timeout list if pending on wheel or expiry queue */

	timeout_t expires;
	/* absolute expiration time */

	x_dlink_t link;
	/* entry member for struct timeout_list lists */

#ifndef TIMEOUT_DISABLE_CALLBACKS
	struct timeout_cb callback;
	/* optional callback information */
#endif
}; /* struct x_timer_t */


TIMEOUT_PUBLIC x_timer_t *timeout_init(x_timer_t *, int);
/* initialize timeout structure (same as TIMEOUT_INITIALIZER) */

TIMEOUT_PUBLIC bool timeout_pending(x_timer_t *);
/* true if on timing wheel, false otherwise */
 
TIMEOUT_PUBLIC bool timeout_expired(x_timer_t *);
/* true if on expired queue, false otherwise */

/*
 * T I M I N G  W H E E L  I N T E R F A C E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

struct timeouts;

TIMEOUT_PUBLIC struct timeouts *timeouts_open();
/* open a new timing wheel, setting optional HZ (for float conversions) */

TIMEOUT_PUBLIC void timeouts_close(struct timeouts *);
/* destroy timing wheel */

TIMEOUT_PUBLIC void timeouts_update(struct timeouts *, timeout_t);
/* update timing wheel with current absolute time */

TIMEOUT_PUBLIC void timeouts_step(struct timeouts *, timeout_t);
/* step timing wheel by relative time */

TIMEOUT_PUBLIC timeout_t timeouts_timeout(struct timeouts *);
/* return interval to next required update */

TIMEOUT_PUBLIC void timeouts_add(struct timeouts *, x_timer_t *, timeout_t);
/* add timeout to timing wheel */

TIMEOUT_PUBLIC void timeouts_del(struct timeouts *, x_timer_t *);
/* remove timeout from any timing wheel or expired queue (okay if on neither) */

TIMEOUT_PUBLIC x_timer_t *timeouts_get(struct timeouts *);
/* return any expired timeout (caller should loop until NULL-return) */

TIMEOUT_PUBLIC bool timeouts_pending(struct timeouts *);
/* return true if any timeouts pending on timing wheel */

TIMEOUT_PUBLIC bool timeouts_expired(struct timeouts *);
/* return true if any timeouts on expired queue */

TIMEOUT_PUBLIC bool timeouts_check(struct timeouts *,
		void (*report_func)(void *arg, const char *msg),
		void *report_arg);
/* return true if invariants hold. describes failures to optional file handle. */

#define TIMEOUTS_PENDING 0x10
#define TIMEOUTS_EXPIRED 0x20
#define TIMEOUTS_ALL     (TIMEOUTS_PENDING|TIMEOUTS_EXPIRED)
#define TIMEOUTS_CLEAR   0x40

#define TIMEOUTS_IT_INITIALIZER(flags) { (flags), 0, 0, 0, 0 }

#define TIMEOUTS_IT_INIT(cur, _flags) do {                              \
	(cur)->flags = (_flags);                                        \
	(cur)->pc = 0;                                                  \
} while (0)

struct timeouts_it {
	int flags;
	unsigned pc, i, j;
	x_timer_t *to;
}; /* struct timeouts_it */

TIMEOUT_PUBLIC x_timer_t *timeouts_next(struct timeouts *, struct timeouts_it *);
/* return next timeout in pending wheel or expired queue. caller can delete
 * the returned timeout, but should not otherwise manipulate the timing
 * wheel. in particular, caller SHOULD NOT delete any other timeout as that
 * could invalidate cursor state and trigger a use-after-free.
 */

#define TIMEOUTS_FOREACH(var, T, flags)                                 \
	struct timeouts_it _it = TIMEOUTS_IT_INITIALIZER((flags));      \
	while (((var) = timeouts_next((T), &_it)))

#endif /* __timeout__hxx__ */
