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


/*
 * T I M E O U T  I N T E R F A C E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

struct x_timer_t {
	using val_t = uint64_t;
	enum { INVALID = (unsigned int)-1, };
	unsigned int bucket{INVALID};
	/* index to timeout list if pending on wheel or expiry queue */

	val_t expires;
	/* absolute expiration time */

	x_dlink_t link;
	/* entry member for struct timeout_list lists */
}; /* struct x_timer_t */


TIMEOUT_PUBLIC bool x_timer_pending(const x_timer_t *);
/* true if on timing wheel, false otherwise */
 
TIMEOUT_PUBLIC bool x_timer_expired(const x_timer_t *);
/* true if on expired queue, false otherwise */

/*
 * T I M I N G  W H E E L  I N T E R F A C E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

struct x_timer_wheel_t;

TIMEOUT_PUBLIC x_timer_wheel_t *x_timer_wheel_create();
/* open a new timing wheel, setting optional HZ (for float conversions) */

TIMEOUT_PUBLIC void x_timer_wheel_free(x_timer_wheel_t *);
/* destroy timing wheel */

TIMEOUT_PUBLIC void x_timer_wheel_update(x_timer_wheel_t *, x_timer_t::val_t);
/* update timing wheel with current absolute time */

TIMEOUT_PUBLIC x_timer_t::val_t x_timer_wheel_timeout(x_timer_wheel_t *);
/* return interval to next required update */

TIMEOUT_PUBLIC void x_timer_wheel_add(x_timer_wheel_t *, x_timer_t *, x_timer_t::val_t);
/* add timeout to timing wheel */

TIMEOUT_PUBLIC void x_timer_wheel_del(x_timer_wheel_t *, x_timer_t *);
/* remove timeout from any timing wheel or expired queue (okay if on neither) */

TIMEOUT_PUBLIC x_timer_t *x_timer_wheel_get(x_timer_wheel_t *);
/* return any expired timeout (caller should loop until NULL-return) */

TIMEOUT_PUBLIC bool x_timer_wheel_pending(x_timer_wheel_t *);
/* return true if any timeouts pending on timing wheel */

TIMEOUT_PUBLIC bool x_timer_wheel_expired(x_timer_wheel_t *);
/* return true if any timeouts on expired queue */

TIMEOUT_PUBLIC bool x_timer_wheel_check(x_timer_wheel_t *,
		void (*report_func)(void *arg, const char *msg),
		void *report_arg);
/* return true if invariants hold. describes failures to optional file handle. */

struct x_timer_wheel_it_t {
	enum flag_t {
		F_PENDING = 0x10,
		F_EXPIRED = 0x20,
		F_ALL = F_PENDING | F_EXPIRED,
		F_CLEAR = 0x40,
	} flags;
	void init(flag_t f) {
		flags = f;
		pc = 0;
	}
	unsigned pc = 0, i = 0;
	x_timer_t *to = nullptr;
}; /* struct x_timer_wheel_it_t */

TIMEOUT_PUBLIC x_timer_t *x_timer_wheel_next(x_timer_wheel_t *, x_timer_wheel_it_t *);
/* return next timeout in pending wheel or expired queue. caller can delete
 * the returned timeout, but should not otherwise manipulate the timing
 * wheel. in particular, caller SHOULD NOT delete any other timeout as that
 * could invalidate cursor state and trigger a use-after-free.
 */

#define X_TIMER_WHEEL_FOREACH(var, T, flags)                                 \
	x_timer_wheel_it_t _it{(flags)};      \
	while (((var) = x_timer_wheel_next((T), &_it)))

#endif /* __timeout__hxx__ */
