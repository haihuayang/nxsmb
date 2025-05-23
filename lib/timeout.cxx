/* ==========================================================================
 * timeout.c - Tickless hierarchical timing wheel.
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
#include "include/timeout.hxx"

#include <limits.h>    /* CHAR_BIT */

#include <stddef.h>    /* NULL */
#include <stdio.h>

#if TIMEOUT_DEBUG - 0
#include "timeout-debug.h"
#endif

/*
 * A N C I L L A R Y  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

using abstime_t = x_timer_t::val_t; /* for documentation purposes */
using reltime_t = x_timer_t::val_t; /* "" */

#if !defined MIN
#define MIN(a, b) (((a) < (b))? (a) : (b))
#endif

#if !defined MAX
#define MAX(a, b) (((a) > (b))? (a) : (b))
#endif


/*
 * B I T  M A N I P U L A T I O N  R O U T I N E S
 *
 * The macros and routines below implement wheel parameterization. The
 * inputs are:
 *
 *   WHEEL_BIT - The number of value bits mapped in each wheel. The
 *               lowest-order WHEEL_BIT bits index the lowest-order (highest
 *               resolution) wheel, the next group of WHEEL_BIT bits the
 *               higher wheel, etc.
 *
 *   WHEEL_NUM - The number of wheels. WHEEL_BIT * WHEEL_NUM = the number of
 *               value bits used by all the wheels. For the default of 6 and
 *               4, only the low 24 bits are processed. Any timeout value
 *               larger than this will cycle through again.
 *
 * The implementation uses bit fields to remember which slot in each wheel
 * is populated, and to generate masks of expiring slots according to the
 * current update interval (i.e. the "tickless" aspect). The slots to
 * process in a wheel are (populated-set & interval-mask).
 *
 * WHEEL_BIT cannot be larger than 6 bits because 2^6 -> 64 is the largest
 * number of slots which can be tracked in a uint64_t integer bit field.
 * WHEEL_BIT cannot be smaller than 3 bits because of our rotr and rotl
 * routines, which only operate on all the value bits in an integer, and
 * there's no integer smaller than uint8_t.
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#if !defined WHEEL_BIT
#define WHEEL_BIT 6
#endif

#if !defined WHEEL_NUM
#define WHEEL_NUM 4
#endif

#define WHEEL_LEN (1U << WHEEL_BIT)
#define WHEEL_MAX (WHEEL_LEN - 1)
#define WHEEL_MASK (WHEEL_LEN - 1)
#define TIMEOUT_MAX ((TIMEOUT_C(1) << (WHEEL_BIT * WHEEL_NUM)) - 1)

#include "timeout-bitops.c"

#if WHEEL_BIT == 6
#define ctz(n) ctz64(n)
#define clz(n) clz64(n)
#define fls(n) ((int)(64 - clz64(n)))
#else
#define ctz(n) ctz32(n)
#define clz(n) clz32(n)
#define fls(n) ((int)(32 - clz32(n)))
#endif

#if WHEEL_BIT == 6
#define WHEEL_C(n) UINT64_C(n)
#define WHEEL_PRIu PRIu64
#define WHEEL_PRIx PRIx64

typedef uint64_t wheel_t;

#elif WHEEL_BIT == 5

#define WHEEL_C(n) UINT32_C(n)
#define WHEEL_PRIu PRIu32
#define WHEEL_PRIx PRIx32

typedef uint32_t wheel_t;

#elif WHEEL_BIT == 4

#define WHEEL_C(n) UINT16_C(n)
#define WHEEL_PRIu PRIu16
#define WHEEL_PRIx PRIx16

typedef uint16_t wheel_t;

#elif WHEEL_BIT == 3

#define WHEEL_C(n) UINT8_C(n)
#define WHEEL_PRIu PRIu8
#define WHEEL_PRIx PRIx8

typedef uint8_t wheel_t;

#else
#error invalid WHEEL_BIT value
#endif


static inline wheel_t rotl(const wheel_t v, int c) {
	if (!(c &= (sizeof v * CHAR_BIT - 1)))
		return v;

	return (v << c) | (v >> (sizeof v * CHAR_BIT - c));
} /* rotl() */


static inline wheel_t rotr(const wheel_t v, int c) {
	if (!(c &= (sizeof v * CHAR_BIT - 1)))
		return v;

	return (v >> c) | (v << (sizeof v * CHAR_BIT - c));
} /* rotr() */


/*
 * T I M E R  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

X_DECLARE_MEMBER_TRAITS(timer_link_traits, x_timer_t, link)
using timeout_list = x_tp_ddlist_t<timer_link_traits>;

struct x_timer_wheel_t {
	timeout_list wheel[WHEEL_NUM * WHEEL_LEN + 1];

	wheel_t pending[WHEEL_NUM]{};

	x_timer_t::val_t curtime{};
}; /* struct x_timer_wheel_t */

#define EXPIRED(T) ((T)->wheel[WHEEL_NUM * WHEEL_LEN])

TIMEOUT_PUBLIC x_timer_wheel_t *x_timer_wheel_create() {
	return new x_timer_wheel_t;
} /* x_timer_wheel_create() */


static void timeouts_reset(x_timer_wheel_t *T) {
	timeout_list reset;
	x_timer_t *to;

	for (auto &w: T->wheel) {
		reset.concat(w);
	}

	for (to = reset.get_front(); to; to = reset.next(to)) {
		to->bucket = x_timer_t::INVALID;
	}
} /* timeouts_reset() */


TIMEOUT_PUBLIC void x_timer_wheel_free(x_timer_wheel_t *T) {
	/*
	 * NOTE: Delete installed timeouts so timeout_pending() and
	 * timeout_expired() worked as expected.
	 */
	timeouts_reset(T);

	delete T;
} /* x_timer_wheel_free() */



TIMEOUT_PUBLIC bool x_timer_wheel_del(x_timer_wheel_t *T, x_timer_t *to) {
	if (to->bucket != x_timer_t::INVALID) {
		timeout_list *pending = &T->wheel[to->bucket];
		pending->remove(to);

		if (to->bucket != WHEEL_NUM * WHEEL_LEN && pending->empty()) {
			ptrdiff_t index = pending - &T->wheel[0];
			long wheel = index / WHEEL_LEN;
			long slot = index % WHEEL_LEN;

			T->pending[wheel] &= ~(WHEEL_C(1) << slot);
		}

		to->bucket = x_timer_t::INVALID;
		return true;
	}
	return false;
} /* timeouts_del() */


static inline reltime_t timeout_rem(x_timer_wheel_t *T, x_timer_t *to) {
	return to->expires - T->curtime;
} /* timeout_rem() */


static inline int timeout_wheel(x_timer_t::val_t timeout) {
	/* must be called with timeout != 0, so fls input is nonzero */
	return (fls(MIN(timeout, TIMEOUT_MAX)) - 1) / WHEEL_BIT;
} /* timeout_wheel() */


static inline int timeout_slot(int wheel, x_timer_t::val_t expires) {
	return WHEEL_MASK & ((expires >> (wheel * WHEEL_BIT)) - !!wheel);
} /* timeout_slot() */


static void timeouts_sched(x_timer_wheel_t *T, x_timer_t *to, x_timer_t::val_t expires) {
	x_timer_t::val_t rem;
	int wheel, slot;

	x_timer_wheel_del(T, to);

	to->expires = expires;

	if (expires > T->curtime) {
		rem = timeout_rem(T, to);

		/* rem is nonzero since:
		 *   rem == timeout_rem(T,to),
		 *       == to->expires - T->curtime
		 *   and above we have expires > T->curtime.
		 */
		wheel = timeout_wheel(rem);
		slot = timeout_slot(wheel, to->expires);

		to->bucket = wheel * WHEEL_LEN + slot;
		timeout_list *pending = &T->wheel[to->bucket];
		pending->push_back(to);

		T->pending[wheel] |= WHEEL_C(1) << slot;
	} else {
		to->bucket = WHEEL_NUM * WHEEL_LEN;
		EXPIRED(T).push_back(to);
	}
} /* timeouts_sched() */



TIMEOUT_PUBLIC void x_timer_wheel_add(x_timer_wheel_t *T, x_timer_t *to,
		x_timer_t::val_t timeout)
{
	timeouts_sched(T, to, timeout);
} /* timeouts_add() */


TIMEOUT_PUBLIC void x_timer_wheel_update(x_timer_wheel_t *T, abstime_t curtime) {
	x_timer_t::val_t elapsed = curtime - T->curtime;
	timeout_list todo;
	int wheel;

	/*
	 * There's no avoiding looping over every wheel. It's best to keep
	 * WHEEL_NUM smallish.
	 */
	for (wheel = 0; wheel < WHEEL_NUM; wheel++) {
		wheel_t pending;

		/*
		 * Calculate the slots expiring in this wheel
		 *
		 * If the elapsed time is greater than the maximum period of
		 * the wheel, mark every position as expiring.
		 *
		 * Otherwise, to determine the expired slots fill in all the
		 * bits between the last slot processed and the current
		 * slot, inclusive of the last slot. We'll bitwise-AND this
		 * with our pending set below.
		 *
		 * If a wheel rolls over, force a tick of the next higher
		 * wheel.
		 */
		if ((elapsed >> (wheel * WHEEL_BIT)) > WHEEL_MAX) {
			pending = (wheel_t)~WHEEL_C(0);
		} else {
			wheel_t _elapsed = WHEEL_MASK & (elapsed >> (wheel * WHEEL_BIT));
			int oslot, nslot;

			/*
			 * TODO: It's likely that at least one of the
			 * following three bit fill operations is redundant
			 * or can be replaced with a simpler operation.
			 */
			oslot = WHEEL_MASK & (T->curtime >> (wheel * WHEEL_BIT));
			pending = rotl(((UINT64_C(1) << _elapsed) - 1), oslot);

			nslot = WHEEL_MASK & (curtime >> (wheel * WHEEL_BIT));
			pending |= rotr(rotl(((WHEEL_C(1) << _elapsed) - 1), nslot), int(_elapsed));
			pending |= WHEEL_C(1) << nslot;
		}

		while (pending & T->pending[wheel]) {
			/* ctz input cannot be zero: loop condition. */
			int slot = ctz(pending & T->pending[wheel]);
			todo.concat(T->wheel[wheel * WHEEL_LEN + slot]);
			T->pending[wheel] &= ~(UINT64_C(1) << slot);
		}

		if (!(0x1 & pending))
			break; /* break if we didn't wrap around end of wheel */

		/* if we're continuing, the next wheel must tick at least once */
		elapsed = MAX(elapsed, (WHEEL_LEN << (wheel * WHEEL_BIT)));
	}

	T->curtime = curtime;

	while (!todo.empty()) {
		x_timer_t *to = todo.get_front();

		todo.remove(to);
		to->bucket = x_timer_t::INVALID;

		timeouts_sched(T, to, to->expires);
	}

	return;
} /* timeouts_update() */


TIMEOUT_PUBLIC bool x_timer_wheel_pending(x_timer_wheel_t *T) {
	wheel_t pending = 0;
	int wheel;

	for (wheel = 0; wheel < WHEEL_NUM; wheel++) {
		pending |= T->pending[wheel];
	}

	return !!pending;
} /* x_timer_wheel_pending() */


TIMEOUT_PUBLIC bool x_timer_wheel_expired(x_timer_wheel_t *T) {
	return !EXPIRED(T).empty();
} /* x_timer_wheel_expired() */


/*
 * Calculate the interval before needing to process any timeouts pending on
 * any wheel.
 *
 * (This is separated from the public API routine so we can evaluate our
 * wheel invariant assertions irrespective of the expired queue.)
 *
 * This might return a timeout value sooner than any installed timeout if
 * only higher-order wheels have timeouts pending. We can only know when to
 * process a wheel, not precisely when a timeout is scheduled. Our timeout
 * accuracy could be off by 2^(N*M)-1 units where N is the wheel number and
 * M is WHEEL_BIT. Only timeouts which have fallen through to wheel 0 can be
 * known exactly.
 *
 * We should never return a timeout larger than the lowest actual timeout.
 */
static x_timer_t::val_t timeouts_int(x_timer_wheel_t *T) {
	x_timer_t::val_t timeout = ~TIMEOUT_C(0), _timeout;
	x_timer_t::val_t relmask;
	int wheel, slot;

	relmask = 0;

	for (wheel = 0; wheel < WHEEL_NUM; wheel++) {
		if (T->pending[wheel]) {
			slot = WHEEL_MASK & (T->curtime >> (wheel * WHEEL_BIT));

			/* ctz input cannot be zero: T->pending[wheel] is
			 * nonzero, so rotr() is nonzero. */
			_timeout = (ctz(rotr(T->pending[wheel], slot)) + !!wheel) << (wheel * WHEEL_BIT);
			/* +1 to higher order wheels as those timeouts are one rotation in the future (otherwise they'd be on a lower wheel or expired) */

			_timeout -= relmask & T->curtime;
			/* reduce by how much lower wheels have progressed */

			timeout = MIN(_timeout, timeout);
		}

		relmask <<= WHEEL_BIT; 
		relmask |= WHEEL_MASK;
	}

	return timeout;
} /* timeouts_int() */


/*
 * Calculate the interval our caller can wait before needing to process
 * events.
 */
TIMEOUT_PUBLIC x_timer_t::val_t x_timer_wheel_timeout(x_timer_wheel_t *T) {
	if (!EXPIRED(T).empty())
		return 0;

	return timeouts_int(T);
} /* x_timer_wheel_timeout() */


TIMEOUT_PUBLIC x_timer_t *x_timer_wheel_get(x_timer_wheel_t *T) {
	timeout_list &expired = EXPIRED(T);
	x_timer_t *to = expired.get_front();
	if (to) {
		expired.remove(to);
		to->bucket = x_timer_t::INVALID;

		return to;
	} else {
		return nullptr;
	}
} /* x_timer_wheel_get() */


/*
 * Use dumb looping to locate the earliest timeout pending on the wheel so
 * our invariant assertions can check the result of our optimized code.
 */
static x_timer_t *timeouts_min(x_timer_wheel_t *T) {
	x_timer_t *to, *min = NULL;
	unsigned i;

	for (i = 0; i < WHEEL_NUM * WHEEL_LEN; i++) {
		auto &wheel = T->wheel[i];
		for (to = wheel.get_front(); to; to = wheel.next(to)) {
			if (!min || to->expires < min->expires)
				min = to;
		}
	}

	return min;
} /* timeouts_min() */


/*
 * Check some basic algorithm invariants. If these invariants fail then
 * something is definitely broken.
 */
#define report(...) do { \
	if ((report_func)) { \
		char buf[1024]; \
		snprintf(buf, sizeof buf, __VA_ARGS__); \
		report_func(report_arg, buf); \
	} \
} while (0)

#define check(expr, ...) do { \
	if (!(expr)) { \
		report(__VA_ARGS__); \
		return 0; \
	} \
} while (0)

TIMEOUT_PUBLIC bool x_timer_wheel_check(x_timer_wheel_t *T,
		void (*report_func)(void *arg, const char *msg),
		void *report_arg)
{
	x_timer_t::val_t timeout;
	x_timer_t *to;

	if ((to = timeouts_min(T))) {
		check(to->expires > T->curtime, "missed timeout (expires:%" TIMEOUT_PRIu " <= curtime:%" TIMEOUT_PRIu ")\n", to->expires, T->curtime);

		timeout = timeouts_int(T);
		check(timeout <= to->expires - T->curtime, "wrong soft timeout (soft:%" TIMEOUT_PRIu " > hard:%" TIMEOUT_PRIu ") (expires:%" TIMEOUT_PRIu "; curtime:%" TIMEOUT_PRIu ")\n", timeout, (to->expires - T->curtime), to->expires, T->curtime);

		timeout = x_timer_wheel_timeout(T);
		check(timeout <= to->expires - T->curtime, "wrong soft timeout (soft:%" TIMEOUT_PRIu " > hard:%" TIMEOUT_PRIu ") (expires:%" TIMEOUT_PRIu "; curtime:%" TIMEOUT_PRIu ")\n", timeout, (to->expires - T->curtime), to->expires, T->curtime);
	} else {
		timeout = x_timer_wheel_timeout(T);

		if (!EXPIRED(T).empty())
			check(timeout == 0, "wrong soft timeout (soft:%" TIMEOUT_PRIu " != hard:%" TIMEOUT_PRIu ")\n", timeout, TIMEOUT_C(0));
		else
			check(timeout == ~TIMEOUT_C(0), "wrong soft timeout (soft:%" TIMEOUT_PRIu " != hard:%" TIMEOUT_PRIu ")\n", timeout, ~TIMEOUT_C(0));
	}

	return 1;
} /* x_timer_wheel_check() */


#define ENTER                                                           \
	do {                                                            \
	static const int pc0 = __LINE__;                                \
	switch (pc0 + it->pc) {                                         \
	case __LINE__: (void)0

#define SAVE_AND_DO(do_statement)                                       \
	do {                                                            \
		it->pc = __LINE__ - pc0;                                \
		do_statement;                                           \
		case __LINE__: (void)0;                                 \
	} while (0)

#define YIELD(rv)                                                       \
	SAVE_AND_DO(return (rv))

#define LEAVE                                                           \
	SAVE_AND_DO(break);                                             \
	}                                                               \
	} while (0)

TIMEOUT_PUBLIC x_timer_t *x_timer_wheel_next(x_timer_wheel_t *T,
		x_timer_wheel_it_t *it)
{
	x_timer_t *to;

	ENTER;

	if (it->flags & x_timer_wheel_it_t::F_EXPIRED) {
		if (it->flags & x_timer_wheel_it_t::F_CLEAR) {
			while ((to = x_timer_wheel_get(T))) {
				YIELD(to);
			}
		} else {
			for (to = EXPIRED(T).get_front(); to; to = it->to) {
				it->to = EXPIRED(T).next(to);
				YIELD(to);
			}
		}
	}

	if (it->flags & x_timer_wheel_it_t::F_PENDING) {
		for (it->i = 0; it->i < WHEEL_NUM * WHEEL_LEN; it->i++) {
			for (to = T->wheel[it->i].get_front();
					to; to = it->to) {
				it->to = T->wheel[it->i].next(to);
				YIELD(to);
			}
		}
	}

	LEAVE;

	return NULL;
} /* x_timer_wheel_next */

#undef LEAVE
#undef YIELD
#undef SAVE_AND_DO
#undef ENTER


/*
 * T I M E O U T  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

TIMEOUT_PUBLIC bool x_timer_pending(const x_timer_t *to) {
	return to->bucket < WHEEL_NUM * WHEEL_LEN;
} /* x_timer_pending() */


TIMEOUT_PUBLIC bool x_timer_expired(const x_timer_t *to) {
	return to->bucket == WHEEL_NUM * WHEEL_LEN;
} /* x_timer_expired() */


