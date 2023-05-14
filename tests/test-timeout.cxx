#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>

#include "include/timeout.hxx"

#define THE_END_OF_TIME ((timeout_t)-1)

static int check_open_close() {
	struct timeouts *tos = timeouts_open();
	if (!tos)
		return 1;
	timeouts_close(tos);
	return 0;
}

/* Not very random */
static timeout_t random_to(timeout_t min, timeout_t max)
{
	if (max <= min)
		return min;
	/* Not actually all that random, but should exercise the code. */
	timeout_t rand64 = random() * (timeout_t)INT_MAX + random();
	return min + (rand64 % (max-min));
}

/* configuration for check_randomized */
struct rand_cfg {
	/* When creating timeouts, smallest possible delay */
	timeout_t min_timeout;
	/* When creating timeouts, largest possible delay */
	timeout_t max_timeout;
	/* First time to start the clock at. */
	timeout_t start_at;
	/* Do not advance the clock past this time. */
	timeout_t end_at;
	/* Number of timeouts to create and monitor. */
	int n_timeouts;
	/* Advance the clock by no more than this each step. */
	timeout_t max_step;
	/* Every time the clock ticks, try removing this many timeouts at
	 * random. */
	int try_removing;
	/* When we're done, advance the clock to the end of time. */
	int finalize;
};

static void report_func(void *arg, const char *msg)
{
	fprintf(stderr, "%s", msg);
}

static int check_randomized(const struct rand_cfg *cfg)
{
#define FAIL() do {					\
		printf("Failure on line %d\n", __LINE__);	\
		goto done;					\
	} while (0)

	long i;
	int rv = 1;
	x_timer_t *t = new x_timer_t[cfg->n_timeouts];
	timeout_t *timeouts = (timeout_t *)calloc(cfg->n_timeouts, sizeof(timeout_t));
	uint8_t *fired = (uint8_t *)calloc(cfg->n_timeouts, sizeof(uint8_t));
        uint8_t *found = (uint8_t *)calloc(cfg->n_timeouts, sizeof(uint8_t));
	uint8_t *deleted = (uint8_t *)calloc(cfg->n_timeouts, sizeof(uint8_t));
	struct timeouts *tos = timeouts_open();
	timeout_t now = cfg->start_at;
	int n_added_pending = 0, cnt_added_pending = 0;
	int n_added_expired = 0, cnt_added_expired = 0;
        struct timeouts_it it_p, it_e, it_all;
        int p_done = 0, e_done = 0, all_done = 0;
	x_timer_t *to = NULL;

	if (!t || !timeouts || !tos || !fired || !found || !deleted)
		FAIL();
	timeouts_update(tos, cfg->start_at);

	for (i = 0; i < cfg->n_timeouts; ++i) {
		if (timeout_pending(&t[i]))
			FAIL();
		if (timeout_expired(&t[i]))
			FAIL();

		timeouts[i] = random_to(cfg->min_timeout, cfg->max_timeout);

		timeouts_add(tos, &t[i], timeouts[i]);
		if (timeouts[i] <= cfg->start_at) {
			if (timeout_pending(&t[i]))
				FAIL();
			if (! timeout_expired(&t[i]))
				FAIL();
			++n_added_expired;
		} else {
			if (! timeout_pending(&t[i]))
				FAIL();
			if (timeout_expired(&t[i]))
				FAIL();
			++n_added_pending;
		}
	}

	if (!!n_added_pending != timeouts_pending(tos))
		FAIL();
	if (!!n_added_expired != timeouts_expired(tos))
		FAIL();

        /* Test foreach, interleaving a few iterators. */
        TIMEOUTS_IT_INIT(&it_p, TIMEOUTS_PENDING);
        TIMEOUTS_IT_INIT(&it_e, TIMEOUTS_EXPIRED);
        TIMEOUTS_IT_INIT(&it_all, TIMEOUTS_ALL);
        while (! (p_done && e_done && all_done)) {
		if (!p_done) {
			to = timeouts_next(tos, &it_p);
			if (to) {
				i = to - &t[0];
				++found[i];
				++cnt_added_pending;
			} else {
				p_done = 1;
			}
		}
		if (!e_done) {
			to = timeouts_next(tos, &it_e);
			if (to) {
				i = to - &t[0];
				++found[i];
				++cnt_added_expired;
			} else {
				e_done = 1;
			}
		}
		if (!all_done) {
			to = timeouts_next(tos, &it_all);
			if (to) {
				i = to - &t[0];
				++found[i];
			} else {
				all_done = 1;
			}
		}
        }

	for (i = 0; i < cfg->n_timeouts; ++i) {
		if (found[i] != 2)
			FAIL();
	}
	if (cnt_added_expired != n_added_expired)
		FAIL();
	if (cnt_added_pending != n_added_pending)
		FAIL();

	while (NULL != (to = timeouts_get(tos))) {
		i = to - &t[0];
		assert(&t[i] == to);
		if (timeouts[i] > cfg->start_at)
			FAIL(); /* shouldn't have happened yet */

		--n_added_expired; /* drop expired timeouts. */
		++fired[i];
	}

	if (n_added_expired != 0)
		FAIL();

	while (now < cfg->end_at) {
		int n_fired_this_time = 0;
		timeout_t first_at = timeouts_timeout(tos) + now;

		timeout_t oldtime = now;
		timeout_t step = random_to(1, cfg->max_step);
		int another;
		now += step;
		timeouts_update(tos, now);

		for (i = 0; i < cfg->try_removing; ++i) {
			long idx = random() % cfg->n_timeouts;
			if (! fired[idx]) {
				timeouts_del(tos, &t[idx]);
				++deleted[idx];
			}
		}

		another = (timeouts_timeout(tos) == 0);

		while (NULL != (to = timeouts_get(tos))) {
			if (! another)
				FAIL(); /* Thought we saw the last one! */
			i = to - &t[0];
			assert(&t[i] == to);
			if (timeouts[i] > now)
				FAIL(); /* shouldn't have happened yet */
			if (timeouts[i] <= oldtime)
				FAIL(); /* should have happened already */
			if (timeouts[i] < first_at)
				FAIL(); /* first_at should've been earlier */
			fired[i]++;
			n_fired_this_time++;
			another = (timeouts_timeout(tos) == 0);
		}
		if (n_fired_this_time && first_at > now)
			FAIL(); /* first_at should've been earlier */
		if (another)
			FAIL(); /* Huh? We think there are more? */
		if (!timeouts_check(tos, report_func, nullptr))
			FAIL();
	}

	for (i = 0; i < cfg->n_timeouts; ++i) {
		if (fired[i] > 1)
			FAIL(); /* Nothing fired twice. */
		if (timeouts[i] <= now) {
			if (!(fired[i] || deleted[i]))
				FAIL();
		} else {
			if (fired[i])
				FAIL();
		}
		if (fired[i] && deleted[i])
			FAIL();
		if (cfg->finalize > 1) {
			if (!fired[i])
				timeouts_del(tos, &t[i]);
		}
	}

	/* Now nothing more should fire between now and the end of time. */
	if (cfg->finalize) {
		timeouts_update(tos, THE_END_OF_TIME);
		if (cfg->finalize > 1) {
			if (timeouts_get(tos))
				FAIL();
			TIMEOUTS_FOREACH(to, tos, TIMEOUTS_ALL)
				FAIL();
		}
	}
	rv = 0;

 done:
	if (tos) timeouts_close(tos);
	if (t) delete[] t;
	if (timeouts) free(timeouts);
	if (fired) free(fired);
	if (found) free(found);
	if (deleted) free(deleted);
	return rv;
}

int
main(int argc, char **argv)
{
	int j;
	int n_failed = 0;
#define DO(fn) do {                             \
		printf("."); fflush(stdout);	\
		if (fn) {			\
			++n_failed;		\
			printf("%s failed\n", #fn);	\
		}					\
        } while (0)

#define DO_N(n, fn) do {			\
		for (j = 0; j < (n); ++j) {	\
			DO(fn);			\
		}				\
	} while (0)

	DO(check_open_close());

	struct rand_cfg cfg1 = {
		.min_timeout = 1,
		.max_timeout = 100,
		.start_at = 5,
		.end_at = 1000,
		.n_timeouts = 1,
		.max_step = 10,
		.try_removing = 0,
		.finalize = 2,
		};
	DO_N(1,check_randomized(&cfg1));

	struct rand_cfg cfg2 = {
		.min_timeout = 20,
		.max_timeout = 1000,
		.start_at = 10,
		.end_at = 100,
		.n_timeouts = 1000,
		.max_step = 5,
		.try_removing = 0,
		.finalize = 2,
		};
	DO_N(300,check_randomized(&cfg2));

	struct rand_cfg cfg2b = {
		.min_timeout = 20,
		.max_timeout = 1000,
		.start_at = 10,
		.end_at = 100,
		.n_timeouts = 1000,
		.max_step = 5,
		.try_removing = 0,
		.finalize = 1,
		};
	DO_N(300,check_randomized(&cfg2b));

	struct rand_cfg cfg2c = {
		.min_timeout = 20,
		.max_timeout = 1000,
		.start_at = 10,
		.end_at = 100,
		.n_timeouts = 1000,
		.max_step = 5,
		.try_removing = 0,
		.finalize = 0,
		};
	DO_N(300,check_randomized(&cfg2c));

	struct rand_cfg cfg3 = {
		.min_timeout = 2000,
		.max_timeout = ((uint64_t)1) << 50,
		.start_at = 100,
		.end_at = ((uint64_t)1) << 49,
		.n_timeouts = 1000,
		.max_step = ((uint64_t)1) << 43,
		.try_removing = 0,
		.finalize = 2,
		};
	DO_N(10,check_randomized(&cfg3));

	struct rand_cfg cfg3b = {
		.min_timeout = ((uint64_t)1) << 50,
		.max_timeout = ((uint64_t)1) << 52,
		.start_at = 100,
		.end_at = ((uint64_t)1) << 53,
		.n_timeouts = 1000,
		.max_step = ((uint64_t)1)<<48,
		.try_removing = 0,
		.finalize = 2,
		};
	DO_N(10,check_randomized(&cfg3b));

	struct rand_cfg cfg4 = {
		.min_timeout = 2000,
		.max_timeout = ((uint64_t)1) << 30,
		.start_at = 100,
		.end_at = ((uint64_t)1) << 26,
		.n_timeouts = 10000,
		.max_step = 1<<16,
		.try_removing = 3,
		.finalize = 2,
		};
	DO_N(10,check_randomized(&cfg4));

        if (n_failed) {
          puts("\nFAIL");
        } else {
          puts("\nOK");
        }
	return !!n_failed;
}

/* TODO:

 * Solve PR#3.

 * Investigate whether any untaken branches are possible.

 */
