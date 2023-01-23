
#include <assert.h>
#include <cstring>
#include "include/librpc/security.hxx"
#include "common.h"

static void test_less(const idl::dom_sid &sid0, const idl::dom_sid &sid1)
{
	X_ASSERT(dom_sid_compare(sid0, sid1) < 0);
	X_ASSERT(dom_sid_compare(sid1, sid0) == -dom_sid_compare(sid0, sid1));
}

static void test_equal(const idl::dom_sid &sid0, const idl::dom_sid &sid1)
{
	X_ASSERT(dom_sid_compare(sid0, sid1) == 0);
	X_ASSERT(dom_sid_compare(sid1, sid0) == 0);
}

static void test_sid()
{
	idl::dom_sid sids[] = {
		{ 1, 2, {0,0,0,0,0,5}, {32,0,}},
		{ 1, 2, {0,0,0,0,0,5}, {32,1,}},
		{ 1, 2, {0,0,0,0,0,5}, {32,0xfffffffeu,}},
		{ 1, 2, {0,0,0,0,0,5}, {32,0xffffffffu,}},
		{ 1, 3, {0,0,0,0,0,5}, {32,1,0,}},
	};

	for (size_t i = 0; i < X_ARRAY_SIZE(sids); ++i) {
		test_equal(sids[i], sids[i]);
		for (size_t j = i + 1; j < X_ARRAY_SIZE(sids); ++j) {
			test_less(sids[i], sids[j]);
		}
	}

	idl::dom_sid domain = { 1, 1, {0,0,0,0,0,5}, {32,},};
	X_ASSERT(dom_sid_compare_domain_and_rid(sids[1], domain, 0) > 0);
	X_ASSERT(dom_sid_compare_domain_and_rid(sids[1], domain, 1) == 0);
}

int main(int argc, char  **argv)
{
	test_sid();
	return 0;
}

