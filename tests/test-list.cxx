
#include "include/xdefines.h"
#include "include/list.hxx"


struct item_t
{
	item_t(int val) : val(val) { }
	x_dlink_t link;
	int val;
};

X_DECLARE_MEMBER_TRAITS(item_link_traits, item_t, link)
using list_t = x_tp_ddlist_t<item_link_traits>;

static void verify(const list_t &l, const std::vector<int> &v)
{
	std::vector<int> lv;
	for (item_t *i = l.get_front(); i; i = l.next(i)) {
		lv.push_back(i->val);
	}
	X_ASSERT(lv == v);
}

static void init_list(list_t &l, std::initializer_list<int> vals)
{
	for (int v: vals) {
		item_t *i = new item_t(v);
		l.push_back(i);
	}
}

static void test_concat()
{
	list_t l1;
	init_list(l1, {0, 2, 4, 6, 8});
	list_t l2;

	l1.concat(l2);
	verify(l1, {0, 2, 4, 6, 8});

	init_list(l2, {1, 3, 5, 7, 9});
	l1.concat(l2);
	verify(l1, {0, 2, 4, 6, 8, 1, 3, 5, 7, 9});
}

int main()
{
	test_concat();
	return 0;
}

