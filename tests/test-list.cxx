
#include "include/utils.hxx"
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

static void test_ddlist_concat()
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

struct sdlist_item_t
{
	sdlist_item_t(int val) : val(val) { }
	x_dlink_t link;
	int val;
};

static void verify_sdlist(x_sdlist_t &queue, const std::vector<int> &vals)
{
	size_t i = 0;
	printf("front=%p &front=%p\n", queue.front, &queue.front);
	sdlist_item_t *item = nullptr;
	for (x_dlink_t *link = queue.get_front(); link; link = link->get_next(), ++i) {
		item = X_CONTAINER_OF(link, sdlist_item_t, link);
		printf("%zu link %p %d next=%p prev=%p\n", i, link, item->val,
				link->next, link->prev);
		X_ASSERT(i < vals.size());
		X_ASSERT(item->val == vals[i]);
	}
	X_ASSERT(i == vals.size());

	for (; item; ) {
		X_ASSERT(i > 0);
		--i;
		X_ASSERT(item->val == vals[i]);
		x_dlink_t *link = item->link.get_prev();
		item = X_CONTAINER_OF(link, sdlist_item_t, link);
	}
	X_ASSERT(i == 0);
}

static void test_sdlist()
{
	x_sdlist_t queue;
	std::vector<sdlist_item_t> items{0, 1, 2, 3, 4 };

	for (auto &item: items) {
		queue.push_front(&item.link);
	}
	verify_sdlist(queue, {4, 3, 2, 1, 0});

	queue.remove(&items[4].link);
	verify_sdlist(queue, {3, 2, 1, 0});

	queue.remove(&items[0].link);
	verify_sdlist(queue, {3, 2, 1});

	queue.remove(&items[2].link);
	verify_sdlist(queue, {3, 1});

	queue.remove(&items[1].link);
	verify_sdlist(queue, {3});

	queue.remove(&items[3].link);
	verify_sdlist(queue, {});
}

struct sdqueue_item_t
{
	sdqueue_item_t(int val) : val(val) { }
	x_dqlink_t link;
	int val;
};

static void verify_sdqueue(x_sdqueue_t &queue, const std::vector<int> &vals)
{
	size_t i = 0;
	printf("front=%p &front=%p\n", queue.front, &queue.front);
	sdqueue_item_t *item = nullptr;
	for (x_dqlink_t *link = queue.get_front(); link; link = link->get_next(), ++i) {
		item = X_CONTAINER_OF(link, sdqueue_item_t, link);
		printf("%zu link %p %d next=%p prev=%p\n", i, link, item->val,
				link->next, link->prev);
		X_ASSERT(i < vals.size());
		X_ASSERT(item->val == vals[i]);
	}
	X_ASSERT(i == vals.size());

	for (; i--; ) {
		X_ASSERT(item->val == vals[i]);
		x_dqlink_t *link = item->link.get_prev();
		item = X_CONTAINER_OF(link, sdqueue_item_t, link);
	}
}

static void test_sdqueue()
{
	x_sdqueue_t queue;
	sdqueue_item_t i0{0};
	sdqueue_item_t i1{1};
	sdqueue_item_t i2{2};
	
	queue.push_front(&i0.link);
	queue.push_front(&i1.link);
	verify_sdqueue(queue, {1, 0});

	queue.remove(&i1.link);
	verify_sdqueue(queue, {0});

	queue.push_front(&i2.link);
	verify_sdqueue(queue, {2, 0});

	queue.remove(&i0.link);
	verify_sdqueue(queue, {2});

	queue.push_front(&i1.link);
	queue.push_front(&i0.link);
	verify_sdqueue(queue, {0, 1, 2});

	queue.remove(&i0.link);
	verify_sdqueue(queue, {1, 2});

	queue.push_front(&i0.link);
	queue.remove(&i1.link);
	verify_sdqueue(queue, {0, 2});

	queue.push_front(&i1.link);
	queue.remove(&i0.link);
	verify_sdqueue(queue, {1, 2});

	queue.push_front(&i0.link);
	queue.remove(&i2.link);
	verify_sdqueue(queue, {0, 1});
}

int main()
{
	test_ddlist_concat();
	test_sdlist();
	test_sdqueue();
	return 0;
}

