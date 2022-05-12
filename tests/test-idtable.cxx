
#include "include/xdefines.h"
#include "include/idtable.hxx"
#include <iostream>

struct void_deleter
{
	void operator()(void *ptr) const {
		std::cout << "deleter " << ptr << std::endl;
	}
};

template <class T>
static void output_table(T &table)
{
	auto iter = table.iter_start();
	while (true) {
		if (!table.iter_entry(iter, [](void *data) {
					std::cout << "iter " << data << std::endl;
					return true;
				})) {
			break;
		}
	}
}

template <class T>
static bool store(T &table, void *p, typename T::id_type &id)
{
	bool ret = table.store(p, id);
	std::cout << "store(" << p << ") =" << (ret ? "succeed " : "fail ") <<
		std::hex << id << std::endl;
	return ret;
}

template <class Traits>
static void test()
{
	typename Traits::id_type ids[8];
	x_idtable_t<void, Traits, void_deleter> table{8};
	for (int i = 0; i < 8; ++i) {
		X_ASSERT(store(table, (void *)(0x1000000ul + i), ids[i]));
	}
	typename Traits::id_type tmp_id;
	X_ASSERT(!store(table, (void *)0x100ul, tmp_id));

	for (int i = 0; i < 8; ++i) {
		auto ret = table.lookup(ids[i]);
		X_ASSERT(ret.first);
		X_ASSERT(ret.second == (void *)(0x1000000ul + i));
		table.decref(ids[i]);
	}

	output_table(table);

	table.remove(ids[0]);
	X_ASSERT(!store(table, (void *)0x100ul, tmp_id));
	table.decref(ids[0]);
	typename Traits::id_type new_id;
       	X_ASSERT(store(table, (void *)0x100ul, new_id));
	X_ASSERT(!table.lookup(ids[0]).first);
	ids[0] = new_id;

	table.incref(ids[1]);
	table.remove(ids[1]);
	X_ASSERT(!store(table, (void *)0x100ul, tmp_id));
	table.decref(ids[1]);
	X_ASSERT(!store(table, (void *)0x100ul, tmp_id));
	table.decref(ids[1]);
	X_ASSERT(!store(table, (void *)0x100ul, tmp_id));
}


int main(int argc, char **argv)
{
	test<x_idtable_32_traits_t>();
	test<x_idtable_64_traits_t>();
	return 0;
}

