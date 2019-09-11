
#ifndef __list__hxx__
#define __list__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include <assert.h>
#include <cstddef>

#define YAPL_CONTAINER_OF(ptr, type, member) \
	        ((type *)((intptr_t *)(ptr)-offsetof(type, member)))

#define YAPL_DECLARE_MEMBER_TRAITS(name, type, member_name) \
struct name \
{ \
	typedef type container_type; \
	typedef decltype(type::member_name) member_type; \
	static type *container(const member_type *member) { \
		return YAPL_CONTAINER_OF(member, type, member_name); \
	} \
	static member_type *member(const container_type *t) { \
		return (member_type *)&t->member_name; \
	} \
};

struct dlink_t
{
	dlink_t *get_next() const { return next; }
	dlink_t *get_prev() const { return prev; }
	//      bool is_linked() const { return link->prev != NULL; }
	dlink_t *next, *prev;
};

struct d2list_t
{
	d2list_t() : front(NULL), back(NULL) { }

	dlink_t *get_front() const {
		return front;
	}
	dlink_t *get_back() const {
		return back;
	}
	bool contain(dlink_t *link) const {
		for (dlink_t *l = get_front(); l; l = l->get_next()) {
			if (l == link) {
				return true;
			}
		}
		return false;
	}
#ifndef NDEBUG
	bool in_list_check(dlink_t *link) const {
		// ???          return link && (link->prev != 0 || link->next != 0 || (front == link && back == link) && contain(link));
		return link && contain(link);
	}
#endif
	bool empty(void) const {
		return front == NULL;
	}
	void remove(dlink_t *link) {
		assert(in_list_check(link));
		if (link->next != 0)
			link->next->prev = link->prev;
		else
			back = link->prev;
		if (link->prev != 0)
			link->prev->next = link->next;
		else
			front = link->next;
#ifndef NDEBUG
		link->prev = link->next = 0;
#endif
	}
	void push_front(dlink_t *link) {
		if ((link->next = front) != 0)
			front->prev = link;
		else
			back = link;
		front = link;
		link->prev = 0;
	}
	void push_back(dlink_t *link) {
		if ((link->prev = back) != 0)
			back->next = link;
		else
			front = link;
		back = link;
		link->next = 0;
	}
	void insert_before(dlink_t *link, dlink_t *next) {
		assert(in_list_check(next));
		if ((link->prev = next->prev) != 0)
			link->prev->next = link;
		else
			front = link;
		next->prev = link;
		link->next = next;
	}
	void insert_after(dlink_t *link, dlink_t *prev) {
		assert(in_list_check(prev));
		if ((link->next = prev->next) != 0)
			link->next->prev = link;
		else
			back = link;
		prev->next = link;
		link->prev = prev;
	}

	dlink_t *front, *back;
};

template <class LinkTraits>
struct tp_d2list_t
{
	typedef typename LinkTraits::container_type item_type;
	static item_type *link_2_item(const dlink_t *link) {
		return link ? LinkTraits::container(link) : NULL;
	}

	bool contain(item_type *item) const {
		return list.contain(LinkTraits::member(item));
	}

	bool empty(void) const {
		return list.empty();
	}
	void remove(item_type *item) {
		list.remove(LinkTraits::member(item));
	}
	void push_front(item_type *item) {
		list.push_front(LinkTraits::member(item));
	}
	void push_back(item_type *item) {
		list.push_back(LinkTraits::member(item));
	}
	void insert_before(item_type *item, const item_type *next) {
		list.insert_before(LinkTraits::member(item), LinkTraits::member(next));
	}
	void insert_after(item_type *item, const item_type *prev) {
		list.insert_after(LinkTraits::member(item), LinkTraits::member(prev));
	}
	item_type *get_front(void) const {
		return link_2_item(list.get_front());
	}
	item_type *get_back(void) const {
		return link_2_item(list.get_back());
	}
	item_type *prev(const item_type *t) const {
		return link_2_item(LinkTraits::member(t)->get_prev());
	}
	item_type *next(const item_type *t) const {
		return link_2_item(LinkTraits::member(t)->get_next());
	}

	d2list_t list;
};

#endif /* __list__hxx__ */

