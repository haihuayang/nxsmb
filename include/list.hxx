
#ifndef __list__hxx__
#define __list__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include <assert.h>
#include <cstddef>
#include <algorithm>

#define X_CONTAINER_OF(ptr, type, member) \
		((type *)((char *)(ptr)-offsetof(type, member)))

#define X_DECLARE_MEMBER_TRAITS(name, type, member_name) \
struct name \
{ \
	typedef type container_type; \
	typedef decltype(type::member_name) member_type; \
	static type *container(const member_type *member) { \
		return X_CONTAINER_OF(member, type, member_name); \
	} \
	static member_type *member(const container_type *t) { \
		return (member_type *)&t->member_name; \
	} \
};

struct x_dlink_t
{
	// static constexpr x_dlink_t * const invalid = reinterpret_cast<x_dlink_t *>(-1l);
	x_dlink_t *get_next() const { return next; }
	x_dlink_t *get_prev() const { return prev; }
	bool is_valid() const { return prev != reinterpret_cast<x_dlink_t *>(-1l); }
	//      bool is_linked() const { return link->prev != NULL; }
	x_dlink_t *next = reinterpret_cast<x_dlink_t *>(-1l), *prev = reinterpret_cast<x_dlink_t *>(-1l);
};

struct x_sdlist_t
{
	x_sdlist_t() : front(nullptr) { }
	x_sdlist_t(x_sdlist_t &&other) : front(nullptr) {
		std::swap(front, other.front);
	}
	x_sdlist_t &operator=(x_sdlist_t &&other) {
		std::swap(front, other.front);
		return *this;
	}
	x_sdlist_t(const x_sdlist_t &) = delete;
	x_sdlist_t &operator=(const x_sdlist_t &) = delete; 

	x_dlink_t *get_front() const {
		return front;
	}
	bool contain(x_dlink_t *link) const {
		for (x_dlink_t *l = get_front(); l; l = l->get_next()) {
			if (l == link) {
				return true;
			}
		}
		return false;
	}
#ifndef NDEBUG
	bool in_list_check(x_dlink_t *link) const {
		// ???	  return link && (link->prev != 0 || link->next != 0 || (front == link && back == link) && contain(link));
		return link && contain(link);
	}
#endif
	bool empty(void) const {
		return front == nullptr;
	}
	void push_front(x_dlink_t *link) {
		if ((link->next = front) != nullptr) {
			front->prev = link;
		}
		front = link;
		link->prev = nullptr;
	}

	x_dlink_t *front;
};

struct x_ddlist_t
{
	x_ddlist_t() : front(nullptr), back(nullptr) { }
	x_ddlist_t(x_ddlist_t &&other) : front(nullptr), back(nullptr) {
		std::swap(front, other.front);
		std::swap(back, other.back);
	}
	x_ddlist_t &operator=(x_ddlist_t &&other) {
		std::swap(front, other.front);
		std::swap(back, other.back);
		return *this;
	}
	x_ddlist_t(const x_ddlist_t &) = delete;
	x_ddlist_t &operator=(const x_ddlist_t &) = delete; 


	x_dlink_t *get_front() const {
		return front;
	}
	x_dlink_t *get_back() const {
		return back;
	}
	bool contain(x_dlink_t *link) const {
		for (x_dlink_t *l = get_front(); l; l = l->get_next()) {
			if (l == link) {
				return true;
			}
		}
		return false;
	}
#ifndef NDEBUG
	bool in_list_check(x_dlink_t *link) const {
		// ???	  return link && (link->prev != 0 || link->next != 0 || (front == link && back == link) && contain(link));
		return link && contain(link);
	}
#endif
	bool empty(void) const {
		return front == nullptr;
	}
	void remove(x_dlink_t *link) {
		assert(in_list_check(link));
		if (link->next != nullptr)
			link->next->prev = link->prev;
		else
			back = link->prev;
		if (link->prev != nullptr)
			link->prev->next = link->next;
		else
			front = link->next;
		link->prev = link->next = reinterpret_cast<x_dlink_t *>(-1l);
	}
	void push_front(x_dlink_t *link) {
		if ((link->next = front) != nullptr)
			front->prev = link;
		else
			back = link;
		front = link;
		link->prev = nullptr;
	}
	void push_back(x_dlink_t *link) {
		if ((link->prev = back) != nullptr)
			back->next = link;
		else
			front = link;
		back = link;
		link->next = nullptr;
	}
	void insert_before(x_dlink_t *link, x_dlink_t *next) {
		assert(in_list_check(next));
		if ((link->prev = next->prev) != nullptr)
			link->prev->next = link;
		else
			front = link;
		next->prev = link;
		link->next = next;
	}
	void insert_after(x_dlink_t *link, x_dlink_t *prev) {
		assert(in_list_check(prev));
		if ((link->next = prev->next) != nullptr)
			link->next->prev = link;
		else
			back = link;
		prev->next = link;
		link->prev = prev;
	}
	void concat(x_ddlist_t &other) {
		if (!front) {
			front = other.front;
			back = other.back;
		} else if (other.front) {
			back->next = other.front;
			back = other.back;
		}
		other.front = other.back = nullptr;
	}

	x_dlink_t *front, *back;
};

template <class LinkTraits>
struct x_tp_sdlist_t
{
	typedef typename LinkTraits::container_type item_type;
	static item_type *link_2_item(const x_dlink_t *link) {
		return link ? LinkTraits::container(link) : nullptr;
	}

	bool contain(item_type *item) const {
		return list.contain(LinkTraits::member(item));
	}

	bool empty(void) const {
		return list.empty();
	}
	void push_front(item_type *item) {
		list.push_front(LinkTraits::member(item));
	}
	item_type *get_front(void) const {
		return link_2_item(list.get_front());
	}
	item_type *prev(const item_type *t) const {
		return link_2_item(LinkTraits::member(t)->get_prev());
	}
	item_type *next(const item_type *t) const {
		return link_2_item(LinkTraits::member(t)->get_next());
	}

	x_sdlist_t list;
};

template <class LinkTraits>
struct x_tp_ddlist_t
{
	typedef typename LinkTraits::container_type item_type;
	static item_type *link_2_item(const x_dlink_t *link) {
		return link ? LinkTraits::container(link) : nullptr;
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
	void concat(x_tp_ddlist_t &other) {
		list.concat(other.list);
	}

	x_ddlist_t list;
};

struct x_dcircle_t
{
	x_dcircle_t() : front((x_dlink_t *)this), back((x_dlink_t *)this) { }
	x_dcircle_t(x_dcircle_t &&other) = delete; // TODO
	x_dcircle_t &operator=(x_dcircle_t &&other) = delete; // TODO
	x_dcircle_t(const x_dcircle_t &) = delete;
	x_dcircle_t &operator=(const x_dcircle_t &) = delete; 

	x_dlink_t *get_front() const {
		return front;
	}
	x_dlink_t *get_back() const {
		return back;
	}
	bool empty(void) const {
		return front == nullptr;
	}
	bool contain(x_dlink_t *link) const {
		for (x_dlink_t *l = get_front(); l != (x_dlink_t *)this; l = l->get_next()) {
			if (l == link) {
				return true;
			}
		}
		return false;
	}
	static void __remove(x_dlink_t *prev, x_dlink_t *next) {
		next->prev = prev;
		prev->next = next;
	}
	static void remove(x_dlink_t *link) {
		__remove(link->prev, link->next);
	}
	static void __insert(x_dlink_t *link, x_dlink_t *prev, x_dlink_t *next)
	{
		link->next = next;
		link->prev = prev;
		next->prev = link;
		prev->next = link;
	}
	void push_front(x_dlink_t *link) {
		__insert(link, (x_dlink_t *)this, front);
	}
	void push_back(x_dlink_t *link) {
		__insert(link, back, (x_dlink_t *)this);
	}
	x_dlink_t *front, *back;
};

template <class LinkTraits>
struct x_tp_dcircle_t
{
	typedef typename LinkTraits::container_type item_type;
	static item_type *link_2_item(const x_dlink_t *link) {
		return link ? LinkTraits::container(link) : nullptr;
	}

	bool contain(item_type *item) const {
		return list.contain(LinkTraits::member(item));
	}

	bool empty(void) const {
		return list.empty();
	}
	static void remove(item_type *item) {
		x_dcircle_t::remove(LinkTraits::member(item));
	}
	void push_front(item_type *item) {
		list.push_front(LinkTraits::member(item));
	}
	void push_back(item_type *item) {
		list.push_back(LinkTraits::member(item));
	}
	item_type *get_front(void) const {
		return link_2_item(list.get_front());
	}
	item_type *get_back(void) const {
		return link_2_item(list.get_back());
	}
#if 0
	should return nullptr???
	item_type *prev(const item_type *t) const {
		return link_2_item(LinkTraits::member(t)->get_prev());
	}
	item_type *next(const item_type *t) const {
		return link_2_item(LinkTraits::member(t)->get_next());
	}
#endif
	x_dcircle_t list;
};

struct x_dqlink_t
{
	x_dqlink_t *get_next() const { return next; }
	x_dqlink_t *get_prev() const { return *prev; }
	void remove() {
		if (next != nullptr) {
			next->prev = prev;
		}
		*prev = next;
	}
	x_dqlink_t *next, **prev;
};

struct x_sdqueue_t
{
	x_sdqueue_t() : front(nullptr) { }
	x_sdqueue_t(x_sdqueue_t &&other) : front(nullptr) {
		std::swap(front, other.front);
	}
	x_sdqueue_t &operator=(x_sdqueue_t &&other) {
		std::swap(front, other.front);
		return *this;
	}
	x_sdqueue_t(const x_sdqueue_t &) = delete;
	x_sdqueue_t &operator=(const x_sdqueue_t &) = delete; 

	x_dqlink_t *get_front() const {
		return front;
	}
	bool contain(x_dqlink_t *link) const {
		for (x_dqlink_t *l = get_front(); l; l = l->get_next()) {
			if (l == link) {
				return true;
			}
		}
		return false;
	}
#ifndef NDEBUG
	bool in_list_check(x_dqlink_t *link) const {
		// ???	  return link && (link->prev != 0 || link->next != 0 || (front == link && back == link) && contain(link));
		return link && contain(link);
	}
#endif
	bool empty(void) const {
		return front == nullptr;
	}
	void push_front(x_dqlink_t *link) {
		if ((link->next = front) != nullptr) {
			front->prev = &(link->next);
		}
		front = link;
		link->prev = &front;
	}
	void remove(x_dqlink_t *link) {
		link->remove();
	}

	x_dqlink_t *front;
};

template <class LinkTraits>
struct x_tp_sdqueue_t
{
	typedef typename LinkTraits::container_type item_type;
	static item_type *link_2_item(const x_dqlink_t *link) {
		return link ? LinkTraits::container(link) : nullptr;
	}

	bool contain(item_type *item) const {
		return list.contain(LinkTraits::member(item));
	}

	bool empty(void) const {
		return list.empty();
	}
	void push_front(item_type *item) {
		list.push_front(LinkTraits::member(item));
	}
	void remove(item_type *item) {
		LinkTraits::member(item)->remove();
	}
	item_type *get_front(void) const {
		return link_2_item(list.get_front());
	}
	item_type *prev(const item_type *t) const {
		return link_2_item(LinkTraits::member(t)->get_prev());
	}
	item_type *next(const item_type *t) const {
		return link_2_item(LinkTraits::member(t)->get_next());
	}

	x_sdlist_t list;
};


#endif /* __list__hxx__ */

