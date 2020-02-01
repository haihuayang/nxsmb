
#ifndef __mbuf__hxx__
#define __mbuf__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include <atomic>
#include "utils.hxx"
#include "list.hxx"

struct x_mbuf_t
{
	explicit x_mbuf_t(size_t s) : size(s) { }
	std::atomic<int> refcnt{1};
	const uint32_t size;
	uint8_t data[];
};

struct x_mref_t
{
	x_dlink_t link;
	x_auto_ref_t<x_mbuf_t> mbuf;
	void *data() const {
		return mbuf->data + offset;
	}
	uint32_t offset;
	uint32_t length;
};

X_DECLARE_MEMBER_TRAITS(x_mref_traits, x_mref_t, link)
struct x_mlist_t
{
	x_tp_ddlist_t<x_mref_traits> mref;
};
#endif /* __mbuf__hxx__ */

