
#include "include/mbuf.hxx"

static x_mbuf_t *x_mbuf_alloc(size_t size)
{
	void *mem = malloc(sizeof(x_mbuf_t) + size);
	if (!mem) {
		return nullptr;
	}
	new(mem) x_mbuf_t(size);
	return (x_mbuf_t *)mem;
}

static void x_mbuf_release(x_mbuf_t *mb)
{
	if (--mb->refcnt == 0) {
		mb->~x_mbuf_t();
		free(mb);
	}
}

int main()
{
	x_mbuf_t *mb = x_mbuf_alloc(32);
	x_mbuf_release(mb);
	return 0;
}
