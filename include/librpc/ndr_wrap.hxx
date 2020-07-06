
#ifndef __ndr_wrap__hxx__
#define __ndr_wrap__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

namespace idl {

struct x_ndr_I_t {
	template <typename T>
	T operator()(T t) const { return t; }
};

template <typename T>
struct x_ndr_at_t
{
	x_ndr_at_t(x_ndr_off_t __pos) : pos(__pos) { }
	void operator()(x_ndr_off_t size, x_ndr_push_t &ndr, x_ndr_off_t epos, uint32_t flags) const {
		x_ndr_off_t bpos = pos;
		bpos = x_ndr_scalars(T(size), ndr, pos, epos, flags, X_NDR_SWITCH_NONE);
		X_ASSERT(bpos > 0);
	}
	T operator()(x_ndr_pull_t &ndr, x_ndr_off_t epos, uint32_t flags) const {
		x_ndr_off_t bpos = pos;
		T tmp;
		bpos = x_ndr_scalars(tmp, ndr, pos, epos, flags, X_NDR_SWITCH_NONE);
		X_ASSERT(bpos > 0);
		return tmp;
	}

	x_ndr_off_t pos;
};

inline void x_ndr_push_at(x_ndr_off_t length, x_ndr_push_t &ndr, x_ndr_off_t epos, uint32_t flags)
{
}

template <typename FT, typename ...Args>
inline void x_ndr_push_at(x_ndr_off_t length, x_ndr_push_t &ndr, x_ndr_off_t epos, uint32_t flags, const FT &ft, const Args&... args)
{
	ft(length, ndr, epos, flags);
	x_ndr_push_at(length, ndr, epos, flags, args...);
}
#if 0
inline void x_ndr_pull_at(x_ndr_off_t length, x_ndr_pull_t &ndr, x_ndr_off_t epos, uint32_t flags)
{
}

template <typename FT, typename ...Args>
inline void x_ndr_pull_at(x_ndr_pull_t &ndr, x_ndr_off_t epos, uint32_t flags, const FT &ft, const Args&... args)
{
	ft(ndr, epos, flags);
	x_ndr_pull_at(ndr, epos, flags, args...);
}
#endif


template <typename T, typename PosPtr>
x_ndr_off_t x_ndr_buffers_relative_ptr(const std::shared_ptr<T> &t,
		x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level,
		const PosPtr &pos_ptr)
{
	if (t) {
		X_NDR_DO_ALIGN(ndr, bpos, epos, flags);
		pos_ptr(bpos - ndr.base, ndr, epos, flags);
		bpos = x_ndr_handler_t<T, typename x_ndr_traits_t<T>::has_buffers>()(*t, ndr,
				bpos, epos, flags, level);
		if (bpos < 0) {
			return bpos;
		}
	}
	return bpos;
}

template <typename T, typename PosPtr>
x_ndr_off_t x_ndr_buffers_relative_ptr(std::shared_ptr<T> &t,
		x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level,
		const PosPtr &pos_ptr)
{
	auto offset = pos_ptr(ndr, epos, flags);
	if (offset) {
		X_NDR_CHECK_ALIGN(ndr, flags, offset);
		t = x_ndr_allocate_ptr<T>(level);

		x_ndr_off_t tmp_bpos = X_NDR_CHECK_POS(ndr.base + offset, 0, epos);

		tmp_bpos = x_ndr_handler_t<T, typename x_ndr_traits_t<T>::has_buffers>()(*t, ndr,
				tmp_bpos, epos, flags, level);
		if (tmp_bpos < 0) {
			return bpos;
		}

		return std::max(bpos, tmp_bpos);
	}
	return bpos;
}

template <typename T, typename PosPtr, typename PosSize, typename Sizer>
x_ndr_off_t x_ndr_buffers_relative_ptr(const std::shared_ptr<T> &t,
		x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level,
		const PosPtr &pos_ptr,
		const PosSize &pos_size, const Sizer &push_sizer)
{
	if (t) {
		X_NDR_DO_ALIGN(ndr, bpos, epos, flags);
		pos_ptr(bpos - ndr.base, ndr, epos, flags);
		x_ndr_off_t orig_bpos = bpos;
		bpos = x_ndr_handler_t<T, typename x_ndr_traits_t<T>::has_buffers>()(*t, ndr,
				bpos, epos, flags, level);
		if (bpos < 0) {
			return bpos;
		}
		pos_size(push_sizer(bpos - orig_bpos), ndr, epos, flags);
	}
	return bpos;
}

template <typename T, typename PosPtr, typename PosSize, typename Sizer>
x_ndr_off_t x_ndr_buffers_relative_ptr(std::shared_ptr<T> &t,
		x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level,
		const PosPtr &pos_ptr,
		const PosSize &pos_size, const Sizer &pull_sizer)
{
	auto offset = pos_ptr(ndr, epos, flags);
	if (offset) {
		X_NDR_CHECK_ALIGN(ndr, flags, offset);
		t = x_ndr_allocate_ptr<T>(level);
		auto size = pull_sizer(pos_size(ndr, epos, flags));

		x_ndr_off_t tmp_bpos = X_NDR_CHECK_POS(ndr.base + offset, 0, epos);
		epos = X_NDR_CHECK_POS(tmp_bpos + size, tmp_bpos, epos);

		tmp_bpos = x_ndr_handler_t<T, typename x_ndr_traits_t<T>::has_buffers>()(*t, ndr,
				tmp_bpos, epos, flags, level);
		if (tmp_bpos < 0) {
			return bpos;
		}

		return std::max(bpos, tmp_bpos);
	}
	return bpos;
}

template <typename T, typename PosPtr, typename PosSize1, typename Sizer1, typename PosSize2, typename Sizer2>
x_ndr_off_t x_ndr_buffers_relative_ptr(const std::shared_ptr<T> &t,
		x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level,
		const PosPtr &pos_ptr,
		const PosSize1 &pos_size1, const Sizer1 &push_sizer1,
		const PosSize2 &pos_size2, const Sizer2 &push_sizer2)
{
	if (t) {
		X_NDR_DO_ALIGN(ndr, bpos, epos, flags);
		pos_ptr(bpos - ndr.base, ndr, epos, flags);
		x_ndr_off_t orig_bpos = bpos;
		bpos = x_ndr_handler_t<T, typename x_ndr_traits_t<T>::has_buffers>()(*t, ndr,
				bpos, epos, flags, level);
		if (bpos < 0) {
			return bpos;
		}
		pos_size1(push_sizer1(bpos - orig_bpos), ndr, epos, flags);
		pos_size2(push_sizer2(bpos - orig_bpos), ndr, epos, flags);
	}
	return bpos;
}

template <typename T, typename PosPtr, typename PosSize1, typename Sizer1, typename PosSize2, typename Sizer2>
x_ndr_off_t x_ndr_buffers_relative_ptr(std::shared_ptr<T> &t,
		x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level,
		const PosPtr &pos_ptr,
		const PosSize1 &pos_size1, const Sizer1 &pull_sizer1,
		const PosSize2 &pos_size2, const Sizer2 &pull_sizer2)
{
	auto offset = pos_ptr(ndr, epos, flags);
	if (offset) {
		X_NDR_CHECK_ALIGN(ndr, flags, offset);
		t = x_ndr_allocate_ptr<T>(level);
		// we ignore the second size
		auto size = pull_sizer1(pos_size1(ndr, epos, flags));

		x_ndr_off_t tmp_bpos = X_NDR_CHECK_POS(ndr.base + offset, 0, epos);
		epos = X_NDR_CHECK_POS(tmp_bpos + size, tmp_bpos, epos);

		tmp_bpos = x_ndr_handler_t<T, typename x_ndr_traits_t<T>::has_buffers>()(*t, ndr,
				tmp_bpos, epos, flags, level);
		if (tmp_bpos < 0) {
			return bpos;
		}

		return std::max(bpos, tmp_bpos);
	}
	return bpos;
}

#define X_NDR_BUFFERS_RELATIVE_PTR(t, ndr, bpos, epos, flags, level, type_ptr, pos_ptr) \
	X_NDR_VERIFY((bpos), x_ndr_buffers_relative_ptr((t), (ndr), (bpos), (epos), (flags), (level), x_ndr_at_t<type_ptr>(pos_ptr)))

#define X_NDR_BUFFERS_RELATIVE_PTR_SIZE_1(t, ndr, bpos, epos, flags, level, type_ptr, pos_ptr, type_size, pos_size, sizer) \
	X_NDR_VERIFY((bpos), x_ndr_buffers_relative_ptr((t), (ndr), (bpos), (epos), (flags), (level), x_ndr_at_t<type_ptr>(pos_ptr), x_ndr_at_t<type_size>(pos_size), sizer))

#define X_NDR_BUFFERS_RELATIVE_PTR_SIZE_2(t, ndr, bpos, epos, flags, level, type_ptr, pos_ptr, type_size1, pos_size1, sizer1, type_size2, pos_size2, sizer2) \
	X_NDR_VERIFY((bpos), x_ndr_buffers_relative_ptr((t), (ndr), (bpos), (epos), (flags), (level), x_ndr_at_t<type_ptr>(pos_ptr), x_ndr_at_t<type_size1>(pos_size1), sizer1, x_ndr_at_t<type_size2>(pos_size2), sizer2))



template <typename T>
inline x_ndr_off_t x_ndr_scalars_unique_ptr(const std::shared_ptr<T> &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	uint3264 ptr;
	if (t) {
		ptr.val = ndr.next_ptr();
	} else {
		ptr.val = 0;
	}
	X_NDR_SCALARS(ptr, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	return bpos;
}

template <typename T>
inline x_ndr_off_t x_ndr_buffers_unique_ptr(const std::shared_ptr<T> &t, x_ndr_push_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	if (t) {
		bpos = x_ndr_handler_t<T, typename x_ndr_traits_t<T>::has_buffers>()(*t, ndr,
				bpos, epos, flags, level);
	}
	return bpos;
}

template <typename T>
inline x_ndr_off_t x_ndr_scalars_unique_ptr(std::shared_ptr<T> &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	uint3264 ptr;
	X_NDR_SCALARS(ptr, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
	if (ptr.val) {
		t = x_ndr_allocate_ptr<T>(level);
	}
	return bpos;
}

template <typename T>
inline x_ndr_off_t x_ndr_buffers_unique_ptr(std::shared_ptr<T> &t, x_ndr_pull_t &ndr,
		x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	if (t) {
		bpos = x_ndr_handler_t<T, typename x_ndr_traits_t<T>::has_buffers>()(*t, ndr,
				bpos, epos, flags, level);
	}
	return bpos;
}

#define X_NDR_SCALARS_UNIQUE_PTR(t, ndr, bpos, epos, ...) \
	X_NDR_VERIFY((bpos), x_ndr_scalars_unique_ptr((t), (ndr), (bpos), (epos), __VA_ARGS__))

#define X_NDR_BUFFERS_UNIQUE_PTR(t, ndr, bpos, epos, ...) \
	X_NDR_VERIFY((bpos), x_ndr_buffers_unique_ptr((t), (ndr), (bpos), (epos), __VA_ARGS__))


template <typename T>
x_ndr_off_t x_ndr_buffers_unique_size_is(const std::shared_ptr<T> &t,
		x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	if (t) {
		uint3264 size = t->size();
		X_NDR_SCALARS(size, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		bpos = x_ndr_handler_t<T, typename x_ndr_traits_t<T>::has_buffers>()(*t, ndr,
				bpos, epos, flags, level);
		if (bpos < 0) {
			return bpos;
		}
	}
	return bpos;
}

template <typename T>
x_ndr_off_t x_ndr_buffers_unique_size_is(std::shared_ptr<T> &t,
		x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level)
{
	if (t) {
		uint3264 size;
		X_NDR_SCALARS(size, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		t->resize(size.val);
		bpos = x_ndr_handler_t<T, typename x_ndr_traits_t<T>::has_buffers>()(*t, ndr,
				bpos, epos, flags, level);
		if (bpos < 0) {
			return bpos;
		}
	}
	return bpos;
}

template <typename T, typename SPos, typename SSizer>
x_ndr_off_t x_ndr_buffers_unique_size_is(const std::shared_ptr<T> &t,
		x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level,
		const SPos &spos, const SSizer &ssizer)
{
	if (t) {
		uint3264 size = t->size();
		X_NDR_SCALARS(size, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		bpos = x_ndr_handler_t<T, typename x_ndr_traits_t<T>::has_buffers>()(*t, ndr,
				bpos, epos, flags, level);
		if (bpos < 0) {
			return bpos;
		}

		spos(ssizer(size.val), ndr, epos, flags);
	}
	return bpos;
}

template <typename T, typename SPos, typename SSizer>
x_ndr_off_t x_ndr_buffers_unique_size_is(std::shared_ptr<T> &t,
		x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level,
		const SPos &spos, const SSizer &ssizer)
{
	if (t) {
		uint3264 size;
		X_NDR_SCALARS(size, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		t->resize(size.val);
		bpos = x_ndr_handler_t<T, typename x_ndr_traits_t<T>::has_buffers>()(*t, ndr,
				bpos, epos, flags, level);
		if (bpos < 0) {
			return bpos;
		}

		// TODO x_ndr_pull_at(size.val, ndr, epos, flags, args...);
	}
	return bpos;
}

#define X_NDR_BUFFERS_UNIQUE_SIZE_IS__0(t, ndr, bpos, epos, flags, level) \
	X_NDR_VERIFY((bpos), x_ndr_buffers_unique_size_is((t), (ndr), (bpos), (epos), (flags), (level)))

#define X_NDR_BUFFERS_UNIQUE_SIZE_IS__1(t, ndr, bpos, epos, flags, level, type_size, pos_size, ssizer) \
	X_NDR_VERIFY((bpos), (x_ndr_buffers_unique_size_is((t), (ndr), (bpos), (epos), (flags), (level), x_ndr_at_t<type_size>(pos_size), (ssizer))))

#define UNUSED_X_NDR_BUFFERS_UNIQUE_SIZE_IS__2(t, ndr, bpos, epos, flags, level, type_0, pos_0, type_1, pos_1) \
	X_NDR_VERIFY((bpos), (x_ndr_buffers_unique_size_is((t), (ndr), (bpos), (epos), (flags), (level), x_ndr_at_t<type_0>(pos_0), x_ndr_at_t<type_1>(pos_1))))


template <typename T>
struct x_ndr_traits_size_is_length_is_t;

template <typename T>
struct x_ndr_traits_size_is_length_is_t<std::vector<T>>
{
	void get_size_length(const std::vector<T> &v, size_t &size, size_t &length) const {
		size = length = v.size();
	}

	void set_size_length(std::vector<T> &v, size_t size, size_t length) const {
		v.resize(length);
	}

	size_t scale(size_t size) const {
		return size;
	}
};

template <>
struct x_ndr_traits_size_is_length_is_t<std::u16string>
{
	void get_size_length(const std::u16string &v, size_t &size, size_t &length) const {
		size = length = v.size();
	}

	void set_size_length(std::u16string &v, size_t size, size_t length) const {
		v.resize(length);
	}

	size_t scale(size_t size) const {
		return size;
	}
};

template <typename T, typename Traits = x_ndr_traits_size_is_length_is_t<T>>
x_ndr_off_t x_ndr_buffers_unique_size_is_length_is(const std::shared_ptr<T> &t,
		x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level,
		const Traits &traits = Traits())
{
	if (t) {
		size_t size, length;
		traits.get_size_length(*t, size, length);
		X_NDR_SCALARS(uint3264(size), ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS(uint3264(0), ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS(uint3264(length), ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		bpos = x_ndr_handler_t<T, typename x_ndr_traits_t<T>::has_buffers>()(*t, ndr,
				bpos, epos, flags, level);
	}
	return bpos;
}

template <typename T, typename Traits = x_ndr_traits_size_is_length_is_t<T>>
x_ndr_off_t x_ndr_buffers_unique_size_is_length_is(std::shared_ptr<T> &t,
		x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level,
		const Traits &traits = Traits())
{
	if (t) {
		uint3264 size, offset, length;
		X_NDR_SCALARS(size, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS(offset, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS(length, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		if (offset.val != 0) {
			return -NDR_ERR_ARRAY_SIZE;
		}
		if (length.val > size.val) {
			return -NDR_ERR_ARRAY_SIZE;
		}
		if (bpos < 0) {
			return bpos;
		}

		traits.set_size_length(*t, size.val, length.val);
		bpos = x_ndr_handler_t<T, typename x_ndr_traits_t<T>::has_buffers>()(*t, ndr,
				bpos, epos, flags, level);
	}
	return bpos;
}

template <typename T, typename SPos, typename LPos, typename Traits = x_ndr_traits_size_is_length_is_t<T>>
x_ndr_off_t x_ndr_buffers_unique_size_is_length_is(const std::shared_ptr<T> &t,
		x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level,
		const SPos &spos, const LPos &lpos,
		const Traits &traits = Traits())

{
	if (t) {
		size_t size, length;
		traits.get_size_length(*t, size, length);
		X_NDR_SCALARS(uint3264(size), ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS(uint3264(0), ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS(uint3264(length), ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		bpos = x_ndr_handler_t<T, typename x_ndr_traits_t<T>::has_buffers>()(*t, ndr,
				bpos, epos, flags, level);
		if (bpos < 0) {
			return bpos;
		}

		spos(traits.scale(size), ndr, epos, flags);
		lpos(traits.scale(length), ndr, epos, flags);
	}
	return bpos;
}

template <typename T, typename SPos, typename LPos, typename Traits = x_ndr_traits_size_is_length_is_t<T>>
x_ndr_off_t x_ndr_buffers_unique_size_is_length_is(std::shared_ptr<T> &t,
		x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level,
		const SPos &spos, const LPos &lpos,
		const Traits &traits = Traits())
{
	if (t) {
		uint3264 size, offset, length;
		X_NDR_SCALARS(size, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS(offset, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		X_NDR_SCALARS(length, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		if (offset.val != 0) {
			return -NDR_ERR_ARRAY_SIZE;
		}
		if (length.val > size.val) {
			return -NDR_ERR_ARRAY_SIZE;
		}

		traits.set_size_length(*t, size.val, length.val);
		bpos = x_ndr_handler_t<T, typename x_ndr_traits_t<T>::has_buffers>()(*t, ndr,
				bpos, epos, flags, level);
		if (bpos < 0) {
			return bpos;
		}

		// TODO sizers x_ndr_pull_at(length.val, ndr, epos, flags, args...);
	}
	return bpos;
}

#define X_NDR_BUFFERS_UNIQUE_SIZE_IS_LENGTH_IS__0(t, ndr, bpos, epos, flags, level, ...) \
	X_NDR_VERIFY((bpos), (x_ndr_buffers_unique_size_is_length_is((t), (ndr), (bpos), (epos), (flags), (level), ##__VA_ARGS__)))

#define X_NDR_BUFFERS_UNIQUE_SIZE_IS_LENGTH_IS__2(t, ndr, bpos, epos, flags, level, type_size, pos_size, type_length, pos_length, ...) \
	X_NDR_VERIFY((bpos), (x_ndr_buffers_unique_size_is_length_is((t), (ndr), (bpos), (epos), (flags), (level), x_ndr_at_t<type_size>(pos_size), x_ndr_at_t<type_length>(pos_length), ##__VA_ARGS__)))

template <typename T, typename SPos>
x_ndr_off_t x_ndr_scalars_size(const T &t,
		x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level,
		const SPos &spos)
{
	x_ndr_off_t orig_bpos = bpos;
	X_NDR_SCALARS(t, ndr, bpos, epos, flags, level);
	spos((bpos - orig_bpos), ndr, epos, flags);
	return bpos;
}

template <typename T, typename SPos>
x_ndr_off_t x_ndr_scalars_size(T &t,
		x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level,
		const SPos &spos)
{
	auto size = spos(ndr, epos, flags);
	epos = X_NDR_CHECK_POS(bpos + size, bpos, epos);
	X_NDR_SCALARS(t, ndr, bpos, epos, flags, level);
	return epos;
}

#define X_NDR_SCALARS_SIZE(t, ndr, bpos, epos, flags, level, type_size, pos_size) \
	X_NDR_VERIFY((bpos), x_ndr_scalars_size((t), (ndr), (bpos), (epos), (flags), (level), x_ndr_at_t<type_size>(pos_size)))

template <typename T, typename SPos>
inline x_ndr_off_t x_ndr_buffers_unique_vector(const std::shared_ptr<std::vector<T>> &t,
		x_ndr_push_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level,
		const SPos &spos)
{
	if (t) {
		uint3264 num = t->size();
		X_NDR_SCALARS(num, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		x_ndr_push_t subndr{ndr.buff, bpos};
		for (auto &e : *t) {
			X_NDR_SCALARS(e, subndr, bpos, epos, flags, level);
		}
		for (auto &e : *t) {
			X_NDR_BUFFERS(e, subndr, bpos, epos, flags, level);
		}
		spos(num.val, ndr, epos, flags);
	}
	return bpos;
}

template <typename T, typename SPos>
inline x_ndr_off_t x_ndr_buffers_unique_vector(std::shared_ptr<std::vector<T>> &t,
		x_ndr_pull_t &ndr, x_ndr_off_t bpos, x_ndr_off_t epos,
		uint32_t flags, x_ndr_switch_t level,
		const SPos &spos)
{
	if (t) {
		uint3264 num;
		X_NDR_SCALARS(num, ndr, bpos, epos, flags, X_NDR_SWITCH_NONE);
		t->resize(num.val);
		x_ndr_pull_t subndr{ndr.buff, bpos};
		for (auto &e : *t) {
			X_NDR_SCALARS(e, subndr, bpos, epos, flags, level);
		}
		for (auto &e : *t) {
			X_NDR_BUFFERS(e, subndr, bpos, epos, flags, level);
		}
	}
	return bpos;
}

#define X_NDR_BUFFERS_UNIQUE_VECTOR(t, ndr, bpos, epos, flags, level, type_size, pos_size) \
	X_NDR_VERIFY((bpos), x_ndr_buffers_unique_vector((t), (ndr), (bpos), (epos), (flags), (level), x_ndr_at_t<type_size>(pos_size)))

}

#endif /* __ndr_wrap__hxx__ */

