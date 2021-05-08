
#ifndef __libndr__h__
#define __libndr__h__

/* from librpc/ndr/libndr.h */

#define LIBNDR_FLAG_BIGENDIAN  (1U<<0)
#define LIBNDR_FLAG_NOALIGN    (1U<<1)

#define LIBNDR_FLAG_STR_ASCII		(1U<<2)
#define LIBNDR_FLAG_STR_LEN4		(1U<<3)
#define LIBNDR_FLAG_STR_SIZE4		(1U<<4)
#define LIBNDR_FLAG_STR_NOTERM		(1U<<5)
#define LIBNDR_FLAG_STR_NULLTERM	(1U<<6)
#define LIBNDR_FLAG_STR_SIZE2		(1U<<7)
#define LIBNDR_FLAG_STR_BYTESIZE	(1U<<8)
#define LIBNDR_FLAG_STR_CONFORMANT	(1U<<10)
#define LIBNDR_FLAG_STR_CHARLEN		(1U<<11)
#define LIBNDR_FLAG_STR_UTF8		(1U<<12)
#define LIBNDR_FLAG_STR_RAW8		(1U<<13)
#define LIBNDR_STRING_FLAGS		(0U | \
		LIBNDR_FLAG_STR_ASCII | \
		LIBNDR_FLAG_STR_LEN4 | \
		LIBNDR_FLAG_STR_SIZE4 | \
		LIBNDR_FLAG_STR_NOTERM | \
		LIBNDR_FLAG_STR_NULLTERM | \
		LIBNDR_FLAG_STR_SIZE2 | \
		LIBNDR_FLAG_STR_BYTESIZE | \
		LIBNDR_FLAG_STR_CONFORMANT | \
		LIBNDR_FLAG_STR_CHARLEN | \
		LIBNDR_FLAG_STR_UTF8 | \
		LIBNDR_FLAG_STR_RAW8 | \
		0)

/*
 * Mark an element as SECRET, it won't be printed by
 * via ndr_print* unless NDR_PRINT_SECRETS is specified.
 */
#define LIBNDR_FLAG_IS_SECRET		(1U<<14)

/* Disable string token compression  */
#define LIBNDR_FLAG_NO_COMPRESSION	(1U<<15)

/*
 * don't debug NDR_ERR_BUFSIZE failures,
 * as the available buffer might be incomplete.
 *
 * return NDR_ERR_INCOMPLETE_BUFFER instead.
 */
#define LIBNDR_FLAG_INCOMPLETE_BUFFER (1U<<16)

/*
 * This lets ndr_pull_subcontext_end() return
 * NDR_ERR_UNREAD_BYTES.
 */
#define LIBNDR_FLAG_SUBCONTEXT_NO_UNREAD_BYTES (1U<<17)

/* set if relative pointers should *not* be marshalled in reverse order */
#define LIBNDR_FLAG_NO_RELATIVE_REVERSE	(1U<<18)

/* set if relative pointers are marshalled in reverse order */
#define LIBNDR_FLAG_RELATIVE_REVERSE	(1U<<19)

#define LIBNDR_FLAG_REF_ALLOC    (1U<<20)
#define LIBNDR_FLAG_REMAINING    (1U<<21)
#define LIBNDR_FLAG_ALIGN2       (1U<<22)
#define LIBNDR_FLAG_ALIGN4       (1U<<23)
#define LIBNDR_FLAG_ALIGN8       (1U<<24)

#define LIBNDR_ALIGN_FLAGS ( 0        | \
		LIBNDR_FLAG_NOALIGN   | \
		LIBNDR_FLAG_REMAINING | \
		LIBNDR_FLAG_ALIGN2    | \
		LIBNDR_FLAG_ALIGN4    | \
		LIBNDR_FLAG_ALIGN8    | \
		0)

#define LIBNDR_PRINT_ARRAY_HEX   (1U<<25)
#define LIBNDR_PRINT_SET_VALUES  (1U<<26)

/* used to force a section of IDL to be little-endian */
#define LIBNDR_FLAG_LITTLE_ENDIAN (1U<<27)

/* used to check if alignment padding is zero */
#define LIBNDR_FLAG_PAD_CHECK     (1U<<28)

#define LIBNDR_FLAG_NDR64         (1U<<29)

/* set if an object uuid will be present */
#define LIBNDR_FLAG_OBJECT_PRESENT    (1U<<30)

/* set to avoid recursion in ndr_size_*() calculation */
#define LIBNDR_FLAG_NO_NDR_SIZE		(1U<<31)


#endif /* __libndr__h__ */

