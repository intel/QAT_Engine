/* generic atomic operations used by progressive locks
 *
 * Copyright (C) 2012-2024 Willy Tarreau <w@1wt.eu>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef PL_ATOMIC_OPS_H
#define PL_ATOMIC_OPS_H


/* compiler-only memory barrier, for use around locks */
#define pl_barrier() do {			\
		asm volatile("" ::: "memory");	\
	} while (0)

#if defined(__i386__) || defined (__i486__) || defined (__i586__) || defined (__i686__) || defined (__x86_64__)

/* full memory barrier using mfence when SSE2 is supported, falling back to
 * "lock add %esp" (gcc uses "lock add" or "lock or").
 */
#if defined(__SSE2__)

#define pl_mb() do {                                 \
		asm volatile("mfence" ::: "memory"); \
	} while (0)

#elif defined(__x86_64__)

#define pl_mb() do {                                                       \
		asm volatile("lock addl $0,0 (%%rsp)" ::: "memory", "cc"); \
	} while (0)

#else /* ix86 */

#define pl_mb() do {                                                       \
		asm volatile("lock addl $0,0 (%%esp)" ::: "memory", "cc"); \
	} while (0)

#endif /* end of pl_mb() case for sse2/x86_64/x86 */

/*
 * Generic functions common to the x86 family
 */

#define pl_cpu_relax() do {                   \
		asm volatile("rep;nop\n");    \
	} while (0)

/* increment integer value pointed to by pointer <ptr>, and return non-zero if
 * result is non-null.
 */
#define pl_inc(ptr) (                                                         \
	(sizeof(long) == 8 && sizeof(*(ptr)) == 8) ? ({                       \
		unsigned char ret;                                            \
		asm volatile("lock incq %0\n"                                 \
			     "setne %1\n"                                     \
			     : "+m" (*(ptr)), "=qm" (ret)                     \
			     :                                                \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 4) ? ({                                       \
		unsigned char ret;                                            \
		asm volatile("lock incl %0\n"                                 \
			     "setne %1\n"                                     \
			     : "+m" (*(ptr)), "=qm" (ret)                     \
			     :                                                \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 2) ? ({                                       \
		unsigned char ret;                                            \
		asm volatile("lock incw %0\n"                                 \
			     "setne %1\n"                                     \
			     : "+m" (*(ptr)), "=qm" (ret)                     \
			     :                                                \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 1) ? ({                                       \
		unsigned char ret;                                            \
		asm volatile("lock incb %0\n"                                 \
			     "setne %1\n"                                     \
			     : "+m" (*(ptr)), "=qm" (ret)                     \
			     :                                                \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : ({                                                               \
		void __unsupported_argument_size_for_pl_inc__(char *,int);    \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                      \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8)) \
			__unsupported_argument_size_for_pl_inc__(__FILE__,__LINE__);   \
		0;                                                            \
	})                                                                    \
)

/* decrement integer value pointed to by pointer <ptr>, and return non-zero if
 * result is non-null.
 */
#define pl_dec(ptr) (                                                         \
	(sizeof(long) == 8 && sizeof(*(ptr)) == 8) ? ({                       \
		unsigned char ret;                                            \
		asm volatile("lock decq %0\n"                                 \
			     "setne %1\n"                                     \
			     : "+m" (*(ptr)), "=qm" (ret)                     \
			     :                                                \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 4) ? ({                                       \
		unsigned char ret;                                            \
		asm volatile("lock decl %0\n"                                 \
			     "setne %1\n"                                     \
			     : "+m" (*(ptr)), "=qm" (ret)                     \
			     :                                                \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 2) ? ({                                       \
		unsigned char ret;                                            \
		asm volatile("lock decw %0\n"                                 \
			     "setne %1\n"                                     \
			     : "+m" (*(ptr)), "=qm" (ret)                     \
			     :                                                \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 1) ? ({                                       \
		unsigned char ret;                                            \
		asm volatile("lock decb %0\n"                                 \
			     "setne %1\n"                                     \
			     : "+m" (*(ptr)), "=qm" (ret)                     \
			     :                                                \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : ({                                                               \
		void __unsupported_argument_size_for_pl_dec__(char *,int);    \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                      \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8)) \
			__unsupported_argument_size_for_pl_dec__(__FILE__,__LINE__);   \
		0;                                                            \
	})                                                                    \
)

/* increment integer value pointed to by pointer <ptr>, no return */
#define pl_inc_noret(ptr) ({                                                  \
	if (sizeof(long) == 8 && sizeof(*(ptr)) == 8) {                       \
		asm volatile("lock incq %0\n"                                 \
			     : "+m" (*(ptr))                                  \
			     :                                                \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 4) {                                     \
		asm volatile("lock incl %0\n"                                 \
			     : "+m" (*(ptr))                                  \
			     :                                                \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 2) {                                     \
		asm volatile("lock incw %0\n"                                 \
			     : "+m" (*(ptr))                                  \
			     :                                                \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 1) {                                     \
		asm volatile("lock incb %0\n"                                 \
			     : "+m" (*(ptr))                                  \
			     :                                                \
			     : "cc");                                         \
	} else {                                                              \
		void __unsupported_argument_size_for_pl_inc_noret__(char *,int);   \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                          \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8))     \
			__unsupported_argument_size_for_pl_inc_noret__(__FILE__,__LINE__); \
	}                                                                     \
})

/* decrement integer value pointed to by pointer <ptr>, no return */
#define pl_dec_noret(ptr) ({                                                  \
	if (sizeof(long) == 8 && sizeof(*(ptr)) == 8) {                       \
		asm volatile("lock decq %0\n"                                 \
			     : "+m" (*(ptr))                                  \
			     :                                                \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 4) {                                     \
		asm volatile("lock decl %0\n"                                 \
			     : "+m" (*(ptr))                                  \
			     :                                                \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 2) {                                     \
		asm volatile("lock decw %0\n"                                 \
			     : "+m" (*(ptr))                                  \
			     :                                                \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 1) {                                     \
		asm volatile("lock decb %0\n"                                 \
			     : "+m" (*(ptr))                                  \
			     :                                                \
			     : "cc");                                         \
	} else {                                                              \
		void __unsupported_argument_size_for_pl_dec_noret__(char *,int);   \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                          \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8))     \
			__unsupported_argument_size_for_pl_dec_noret__(__FILE__,__LINE__); \
	}                                                                     \
})

/* add integer constant <x> to integer value pointed to by pointer <ptr>,
 * no return. Size of <x> is not checked.
 */
#define pl_add(ptr, x) ({                                                     \
	if (sizeof(long) == 8 && sizeof(*(ptr)) == 8) {                       \
		asm volatile("lock addq %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned long)(x))                      \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 4) {                                     \
		asm volatile("lock addl %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned int)(x))                       \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 2) {                                     \
		asm volatile("lock addw %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned short)(x))                     \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 1) {                                     \
		asm volatile("lock addb %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned char)(x))                      \
			     : "cc");                                         \
	} else {                                                              \
		void __unsupported_argument_size_for_pl_add__(char *,int);    \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                          \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8))     \
			__unsupported_argument_size_for_pl_add__(__FILE__,__LINE__);       \
	}                                                                     \
})

/* subtract integer constant <x> from integer value pointed to by pointer
 * <ptr>, no return. Size of <x> is not checked.
 */
#define pl_sub(ptr, x) ({                                                     \
	if (sizeof(long) == 8 && sizeof(*(ptr)) == 8) {                       \
		asm volatile("lock subq %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned long)(x))                      \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 4) {                                     \
		asm volatile("lock subl %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned int)(x))                       \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 2) {                                     \
		asm volatile("lock subw %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned short)(x))                     \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 1) {                                     \
		asm volatile("lock subb %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned char)(x))                      \
			     : "cc");                                         \
	} else {                                                              \
		void __unsupported_argument_size_for_pl_sub__(char *,int);    \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                      \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8)) \
			__unsupported_argument_size_for_pl_sub__(__FILE__,__LINE__);   \
	}                                                                     \
})

/* binary and integer value pointed to by pointer <ptr> with constant <x>, no
 * return. Size of <x> is not checked.
 */
#define pl_and(ptr, x) ({                                                     \
	if (sizeof(long) == 8 && sizeof(*(ptr)) == 8) {                       \
		asm volatile("lock andq %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned long)(x))                      \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 4) {                                     \
		asm volatile("lock andl %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned int)(x))                       \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 2) {                                     \
		asm volatile("lock andw %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned short)(x))                     \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 1) {                                     \
		asm volatile("lock andb %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned char)(x))                      \
			     : "cc");                                         \
	} else {                                                              \
		void __unsupported_argument_size_for_pl_and__(char *,int);    \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                       \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8))  \
			__unsupported_argument_size_for_pl_and__(__FILE__,__LINE__);    \
	}                                                                     \
})

/* binary or integer value pointed to by pointer <ptr> with constant <x>, no
 * return. Size of <x> is not checked.
 */
#define pl_or(ptr, x) ({                                                      \
	if (sizeof(long) == 8 && sizeof(*(ptr)) == 8) {                       \
		asm volatile("lock orq %1, %0\n"                              \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned long)(x))                      \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 4) {                                     \
		asm volatile("lock orl %1, %0\n"                              \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned int)(x))                       \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 2) {                                     \
		asm volatile("lock orw %1, %0\n"                              \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned short)(x))                     \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 1) {                                     \
		asm volatile("lock orb %1, %0\n"                              \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned char)(x))                      \
			     : "cc");                                         \
	} else {                                                              \
		void __unsupported_argument_size_for_pl_or__(char *,int);     \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                       \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8))  \
			__unsupported_argument_size_for_pl_or__(__FILE__,__LINE__);     \
	}                                                                     \
})

/* binary xor integer value pointed to by pointer <ptr> with constant <x>, no
 * return. Size of <x> is not checked.
 */
#define pl_xor(ptr, x) ({                                                     \
	if (sizeof(long) == 8 && sizeof(*(ptr)) == 8) {                       \
		asm volatile("lock xorq %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned long)(x))                      \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 4) {                                     \
		asm volatile("lock xorl %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned int)(x))                       \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 2) {                                     \
		asm volatile("lock xorw %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned short)(x))                     \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 1) {                                     \
		asm volatile("lock xorb %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned char)(x))                      \
			     : "cc");                                         \
	} else {                                                              \
		void __unsupported_argument_size_for_pl_xor__(char *,int);    \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                       \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8))  \
		__unsupported_argument_size_for_pl_xor__(__FILE__,__LINE__);            \
	}                                                                     \
})

/* test and set bit <bit> in integer value pointed to by pointer <ptr>. Returns
 * 0 if the bit was not set, or ~0 of the same type as *ptr if it was set. Note
 * that there is no 8-bit equivalent operation.
 */
#define pl_bts(ptr, bit) (                                                    \
	(sizeof(long) == 8 && sizeof(*(ptr)) == 8) ? ({                       \
		unsigned long ret;                                            \
		asm volatile("lock btsq %2, %0\n\t"                           \
			     "sbb %1, %1\n\t"                                 \
			     : "+m" (*(ptr)), "=r" (ret)                      \
			     : "Ir" ((unsigned long)(bit))                    \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 4) ? ({                                       \
		unsigned int ret;                                             \
		asm volatile("lock btsl %2, %0\n\t"                           \
			     "sbb %1, %1\n\t"                                 \
			     : "+m" (*(ptr)), "=r" (ret)                      \
			     : "Ir" ((unsigned int)(bit))                     \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 2) ? ({                                       \
		unsigned short ret;                                           \
		asm volatile("lock btsw %2, %0\n\t"                           \
			     "sbb %1, %1\n\t"                                 \
			     : "+m" (*(ptr)), "=r" (ret)                      \
			     : "Ir" ((unsigned short)(bit))                   \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : ({                                                               \
		void __unsupported_argument_size_for_pl_bts__(char *,int);    \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                      \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8)) \
			__unsupported_argument_size_for_pl_bts__(__FILE__,__LINE__);   \
		0;                                                            \
	})                                                                    \
)

/* Note: for an unclear reason, gcc's __sync_fetch_and_add() implementation
 * produces less optimal than hand-crafted asm code so let's implement here the
 * operations we need for the most common archs.
 */

/* fetch-and-add: fetch integer value pointed to by pointer <ptr>, add <x> to
 * to <*ptr> and return the previous value.
 */
#define pl_xadd(ptr, x) (                                                     \
	(sizeof(long) == 8 && sizeof(*(ptr)) == 8) ? ({                       \
		unsigned long ret = (unsigned long)(x);                       \
		asm volatile("lock xaddq %0, %1\n"                            \
			     :  "=r" (ret), "+m" (*(ptr))                     \
			     : "0" (ret)                                      \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 4) ? ({                                       \
		unsigned int ret = (unsigned int)(x);                         \
		asm volatile("lock xaddl %0, %1\n"                            \
			     :  "=r" (ret), "+m" (*(ptr))                     \
			     : "0" (ret)                                      \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 2) ? ({                                       \
		unsigned short ret = (unsigned short)(x);                     \
		asm volatile("lock xaddw %0, %1\n"                            \
			     :  "=r" (ret), "+m" (*(ptr))                     \
			     : "0" (ret)                                      \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 1) ? ({                                       \
		unsigned char ret = (unsigned char)(x);                       \
		asm volatile("lock xaddb %0, %1\n"                            \
			     :  "=r" (ret), "+m" (*(ptr))                     \
			     : "0" (ret)                                      \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : ({                                                               \
		void __unsupported_argument_size_for_pl_xadd__(char *,int);   \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                       \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8))  \
			__unsupported_argument_size_for_pl_xadd__(__FILE__,__LINE__);   \
		0;                                                            \
	})                                                                    \
)

/* exchange value <x> with integer value pointed to by pointer <ptr>, and return
 * previous <*ptr> value. <x> must be of the same size as <*ptr>.
 */
#define pl_xchg(ptr, x) (                                                     \
	(sizeof(long) == 8 && sizeof(*(ptr)) == 8) ? ({                       \
		unsigned long ret = (unsigned long)(x);                       \
		asm volatile("xchgq %0, %1\n"                                 \
			     :  "=r" (ret), "+m" (*(ptr))                     \
			     : "0" (ret)                                      \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 4) ? ({                                       \
		unsigned int ret = (unsigned int)(x);                         \
		asm volatile("xchgl %0, %1\n"                                 \
			     :  "=r" (ret), "+m" (*(ptr))                     \
			     : "0" (ret)                                      \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 2) ? ({                                       \
		unsigned short ret = (unsigned short)(x);                     \
		asm volatile("xchgw %0, %1\n"                                 \
			     :  "=r" (ret), "+m" (*(ptr))                     \
			     : "0" (ret)                                      \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 1) ? ({                                       \
		unsigned char ret = (unsigned char)(x);                       \
		asm volatile("xchgb %0, %1\n"                                 \
			     :  "=r" (ret), "+m" (*(ptr))                     \
			     : "0" (ret)                                      \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : ({                                                               \
		void __unsupported_argument_size_for_pl_xchg__(char *,int);   \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                       \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8))  \
		__unsupported_argument_size_for_pl_xchg__(__FILE__,__LINE__);           \
		0;                                                            \
	})                                                                    \
)

/* compare integer value <*ptr> with <old> and exchange it with <new> if
 * it matches, and return <old>. <old> and <new> must be of the same size as
 * <*ptr>.
 */
#define pl_cmpxchg(ptr, old, new) (                                           \
	(sizeof(long) == 8 && sizeof(*(ptr)) == 8) ? ({                       \
		unsigned long ret;                                            \
		asm volatile("lock cmpxchgq %2,%1"                            \
			     : "=a" (ret), "+m" (*(ptr))                      \
			     : "r" ((unsigned long)(new)),                    \
			       "0" ((unsigned long)(old))                     \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 4) ? ({                                       \
		unsigned int ret;                                             \
		asm volatile("lock cmpxchgl %2,%1"                            \
			     : "=a" (ret), "+m" (*(ptr))                      \
			     : "r" ((unsigned int)(new)),                     \
			       "0" ((unsigned int)(old))                      \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 2) ? ({                                       \
		unsigned short ret;                                           \
		asm volatile("lock cmpxchgw %2,%1"                            \
			     : "=a" (ret), "+m" (*(ptr))                      \
			     : "r" ((unsigned short)(new)),                   \
			       "0" ((unsigned short)(old))                    \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 1) ? ({                                       \
		unsigned char ret;                                            \
		asm volatile("lock cmpxchgb %2,%1"                            \
			     : "=a" (ret), "+m" (*(ptr))                      \
			     : "r" ((unsigned char)(new)),                    \
			       "0" ((unsigned char)(old))                     \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : ({                                                               \
		void __unsupported_argument_size_for_pl_cmpxchg__(char *,int);   \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                      \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8)) \
		__unsupported_argument_size_for_pl_cmpxchg__(__FILE__,__LINE__);       \
		0;                                                            \
	})                                                                    \
)

#else
/* generic implementations */

#if defined(__aarch64__)

/* This was shown to improve fairness on modern ARMv8 such as Neoverse N1 */
#define pl_cpu_relax() do {				\
		asm volatile("isb" ::: "memory");	\
	} while (0)

#else

#define pl_cpu_relax() do {             \
		asm volatile("");       \
	} while (0)

#endif

/* full memory barrier */
#define pl_mb() do {                    \
		__sync_synchronize();   \
	} while (0)

#define pl_inc_noret(ptr)     ({ __sync_add_and_fetch((ptr), 1);   })
#define pl_dec_noret(ptr)     ({ __sync_sub_and_fetch((ptr), 1);   })
#define pl_inc(ptr)           ({ __sync_add_and_fetch((ptr), 1);   })
#define pl_dec(ptr)           ({ __sync_sub_and_fetch((ptr), 1);   })
#define pl_add(ptr, x)        ({ __sync_add_and_fetch((ptr), (x)); })
#define pl_and(ptr, x)        ({ __sync_and_and_fetch((ptr), (x)); })
#define pl_or(ptr, x)         ({ __sync_or_and_fetch((ptr), (x));  })
#define pl_xor(ptr, x)        ({ __sync_xor_and_fetch((ptr), (x)); })
#define pl_sub(ptr, x)        ({ __sync_sub_and_fetch((ptr), (x)); })
#define pl_bts(ptr, bit)      ({ typeof(*(ptr)) __pl_t = (1u << (bit));         \
                                 __sync_fetch_and_or((ptr), __pl_t) & __pl_t;	\
                              })
#define pl_xadd(ptr, x)       ({ __sync_fetch_and_add((ptr), (x)); })
#define pl_cmpxchg(ptr, o, n) ({ __sync_val_compare_and_swap((ptr), (o), (n)); })
#define pl_xchg(ptr, x)       ({ typeof(*(ptr)) __pl_t;                                       \
                                 do { __pl_t = *(ptr);                                        \
                                 } while (!__sync_bool_compare_and_swap((ptr), __pl_t, (x))); \
                                 __pl_t;                                                      \
                              })

#endif

#endif /* PL_ATOMIC_OPS_H */