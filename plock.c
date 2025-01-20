/* pthread_rwlock emulation (version without exponential back-off)
 *
 * Copyright (C) 2022-2025 Willy Tarreau <w@1wt.eu>
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


/* Pthread rwlock emulation using plocks (to avoid expensive futexes).
 *
 * These are a direct mapping on Progressive Locks, with the exception that
 * since there's a common unlock operation in pthreads, we need to know if
 * we need to unlock for reads or writes, so we set the topmost bit to 1 when
 * a write lock is acquired to indicate that a write unlock needs to be
 * performed. This only divides by two the maximum number of threads that
 * may be supported compared to the default plock implementation, which is
 * generally OK. In order to ease integration into existing code, the storage
 * here is the provided pthread_rwlock_t cast as a unsigned long. It is
 * expected to be zero when unlocked so that code that would forget to
 * call pthread_rwlock_init() after a calloc() and that would happen to work
 * by pure luck would continue to work.
 *
 * This variant does NOT use exponential backoff as it was found to
 * significantly reduce performance on some platforms when the application
 * makes excessive use of pthread_rwlocks but contention remains low (which
 * is often the case when using rwlocks). If this is needed in the future,
 * please do not do it in this file and provide it in an alternate one
 * instead so that users can choose the one they want.
 *
 * It is recommended to link this code statically into the target executable
 * to make sure that the redefined symbols have precedence over the ones
 * provided by an external shared pthread library. It has no other dependency
 * beyond pthread and plock.h, so the build process is trivial:
 *
 *   $ cc -O2 -c pth_rwl.c -pthread
 *   # link the resulting .o into the final executable
 *
 * This source file (and its required dependencies) may be directly copied into
 * the target project as long as its license is compatible with this one (which
 * should generally be the case).
 */

#include <pthread.h>
#include "plock.h"

int pthread_rwlock_init(pthread_rwlock_t *restrict rwlock, const pthread_rwlockattr_t *restrict attr)
{
	unsigned long *lock = (unsigned long *)rwlock;

	*lock = 0;
	return 0;
}

int pthread_rwlock_destroy(pthread_rwlock_t *rwlock)
{
	unsigned long *lock = (unsigned long *)rwlock;

	*lock = 0;
	return 0;
}

int pthread_rwlock_rdlock(pthread_rwlock_t *rwlock)
{
	pl_lorw_rdlock((unsigned long *)rwlock);
	return 0;
}

int pthread_rwlock_tryrdlock(pthread_rwlock_t *rwlock)
{
	return !!pl_cmpxchg((unsigned long *)rwlock, 0, PLOCK_LORW_SHR_BASE);
}

int pthread_rwlock_timedrdlock(pthread_rwlock_t *restrict rwlock, const struct timespec *restrict abstime)
{
	return pthread_rwlock_tryrdlock(rwlock);
}

int pthread_rwlock_wrlock(pthread_rwlock_t *rwlock)
{
	pl_lorw_wrlock((unsigned long *)rwlock);
	return 0;
}

int pthread_rwlock_trywrlock(pthread_rwlock_t *rwlock)
{
	return !!pl_cmpxchg((unsigned long *)rwlock, 0, PLOCK_LORW_EXC_BASE);
}

int pthread_rwlock_timedwrlock(pthread_rwlock_t *restrict rwlock, const struct timespec *restrict abstime)
{
	return pthread_rwlock_trywrlock(rwlock);
}

int pthread_rwlock_unlock(pthread_rwlock_t *rwlock)
{
	pl_lorw_unlock((unsigned long *)rwlock);
	return 0;
}
