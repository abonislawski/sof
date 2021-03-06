/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2018 Intel Corporation. All rights reserved.
 *
 * Author: Liam Girdwood <liam.r.girdwood@linux.intel.com>
 *         Ranjani Sridharan <ranjani.sridharan@linux.intel.com>
 */

#ifndef __ARCH_ATOMIC_H_
#define __ARCH_ATOMIC_H_

#include <stdint.h>
#include <errno.h>

typedef struct {
	volatile int32_t value;
} atomic_t;

static inline int32_t arch_atomic_read(const atomic_t *a)
{
	return (*(volatile int32_t *)&a->value);
}

static inline void arch_atomic_set(atomic_t *a, int32_t value)
{
	a->value = value;
}

static inline void arch_atomic_init(atomic_t *a, int32_t value)
{
	arch_atomic_set(a, value);
}

/* use gcc atomic built-ins for host library */
static inline int32_t arch_atomic_add(atomic_t *a, int32_t value)
{
	return __sync_fetch_and_add(&a->value, value);
}

static inline int32_t arch_atomic_sub(atomic_t *a, int32_t value)
{
	return __sync_fetch_and_sub(&a->value, value);
}

#endif
