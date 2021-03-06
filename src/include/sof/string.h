/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2018 Intel Corporation. All rights reserved.
 *
 * Author: Liam Girdwood <liam.r.girdwood@linux.intel.com>
 */

#ifndef __INCLUDE_STRING_SOF__
#define __INCLUDE_STRING_SOF__

#include <arch/string.h>

/* C memcpy for arch that don't have arch_memcpy() */
void cmemcpy(void *dest, void *src, size_t size);
int rstrlen(const char *s);
int rstrcmp(const char *s1, const char *s2);

#if defined(arch_memcpy)
#define rmemcpy(dest, src, size) \
	arch_memcpy(dest, src, size)
#else
#define rmemcpy(dest, src, size) \
	cmemcpy(dest, src, size)
#endif

#endif
