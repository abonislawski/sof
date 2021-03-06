/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2018 Intel Corporation. All rights reserved.
 *
 * Author: Marcin Maka <marcin.maka@linux.intel.com>
 */

/**
  * \file include/sof/platform.h
  * \brief Platform API definition
  * \author Marcin Maka <marcin.maka@linux.intel.com>
  */

#ifndef __INCLUDE_SOF_PLATFORM_H__
#define __INCLUDE_SOF_PLATFORM_H__

#include <sof/sof.h>

/** \addtogroup platform_api Platform API
 *  Platform API specification.
 *  @{
 */

/* data cache line alignment */
#if DCACHE_LINE_SIZE > 0
#define PLATFORM_DCACHE_ALIGN	DCACHE_LINE_SIZE
#else
#define PLATFORM_DCACHE_ALIGN	sizeof(uint32_t)
#endif

/*
 * APIs declared here are defined for every platform.
 */

/**
 * \brief Platform specific implementation of the On Boot Complete handler.
 * \param[in] boot_message Boot status code.
 * \return 0 if successful, error code otherwise.
 */
int platform_boot_complete(uint32_t boot_message);

/**
 * \brief Platform initialization entry, called during FW initialization.
 * \param[in] sof Context.
 * \return 0 if successful, error code otherwise.
 */
int platform_init(struct sof *sof);

/** @}*/

#endif
