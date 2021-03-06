/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2016 Intel Corporation. All rights reserved.
 *
 * Author: Liam Girdwood <liam.r.girdwood@linux.intel.com>
 *         Keyon Jie <yang.jie@linux.intel.com>
 */

#ifndef __INCLUDE_SOF_STREAM__
#define __INCLUDE_SOF_STREAM__

#include <stdint.h>
#include <platform/platform.h>
#include <ipc/stream.h>

enum stream_type {
	STREAM_TYPE_PCM		= 0,
	STREAM_TYPE_VORBIS	= 1,
};

struct stream_params {
	enum stream_type type;
	union {
		struct sof_ipc_pcm_params *pcm;
		struct sof_ipc_vorbis_params *vorbis;
	};
};

#endif
