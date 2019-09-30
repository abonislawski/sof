/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2019 Intel Corporation. All rights reserved.
 *
 * Author: Adrian Bonislawski <adrian.bonislawski@linux.intel.com>
 *         Artur Kloniecki <arturx.kloniecki@linux.intel.com>
 */

/**
 * \file include/ipc/probe.h
 * \brief Probe IPC definitions
 * \author Adrian Bonislawski <adrian.bonislawski@linux.intel.com>
 * \author Artur Kloniecki <arturx.kloniecki@linux.intel.com>
 */

#ifndef __IPC_PROBE_H__
#define __IPC_PROBE_H__

#include <ipc/header.h>
#include <stdint.h>

#define PROBE_PURPOSE_EXTRACTION	0x1
#define PROBE_PURPOSE_INJECTION		0x2

/* Header for data packets sent via compressed PCM from extraction probes */
struct probe_data_packet {
	uint32_t sync_word;
	uint32_t buffer_id;
	uint32_t format;
	uint32_t timestamp_low;
	uint32_t timestamp_high;
	uint64_t checksum;
	uint32_t data_size_bytes;
	uint32_t data[];
} __attribute__((packed));

struct probe_dma {
	uint32_t stream_tag;
	uint32_t dma_buffer_size;
} __attribute__((packed));

struct probe_point {
	uint32_t buffer_id;
	uint32_t purpose;
	uint32_t stream_tag;
} __attribute__((packed));

/* DMA SET for probes - SOF_IPC_PROBE_INIT, SOF_IPC_PROBE_DMA_SET */
struct sof_ipc_probe_dma_set_params {
	struct sof_ipc_cmd_hdr hdr;
	struct probe_dma probe_dma[];
} __attribute__((packed));

/* Reply to GET functions - SOF_IPC_PROBE_DMA_GET, SOF_IPC_PROBE_POINT_GET */
struct sof_ipc_probe_get_params {
	struct sof_ipc_reply rhdr;
	union {
		struct probe_dma probe_dma[0];
		struct probe_point probe_point[0];
	};
} __attribute__((packed));

/* DMA detach - SOF_IPC_PROBE_DMA_DETACH */
struct sof_ipc_probe_dma_detach_params {
	struct sof_ipc_cmd_hdr hdr;
	uint32_t stream_tag[];
} __attribute__((packed));

/* Connect probe points - SOF_IPC_PROBE_POINT_SET */
struct sof_ipc_probe_point_set_params {
	struct sof_ipc_cmd_hdr hdr;
	struct probe_point probe_point[];
} __attribute__((packed));

/* Disconnect probe - SOF_IPC_PROBE_POINT_REMOVE */
struct sof_ipc_probe_point_remove_params {
	struct sof_ipc_cmd_hdr hdr;
	uint32_t buffer_id[];
} __attribute__((packed));

#endif /* __IPC_PROBE_H__ */
