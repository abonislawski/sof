// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright(c) 2019 Intel Corporation. All rights reserved.
//
// Author: Artur Kloniecki <arturx.kloniecki@linux.intel.com>

#include <sof/probe/probe.h>
#include <sof/trace/trace.h>
#include <user/trace.h>

#define trace_probe(__e, ...) \
	trace_event(TRACE_CLASS_PROBE, __e, ##__VA_ARGS__)
#define tracev_probe(__e, ...) \
	tracev_event(TRACE_CLASS_PROBE, __e, ##__VA_ARGS__)
#define trace_probe_error(__e, ...) \
	trace_error(TRACE_CLASS_PROBE, __e, ##__VA_ARGS__)

int probe_init(struct probe_dma *probe_dma)
{
	trace_probe("probe_init()");

	if (probe_dma)
		trace_probe("\tstream_tag = %u, dma_buffer_size = %u",
			    probe_dma->stream_tag, probe_dma->dma_buffer_size);
	else
		trace_probe("\tno extraction DMA setup");

	return 0;
}

int probe_deinit(void)
{
	trace_probe("probe_deinit()");

	return 0;
}

int probe_dma_set(uint32_t count, struct probe_dma *probe_dma)
{
	uint32_t i;

	trace_probe("probe_dma_set() count = %u", count);

	for (i = 0; i < count; i++)
		trace_probe("\tprobe_dma[%u] stream_tag = %u, dma_buffer_size "
			    "= %u", i, probe_dma[i].stream_tag,
			    probe_dma[i].dma_buffer_size);

	return 0;
}

int probe_dma_get(struct sof_ipc_probe_get_params *data, uint32_t max_size)
{
	trace_probe("probe_dma_get()");

	return 0;
}

int probe_dma_detach(uint32_t count, uint32_t *stream_tag)
{
	uint32_t i;

	trace_probe("probe_dma_detach() count = %u", count);

	for (i = 0; i < count; i++)
		trace_probe("\tstream_tag[%u] = %u", i, stream_tag[i]);

	return 0;
}

int probe_point_set(uint32_t count, struct probe_point *probe)
{
	uint32_t i;

	trace_probe("probe_point_set() count = %u", count);

	for (i = 0; i < count; i++)
		trace_probe("\tprobe[%u] buffer_id = %u, purpose = %u, "
			    "stream_tag = %u", i, probe[i].buffer_id,
			    probe[i].purpose, probe[i].stream_tag);

	return 0;
}

int probe_point_get(struct sof_ipc_probe_get_params *data, uint32_t max_size)
{
	trace_probe("probe_point_get()");

	return 0;
}

int probe_point_remove(uint32_t count, uint32_t *buffer_id)
{
	uint32_t i;

	trace_probe("probe_point_remove() count = %u", count);

	for (i = 0; i < count; i++)
		trace_probe("\tbuffer_id[%u] = %u", i, buffer_id[i]);

	return 0;
}
