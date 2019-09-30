// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright(c) 2019 Intel Corporation. All rights reserved.
//
// Author: Artur Kloniecki <arturx.kloniecki@linux.intel.com>

#include <config.h>

#if CONFIG_PROBE

#include <sof/probe/probe.h>
#include <sof/trace/trace.h>
#include <user/trace.h>
#include <sof/lib/alloc.h>
#include <ipc/topology.h>

#define trace_probe(__e, ...) \
	trace_event(TRACE_CLASS_PROBE, __e, ##__VA_ARGS__)
#define tracev_probe(__e, ...) \
	tracev_event(TRACE_CLASS_PROBE, __e, ##__VA_ARGS__)
#define trace_probe_error(__e, ...) \
	trace_error(TRACE_CLASS_PROBE, __e, ##__VA_ARGS__)

#define PROBE_DMA_INVALID	0xFFFFFFFF
#define PROBE_POINT_INVALID	0xFFFFFFFF

struct probe_pdata {
	struct probe_dma ext_dma;
	struct probe_dma inject_dma[CONFIG_PROBE_DMA_MAX];
	struct probe_point probe_points[CONFIG_PROBE_POINTS_MAX];
};

static struct probe_pdata *_probe;

int probe_init(struct probe_dma *probe_dma)
{
	uint32_t i;

	trace_probe("probe_init()");

	if (_probe) {
		trace_probe_error("probe_init() error: Probes already "
				  "initialized.");
		return -EINVAL;
	}

	_probe = rzalloc(RZONE_SYS_RUNTIME, SOF_MEM_CAPS_RAM, sizeof(*_probe));

	if (!_probe) {
		trace_probe_error("probe_init() error: Alloc failed.");
		return -ENOMEM;
	}

	if (probe_dma) {
		trace_probe("\tstream_tag = %u, dma_buffer_size = %u",
			    probe_dma->stream_tag, probe_dma->dma_buffer_size);

		_probe->ext_dma.stream_tag = probe_dma->stream_tag;
		_probe->ext_dma.dma_buffer_size = probe_dma->dma_buffer_size;
	} else {
		trace_probe("\tno extraction DMA setup");

		_probe->ext_dma.stream_tag = PROBE_DMA_INVALID;
	}

	/* TODO: Take ownership of Host DMA specified by ext_dma.stream_tag */

	/* initialize injection DMAs as invalid */
	for (i = 0; i < CONFIG_PROBE_DMA_MAX; i++)
		_probe->inject_dma[i].stream_tag = PROBE_DMA_INVALID;

	/* initialize probe points as invalid */
	for (i = 0; i < CONFIG_PROBE_POINTS_MAX; i++)
		_probe->probe_points[i].stream_tag = PROBE_POINT_INVALID;

	return 0;
}

int probe_deinit(void)
{
	uint32_t i;

	trace_probe("probe_deinit()");

	if (!_probe) {
		trace_probe_error("probe_deinit() error: Not initialized.");

		return -EINVAL;
	}

	/* check for attached injection probe DMAs */
	for (i = 0; i < CONFIG_PROBE_DMA_MAX; i++) {
		if (_probe->inject_dma[i].stream_tag != PROBE_DMA_INVALID) {
			trace_probe_error("probe_deinit() error: Cannot "
					  "deinitialize with injection DMAs "
					  "attached.");
			return -EINVAL;
		}
	}

	/* check for connected probe points */
	for (i = 0; i < CONFIG_PROBE_POINTS_MAX; i++) {
		if (_probe->probe_points[i].stream_tag != PROBE_POINT_INVALID) {
			trace_probe_error("probe_deinit() error: Cannot "
					  "deinitialize with probe points "
					  "connected.");
			return -EINVAL;
		}
	}

	if (_probe->ext_dma.stream_tag != PROBE_DMA_INVALID) {
		/* TODO: Release extraction DMA */

		trace_probe("probe_deinit() Freeing extraction DMA.");
	}

	rfree(_probe);
	_probe = NULL;

	return 0;
}

int probe_dma_set(uint32_t count, struct probe_dma *probe_dma)
{
	uint32_t i;
	uint32_t j;
	uint32_t stream_tag;
	uint32_t first_free;

	trace_probe("probe_dma_set() count = %u", count);

	if (!_probe) {
		trace_probe_error("probe_dma_set() error: Not initialized.");

		return -EINVAL;
	}

	for (i = 0; i < count; i++) {
		trace_probe("\tprobe_dma[%u] stream_tag = %u, dma_buffer_size "
			    "= %u", i, probe_dma[i].stream_tag,
			    probe_dma[i].dma_buffer_size);

		first_free = CONFIG_PROBE_DMA_MAX;

		for (j = 0; j < CONFIG_PROBE_DMA_MAX; j++) {
			stream_tag = _probe->inject_dma[j].stream_tag;
			if (stream_tag == probe_dma[i].stream_tag) {
				trace_probe_error("probe_dma_set() error: Probe"
						  " DMA %u already attached.",
						  stream_tag);
				return -EINVAL;
			}

			if (first_free == CONFIG_PROBE_DMA_MAX &&
			    stream_tag == PROBE_DMA_INVALID) {
				first_free = j;
			}
		}

		if (first_free == CONFIG_PROBE_DMA_MAX) {
			trace_probe_error("probe_dma_set() error: Exceeded "
					  "maximum number of DMAs attached = "
					  META_QUOTE(CONFIG_PROBE_DMA_MAX));
			return -EINVAL;
		}

		_probe->inject_dma[first_free].stream_tag =
			probe_dma[i].stream_tag;
		_probe->inject_dma[first_free].dma_buffer_size =
			probe_dma[i].dma_buffer_size;

		/* TODO: Take ownership of the DMA */
	}

	return 0;
}

int probe_dma_get(struct sof_ipc_probe_get_params *data, uint32_t max_size)
{
	uint32_t i = 0;
	uint32_t j = 0;
	uint32_t *size = &data->rhdr.hdr.size;

	trace_probe("probe_dma_get()");

	if (!_probe) {
		trace_probe_error("probe_dma_get() error: Not initialized.");

		return -EINVAL;
	}

	*size = sizeof(*data);

	while (*size + sizeof(struct probe_dma) < max_size &&
	       i < CONFIG_PROBE_DMA_MAX) {
		if (_probe->inject_dma[i].stream_tag != PROBE_DMA_INVALID) {
			data->probe_dma[j].stream_tag =
				_probe->inject_dma[i].stream_tag;
			data->probe_dma[j].dma_buffer_size =
				_probe->inject_dma[i].dma_buffer_size;
			j++;
			*size += sizeof(struct probe_dma);
		}

		i++;
	}

	return 1;
}

int probe_dma_detach(uint32_t count, uint32_t *stream_tag)
{
	uint32_t i;
	uint32_t j;

	trace_probe("probe_dma_detach() count = %u", count);

	if (!_probe) {
		trace_probe_error("probe_dma_detach() error: Not initialized.");

		return -EINVAL;
	}

	for (i = 0; i < count; i++) {
		trace_probe("\tstream_tag[%u] = %u", i, stream_tag[i]);

		for (j = 0; j < CONFIG_PROBE_DMA_MAX; j++) {
			if (_probe->inject_dma[j].stream_tag == stream_tag[i]) {
				/* TODO: Check for probes attached to this
				 * stream tag and return error if the are any
				 */

				/* TODO: Release DMA */

				_probe->inject_dma[j].stream_tag =
					PROBE_DMA_INVALID;
			}
		}
	}

	return 0;
}

int probe_point_set(uint32_t count, struct probe_point *probe)
{
	uint32_t i;
	uint32_t j;
	uint32_t buffer_id;
	uint32_t first_free;
	uint32_t dma_found;

	trace_probe("probe_point_set() count = %u", count);

	if (!_probe) {
		trace_probe_error("probe_point_set() error: Not initialized.");

		return -EINVAL;
	}

	for (i = 0; i < count; i++) {
		trace_probe("\tprobe[%u] buffer_id = %u, purpose = %u, "
			    "stream_tag = %u", i, probe[i].buffer_id,
			    probe[i].purpose, probe[i].stream_tag);

		first_free = CONFIG_PROBE_POINTS_MAX;

		for (j = 0; j < CONFIG_PROBE_POINTS_MAX; j++) {
			if (_probe->probe_points[j].stream_tag ==
			    PROBE_POINT_INVALID) {
				if (first_free == CONFIG_PROBE_POINTS_MAX)
					first_free = j;

				continue;
			}

			buffer_id = _probe->probe_points[j].buffer_id;
			if (buffer_id == probe[i].buffer_id) {
				if (_probe->probe_points[j].purpose ==
				    probe[i].purpose) {
					trace_probe_error("probe_point_set() "
							  "error: Probe already"
							  " attached to buffer "
							  "%u with purpose %u",
							  buffer_id,
							  probe[i].purpose);

					return -EINVAL;
				}
			}
		}

		if (first_free == CONFIG_PROBE_POINTS_MAX) {
			trace_probe_error("probe_point_set() error: Maximum "
					  "number of probe points connected "
					  "aleady "
					  META_QUOTE(CONFIG_PROBE_POINTS_MAX));

			return -EINVAL;
		}

		/* if connecting injection probe, check for associated DMA */
		if (probe[i].purpose == PROBE_PURPOSE_INJECTION) {
			dma_found = 0;

			for (j = 0; j < CONFIG_PROBE_DMA_MAX; j++) {
				if (_probe->inject_dma[j].stream_tag !=
				    PROBE_DMA_INVALID &&
				    _probe->inject_dma[j].stream_tag ==
				    probe[i].stream_tag) {
					dma_found = 1;
					break;
				}
			}

			if (!dma_found) {
				trace_probe_error("probe_point_set() error: No "
						  "DMA with stream tag %u found"
						  " for injection.",
						  probe[i].stream_tag);

				return -EINVAL;
			}
		}

		_probe->probe_points[first_free].buffer_id = probe[i].buffer_id;
		_probe->probe_points[first_free].purpose = probe[i].purpose;
		_probe->probe_points[first_free].stream_tag =
			probe[i].stream_tag;

		/* TODO: Hook up callbacks to buffer and DMA */
	}

	return 0;
}

int probe_point_get(struct sof_ipc_probe_get_params *data, uint32_t max_size)
{
	uint32_t i = 0;
	uint32_t j = 0;
	uint32_t *size = &data->rhdr.hdr.size;

	trace_probe("probe_point_get()");

	if (!_probe) {
		trace_probe_error("probe_point_get() error: Not initialized.");

		return -EINVAL;
	}

	*size = sizeof(*data);

	while (*size + sizeof(struct probe_point) < max_size &&
	       i < CONFIG_PROBE_POINTS_MAX) {
		if (_probe->probe_points[i].stream_tag != PROBE_POINT_INVALID) {
			data->probe_point[j].buffer_id =
				_probe->probe_points[i].buffer_id;
			data->probe_point[j].purpose =
				_probe->probe_points[i].purpose;
			data->probe_point[j].stream_tag =
				_probe->probe_points[i].stream_tag;
			j++;
			*size += sizeof(struct probe_point);
		}

		i++;
	}

	return 1;
}

int probe_point_remove(uint32_t count, uint32_t *buffer_id)
{
	uint32_t i;
	uint32_t j;

	trace_probe("probe_point_remove() count = %u", count);

	if (!_probe) {
		trace_probe_error("probe_point_remove() error: Not "
				  "initialized.");

		return -EINVAL;
	}

	for (i = 0; i < count; i++) {
		trace_probe("\tbuffer_id[%u] = %u", i, buffer_id[i]);

		for (j = 0; j < CONFIG_PROBE_POINTS_MAX; j++) {
			if (_probe->probe_points[j].buffer_id == buffer_id[i]) {
				/* TODO: Remove callbacks from buffer and DMA */

				_probe->probe_points[j].stream_tag =
					PROBE_POINT_INVALID;
			}
		}
	}

	return 0;
}
#endif /* CONFIG_PROBE */
