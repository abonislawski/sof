/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2019 Intel Corporation. All rights reserved.
 *
 * Author: Lech Betlej <lech.betlej@linux.intel.com>
 */

/**
 * \file audio/selector.h
 * \brief Channel selector component header file
 * \authors Lech Betlej <lech.betlej@linux.intel.com>
 */

#ifndef SELECTOR_H
#define SELECTOR_H

#include <stdint.h>
#include <sof/audio/component.h>
#include <sof/audio/pipeline.h>
#include <sof/audio/format.h>

/** \brief Selector trace function. */
#define trace_selector(__e, ...) \
	trace_event(TRACE_CLASS_SELECTOR, __e, ##__VA_ARGS__)

/** \brief Selector trace verbose function. */
#define tracev_selector(__e, ...) \
	tracev_event(TRACE_CLASS_SELECTOR, __e, ##__VA_ARGS__)

/** \brief Selector trace error function. */
#define trace_selector_error(__e, ...) \
	trace_error(TRACE_CLASS_SELECTOR, __e, ##__VA_ARGS__)

/** \brief Supported channel count on input. */
#define SEL_SOURCE_2CH 2
#define SEL_SOURCE_4CH 4

/** \brief Supported channel count on output. */
#define SEL_SINK_1CH 1
#define SEL_SINK_2CH 2
#define SEL_SINK_4CH 4

/** \brief Selector component configuration data. */
struct sof_sel_config {
	/* selector supports 1 input and 1 output */
	uint32_t in_channels_count;	/**< accepted values 2 or 4 */
	uint32_t out_channels_count;	/**< accepted values 1 or 2 or 4 */
	/* note: if 2 or 4 output channels selected the component works in
	 * a passthrough mode
	 */
	uint32_t sel_channel;	/**< 0..3 */
};

/** \brief Selector component private data. */
struct comp_data {
	uint32_t source_period_bytes;	/**< source number of period bytes */
	uint32_t sink_period_bytes;	/**< sink number of period bytes */
	enum sof_ipc_frame source_format;	/**< source frame format */
	enum sof_ipc_frame sink_format;		/**< sink frame format */
	struct sof_sel_config config;	/**< component configuration data */
	/**< channel selector processing function */
	void (*sel_func)(struct comp_dev *dev, struct comp_buffer *sink,
			 struct comp_buffer *source, uint32_t frames);
};

/** \brief Selector processing functions map. */
struct comp_func_map {
	uint16_t source;	/**< source frame format */
	uint32_t out_channels;	/**< number of output stream channels */
	/**< selector processing function */
	void (*sel_func)(struct comp_dev *dev, struct comp_buffer *sink,
			 struct comp_buffer *source, uint32_t frames);
};

/** \brief Map of formats with dedicated processing functions. */
extern const struct comp_func_map func_map[];

typedef void (*sel_func)(struct comp_dev *, struct comp_buffer *,
			 struct comp_buffer *, uint32_t);

/**
 * \brief Retrieves selector processing function.
 * \param[in,out] dev Selector base component device.
 */
sel_func sel_get_processing_function(struct comp_dev *dev);

#endif /* SELECTOR_H */
