/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This is mainly copied from tools/perf/arch/arm64/util/arm-spe.c
 * so any updates to that file should be merged here.
 *
 * Snapshot support copied from tools/perf/arch/arm/util/cs-etm.c
 */

#include <linux/log2.h>
#include <linux/zalloc.h>
#include <stdbool.h>
#include <internal/lib.h> /* page_size */

#include "../../util/auxtrace.h"
#include "../../util/debug.h"
#include "../../util/color.h"
#include "../../util/evlist.h"
#include "../../util/pmu.h"
#include "../../util/record.h"
#include "../../util/session.h"
#include "../../util/e2k-dimtp.h"

#define E2K_DIMTP_ALIGN 32

#define KiB(x) ((x) * 1024)
#define MiB(x) ((x) * 1024 * 1024)

struct dimtp_recording {
	struct auxtrace_record	itr;
	struct perf_pmu		*dimtp_pmu;
	struct evlist		*evlist;
	/* Snapshot support */
	int			wrapped_cnt;
	bool			*wrapped;
	bool			snapshot_mode;
	size_t			snapshot_size;
};

#define itr_to_recording(_itr) \
	container_of((_itr), struct dimtp_recording, itr);


static size_t
dimtp_info_priv_size(struct auxtrace_record *itr __maybe_unused,
		     struct evlist *evlist __maybe_unused)
{
	return E2K_DIMTP_AUXTRACE_PRIV_SIZE;
}

static int dimtp_info_fill(struct auxtrace_record *itr,
			     struct perf_session *session,
			     struct perf_record_auxtrace_info *auxtrace_info,
			     size_t priv_size)
{
	struct dimtp_recording *dimtp_rec = itr_to_recording(itr);
	struct perf_pmu *dimtp_pmu = dimtp_rec->dimtp_pmu;

	if (priv_size != E2K_DIMTP_AUXTRACE_PRIV_SIZE)
		return -EINVAL;

	if (!session->evlist->core.nr_mmaps)
		return -EINVAL;

	auxtrace_info->type = PERF_AUXTRACE_E2K_DIMTP;
	auxtrace_info->priv[E2K_DIMTP_PMU_TYPE] = dimtp_pmu->type;

	return 0;
}

static int dimtp_recording_options(struct auxtrace_record *itr,
				   struct evlist *evlist,
				   struct record_opts *opts)
{
	struct dimtp_recording *dimtp_rec = itr_to_recording(itr);
	struct perf_pmu *dimtp_pmu = dimtp_rec->dimtp_pmu;
	struct evsel *evsel, *dimtp_evsel = NULL;
	bool privileged = perf_event_paranoid_check(-1);

	dimtp_rec->evlist = evlist;

	/* Set 'full_auxtrace'
	 * (don't know what it does, documentation is missing).
	 *
	 * Also set default values: -c2 */
	evlist__for_each_entry(evlist, evsel) {
		if (evsel->core.attr.type == dimtp_pmu->type) {
			if (dimtp_evsel) {
				pr_err("There may be only one " E2K_DIMTP_PMU_NAME " event\n");
				return -EINVAL;
			}
			evsel->core.attr.freq = 0;
			evsel->core.attr.sample_period = 2;
			dimtp_evsel = evsel;
			opts->full_auxtrace = true;
		}
	}

	if (!opts->full_auxtrace)
		return 0;

	if (opts->auxtrace_snapshot_mode) {
		/*
		 * If no size were given to '-S' or '-m,' we go with the default
		 */
		if (!opts->auxtrace_snapshot_size &&
		    !opts->auxtrace_mmap_pages) {
			if (privileged) {
				opts->auxtrace_mmap_pages = MiB(4) / page_size;
			} else {
				opts->auxtrace_mmap_pages =
							KiB(128) / page_size;
				if (opts->mmap_pages == UINT_MAX)
					opts->mmap_pages = KiB(256) / page_size;
			}
		} else if (!opts->auxtrace_mmap_pages && !privileged &&
						opts->mmap_pages == UINT_MAX) {
			opts->mmap_pages = KiB(256) / page_size;
		}

		/*
		 * '-m,xyz' was specified but no snapshot size, so make the
		 * snapshot size as big as the auxtrace mmap area.
		 */
		if (!opts->auxtrace_snapshot_size) {
			opts->auxtrace_snapshot_size =
				opts->auxtrace_mmap_pages * (size_t) page_size;
		}

		/*
		 * -Sxyz was specified but no auxtrace mmap area, so make the
		 * auxtrace mmap area big enough to fit the requested snapshot
		 * size.
		 */
		if (!opts->auxtrace_mmap_pages) {
			size_t sz = opts->auxtrace_snapshot_size;

			sz = round_up(sz, page_size) / page_size;
			opts->auxtrace_mmap_pages = sz;
		}

		/* Snapshot size can't be bigger than the auxtrace area */
		if (opts->auxtrace_snapshot_size >
				opts->auxtrace_mmap_pages * (size_t) page_size) {
			pr_err("Snapshot size %zu must not be greater than AUX area tracing mmap size %zu\n",
			       opts->auxtrace_snapshot_size,
			       opts->auxtrace_mmap_pages * (size_t) page_size);
			return -EINVAL;
		}

		/* Something went wrong somewhere - this shouldn't happen */
		if (!opts->auxtrace_snapshot_size ||
		    !opts->auxtrace_mmap_pages) {
			pr_err("Failed to calculate default snapshot size and/or AUX area tracing mmap pages\n");
			return -EINVAL;
		}
	}

	/* We are in full trace mode but '-m,xyz' wasn't specified */
	if (opts->full_auxtrace && !opts->auxtrace_mmap_pages) {
		if (privileged) {
			opts->auxtrace_mmap_pages = MiB(4) / page_size;
		} else {
			opts->auxtrace_mmap_pages = KiB(128) / page_size;
			if (opts->mmap_pages == UINT_MAX)
				opts->mmap_pages = KiB(256) / page_size;
		}
	}

	/* Validate auxtrace_mmap_pages */
	if (opts->auxtrace_mmap_pages) {
		unsigned int max_pages = (KiB(128) / page_size);

		if (!privileged && opts->auxtrace_mmap_pages > max_pages) {
			opts->auxtrace_mmap_pages = max_pages;
			pr_err("auxtrace too big for unprivileged user, truncating to %d\n",
					max_pages);
		}

		size_t sz = opts->auxtrace_mmap_pages * (size_t) page_size;
		if (sz % E2K_DIMTP_ALIGN) {
			pr_err("Invalid mmap size for DIMTP: must be %d bytes aligned\n",
					E2K_DIMTP_ALIGN);
			return -EINVAL;
		}
	}

	if (opts->auxtrace_snapshot_mode)
		pr_debug2(E2K_DIMTP_PMU_NAME " snapshot size: %zu\n",
			  opts->auxtrace_snapshot_size);


	/*
	 * To obtain the auxtrace buffer file descriptor, the auxtrace event
	 * must come first.
	 */
	perf_evlist__to_front(evlist, dimtp_evsel);

	evsel__set_sample_bit(dimtp_evsel, CPU);
	evsel__set_sample_bit(dimtp_evsel, TIME);
	evsel__set_sample_bit(dimtp_evsel, TID);

	return 0;
}

static void dimtp_recording_free(struct auxtrace_record *itr)
{
	struct dimtp_recording *dimtp_rec = itr_to_recording(itr);

	free(dimtp_rec);
}

static u64 dimtp_reference(struct auxtrace_record *itr __maybe_unused)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);

	return ts.tv_sec ^ ts.tv_nsec;
}

static int dimtp_read_finish(struct auxtrace_record *itr, int idx)
{
	struct dimtp_recording *dimtp_rec = itr_to_recording(itr);
	struct evsel *evsel;

	evlist__for_each_entry(dimtp_rec->evlist, evsel) {
		if (evsel->core.attr.type == dimtp_rec->dimtp_pmu->type) {
			if (evsel->disabled)
				return 0;
			return perf_evlist__enable_event_idx(dimtp_rec->evlist,
							     evsel, idx);
		}
	}
	return -EINVAL;
}

static int dimtp_parse_snapshot_options(struct auxtrace_record *itr,
		struct record_opts *opts, const char *str)
{
	struct dimtp_recording *dimtp_rec = itr_to_recording(itr);
	unsigned long long snapshot_size = 0;
	char *endptr;

	if (str) {
		snapshot_size = strtoull(str, &endptr, 0);
		if (*endptr || snapshot_size > SIZE_MAX)
			return -1;
	}

	opts->auxtrace_snapshot_mode = true;
	opts->auxtrace_snapshot_size = snapshot_size;
	dimtp_rec->snapshot_size = snapshot_size;

	return 0;
}

static int dimtp_alloc_wrapped_array(struct dimtp_recording *dimtp_rec, int idx)
{
	bool *wrapped;
	int cnt = dimtp_rec->wrapped_cnt;

	/* Make @ptr->wrapped as big as @idx */
	while (cnt <= idx)
		cnt++;

	/*
	 * Free'ed in cs_etm_recording_free().  Using realloc() to avoid
	 * cross compilation problems where the host's system supports
	 * reallocarray() but not the target.
	 */
	wrapped = realloc(dimtp_rec->wrapped, cnt * sizeof(bool));
	if (!wrapped)
		return -ENOMEM;

	wrapped[cnt - 1] = false;
	dimtp_rec->wrapped_cnt = cnt;
	dimtp_rec->wrapped = wrapped;

	return 0;
}

static bool dimtp_buffer_has_wrapped(unsigned char *buffer,
		size_t buffer_size, u64 head)
{
	u64 i, watermark;
	u64 *buf = (u64 *)buffer;
	size_t buf_size = buffer_size;

	/*
	 * We want to look the very last 512 byte (chosen arbitrarily) in
	 * the ring buffer.
	 */
	watermark = buf_size - 512;

	/*
	 * @head is continuously increasing - if its value is equal or greater
	 * than the size of the ring buffer, it has wrapped around.
	 */
	if (head >= buffer_size)
		return true;

	/*
	 * The value of @head is somewhere within the size of the ring buffer.
	 * This can be that there hasn't been enough data to fill the ring
	 * buffer yet or the trace time was so long that @head has numerically
	 * wrapped around.  To find we need to check if we have data at the very
	 * end of the ring buffer.  We can reliably do this because mmap'ed
	 * pages are zeroed out and there is a fresh mapping with every new
	 * session.
	 */

	/* @head is less than 512 byte from the end of the ring buffer */
	if (head > watermark)
		watermark = head;

	/*
	 * Speed things up by using 64 bit transactions (see "u64 *buf" above)
	 */
	watermark >>= 3;
	buf_size >>= 3;

	/*
	 * If we find trace data at the end of the ring buffer, @head has
	 * been there and has numerically wrapped around at least once.
	 */
	for (i = watermark; i < buf_size; i++)
		if (buf[i])
			return true;

	return false;
}

static int dimtp_find_snapshot(struct auxtrace_record *itr,
		int idx, struct auxtrace_mmap *mm, unsigned char *data,
		u64 *head, u64 *old)
{
	int err;
	bool wrapped;
	struct dimtp_recording *dimtp_rec = itr_to_recording(itr);

	/*
	 * Allocate memory to keep track of wrapping if this is the first
	 * time we deal with this *mm.
	 */
	if (idx >= dimtp_rec->wrapped_cnt) {
		err = dimtp_alloc_wrapped_array(dimtp_rec, idx);
		if (err)
			return err;
	}

	/*
	 * Check to see if *head has wrapped around.  If it hasn't only the
	 * amount of data between *head and *old is snapshot'ed to avoid
	 * bloating the perf.data file with zeros.  But as soon as *head has
	 * wrapped around the entire size of the AUX ring buffer it taken.
	 */
	wrapped = dimtp_rec->wrapped[idx];
	if (!wrapped && dimtp_buffer_has_wrapped(data, mm->len, *head)) {
		wrapped = true;
		dimtp_rec->wrapped[idx] = true;
	}

	pr_debug3("%s: mmap index %d old head %zu new head %zu size %zu\n",
		  __func__, idx, (size_t) *old, (size_t) *head, mm->len);

	/* No wrap has occurred, we can just use *head and *old. */
	if (!wrapped)
		return 0;

	/*
	 * *head has wrapped around - adjust *head and *old to pickup the
	 * entire content of the AUX buffer.
	 */
	if (*head >= mm->len) {
		*old = *head - mm->len;
	} else {
		*head += mm->len;
		*old = *head - mm->len;
	}

	return 0;
}

static int dimtp_snapshot_start(struct auxtrace_record *itr)
{
	struct dimtp_recording *dimtp_rec = itr_to_recording(itr);
	struct evsel *evsel;

	evlist__for_each_entry(dimtp_rec->evlist, evsel) {
		if (evsel->core.attr.type == dimtp_rec->dimtp_pmu->type)
			return evsel__disable(evsel);
	}
	return -EINVAL;
}

static int dimtp_snapshot_finish(struct auxtrace_record *itr)
{
	struct dimtp_recording *dimtp_rec = itr_to_recording(itr);
	struct evsel *evsel;

	evlist__for_each_entry(dimtp_rec->evlist, evsel) {
		if (evsel->core.attr.type == dimtp_rec->dimtp_pmu->type)
			return evsel__enable(evsel);
	}
	return -EINVAL;
}

static struct auxtrace_record *dimtp_recording_init(int *err,
		struct perf_pmu *dimtp_pmu)
{
	struct dimtp_recording *dimtp_rec;

	if (!dimtp_pmu) {
		*err = -ENODEV;
		return NULL;
	}

	dimtp_rec = zalloc(sizeof(*dimtp_rec));
	if (!dimtp_rec) {
		*err = -ENOMEM;
		return NULL;
	}

	dimtp_rec->dimtp_pmu = dimtp_pmu;
	dimtp_rec->itr.recording_options = dimtp_recording_options;
	dimtp_rec->itr.info_priv_size = dimtp_info_priv_size;
	dimtp_rec->itr.info_fill = dimtp_info_fill;
	dimtp_rec->itr.free = dimtp_recording_free;
	dimtp_rec->itr.reference = dimtp_reference;
	dimtp_rec->itr.read_finish = dimtp_read_finish;
	dimtp_rec->itr.alignment = 32;
	dimtp_rec->itr.parse_snapshot_options = dimtp_parse_snapshot_options;
	dimtp_rec->itr.find_snapshot = dimtp_find_snapshot;
	dimtp_rec->itr.snapshot_start = dimtp_snapshot_start;
	dimtp_rec->itr.snapshot_finish = dimtp_snapshot_finish;

	*err = 0;
	return &dimtp_rec->itr;
}

struct auxtrace_record
*auxtrace_record__init(struct evlist *evlist, int *err)
{
	struct perf_pmu	*dimtp_pmu;
	struct evsel *evsel;
	bool found = false;

	if (!evlist)
		return NULL;

	dimtp_pmu = perf_pmu__find(E2K_DIMTP_PMU_NAME);

	evlist__for_each_entry(evlist, evsel) {
		if (dimtp_pmu &&
		    evsel->core.attr.type == dimtp_pmu->type) {
			found = true;
			break;
		}
	}

	if (found)
		return dimtp_recording_init(err, dimtp_pmu);

	/*
	 * Clear 'err' even if we haven't found an event - that way perf
	 * record can still be used even if tracers aren't present.  The NULL
	 * return value will take care of telling the infrastructure HW tracing
	 * isn't available.
	 */
	*err = 0;
	return NULL;
}


struct dimtp {
	struct auxtrace			auxtrace;
	struct auxtrace_queues		queues;
};

#define PACKET_BEGIN(word) ((word) & (1ull << 63))

static void dimtp_dump_event(__u64 *buf, size_t len)
{
	const char *color = PERF_COLOR_BLUE;

	printf(".\n");
	color_fprintf(stdout, color,
		      ". ... DIMTP data: size %zu bytes",
		      len);

	while (len >= 8) {
		if (PACKET_BEGIN(*buf))
			printf("\n.");

		color_fprintf(stdout, color, "  %016llx", *buf);
		++buf;
		len -= sizeof(*buf);
	}
	printf("\n");
}

static int dimtp_process_event(struct perf_session *session __maybe_unused,
			       union perf_event *event __maybe_unused,
			       struct perf_sample *sample __maybe_unused,
			       struct perf_tool *tool __maybe_unused)
{
	return 0;
}

static int dimtp_process_auxtrace_event(struct perf_session *session,
					union perf_event *event,
					struct perf_tool *tool __maybe_unused)
{
	struct dimtp *dimtp = container_of(session->auxtrace, struct dimtp,
					   auxtrace);
	struct auxtrace_buffer *buffer;
	off_t data_offset;
	int fd = perf_data__fd(session->data);
	int err;

	if (perf_data__is_pipe(session->data)) {
		data_offset = 0;
	} else {
		data_offset = lseek(fd, 0, SEEK_CUR);
		if (data_offset == -1)
			return -errno;
	}

	err = auxtrace_queues__add_event(&dimtp->queues, session, event,
					 data_offset, &buffer);
	if (err)
		return err;

	/* Dump here now we have copied a piped trace out of the pipe */
	if (dump_trace) {
		if (auxtrace_buffer__get_data(buffer, fd)) {
			dimtp_dump_event(buffer->data,
					     buffer->size);
			auxtrace_buffer__put_data(buffer);
		}
	}

	return 0;
}

static int dimtp_flush(struct perf_session *session __maybe_unused,
		       struct perf_tool *tool __maybe_unused)
{
	return 0;
}

static void dimtp_free_events(struct perf_session *session)
{
	struct dimtp *dimtp = container_of(session->auxtrace, struct dimtp,
					   auxtrace);
	struct auxtrace_queues *queues = &dimtp->queues;
	unsigned int i;

	for (i = 0; i < queues->nr_queues; i++) {
		if (queues->queue_array[i].priv) {
			free(queues->queue_array[i].priv);
			queues->queue_array[i].priv = NULL;
		}
	}

	auxtrace_queues__free(queues);
}

static void dimtp_free(struct perf_session *session)
{
	struct dimtp *dimtp = container_of(session->auxtrace, struct dimtp,
					   auxtrace);

	dimtp_free_events(session);
	session->auxtrace = NULL;
	free(dimtp);
}

int e2k_dimtp_process_auxtrace_info(union perf_event *event,
				struct perf_session *session)
{
	struct perf_record_auxtrace_info *auxtrace_info = &event->auxtrace_info;
	size_t min_sz = sizeof(u64) * E2K_DIMTP_PMU_TYPE;
	struct dimtp *dimtp;
	int err;

	if (auxtrace_info->header.size <
			sizeof(struct perf_record_auxtrace_info) + min_sz)
		return -EINVAL;

	dimtp = zalloc(sizeof(struct dimtp));
	if (!dimtp)
		return -ENOMEM;

	err = auxtrace_queues__init(&dimtp->queues);
	if (err)
		goto err_free;

	dimtp->auxtrace.process_event = dimtp_process_event;
	dimtp->auxtrace.process_auxtrace_event = dimtp_process_auxtrace_event;
	dimtp->auxtrace.flush_events = dimtp_flush;
	dimtp->auxtrace.free_events = dimtp_free_events;
	dimtp->auxtrace.free = dimtp_free;
	session->auxtrace = &dimtp->auxtrace;

	if (dump_trace)
		fprintf(stdout, "  PMU Type           %llu\n",
				auxtrace_info->priv[E2K_DIMTP_PMU_TYPE]);

	return 0;

err_free:
	free(dimtp);
	return err;
}
