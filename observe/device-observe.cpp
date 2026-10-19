// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

/**
 * device-observe - Monitor camera and microphone device access
 *
 * Tracks which processes open/use camera (V4L2) and microphone (ALSA capture)
 * devices, recording PID, timestamp, and operation type.
 */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <linux/types.h>
#include "device-observe.skel.h"
#include "device-observe.h"
#include "com.h"

static struct ring_buffer *rb = NULL;
static struct device_observe_bpf *obj = NULL;
static volatile bool exiting = false;

struct env
{
	__u32 pid;
	bool camera;
	bool microphone;
	bool timestamp;
	bool verbose;
} env = {
	.pid = 0,
	.camera = true,
	.microphone = true,
	.timestamp = false,
	.verbose = false,
};

static const struct argp_option opts[] = {
	{"pid",       'p', "PID",  0, "Trace process with this PID only"},
	{"camera",    'c', NULL,   0, "Monitor camera devices (default: on)"},
	{"no-camera", 'C', NULL,   0, "Disable camera monitoring"},
	{"microphone",'m', NULL,   0, "Monitor microphone devices (default: on)"},
	{"no-microphone", 'M', NULL, 0, "Disable microphone monitoring"},
	{"timestamp", 't', NULL,   0, "Include timestamp in output"},
	{"verbose",   'v', NULL,   0, "Verbose output (show all ioctl events)"},
	{NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
	{},
};

static const char program_doc[] =
	"device-observe - Monitor camera and microphone device access\n"
	"\n"
	"USAGE: device-observe [OPTIONS]\n"
	"\n"
	"EXAMPLES:\n"
	"    device-observe                    # Monitor all camera and mic events\n"
	"    device-observe -c                 # Monitor camera only\n"
	"    device-observe -m                 # Monitor microphone only\n"
	"    device-observe -p 1234            # Monitor process 1234 only\n"
	"    device-observe -t -v              # Timestamp + verbose output\n";

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key)
	{
	case 'p':
		errno = 0;
		env.pid = strtoul(arg, NULL, 10);
		if (errno)
		{
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'c':
		env.camera = true;
		break;
	case 'C':
		env.camera = false;
		break;
	case 'm':
		env.microphone = true;
		break;
	case 'M':
		env.microphone = false;
		break;
	case 't':
		env.timestamp = true;
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const char *device_type_str(__u32 type)
{
	switch (type)
	{
	case DEV_TYPE_CAMERA:
		return "CAMERA";
	case DEV_TYPE_MICROPHONE:
		return "MIC";
	default:
		return "UNKNOWN";
	}
}

static const char *event_type_str(__u32 type)
{
	switch (type)
	{
	case DEV_EVT_OPEN:
		return "OPEN";
	case DEV_EVT_CLOSE:
		return "CLOSE";
	case DEV_EVT_STREAM_ON:
		return "STREAM_ON";
	case DEV_EVT_STREAM_OFF:
		return "STREAM_OFF";
	case DEV_EVT_IOCTL:
		return "IOCTL";
	default:
		return "UNKNOWN";
	}
}

static const char *ioctl_cmd_name(__u32 device_type, __u32 cmd)
{
	if (device_type == DEV_TYPE_CAMERA)
	{
		if (cmd == V4L2_STREAM_ON)
			return "VIDIOC_STREAMON";
		if (cmd == V4L2_STREAM_OFF)
			return "VIDIOC_STREAMOFF";
		return NULL;
	}
	if (device_type == DEV_TYPE_MICROPHONE)
	{
		if (cmd == ALSA_PCM_START)
			return "SNDRV_PCM_IOCTL_START";
		if (cmd == ALSA_PCM_DROP)
			return "SNDRV_PCM_IOCTL_DROP";
		return NULL;
	}
	return NULL;
}

static void print_event(const struct devobs_event *e)
{
	char ts[32] = "";
	if (env.timestamp)
	{
		time_t t = e->timestamp_ns / 1000000000ULL;
		struct tm *tm_info = localtime(&t);
		if (tm_info)
			strftime(ts, sizeof(ts), "%H:%M:%S", tm_info);
	}

	const char *iname = ioctl_cmd_name(e->device_type, e->ioctl_cmd);

	if (env.timestamp)
		printf("%-8s ", ts);

	printf("%-12s %-10s %-24s %-6u %-16s %-6u ",
		   device_type_str(e->device_type),
		   event_type_str(e->event_type),
		   iname ? iname : "",
		   e->pid,
		   e->comm,
		   e->uid);

	/* non-verbose mode: skip generic ioctl (only show STREAM_ON/OFF) */
	if (e->event_type == DEV_EVT_IOCTL && !env.verbose)
	{
		printf("%s fd=%d\n", e->device_path, e->fd);
		return;
	}

	printf("%s fd=%d", e->device_path, e->fd);

	if (e->event_type == DEV_EVT_IOCTL && iname)
		printf(" cmd=0x%x", e->ioctl_cmd);

	printf("\n");
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct devobs_event *e = (const struct devobs_event *)data;
	print_event(e);
	return 0;
}

static void sig_handler(int sig)
{
	exiting = true;
}

int main(int argc, char **argv)
{
	int err;
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = program_doc,
	};

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!env.camera && !env.microphone)
	{
		fprintf(stderr, "error: at least one of --camera or --microphone must be enabled\n");
		return 1;
	}

	/* print column headers */
	if (env.timestamp)
		printf("%-8s ", "TIME");
	printf("%-12s %-10s %-24s %-6s %-16s %-6s %s\n",
		   "DEVICE", "EVENT", "IOCTL", "PID", "COMM", "UID", "PATH");

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	obj = device_observe_bpf__open();
	if (!obj)
	{
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	/* set filter via rodata */
	obj->rodata->filter_camera = env.camera;
	obj->rodata->filter_microphone = env.microphone;
	obj->rodata->target_pid = env.pid;

	err = device_observe_bpf__load(obj);
	if (err)
	{
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = device_observe_bpf__attach(obj);
	if (err)
	{
		fprintf(stderr, "failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	rb = ring_buffer__new(
		bpf_map__fd(obj->maps.events),
		handle_event,
		NULL,
		NULL);
	if (!rb)
	{
		fprintf(stderr, "failed to create ring buffer\n");
		err = -1;
		goto cleanup;
	}

	printf("Tracing device access... Hit Ctrl-C to end.\n");

	while (!exiting)
	{
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR)
		{
			err = 0;
			break;
		}
		if (err < 0)
		{
			printf("Error polling ring buffer: %d\n", err);
			break;
		}
	}

cleanup:
	if (rb)
		ring_buffer__free(rb);
	device_observe_bpf__destroy(obj);
	return err != 0;
}
