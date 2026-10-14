// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

#ifndef __DEVICE_OBSERVE_H
#define __DEVICE_OBSERVE_H

/* 设备类型 */
enum devobs_type
{
	DEV_TYPE_CAMERA = 1,
	DEV_TYPE_MICROPHONE = 2,
};

/* 事件类型 */
enum devobs_evt
{
	DEV_EVT_OPEN = 1,
	DEV_EVT_CLOSE = 2,
	DEV_EVT_STREAM_ON = 3,
	DEV_EVT_STREAM_OFF = 4,
	DEV_EVT_IOCTL = 5,
};

#define DEV_OBS_PATH_MAX 64

/* 内核/用户空间共享的事件结构体 */
struct devobs_event
{
	__u64 timestamp_ns;
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__u32 device_type;
	__u32 event_type;
	int fd;
	__u32 ioctl_cmd;
	char comm[16];
	char device_path[DEV_OBS_PATH_MAX];
};

/* V4L2 关键 ioctl 命令 */
#define V4L2_STREAM_ON  0x40045612UL  /* VIDIOC_STREAMON */
#define V4L2_STREAM_OFF 0x40045613UL  /* VIDIOC_STREAMOFF */

/* ALSA 关键 ioctl 命令 */
#define ALSA_PCM_START  0x00004142UL  /* SNDRV_PCM_IOCTL_START  _IO(\'A\', 0x42) */
#define ALSA_PCM_DROP   0x00004143UL  /* SNDRV_PCM_IOCTL_DROP   _IO(\'A\', 0x43) */

#endif /* __DEVICE_OBSERVE_H */
