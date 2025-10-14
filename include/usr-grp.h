// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

#ifndef __USR_GRP_H__
#define __USR_GRP_H__

#include <stdio.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

#define ACL_READ (0x04)
#define ACL_WRITE (0x02)
#define ACL_EXECUTE (0x01)

#define ACL_UNDEFINED_TAG (0x00)
#define ACL_USER_OBJ (0x01)
#define ACL_USER (0x02)
#define ACL_GROUP_OBJ (0x04)
#define ACL_GROUP (0x08)
#define ACL_MASK (0x10)
#define ACL_OTHER (0x20)

#define ACL_UNDEFINED_ID ((id_t)-1)

static const char *user_name(uid_t uid)
{
	struct passwd *passwd = getpwuid(uid);
	static char uid_str[22];
	int ret;

	if (passwd != NULL)
	{
		return passwd->pw_name;
	}
	ret = snprintf(uid_str, sizeof(uid_str), "%ld", (long)uid);
	if (ret < 1 || (size_t)ret >= sizeof(uid_str))
	{
		return "?";
	}
	return uid_str;
}

static const char *group_name(gid_t gid)
{
	struct group *group = getgrgid(gid);
	static char gid_str[22];
	int ret;

	if (group != NULL)
	{
		return group->gr_name;
	}
	ret = snprintf(gid_str, sizeof(gid_str), "%ld", (long)gid);
	if (ret < 1 || (size_t)ret >= sizeof(gid_str))
	{
		return "?";
	}
	return gid_str;
}

static const char *mode_str(unsigned short mode)
{
	static char buf[4] = {};
	buf[0] = mode & ACL_READ ? 'r' : '-';
	buf[1] = mode & ACL_WRITE ? 'w' : '-';
	buf[2] = mode & ACL_EXECUTE ? 'x' : '-';
	return buf;
}

#endif