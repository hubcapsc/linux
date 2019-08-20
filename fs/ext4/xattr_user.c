// SPDX-License-Identifier: GPL-2.0
/*
 * linux/fs/ext4/xattr_user.c
 * Handler for extended user attributes.
 *
 * Copyright (C) 2001 by Andreas Gruenbacher, <a.gruenbacher@computer.org>
 */

#include <linux/string.h>
#include <linux/fs.h>
#include "ext4_jbd2.h"
#include "ext4.h"
#include "xattr.h"

static bool
ext4_xattr_user_list(struct dentry *dentry)
{
	return test_opt(dentry->d_sb, XATTR_USER);
}

static int
ext4_xattr_user_get(const struct xattr_handler *handler,
		    struct xattr_gs_args *args)
{
	if (!test_opt(args->inode->i_sb, XATTR_USER))
		return -EOPNOTSUPP;
	return ext4_xattr_get(args->inode, EXT4_XATTR_INDEX_USER,
			      args->name, args->buffer, args->size);
}

static int
ext4_xattr_user_set(const struct xattr_handler *handler,
		    struct xattr_gs_args *args)
{
	if (!test_opt(args->inode->i_sb, XATTR_USER))
		return -EOPNOTSUPP;
	return ext4_xattr_set(args->inode, EXT4_XATTR_INDEX_USER,
			      args->name, args->value, args->size, args->flags);
}

const struct xattr_handler ext4_xattr_user_handler = {
	.prefix	= XATTR_USER_PREFIX,
	.list	= ext4_xattr_user_list,
	.get	= ext4_xattr_user_get,
	.set	= ext4_xattr_user_set,
};
