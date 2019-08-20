// SPDX-License-Identifier: GPL-2.0
#include "reiserfs.h"
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/xattr.h>
#include "xattr.h"
#include <linux/uaccess.h>

static int
user_get(const struct xattr_handler *handler, struct xattr_gs_args *args)
{
	if (!reiserfs_xattrs_user(args->inode->i_sb))
		return -EOPNOTSUPP;
	return reiserfs_xattr_get(args->inode,
				  xattr_full_name(handler, args->name),
				  args->buffer, args->size);
}

static int
user_set(const struct xattr_handler *handler, struct xattr_gs_args *args)
{
	if (!reiserfs_xattrs_user(args->inode->i_sb))
		return -EOPNOTSUPP;
	return reiserfs_xattr_set(args->inode,
				  xattr_full_name(handler, args->name),
				  args->value, args->size, args->flags);
}

static bool user_list(struct dentry *dentry)
{
	return reiserfs_xattrs_user(dentry->d_sb);
}

const struct xattr_handler reiserfs_xattr_user_handler = {
	.prefix = XATTR_USER_PREFIX,
	.get = user_get,
	.set = user_set,
	.list = user_list,
};
