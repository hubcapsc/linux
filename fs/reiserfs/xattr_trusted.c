// SPDX-License-Identifier: GPL-2.0
#include "reiserfs.h"
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/xattr.h>
#include "xattr.h"
#include <linux/uaccess.h>

static int
trusted_get(const struct xattr_handler *handler, struct xattr_gs_args *args)
{
	if (!capable(CAP_SYS_ADMIN) || IS_PRIVATE(args->inode))
		return -EPERM;

	return reiserfs_xattr_get(args->inode,
				  xattr_full_name(handler, args->name),
				  args->buffer, args->size);
}

static int
trusted_set(const struct xattr_handler *handler, struct xattr_gs_args *args)
{
	if (!capable(CAP_SYS_ADMIN) || IS_PRIVATE(args->inode))
		return -EPERM;

	return reiserfs_xattr_set(args->inode,
				  xattr_full_name(handler, args->name),
				  args->value, args->size, args->flags);
}

static bool trusted_list(struct dentry *dentry)
{
	return capable(CAP_SYS_ADMIN) && !IS_PRIVATE(d_inode(dentry));
}

const struct xattr_handler reiserfs_xattr_trusted_handler = {
	.prefix = XATTR_TRUSTED_PREFIX,
	.get = trusted_get,
	.set = trusted_set,
	.list = trusted_list,
};
