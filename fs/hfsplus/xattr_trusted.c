// SPDX-License-Identifier: GPL-2.0
/*
 * linux/fs/hfsplus/xattr_trusted.c
 *
 * Vyacheslav Dubeyko <slava@dubeyko.com>
 *
 * Handler for trusted extended attributes.
 */

#include <linux/nls.h>

#include "hfsplus_fs.h"
#include "xattr.h"

static int hfsplus_trusted_getxattr(const struct xattr_handler *handler,
				    struct xattr_gs_args *args)
{
	return hfsplus_getxattr(args->inode, args->name,
				args->buffer, args->size,
				XATTR_TRUSTED_PREFIX,
				XATTR_TRUSTED_PREFIX_LEN);
}

static int hfsplus_trusted_setxattr(const struct xattr_handler *handler,
				    struct xattr_gs_args *args)
{
	return hfsplus_setxattr(args->inode, args->name,
				args->buffer, args->size, args->flags,
				XATTR_TRUSTED_PREFIX, XATTR_TRUSTED_PREFIX_LEN);
}

const struct xattr_handler hfsplus_xattr_trusted_handler = {
	.prefix	= XATTR_TRUSTED_PREFIX,
	.get	= hfsplus_trusted_getxattr,
	.set	= hfsplus_trusted_setxattr,
};
