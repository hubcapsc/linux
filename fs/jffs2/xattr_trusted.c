/*
 * JFFS2 -- Journalling Flash File System, Version 2.
 *
 * Copyright © 2006  NEC Corporation
 *
 * Created by KaiGai Kohei <kaigai@ak.jp.nec.com>
 *
 * For licensing information, see the file 'LICENCE' in this directory.
 *
 */

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/jffs2.h>
#include <linux/xattr.h>
#include <linux/mtd/mtd.h>
#include "nodelist.h"

static int jffs2_trusted_getxattr(const struct xattr_handler *handler,
				  struct xattr_gs_args *args)
{
	return do_jffs2_getxattr(args->inode, JFFS2_XPREFIX_TRUSTED,
				 args->name, args->buffer, args->size);
}

static int jffs2_trusted_setxattr(const struct xattr_handler *handler,
				  struct xattr_gs_args *args)
{
	return do_jffs2_setxattr(args->inode, JFFS2_XPREFIX_TRUSTED,
				 args->name, args->value, args->size,
				 args->flags);
}

static bool jffs2_trusted_listxattr(struct dentry *dentry)
{
	return capable(CAP_SYS_ADMIN);
}

const struct xattr_handler jffs2_trusted_xattr_handler = {
	.prefix = XATTR_TRUSTED_PREFIX,
	.list = jffs2_trusted_listxattr,
	.set = jffs2_trusted_setxattr,
	.get = jffs2_trusted_getxattr
};
