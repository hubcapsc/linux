// SPDX-License-Identifier: GPL-2.0
/*
 * linux/fs/ext4/xattr_security.c
 * Handler for storing security labels as extended attributes.
 */

#include <linux/string.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/slab.h>
#include "ext4_jbd2.h"
#include "ext4.h"
#include "xattr.h"

static int
ext4_xattr_security_get(const struct xattr_handler *handler,
			struct xattr_gs_args *args)
{
	return ext4_xattr_get(args->inode, EXT4_XATTR_INDEX_SECURITY,
			      args->name, args->buffer, args->size);
}

static int
ext4_xattr_security_set(const struct xattr_handler *handler,
			struct xattr_gs_args *args)
{
	return ext4_xattr_set(args->inode, EXT4_XATTR_INDEX_SECURITY,
			      args->name, args->value, args->size, args->flags);
}

static int
ext4_initxattrs(struct inode *inode, const struct xattr *xattr_array,
		void *fs_info)
{
	const struct xattr *xattr;
	handle_t *handle = fs_info;
	int err = 0;

	for (xattr = xattr_array; xattr->name != NULL; xattr++) {
		err = ext4_xattr_set_handle(handle, inode,
					    EXT4_XATTR_INDEX_SECURITY,
					    xattr->name, xattr->value,
					    xattr->value_len, XATTR_CREATE);
		if (err < 0)
			break;
	}
	return err;
}

int
ext4_init_security(handle_t *handle, struct inode *inode, struct inode *dir,
		   const struct qstr *qstr)
{
	return security_inode_init_security(inode, dir, qstr,
					    &ext4_initxattrs, handle);
}

const struct xattr_handler ext4_xattr_security_handler = {
	.prefix	= XATTR_SECURITY_PREFIX,
	.get	= ext4_xattr_security_get,
	.set	= ext4_xattr_security_set,
};
