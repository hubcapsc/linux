/*
 * (C) 2001 Clemson University and The University of Chicago
 *
 * See COPYING in top-level directory.
 */

/*
 *  Linux VFS extended attribute operations.
 */

#include "hubcap.h"
#include "pvfs2-kernel.h"
#include "pvfs2-bufmap.h"
#include <linux/posix_acl_xattr.h>
#include <linux/xattr.h>

/*
 * NOTES from fs/xattr.c
 * In order to implement different sets of xattr operations for each xattr
 * prefix with the generic xattr API, a filesystem should create a
 * null-terminated array of struct xattr_handler (one for each prefix) and
 * hang a pointer to it off of the s_xattr field of the superblock.
 */
const struct xattr_handler *pvfs2_xattr_handlers[] = {
	/*
	 * ACL xattrs have special prefixes that I am handling separately
	 * so that we get control when the acl's are set or listed or queried!
	 */
	&pvfs2_xattr_acl_access_handler,
	&pvfs2_xattr_acl_default_handler,
	&pvfs2_xattr_trusted_handler,
	&pvfs2_xattr_default_handler,
	NULL
};

ssize_t pvfs2_listxattr(struct dentry *dentry, char *buffer, size_t size)
{
	struct inode *inode = dentry->d_inode;
	return pvfs2_inode_listxattr(inode, buffer, size);
}

int pvfs2_removexattr(struct dentry *dentry, const char *name)
{
	struct inode *inode = dentry->d_inode;
	return pvfs2_inode_removexattr(inode, NULL, name, XATTR_REPLACE);
}
