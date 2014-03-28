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

static inline int convert_to_internal_xattr_flags(int setxattr_flags)
{
	int internal_flag = 0;

	if (setxattr_flags & XATTR_REPLACE) {
		/* Attribute must exist! */
		internal_flag = PVFS_XATTR_REPLACE;
	} else if (setxattr_flags & XATTR_CREATE) {
		/* Attribute must not exist */
		internal_flag = PVFS_XATTR_CREATE;
	}
	return internal_flag;
}


int pvfs2_xattr_set_default(struct dentry *dentry,
			    const char *name,
			    const void *buffer,
			    size_t size,
			    int flags,
			    int handler_flags)
{
	int internal_flag = 0;

	if (strcmp(name, "") == 0)
		return -EINVAL;

	if (!S_ISREG(dentry->d_inode->i_mode) &&
	    (!S_ISDIR(dentry->d_inode->i_mode) ||
	     dentry->d_inode->i_mode & S_ISVTX)) {
		gossip_err
		    ("pvfs2_xattr_set_default: Returning EPERM for inode %p.\n",
		     dentry->d_inode);
		return -EPERM;
	}

	gossip_debug(GOSSIP_XATTR_DEBUG, "pvfs2_setxattr_default %s\n", name);
	internal_flag = convert_to_internal_xattr_flags(flags);

	return pvfs2_inode_setxattr(dentry->d_inode,
				    PVFS2_XATTR_NAME_DEFAULT_PREFIX,
				    name,
				    buffer,
				    size,
				    internal_flag);
}

int pvfs2_xattr_get_default(struct dentry *dentry,
			    const char *name,
			    void *buffer,
			    size_t size,
			    int handler_flags)
{
	if (strcmp(name, "") == 0)
		return -EINVAL;

	gossip_debug(GOSSIP_XATTR_DEBUG, "pvfs2_getxattr_default %s\n", name);

	return pvfs2_inode_getxattr(dentry->d_inode,
				    PVFS2_XATTR_NAME_DEFAULT_PREFIX,
				    name,
				    buffer,
				    size);

}

static int pvfs2_xattr_set_trusted(struct dentry *dentry,
			    const char *name,
			    const void *buffer,
			    size_t size,
			    int flags,
			    int handler_flags)
{
	int internal_flag = 0;

	gossip_debug(GOSSIP_XATTR_DEBUG,
		     "pvfs2_xattr_set_trusted: name %s, buffer_size %zd\n",
		     name,
		     size);

	if (strcmp(name, "") == 0)
		return -EINVAL;

	if (!capable(CAP_SYS_ADMIN)) {
		gossip_err
		    ("pvfs2_xattr_set_trusted: operation not permitted\n");
		return -EPERM;
	}

	internal_flag = convert_to_internal_xattr_flags(flags);

	return pvfs2_inode_setxattr(dentry->d_inode,
				    PVFS2_XATTR_NAME_TRUSTED_PREFIX,
				    name,
				    buffer,
				    size,
				    internal_flag);
}

static int pvfs2_xattr_get_trusted(struct dentry *dentry,
			    const char *name,
			    void *buffer,
			    size_t size,
			    int handler_flags)
{
	gossip_debug(GOSSIP_XATTR_DEBUG,
		     "pvfs2_xattr_get_trusted: name %s, buffer_size %zd\n",
		     name,
		     size);

	if (strcmp(name, "") == 0)
		return -EINVAL;

	if (!capable(CAP_SYS_ADMIN)) {
		gossip_err
		    ("pvfs2_xattr_get_trusted: operation not permitted\n");
		return -EPERM;
	}

	return pvfs2_inode_getxattr(dentry->d_inode,
				    PVFS2_XATTR_NAME_TRUSTED_PREFIX,
				    name,
				    buffer,
				    size);
}

static struct xattr_handler pvfs2_xattr_trusted_handler = {
	.prefix = PVFS2_XATTR_NAME_TRUSTED_PREFIX,
	.get = pvfs2_xattr_get_trusted,
	.set = pvfs2_xattr_set_trusted,
};

static struct xattr_handler pvfs2_xattr_default_handler = {
	/*
	 * NOTE: this is set to be the empty string.
	 * so that all un-prefixed xattrs keys get caught
	 * here!
	 */
	.prefix = PVFS2_XATTR_NAME_DEFAULT_PREFIX,
	.get = pvfs2_xattr_get_default,
	.set = pvfs2_xattr_set_default,
};

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
