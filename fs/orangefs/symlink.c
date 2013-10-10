/*
 * (C) 2001 Clemson University and The University of Chicago
 *
 * See COPYING in top-level directory.
 */

#include "hubcap.h"
#include "pvfs2-kernel.h"
#include "pvfs2-bufmap.h"

static int pvfs2_readlink(struct dentry *dentry,
			  char __user *buffer,
			  int buflen)
{
	pvfs2_inode_t *pvfs2_inode = PVFS2_I(dentry->d_inode);

	gossip_debug(GOSSIP_INODE_DEBUG,
		     "pvfs2_readlink called on inode %pU\n",
		     get_khandle_from_ino(dentry->d_inode));

	/*
	 * if we're getting called, the vfs has no doubt already done a
	 * getattr, so we should always have the link_target string
	 * available in the pvfs2_inode private data
	 */
	return vfs_readlink(dentry, buffer, buflen, pvfs2_inode->link_target);
}

static void *pvfs2_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	pvfs2_inode_t *pvfs2_inode = PVFS2_I(dentry->d_inode);

	gossip_debug(GOSSIP_INODE_DEBUG,
		     "pvfs2: pvfs2_follow_link called on %s (target is %p)\n",
		     (char *)dentry->d_name.name,
		     pvfs2_inode->link_target);

	/*
	 * we used to use vfs_follow_link here, instead of nd_set_link.
	 * vfs_follow_link had an int return value, nd_set_link does not,
	 * so now we'll just call nd_set_link and return NULL...
	 */
	nd_set_link(nd, pvfs2_inode->link_target);
	return NULL;
}

struct inode_operations pvfs2_symlink_inode_operations = {
	.readlink = pvfs2_readlink,
	.follow_link = pvfs2_follow_link,
	.setattr = pvfs2_setattr,
	.getattr = pvfs2_getattr,
	.listxattr = pvfs2_listxattr,
	.setxattr = generic_setxattr,
};
