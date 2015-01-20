/*
 * (C) 2001 Clemson University and The University of Chicago
 *
 * See COPYING in top-level directory.
 */

#include "protocol.h"
#include "pvfs2-kernel.h"
#include "pvfs2-bufmap.h"

static void *pvfs2_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	char *target =  PVFS2_I(dentry->d_inode)->link_target;

	gossip_debug(GOSSIP_INODE_DEBUG,
		     "pvfs2: %s called on %s (target is %p)\n",
		     __func__, (char *)dentry->d_name.name, target);

	nd_set_link(nd, target);
	return NULL;
}

struct inode_operations pvfs2_symlink_inode_operations = {
	.readlink = generic_readlink,
	.follow_link = pvfs2_follow_link,
	.setattr = pvfs2_setattr,
	.getattr = pvfs2_getattr,
	.listxattr = pvfs2_listxattr,
	.setxattr = generic_setxattr,
};
