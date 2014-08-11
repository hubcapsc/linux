/*
 * (C) 2001 Clemson University and The University of Chicago
 *
 * See COPYING in top-level directory.
 */

/*
 *  Implementation of dentry (directory cache) functions.
 */

#include "protocol.h"
#include "pvfs2-kernel.h"

/* Returns 1 if dentry can still be trusted, else 0. */
static int pvfs2_revalidate_lookup(struct dentry *dentry)
{
	struct inode *parent_inode = dentry->d_parent->d_inode;
	struct pvfs2_inode_s *parent = PVFS2_I(parent_inode);
	struct inode *inode = dentry->d_inode;
	struct pvfs2_kernel_op *new_op;
	int ret = 0;

	gossip_debug(GOSSIP_DCACHE_DEBUG, "%s: attempting lookup.\n", __func__);

	new_op = op_alloc(PVFS2_VFS_OP_LOOKUP);
	if (!new_op)
		return 0;

	new_op->upcall.req.lookup.sym_follow = PVFS2_LOOKUP_LINK_NO_FOLLOW;
	new_op->upcall.req.lookup.parent_refn = parent->refn;
	strncpy(new_op->upcall.req.lookup.d_name, dentry->d_name.name, PVFS2_NAME_LEN);

	gossip_debug(GOSSIP_DCACHE_DEBUG,
		     "%s:%s:%d interrupt flag [%d]\n",
		     __FILE__,
		     __func__,
		     __LINE__,
		     get_interruptible_flag(parent_inode));

	ret = service_operation(new_op, "pvfs2_lookup",
			get_interruptible_flag(parent_inode));

	if (new_op->downcall.status != 0 ||
	    !match_handle(new_op->downcall.resp.lookup.refn.khandle, inode)) {
		gossip_debug(GOSSIP_DCACHE_DEBUG,
			"%s:%s:%d "
			"lookup failure |%s| or no match |%s|.\n",
			__FILE__,
			__func__,
			__LINE__,
			new_op->downcall.status ? "true" : "false",
			match_handle(new_op->downcall.resp.lookup.refn.khandle,
					inode) ? "false" : "true");
		op_release(new_op);

		gossip_debug(GOSSIP_DCACHE_DEBUG,
			     "%s:%s:%d setting revalidate_failed = 1\n",
			     __FILE__, __func__, __LINE__);
		/* set a flag that we can detect later in d_delete() */
		PVFS2_I(inode)->revalidate_failed = 1;
		d_drop(dentry);
		return 0;
	}

	op_release(new_op);
	return 1;
}

/*
 * Verify that dentry is valid.
 *
 * Should return 1 if dentry can still be trusted, else 0
 */
static int pvfs2_d_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct inode *inode;
	int ret = 0;

	if (flags & LOOKUP_RCU)
		return -ECHILD;

	gossip_debug(GOSSIP_DCACHE_DEBUG, "%s: called on dentry %p.\n",
		     __func__, dentry);

	/* find inode from dentry */
	if (!dentry || !dentry->d_inode) {
		gossip_debug(GOSSIP_DCACHE_DEBUG, "%s: inode not valid.\n",
			     __func__);
		goto invalid_exit;
	}

	gossip_debug(GOSSIP_DCACHE_DEBUG, "%s: inode valid.\n", __func__);
	inode = dentry->d_inode;

	/* find parent inode */
	if (!dentry || !dentry->d_parent) {
		gossip_debug(GOSSIP_DCACHE_DEBUG, "%s: parent not found.\n",
			     __func__);
		goto invalid_exit;
	}

	gossip_debug(GOSSIP_DCACHE_DEBUG, "%s: parent found.\n", __func__);

	/*
	 * first perform a lookup to make sure that the object not only
	 * exists, but is still in the expected place in the name space
	 */
	if (!is_root_handle(inode)) {
		if (!pvfs2_revalidate_lookup(dentry))
			goto invalid_exit;
	} else {
		gossip_debug(GOSSIP_DCACHE_DEBUG,
			     "%s: root handle, lookup skipped.\n",
			     __func__);
	}

	/* now perform getattr */
	gossip_debug(GOSSIP_DCACHE_DEBUG,
		     "%s: doing getattr: inode: %p, handle: %pU\n",
		     __func__,
		     inode,
		     get_khandle_from_ino(inode));
	ret = pvfs2_inode_getattr(inode, PVFS_ATTR_SYS_ALL_NOHINT);
	gossip_debug(GOSSIP_DCACHE_DEBUG,
		     "%s: getattr %s (ret = %d), returning %s for dentry i_count=%d\n",
		     __func__,
		     (ret == 0 ? "succeeded" : "failed"),
		     ret,
		     (ret == 0 ? "valid" : "INVALID"),
		     atomic_read(&inode->i_count));
	if (ret != 0)
		goto invalid_exit;

	/* dentry is valid! */
	return 1;

invalid_exit:
	return 0;
}

static int pvfs2_d_delete(const struct dentry *dentry)
{
	gossip_debug(GOSSIP_DCACHE_DEBUG,
		     "%s: called on dentry %p.\n", __func__, dentry);
	if (dentry->d_inode
	    && PVFS2_I(dentry->d_inode)->revalidate_failed == 1) {
		gossip_debug(GOSSIP_DCACHE_DEBUG,
			     "%s: returning 1 (bad inode).\n",
			     __func__);
		return 1;
	} else {
		gossip_debug(GOSSIP_DCACHE_DEBUG,
			     "%s: returning 0 (inode looks ok).\n",
			     __func__);
		return 0;
	}
}

/* PVFS2 implementation of VFS dentry operations */
const struct dentry_operations pvfs2_dentry_operations = {
	.d_revalidate = pvfs2_d_revalidate,
	.d_delete = pvfs2_d_delete,
};
