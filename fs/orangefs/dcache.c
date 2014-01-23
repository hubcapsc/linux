/*
 * (C) 2001 Clemson University and The University of Chicago
 *
 * See COPYING in top-level directory.
 */

/*
 *  Implementation of dentry (directory cache) functions.
 */

#include "hubcap.h"
#include "pvfs2-kernel.h"

static void __attribute__ ((unused)) print_dentry(struct dentry *entry,
						  int ret);

/* should return 1 if dentry can still be trusted, else 0 */
static int pvfs2_d_revalidate_common(struct dentry *dentry)
{
	int ret = 0;
	struct inode *inode;
	struct inode *parent_inode = NULL;
	pvfs2_kernel_op_t *new_op = NULL;
	pvfs2_inode_t *parent = NULL;

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
	parent_inode = dentry->d_parent->d_inode;

	/*
	 * first perform a lookup to make sure that the object not only
	 * exists, but is still in the expected place in the name space
	 */
	if (!is_root_handle(inode)) {
		gossip_debug(GOSSIP_DCACHE_DEBUG, "%s: attempting lookup.\n",
			     __func__);
		new_op = op_alloc(PVFS2_VFS_OP_LOOKUP);
		if (!new_op)
			goto invalid_exit;
		new_op->upcall.req.lookup.sym_follow =
		    PVFS2_LOOKUP_LINK_NO_FOLLOW;
		parent = PVFS2_I(parent_inode);
		if (parent && parent->refn.handle != PVFS_HANDLE_NULL &&
		    parent->refn.fs_id != PVFS_FS_ID_NULL) {
			new_op->upcall.req.lookup.parent_refn = parent->refn;
		} else {
			gossip_lerr("Critical error: i_ino cannot be relied upon when using iget5/iget4\n");
			op_release(new_op);
			goto invalid_exit;
		}
		strncpy(new_op->upcall.req.lookup.d_name,
			dentry->d_name.name, PVFS2_NAME_LEN);

		gossip_debug(GOSSIP_DCACHE_DEBUG,
			     "%s:%s:%d interrupt flag [%d]\n",
			     __FILE__,
			     __func__,
			     __LINE__,
			     get_interruptible_flag(parent_inode));

		ret = service_operation(new_op,
					"pvfs2_lookup",
					get_interruptible_flag(parent_inode));

		if ((new_op->downcall.status != 0) ||
		    !match_handle(new_op->downcall.resp.lookup.refn.handle,
				  inode)) {
			gossip_debug(GOSSIP_DCACHE_DEBUG,
				"%s:%s:%d "
				"lookup failure |%s| or no match |%s|.\n",
				__FILE__,
				__func__,
				__LINE__,
				(new_op->downcall.status != 0) ?
				    "true" :
				    "false",
				(!match_handle
				    (new_op->downcall.resp.lookup.refn.handle,
				    inode)) ?
					"true" :
					"false");
			op_release(new_op);
			gossip_debug(GOSSIP_DCACHE_DEBUG,
				     "%s:%s:%d setting revalidate_failed = 1\n",
				     __FILE__, __func__, __LINE__);
			/* set a flag that we can detect later in d_delete() */
			PVFS2_I(inode)->revalidate_failed = 1;
			d_drop(dentry);
			goto invalid_exit;
		}
		op_release(new_op);
	} else {
		gossip_debug(GOSSIP_DCACHE_DEBUG,
			     "%s: root handle, lookup skipped.\n",
			     __func__);
	}

	/* now perform getattr */
	gossip_debug(GOSSIP_DCACHE_DEBUG,
		     "%s: doing getattr: inode: %p, handle: %llu\n",
		     __func__,
		     inode,
		     llu(get_handle_from_ino(inode)));
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

/*
 * Verify that dentry is valid.
 *
 * Should return 1 if dentry can still be trusted, else 0
 */
static int pvfs2_d_revalidate(struct dentry *dentry, unsigned int flags)
{
	if (flags & LOOKUP_RCU)
		return -ECHILD;

	if ((flags & LOOKUP_FOLLOW) && (!(flags & LOOKUP_CREATE))) {
		gossip_debug(GOSSIP_DCACHE_DEBUG,
			     "\n%s: Trusting intent; skipping getattr\n",
			     __func__);
		return 1;
	}

	return pvfs2_d_revalidate_common(dentry);
}

/* PVFS2 implementation of VFS dentry operations */
const struct dentry_operations pvfs2_dentry_operations = {
	.d_revalidate = pvfs2_d_revalidate,
	.d_delete = pvfs2_d_delete,
};

/* print_dentry()
 *
 * Available for debugging purposes.  Please remove the unused attribute
 * before invoking
 */
static void __attribute__ ((unused)) print_dentry(struct dentry *entry, int ret)
{
	unsigned int local_count = 0;
	if (!entry) {
		pr_info("--- dentry %p: no entry, ret: %d\n", entry, ret);
		return;
	}

	if (!entry->d_inode) {
		pr_info("--- dentry %p: no d_inode, ret: %d\n", entry, ret);
		return;
	}

	if (!entry->d_parent) {
		pr_info("--- dentry %p: no d_parent, ret: %d\n", entry, ret);
		return;
	}

	spin_lock(&entry->d_lock);
	local_count = entry->d_lockref.count;
	spin_unlock(&entry->d_lock);

	pr_info("--- dentry %p: d_count: %d, name: %s, parent: %p, parent name: %s, ret: %d\n",
	     entry, local_count, entry->d_name.name, entry->d_parent,
	     entry->d_parent->d_name.name, ret);
}
