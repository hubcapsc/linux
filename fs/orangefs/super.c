/*
 * (C) 2001 Clemson University and The University of Chicago
 *
 * See COPYING in top-level directory.
 */

#include "hubcap.h"
#include "pvfs2-kernel.h"
#include "pvfs2-bufmap.h"

/* list for storing pvfs2 specific superblocks in use */
LIST_HEAD(pvfs2_superblocks);

DEFINE_SPINLOCK(pvfs2_superblocks_lock);

static char *keywords[] = { "intr", "acl", };

static int num_possible_keywords = sizeof(keywords) / sizeof(char *);

static int parse_mount_options(char *option_str,
			       struct super_block *sb,
			       int silent)
{
	char *ptr = option_str;
	pvfs2_sb_info_t *pvfs2_sb = NULL;
	int i = 0;
	int j = 0;
	int num_keywords = 0;
	int got_device = 0;

	static char options[PVFS2_MAX_NUM_OPTIONS][PVFS2_MAX_MOUNT_OPT_LEN];

	if (!silent) {
		if (option_str)
			gossip_debug(GOSSIP_SUPER_DEBUG,
				     "pvfs2: parse_mount_options called with:  %s\n",
				     option_str);
		else
			/* We need a non-NULL option string */
			goto exit;
	}


	if (sb && PVFS2_SB(sb)) {
		memset(options,
		       0,
		       (PVFS2_MAX_NUM_OPTIONS * PVFS2_MAX_MOUNT_OPT_LEN));

		pvfs2_sb = PVFS2_SB(sb);
		memset(&pvfs2_sb->mnt_options,
		       0,
		       sizeof(struct pvfs2_mount_options_t));

		while (ptr && (*ptr != '\0')) {
			options[num_keywords][j++] = *ptr;

			if (j == PVFS2_MAX_MOUNT_OPT_LEN) {
				gossip_err("Cannot parse mount time options (length exceeded)\n");
				got_device = 0;
				goto exit;
			}

			if (*ptr == ',') {
				options[num_keywords++][j - 1] = '\0';
				if (num_keywords == PVFS2_MAX_NUM_OPTIONS) {
					gossip_err("Cannot parse mount time options (option number exceeded)\n");
					got_device = 0;
					goto exit;
				}
				j = 0;
			}
			ptr++;
		}
		num_keywords++;

		for (i = 0; i < num_keywords; i++) {
		  for (j = 0; j < num_possible_keywords; j++) {
		    if (strcmp(options[i], keywords[j]) == 0) {
		      if (strncmp(options[i], "intr", 4) == 0) {
			if (!silent) {
			  gossip_debug(GOSSIP_SUPER_DEBUG,
			    "pvfs2: mount option intr specified\n");
			}
			pvfs2_sb->mnt_options.intr = 1;
			break;
		      } else if (strncmp(options[i], "acl", 3) == 0) {
			if (!silent) {
			  gossip_debug(GOSSIP_SUPER_DEBUG,
			    "pvfs2: mount option acl specified\n");
			}
			pvfs2_sb->mnt_options.acl = 1;
			break;
		      }
		    }
		  }

		  /* option string did not match any of the known keywords */
		  if (j == num_possible_keywords) {
			/* filter out NULL option strings (older 2.6 kernels
			 * may leave these after parsing out standard options
			 * like noatime)
			 */
			if (options[i][0] != '\0') {
				/* in the 2.6 kernel, we don't pass device name
				 * through this path; we must have gotten an
				 * unsupported option.
				 */
				gossip_err("Error: mount option [%s] is not supported.\n",
					   options[i]);
				return -EINVAL;
			}
		  }
		}
	}
exit:
	return 0;
}

static struct inode *pvfs2_alloc_inode(struct super_block *sb)
{
	struct inode *new_inode = NULL;
	pvfs2_inode_t *pvfs2_inode = NULL;

	pvfs2_inode = pvfs2_inode_alloc();
	if (pvfs2_inode) {
		new_inode = &pvfs2_inode->vfs_inode;
		gossip_debug(GOSSIP_SUPER_DEBUG,
			     "pvfs2_alloc_inode: allocated %p\n",
			     pvfs2_inode);
	}
	return new_inode;
}

static void pvfs2_destroy_inode(struct inode *inode)
{
	pvfs2_inode_t *pvfs2_inode = PVFS2_I(inode);

	if (pvfs2_inode) {
		gossip_debug(GOSSIP_SUPER_DEBUG,
			     "pvfs2_destroy_inode: deallocated %p"
			     " destroying inode %pU\n",
			     pvfs2_inode,
			     get_khandle_from_ino(inode));

		pvfs2_inode_finalize(pvfs2_inode);
		pvfs2_inode_release(pvfs2_inode);
	}
}

/*
 * NOTE: information filled in here is typically reflected in the
 * output of the system command 'df'
*/
static int pvfs2_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	int ret = -ENOMEM;
	pvfs2_kernel_op_t *new_op = NULL;
	int flags = 0;
	struct super_block *sb = NULL;

	sb = dentry->d_sb;

	gossip_debug(GOSSIP_SUPER_DEBUG,
		     "pvfs2_statfs: called on sb %p (fs_id is %d)\n",
		     sb,
		     (int)(PVFS2_SB(sb)->fs_id));

	new_op = op_alloc(PVFS2_VFS_OP_STATFS);
	if (!new_op)
		return ret;
	new_op->upcall.req.statfs.fs_id = PVFS2_SB(sb)->fs_id;

	if (PVFS2_SB(sb)->mnt_options.intr)
		flags = PVFS2_OP_INTERRUPTIBLE;

	ret = service_operation(new_op, "pvfs2_statfs", flags);

	if (new_op->downcall.status > -1) {
		gossip_debug(GOSSIP_SUPER_DEBUG,
			     "pvfs2_statfs: got %ld blocks available | "
			     "%ld blocks total | %ld block size\n",
			     (long)new_op->downcall.resp.statfs.blocks_avail,
			     (long)new_op->downcall.resp.statfs.blocks_total,
			     (long)new_op->downcall.resp.statfs.block_size);

		buf->f_type = sb->s_magic;
		/* stash the fsid as well */
		memcpy(&buf->f_fsid,
		       &(PVFS2_SB(sb)->fs_id),
		       sizeof(PVFS2_SB(sb)->fs_id));
		buf->f_bsize = new_op->downcall.resp.statfs.block_size;
		buf->f_namelen = PVFS2_NAME_LEN;

		buf->f_blocks =
		    (sector_t) new_op->downcall.resp.statfs.blocks_total;
		buf->f_bfree =
		    (sector_t) new_op->downcall.resp.statfs.blocks_avail;
		buf->f_bavail =
		    (sector_t) new_op->downcall.resp.statfs.blocks_avail;
		buf->f_files =
		    (sector_t) new_op->downcall.resp.statfs.files_total;
		buf->f_ffree =
		    (sector_t) new_op->downcall.resp.statfs.files_avail;

		do {
			struct statfs tmp_statfs;

			buf->f_frsize = sb->s_blocksize;

			gossip_debug(GOSSIP_SUPER_DEBUG,
				     "sizeof(kstatfs)=%d\n",
				     (int)sizeof(struct kstatfs));
			gossip_debug(GOSSIP_SUPER_DEBUG,
				     "sizeof(kstatfs->f_blocks)=%d\n",
				     (int)sizeof(buf->f_blocks));
			gossip_debug(GOSSIP_SUPER_DEBUG,
				     "sizeof(statfs)=%d\n",
				     (int)sizeof(struct statfs));
			gossip_debug(GOSSIP_SUPER_DEBUG,
				     "sizeof(statfs->f_blocks)=%d\n",
				     (int)sizeof(tmp_statfs.f_blocks));
			gossip_debug(GOSSIP_SUPER_DEBUG,
				     "sizeof(sector_t)=%d\n",
				     (int)sizeof(sector_t));

			if ((sizeof(struct statfs) != sizeof(struct kstatfs)) &&
			    (sizeof(tmp_statfs.f_blocks) == 4)) {
				/*
				 * in this case, we need to truncate the values
				 * here to be no bigger than the max 4 byte
				 * long value because the kernel will return an
				 * overflow if it's larger otherwise. see
				 * vfs_statfs_native in open.c for the actual
				 * overflow checks made.
				 */
				buf->f_blocks &= 0x00000000FFFFFFFFULL;
				buf->f_bfree &= 0x00000000FFFFFFFFULL;
				buf->f_bavail &= 0x00000000FFFFFFFFULL;
				buf->f_files &= 0x00000000FFFFFFFFULL;
				buf->f_ffree &= 0x00000000FFFFFFFFULL;

				gossip_debug(GOSSIP_SUPER_DEBUG,
					     "pvfs2_statfs (T) got %lu"
					     " files total | %lu "
					     "files_avail\n",
					     (unsigned long)buf->f_files,
					     (unsigned long)buf->f_ffree);
			} else {
				gossip_debug(GOSSIP_SUPER_DEBUG,
					     "pvfs2_statfs (N) got %lu"
					     " files total | %lu "
					     "files_avail\n",
					     (unsigned long)buf->f_files,
					     (unsigned long)buf->f_ffree);
			}
		} while (0);
	}

	op_release(new_op);

	gossip_debug(GOSSIP_SUPER_DEBUG, "pvfs2_statfs: returning %d\n", ret);
	return ret;
}

/*
 * pvfs2_remount_fs()
 *
 * remount as initiated by VFS layer.  We just need to reparse the mount
 * options, no need to signal pvfs2-client-core about it.
 */
static int pvfs2_remount_fs(struct super_block *sb, int *flags, char *data)
{
	int ret = -EINVAL;

	gossip_debug(GOSSIP_SUPER_DEBUG, "pvfs2_remount_fs: called\n");

	if (sb && PVFS2_SB(sb)) {
		if (data && data[0] != '\0') {
			ret = parse_mount_options(data, sb, 1);
			if (ret)
				return ret;

			/*
			 * mark the superblock as whether it supports acl's
			 * or not
			 */
			sb->s_flags =
				((sb->s_flags & ~MS_POSIXACL) |
				 ((PVFS2_SB(sb)->mnt_options.acl == 1) ?
					 MS_POSIXACL :
					 0));
		}

		if (data)
			strncpy(PVFS2_SB(sb)->data,
				data,
				PVFS2_MAX_MOUNT_OPT_LEN);
	}
	return 0;
}

/*
 * Remount as initiated by pvfs2-client-core on restart.  This is used to
 * repopulate mount information left from previous pvfs2-client-core.
 *
 * the idea here is that given a valid superblock, we're
 * re-initializing the user space client with the initial mount
 * information specified when the super block was first initialized.
 * this is very different than the first initialization/creation of a
 * superblock.  we use the special service_priority_operation to make
 * sure that the mount gets ahead of any other pending operation that
 * is waiting for servicing.  this means that the pvfs2-client won't
 * fail to start several times for all other pending operations before
 * the client regains all of the mount information from us.
 * NOTE: this function assumes that the request_semaphore is already acquired!
 */
int pvfs2_remount(struct super_block *sb, int *flags, char *data)
{
	int ret = -EINVAL;
	pvfs2_kernel_op_t *new_op = NULL;

	gossip_debug(GOSSIP_SUPER_DEBUG, "pvfs2_remount: called\n");

	if (sb && PVFS2_SB(sb)) {
		if (data && data[0] != '\0') {
			ret = parse_mount_options(data, sb, 1);
			if (ret)
				return ret;

			/*
			 * mark the superblock as whether it supports acl's
			 * or not
			 */
			sb->s_flags =
				((sb->s_flags & ~MS_POSIXACL) |
				 ((PVFS2_SB(sb)->mnt_options.acl == 1) ?
					MS_POSIXACL :
					0));
		}

		new_op = op_alloc(PVFS2_VFS_OP_FS_MOUNT);
		if (!new_op)
			return -ENOMEM;
		strncpy(new_op->upcall.req.fs_mount.pvfs2_config_server,
			PVFS2_SB(sb)->devname,
			PVFS_MAX_SERVER_ADDR_LEN);

		gossip_debug(GOSSIP_SUPER_DEBUG,
			     "Attempting PVFS2 Remount via host %s\n",
			     new_op->upcall.req.fs_mount.pvfs2_config_server);

		/*
		 * we assume that the calling function has already acquire the
		 * request_semaphore to prevent other operations from bypassing
		 * this one
		 */
		ret = service_operation(new_op,
					"pvfs2_remount",
					(PVFS2_OP_PRIORITY |
					 PVFS2_OP_NO_SEMAPHORE));

		gossip_debug(GOSSIP_SUPER_DEBUG,
			     "pvfs2_remount: mount got return value of %d\n",
			     ret);
		if (ret == 0) {
			/*
			 * store the id assigned to this sb -- it's just a
			 * short-lived mapping that the system interface uses
			 * to map this superblock to a particular mount entry
			 */
			PVFS2_SB(sb)->id = new_op->downcall.resp.fs_mount.id;

			if (data)
				strncpy(PVFS2_SB(sb)->data,
					data,
					PVFS2_MAX_MOUNT_OPT_LEN);
			PVFS2_SB(sb)->mount_pending = 0;
		}

		op_release(new_op);
	}
	return ret;
}

int fsid_key_table_initialize(void)
{
	return 0;
}

void fsid_key_table_finalize(void)
{
	return;
}

/* Called whenever the VFS dirties the inode in response to atime updates */
static void pvfs2_dirty_inode(struct inode *inode, int flags)
{
	if (inode) {
		pvfs2_inode_t *pvfs2_inode = PVFS2_I(inode);

		gossip_debug(GOSSIP_SUPER_DEBUG,
			     "pvfs2_dirty_inode: %pU\n",
			     get_khandle_from_ino(inode));
		SetAtimeFlag(pvfs2_inode);
	}
	return;
}

struct super_operations pvfs2_s_ops = {
	.alloc_inode = pvfs2_alloc_inode,
	.destroy_inode = pvfs2_destroy_inode,
	.dirty_inode = pvfs2_dirty_inode,
	.drop_inode = generic_delete_inode,
	.statfs = pvfs2_statfs,
	.remount_fs = pvfs2_remount_fs,
	.show_options = generic_show_options,
};

struct dentry *pvfs2_fh_to_dentry(struct super_block *sb,
				  struct fid *fid,
				  int fh_len,
				  int fh_type)
{
	PVFS_object_kref refn;

	if (fh_len < 5 || fh_type > 2)
		return NULL;

	PVFS_khandle_from(&(refn.khandle), fid->raw, 16);
	refn.fs_id = (u32) fid->raw[4];
	gossip_debug(GOSSIP_SUPER_DEBUG,
		     "fh_to_dentry: handle %pU, fs_id %d\n",
		     &refn.khandle,
		     refn.fs_id);

	return d_obtain_alias(pvfs2_iget(sb, &refn));
}

int pvfs2_encode_fh(struct inode *inode,
		    __u32 *fh,
		    int *max_len,
		    struct inode *parent)
{
	int len = parent ? 10 : 5;
	int type = 1;
	PVFS_object_kref refn;

	if (*max_len < len) {
		gossip_lerr("fh buffer is too small for encoding\n");
		*max_len = len;
		type = 255;
		goto out;
	}

	refn = PVFS2_I(inode)->refn;
	PVFS_khandle_to(&refn.khandle, fh, 16);
	fh[4] = refn.fs_id;

	gossip_debug(GOSSIP_SUPER_DEBUG,
		     "Encoding fh: handle %pU, fsid %u\n",
		     &refn.khandle,
		     refn.fs_id);


	if (parent) {
		refn = PVFS2_I(parent)->refn;
		PVFS_khandle_to(&refn.khandle, (char *) fh + 20, 16);
		fh[9] = refn.fs_id;

		type = 2;
		gossip_debug(GOSSIP_SUPER_DEBUG,
			     "Encoding parent: handle %pU, fsid %u\n",
			     &refn.khandle,
			     refn.fs_id);
	}
	*max_len = len;

out:
	return type;
}

static struct export_operations pvfs2_export_ops = {
	.encode_fh = pvfs2_encode_fh,
	.fh_to_dentry = pvfs2_fh_to_dentry,
};

int pvfs2_fill_sb(struct super_block *sb, void *data, int silent)
{
	int ret = -EINVAL;
	struct inode *root = NULL;
	struct dentry *root_dentry = NULL;
	struct pvfs2_mount_sb_info_t *mount_sb_info =
		(struct pvfs2_mount_sb_info_t *) data;
	PVFS_object_kref root_object;

	/* alloc and init our private pvfs2 sb info */
	sb->s_fs_info = kmalloc(sizeof(pvfs2_sb_info_t), PVFS2_GFP_FLAGS);
	if (!PVFS2_SB(sb))
		return -ENOMEM;
	memset(sb->s_fs_info, 0, sizeof(pvfs2_sb_info_t));
	PVFS2_SB(sb)->sb = sb;

	PVFS2_SB(sb)->root_khandle = mount_sb_info->root_khandle;
	PVFS2_SB(sb)->fs_id = mount_sb_info->fs_id;
	PVFS2_SB(sb)->id = mount_sb_info->id;

	if (mount_sb_info->data) {
		ret = parse_mount_options((char *)mount_sb_info->data,
					  sb,
					  silent);
		if (ret)
			return ret;

		/* mark the superblock as whether it supports acl's or not */
		sb->s_flags =
			((sb->s_flags & ~MS_POSIXACL) |
			 ((PVFS2_SB(sb)->mnt_options.acl == 1) ?
				MS_POSIXACL :
				0));
	} else {
		sb->s_flags &= ~MS_POSIXACL;
	}

	/* Hang the xattr handlers off the superblock */
	sb->s_xattr = pvfs2_xattr_handlers;
	sb->s_magic = PVFS2_SUPER_MAGIC;
	sb->s_op = &pvfs2_s_ops;
	sb->s_d_op = &pvfs2_dentry_operations;
	sb->s_type = &pvfs2_fs_type;

	sb->s_blocksize = pvfs_bufmap_size_query();
	sb->s_blocksize_bits = pvfs_bufmap_shift_query();
	sb->s_maxbytes = MAX_LFS_FILESIZE;

	root_object.khandle = PVFS2_SB(sb)->root_khandle;
	root_object.fs_id = PVFS2_SB(sb)->fs_id;
	gossip_debug(GOSSIP_SUPER_DEBUG,
		     "get inode %pU, fsid %d\n",
		     &root_object.khandle,
		     root_object.fs_id);

	root = pvfs2_iget(sb, &root_object);
	if (IS_ERR(root))
		return PTR_ERR(root);

	gossip_debug(GOSSIP_SUPER_DEBUG,
		     "Allocated root inode [%p] with mode %x\n",
		     root,
		     root->i_mode);

	/* allocates and places root dentry in dcache */
	root_dentry = d_make_root(root);
	if (!root_dentry) {
		iput(root);
		return -ENOMEM;
	}

	sb->s_export_op = &pvfs2_export_ops;
	sb->s_root = root_dentry;
	return 0;
}

struct dentry *pvfs2_mount(struct file_system_type *fst,
			   int flags,
			   const char *devname,
			   void *data)
{
	int ret = -EINVAL;
	struct super_block *sb = ERR_PTR(-EINVAL);
	pvfs2_kernel_op_t *new_op;
	struct pvfs2_mount_sb_info_t mount_sb_info;
	struct dentry *mnt_sb_d = ERR_PTR(-EINVAL);

	gossip_debug(GOSSIP_SUPER_DEBUG,
		     "pvfs2_mount: called with devname %s\n",
		     devname);

	if (devname) {
		new_op = op_alloc(PVFS2_VFS_OP_FS_MOUNT);
		if (!new_op) {
			ret = -ENOMEM;
			return ERR_PTR(ret);
		}
		strncpy(new_op->upcall.req.fs_mount.pvfs2_config_server,
			devname,
			PVFS_MAX_SERVER_ADDR_LEN);

		gossip_debug(GOSSIP_SUPER_DEBUG,
			     "Attempting PVFS2 Mount via host %s\n",
			     new_op->upcall.req.fs_mount.pvfs2_config_server);

		ret = service_operation(new_op, "pvfs2_mount", 0);

		gossip_debug(GOSSIP_SUPER_DEBUG,
			     "pvfs2_mount: mount got return value of %d\n",
			     ret);
		if (ret)
			goto free_op;

		if (new_op->downcall.resp.fs_mount.fs_id == PVFS_FS_ID_NULL) {
			gossip_err
			    ("ERROR: Retrieved null fs_id\n");
			ret = -EINVAL;
			goto free_op;
		}

		/* fill in temporary structure passed to fill_sb method */
		mount_sb_info.data = data;
		mount_sb_info.root_khandle =
		    new_op->downcall.resp.fs_mount.root_khandle;
		mount_sb_info.fs_id = new_op->downcall.resp.fs_mount.fs_id;
		mount_sb_info.id = new_op->downcall.resp.fs_mount.id;

		/*
		 * the mount_sb_info structure looks odd, but it's used because
		 * the private sb info isn't allocated until we call
		 * pvfs2_fill_sb, yet we have the info we need to fill it with
		 * here.  so we store it temporarily and pass all of the info
		 * to fill_sb where it's properly copied out
		 */
		mnt_sb_d = mount_nodev(fst,
				       flags,
				       (void *)&mount_sb_info,
				       pvfs2_fill_sb);
		if (!IS_ERR(mnt_sb_d)) {
			sb = mnt_sb_d->d_sb;
		} else {
			sb = ERR_CAST(mnt_sb_d);
			goto free_op;
		}

		if (sb && !IS_ERR(sb) && (PVFS2_SB(sb))) {
			/*
			 * on successful mount, store the devname and data
			 * used
			 */
			strncpy(PVFS2_SB(sb)->devname,
				devname,
				PVFS_MAX_SERVER_ADDR_LEN);
			if (data)
				strncpy(PVFS2_SB(sb)->data,
					data,
					PVFS2_MAX_MOUNT_OPT_LEN);

			/* mount_pending must be cleared */
			PVFS2_SB(sb)->mount_pending = 0;
			/*
			 * finally, add this sb to our list of known pvfs2
			 * sb's
			 */
			add_pvfs2_sb(sb);
		} else {
			ret = -EINVAL;
			gossip_err("got Invalid superblock from mount_nodev (%p)\n",
				   sb);
		}
		op_release(new_op);
	} else {
		gossip_err("ERROR: device name not specified.\n");
	}
	return mnt_sb_d;

free_op:
	gossip_err("pvfs2_mount: mount request failed with %d\n", ret);
	if (ret == -EINVAL) {
		gossip_err("Ensure that all pvfs2-servers have the same FS configuration files\n");
		gossip_err("Look at pvfs2-client-core log file (typically /tmp/pvfs2-client.log) for more details\n");
	}

	if (new_op)
		op_release(new_op);

	gossip_debug(GOSSIP_SUPER_DEBUG,
		     "pvfs2_mount: returning dentry %p\n",
		     mnt_sb_d);
	return mnt_sb_d;
}

static void pvfs2_flush_sb(struct super_block *sb)
{
	return;
}

void pvfs2_kill_sb(struct super_block *sb)
{
	gossip_debug(GOSSIP_SUPER_DEBUG, "pvfs2_kill_sb: called\n");

	if (sb && !IS_ERR(sb)) {
		/*
		 * Flush any dirty inodes atimes, mtimes to server
		 */
		pvfs2_flush_sb(sb);
		/*
		 * issue the unmount to userspace to tell it to remove the
		 * dynamic mount info it has for this superblock
		 */
		pvfs2_unmount_sb(sb);

		/* remove the sb from our list of pvfs2 specific sb's */
		remove_pvfs2_sb(sb);

		/* prune dcache based on sb */
		shrink_dcache_sb(sb);

		/* provided sb cleanup */
		kill_litter_super(sb);

		/* release the allocated root dentry */
		if (sb->s_root)
			dput(sb->s_root);

		/* free the pvfs2 superblock private data */
		kfree(PVFS2_SB(sb));
	} else {
		gossip_debug(GOSSIP_SUPER_DEBUG,
			     "pvfs2_kill_sb: skipping due to invalid sb\n");
	}
	gossip_debug(GOSSIP_SUPER_DEBUG, "pvfs2_kill_sb: returning normally\n");
}
