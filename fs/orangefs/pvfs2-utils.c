/*
 * (C) 2001 Clemson University and The University of Chicago
 *
 * See COPYING in top-level directory.
 */
#define  __PINT_PROTO_ENCODE_OPAQUE_HANDLE
#include "hubcap.h"
#include "pvfs2-kernel.h"
#include "pvfs2-dev-proto.h"
#include "pvfs2-bufmap.h"

PVFS_fs_id fsid_of_op(pvfs2_kernel_op_t *op)
{
	PVFS_fs_id fsid = PVFS_FS_ID_NULL;
	if (op) {
		switch (op->upcall.type) {
		case PVFS2_VFS_OP_FILE_IO:
			fsid = op->upcall.req.io.refn.fs_id;
			break;
		case PVFS2_VFS_OP_LOOKUP:
			fsid = op->upcall.req.lookup.parent_refn.fs_id;
			break;
		case PVFS2_VFS_OP_CREATE:
			fsid = op->upcall.req.create.parent_refn.fs_id;
			break;
		case PVFS2_VFS_OP_GETATTR:
			fsid = op->upcall.req.getattr.refn.fs_id;
			break;
		case PVFS2_VFS_OP_REMOVE:
			fsid = op->upcall.req.remove.parent_refn.fs_id;
			break;
		case PVFS2_VFS_OP_MKDIR:
			fsid = op->upcall.req.mkdir.parent_refn.fs_id;
			break;
		case PVFS2_VFS_OP_READDIR:
			fsid = op->upcall.req.readdir.refn.fs_id;
			break;
		case PVFS2_VFS_OP_SETATTR:
			fsid = op->upcall.req.setattr.refn.fs_id;
			break;
		case PVFS2_VFS_OP_SYMLINK:
			fsid = op->upcall.req.sym.parent_refn.fs_id;
			break;
		case PVFS2_VFS_OP_RENAME:
			fsid = op->upcall.req.rename.old_parent_refn.fs_id;
			break;
		case PVFS2_VFS_OP_STATFS:
			fsid = op->upcall.req.statfs.fs_id;
			break;
		case PVFS2_VFS_OP_TRUNCATE:
			fsid = op->upcall.req.truncate.refn.fs_id;
			break;
		case PVFS2_VFS_OP_MMAP_RA_FLUSH:
			fsid = op->upcall.req.ra_cache_flush.refn.fs_id;
			break;
		case PVFS2_VFS_OP_FS_UMOUNT:
			fsid = op->upcall.req.fs_umount.fs_id;
			break;
		case PVFS2_VFS_OP_GETXATTR:
			fsid = op->upcall.req.getxattr.refn.fs_id;
			break;
		case PVFS2_VFS_OP_SETXATTR:
			fsid = op->upcall.req.setxattr.refn.fs_id;
			break;
		case PVFS2_VFS_OP_LISTXATTR:
			fsid = op->upcall.req.listxattr.refn.fs_id;
			break;
		case PVFS2_VFS_OP_REMOVEXATTR:
			fsid = op->upcall.req.removexattr.refn.fs_id;
			break;
		case PVFS2_VFS_OP_FSYNC:
			fsid = op->upcall.req.fsync.refn.fs_id;
			break;
		default:
			break;
		}
	}
	return fsid;
}

static void pvfs2_set_inode_flags(struct inode *inode, PVFS_sys_attr *attrs)
{
	if (attrs->flags & PVFS_IMMUTABLE_FL)
		inode->i_flags |= S_IMMUTABLE;
	else
		inode->i_flags &= ~S_IMMUTABLE;

	if (attrs->flags & PVFS_APPEND_FL)
		inode->i_flags |= S_APPEND;
	else
		inode->i_flags &= ~S_APPEND;

	if (attrs->flags & PVFS_NOATIME_FL)
		inode->i_flags |= S_NOATIME;
	else
		inode->i_flags &= ~S_NOATIME;

	return;
}

/* NOTE: symname is ignored unless the inode is a sym link */
static int copy_attributes_to_inode(struct inode *inode,
			     PVFS_sys_attr *attrs,
			     char *symname)
{
	int ret = -1;
	int perm_mode = 0;
	pvfs2_inode_t *pvfs2_inode = PVFS2_I(inode);
	loff_t inode_size = 0;
	loff_t rounded_up_size = 0;


	/*
	   arbitrarily set the inode block size; FIXME: we need to
	   resolve the difference between the reported inode blocksize
	   and the PAGE_CACHE_SIZE, since our block count will always
	   be wrong.

	   For now, we're setting the block count to be the proper
	   number assuming the block size is 512 bytes, and the size is
	   rounded up to the nearest 4K.  This is apparently required
	   to get proper size reports from the 'du' shell utility.

	   changing the inode->i_blkbits to something other than
	   PAGE_CACHE_SHIFT breaks mmap/execution as we depend on that.
	 */
	gossip_debug(GOSSIP_UTILS_DEBUG,
		     "attrs->mask = %x (objtype = %s)\n",
		     attrs->mask,
		     attrs->objtype == PVFS_TYPE_METAFILE ? "file" :
		     attrs->objtype == PVFS_TYPE_DIRECTORY ? "directory" :
		     attrs->objtype == PVFS_TYPE_SYMLINK ? "symlink" :
			"invalid/unknown");

	switch (attrs->objtype) {
	case PVFS_TYPE_METAFILE:
		pvfs2_set_inode_flags(inode, attrs);
		if (attrs->mask & PVFS_ATTR_SYS_SIZE) {
			inode_size = (loff_t) attrs->size;
			rounded_up_size =
			    (inode_size + (4096 - (inode_size % 4096)));

			pvfs2_lock_inode(inode);
			inode->i_bytes = inode_size;
			inode->i_blocks =
			    (unsigned long)(rounded_up_size / 512);
			pvfs2_unlock_inode(inode);

			/*
			 * NOTE: make sure all the places we're called
			 * from have the inode->i_sem lock. We're fine
			 * in 99% of the cases since we're mostly
			 * called from a lookup.
			 */
			inode->i_size = inode_size;
		}
		break;
	case PVFS_TYPE_SYMLINK:
		if (symname != NULL) {
			inode->i_size = (loff_t) strlen(symname);
			break;
		}
		/*FALLTHRU*/
	default:
		pvfs2_lock_inode(inode);
		inode->i_bytes = PAGE_CACHE_SIZE;
		inode->i_blocks = (unsigned long)(PAGE_CACHE_SIZE / 512);
		pvfs2_unlock_inode(inode);

		inode->i_size = PAGE_CACHE_SIZE;
		break;
	}

	inode->i_uid = make_kuid(&init_user_ns, attrs->owner);
	inode->i_gid = make_kgid(&init_user_ns, attrs->group);
	inode->i_atime.tv_sec = (time_t) attrs->atime;
	inode->i_mtime.tv_sec = (time_t) attrs->mtime;
	inode->i_ctime.tv_sec = (time_t) attrs->ctime;
	inode->i_atime.tv_nsec = 0;
	inode->i_mtime.tv_nsec = 0;
	inode->i_ctime.tv_nsec = 0;

	if (attrs->perms & PVFS_O_EXECUTE)
		perm_mode |= S_IXOTH;
	if (attrs->perms & PVFS_O_WRITE)
		perm_mode |= S_IWOTH;
	if (attrs->perms & PVFS_O_READ)
		perm_mode |= S_IROTH;

	if (attrs->perms & PVFS_G_EXECUTE)
		perm_mode |= S_IXGRP;
	if (attrs->perms & PVFS_G_WRITE)
		perm_mode |= S_IWGRP;
	if (attrs->perms & PVFS_G_READ)
		perm_mode |= S_IRGRP;

	if (attrs->perms & PVFS_U_EXECUTE)
		perm_mode |= S_IXUSR;
	if (attrs->perms & PVFS_U_WRITE)
		perm_mode |= S_IWUSR;
	if (attrs->perms & PVFS_U_READ)
		perm_mode |= S_IRUSR;

	if (attrs->perms & PVFS_G_SGID)
		perm_mode |= S_ISGID;
	if (attrs->perms & PVFS_U_SUID)
		perm_mode |= S_ISUID;

	inode->i_mode = perm_mode;

	if (is_root_handle(inode)) {
		/* special case: mark the root inode as sticky */
		inode->i_mode |= S_ISVTX;
		gossip_debug(GOSSIP_UTILS_DEBUG,
			     "Marking inode %llu as sticky\n",
			     llu(get_handle_from_ino(inode)));
	}

	switch (attrs->objtype) {
	case PVFS_TYPE_METAFILE:
		inode->i_mode |= S_IFREG;
		ret = 0;
		break;
	case PVFS_TYPE_DIRECTORY:
		inode->i_mode |= S_IFDIR;
		/* NOTE: we have no good way to keep nlink consistent
		 * for directories across clients; keep constant at 1.
		 * Why 1?  If we go with 2, then find(1) gets confused
		 * and won't work properly withouth the -noleaf option
		 */
		set_nlink(inode, 1);
		ret = 0;
		break;
	case PVFS_TYPE_SYMLINK:
		inode->i_mode |= S_IFLNK;

		/* copy link target to inode private data */
		if (pvfs2_inode && symname) {
			strncpy(pvfs2_inode->link_target,
				symname,
				PVFS_NAME_MAX);
			gossip_debug(GOSSIP_UTILS_DEBUG,
				     "Copied attr link target %s\n",
				     pvfs2_inode->link_target);
		}
		gossip_debug(GOSSIP_UTILS_DEBUG,
			     "symlink mode %o\n",
			     inode->i_mode);
		ret = 0;
		break;
	default:
		gossip_err("pvfs2:copy_attributes_to_inode: got invalid attribute type %x\n",
			attrs->objtype);
	}

	gossip_debug(GOSSIP_UTILS_DEBUG,
		     "pvfs2: copy_attributes_to_inode: setting i_mode to %o, i_size to %lu\n",
		     inode->i_mode,
		     (unsigned long)i_size_read(inode));
	return ret;
}

/*
 * NOTE: in kernel land, we never use the sys_attr->link_target for
 * anything, so don't bother copying it into the sys_attr object here.
 */
static inline int copy_attributes_from_inode(struct inode *inode,
					     PVFS_sys_attr *attrs,
					     struct iattr *iattr)
{
	umode_t tmp_mode;

	if (!iattr || !inode || !attrs) {
		gossip_err("NULL iattr (%p), inode (%p), attrs (%p) in copy_attributes_from_inode!\n",
			   iattr,
			   inode,
			   attrs);
		return -EINVAL;
	}
	/*
	 * We need to be careful to only copy the attributes out of the
	 * iattr object that we know are valid.
	 */
	attrs->mask = 0;
	if (iattr->ia_valid & ATTR_UID) {
		attrs->owner = from_kuid(&init_user_ns, iattr->ia_uid);
		attrs->mask |= PVFS_ATTR_SYS_UID;
		gossip_debug(GOSSIP_UTILS_DEBUG, "(UID) %d\n", attrs->owner);
	}
	if (iattr->ia_valid & ATTR_GID) {
		attrs->group = from_kgid(&init_user_ns, iattr->ia_gid);
		attrs->mask |= PVFS_ATTR_SYS_GID;
		gossip_debug(GOSSIP_UTILS_DEBUG, "(GID) %d\n", attrs->group);
	}

	if (iattr->ia_valid & ATTR_ATIME) {
		attrs->mask |= PVFS_ATTR_SYS_ATIME;
		if (iattr->ia_valid & ATTR_ATIME_SET) {
			attrs->atime =
			    pvfs2_convert_time_field((void *)&iattr->ia_atime);
			attrs->mask |= PVFS_ATTR_SYS_ATIME_SET;
		}
	}
	if (iattr->ia_valid & ATTR_MTIME) {
		attrs->mask |= PVFS_ATTR_SYS_MTIME;
		if (iattr->ia_valid & ATTR_MTIME_SET) {
			attrs->mtime =
			    pvfs2_convert_time_field((void *)&iattr->ia_mtime);
			attrs->mask |= PVFS_ATTR_SYS_MTIME_SET;
		}
	}
	if (iattr->ia_valid & ATTR_CTIME)
		attrs->mask |= PVFS_ATTR_SYS_CTIME;

	/*
	 * PVFS2 cannot set size with a setattr operation.  Probably not likely
	 * to be requested through the VFS, but just in case, don't worry about
	 * ATTR_SIZE
	 */

	if (iattr->ia_valid & ATTR_MODE) {
		tmp_mode = iattr->ia_mode;
		if (tmp_mode & (S_ISVTX)) {
			if (is_root_handle(inode)) {
				/*
				 * allow sticky bit to be set on root (since
				 * it shows up that way by default anyhow),
				 * but don't show it to the server
				 */
				tmp_mode -= S_ISVTX;
			} else {
				gossip_debug(GOSSIP_UTILS_DEBUG,
					     "User attempted to set sticky bit on non-root directory; returning EINVAL.\n");
				return -EINVAL;
			}
		}

		if (tmp_mode & (S_ISUID)) {
			gossip_debug(GOSSIP_UTILS_DEBUG,
				     "Attempting to set setuid bit (not supported); returning EINVAL.\n");
			return -EINVAL;
		}

		attrs->perms = PVFS_util_translate_mode(tmp_mode);
		attrs->mask |= PVFS_ATTR_SYS_PERM;
	}

	return 0;
}

/*
 * issues a pvfs2 getattr request and fills in the appropriate inode
 * attributes if successful.  returns 0 on success; -errno otherwise
 */
int pvfs2_inode_getattr(struct inode *inode, uint32_t getattr_mask)
{
	pvfs2_inode_t *pvfs2_inode = PVFS2_I(inode);
	pvfs2_kernel_op_t *new_op;
	int ret = -EINVAL;

	gossip_debug(GOSSIP_UTILS_DEBUG, "%s: called on inode %llu\n",
		     __func__, llu(get_handle_from_ino(inode)));

	new_op = op_alloc(PVFS2_VFS_OP_GETATTR);
	if (!new_op)
		return -ENOMEM;
	new_op->upcall.req.getattr.refn = pvfs2_inode->refn;
	new_op->upcall.req.getattr.mask = getattr_mask;

	ret = service_operation(new_op, __func__,
				get_interruptible_flag(inode));
	if (ret != 0)
		goto out;

	if (copy_attributes_to_inode(inode,
			&new_op->downcall.resp.getattr.attributes,
			new_op->downcall.resp.getattr.link_target)) {
		gossip_err("%s: failed to copy attributes\n", __func__);
		ret = -ENOENT;
		goto out;
	}

	/*
	 * Store blksize in pvfs2 specific part of inode structure; we are
	 * only going to use this to report to stat to make sure it doesn't
	 * perturb any inode related code paths.
	 */
	if (new_op->downcall.resp.getattr.attributes.objtype ==
			PVFS_TYPE_METAFILE) {
		pvfs2_inode->blksize =
			new_op->downcall.resp.getattr.attributes.blksize;
	} else {
		/* mimic behavior of generic_fillattr() for other types. */
		pvfs2_inode->blksize = (1 << inode->i_blkbits);

	}

out:
	gossip_debug(GOSSIP_UTILS_DEBUG,
		     "Getattr on handle %llu, "
		     "fsid %d\n  (inode ct = %d) returned %d\n",
		     llu(pvfs2_inode->refn.handle),
		     pvfs2_inode->refn.fs_id,
		     (int)atomic_read(&inode->i_count),
		     ret);
	/*
	 * store error code in the inode so that we can retrieve
	 * it later if needed
	 */
	if (ret < 0)
		pvfs2_inode->error_code = ret;

	op_release(new_op);
	return ret;
}

/*
 * issues a pvfs2 setattr request to make sure the new attribute values
 * take effect if successful.  returns 0 on success; -errno otherwise
 */
int pvfs2_inode_setattr(struct inode *inode, struct iattr *iattr)
{
	int ret = -ENOMEM;
	pvfs2_kernel_op_t *new_op = NULL;
	pvfs2_inode_t *pvfs2_inode = NULL;

	if (inode) {
		pvfs2_inode = PVFS2_I(inode);

		new_op = op_alloc(PVFS2_VFS_OP_SETATTR);
		if (!new_op)
			return ret;

		new_op->upcall.req.setattr.refn = pvfs2_inode->refn;
		if ((new_op->upcall.req.setattr.refn.handle == PVFS_HANDLE_NULL)
		    && (new_op->upcall.req.setattr.refn.fs_id ==
			PVFS_FS_ID_NULL)) {
			struct super_block *sb = inode->i_sb;
			new_op->upcall.req.setattr.refn.handle =
			    PVFS2_SB(sb)->root_handle;
			new_op->upcall.req.setattr.refn.fs_id =
			    PVFS2_SB(sb)->fs_id;
		}
		ret = copy_attributes_from_inode(inode,
			       &new_op->upcall.req.setattr.attributes,
			       iattr);
		if (ret < 0) {
			op_release(new_op);
			return ret;
		}

		ret = service_operation(new_op,
					"pvfs2_inode_setattr",
					get_interruptible_flag(inode));

		gossip_debug(GOSSIP_UTILS_DEBUG,
			     "pvfs2_inode_setattr: returning %d\n",
			     ret);

		/* when request is serviced properly, free req op struct */
		op_release(new_op);

		/*
		 * successful setattr should clear the atime, mtime and
		 * ctime flags.
		 */
		if (ret == 0) {
			ClearAtimeFlag(pvfs2_inode);
			ClearMtimeFlag(pvfs2_inode);
			ClearCtimeFlag(pvfs2_inode);
			ClearModeFlag(pvfs2_inode);
		}
	}
	return ret;
}

int pvfs2_flush_inode(struct inode *inode)
{
	/*
	 * If it is a dirty inode, this function gets called.
	 * Gather all the information that needs to be setattr'ed
	 * Right now, this will only be used for mode, atime, mtime
	 * and/or ctime.
	 */
	struct iattr wbattr;
	int ret;
	int mtime_flag;
	int ctime_flag;
	int atime_flag;
	int mode_flag;
	pvfs2_inode_t *pvfs2_inode = PVFS2_I(inode);
	memset(&wbattr, 0, sizeof(wbattr));

	/*
	 * check inode flags up front, and clear them if they are set.  This
	 * will prevent multiple processes from all trying to flush the same
	 * inode if they call close() simultaneously
	 */
	mtime_flag = MtimeFlag(pvfs2_inode);
	ClearMtimeFlag(pvfs2_inode);
	ctime_flag = CtimeFlag(pvfs2_inode);
	ClearCtimeFlag(pvfs2_inode);
	atime_flag = AtimeFlag(pvfs2_inode);
	ClearAtimeFlag(pvfs2_inode);
	mode_flag = ModeFlag(pvfs2_inode);
	ClearModeFlag(pvfs2_inode);

	/*  -- Lazy atime,mtime and ctime update --
	 * Note: all times are dictated by server in the new scheme
	 * and not by the clients
	 *
	 * Also mode updates are being handled now..
	 */

	if (mtime_flag)
		wbattr.ia_valid |= ATTR_MTIME;
	if (ctime_flag)
		wbattr.ia_valid |= ATTR_CTIME;
	if (atime_flag)
		wbattr.ia_valid |= ATTR_ATIME;

	if (mode_flag) {
		wbattr.ia_mode = inode->i_mode;
		wbattr.ia_valid |= ATTR_MODE;
	}

	gossip_debug(GOSSIP_UTILS_DEBUG,
		     "*********** pvfs2_flush_inode: %llu "
		     "(ia_valid %d)\n",
		     llu(get_handle_from_ino(inode)),
		     wbattr.ia_valid);
	if (wbattr.ia_valid == 0) {
		gossip_debug(GOSSIP_UTILS_DEBUG,
			     "pvfs2_flush_inode skipping setattr()\n");
		return 0;
	}

	gossip_debug(GOSSIP_UTILS_DEBUG,
		     "pvfs2_flush_inode (%llu) writing mode %o\n",
		     llu(get_handle_from_ino(inode)),
		     inode->i_mode);

	ret = pvfs2_inode_setattr(inode, &wbattr);
	return ret;
}

#define SYSTEM_PVFS2_KEY "system.pvfs2."
#define SYSTEM_PVFS2_KEY_LEN 13
/*
 * this function returns
 *   0 if the key corresponding to name is not meant to be printed as part
 *     of a listxattr.
 *   1 if the key corresponding to name is meant to be returned as part of
 *     a listxattr.
 * The ones that start SYSTEM_PVFS2_KEY are the ones to avoid printing.
 */
static int is_reserved_key(const char *key, size_t size)
{

	if (size < SYSTEM_PVFS2_KEY_LEN)
		return 1;

	return strncmp(key, SYSTEM_PVFS2_KEY, SYSTEM_PVFS2_KEY_LEN) ?
		 1 :
		 0 ;
}

/*
 * Tries to get a specified key's attributes of a given
 * file into a user-specified buffer. Note that the getxattr
 * interface allows for the users to probe the size of an
 * extended attribute by passing in a value of 0 to size.
 * Thus our return value is always the size of the attribute
 * unless the key does not exist for the file and/or if
 * there were errors in fetching the attribute value.
 */
ssize_t pvfs2_inode_getxattr(struct inode *inode,
			     const char *prefix,
			     const char *name,
			     void *buffer,
			     size_t size)
{
	ssize_t ret = -ENOMEM;
	pvfs2_kernel_op_t *new_op = NULL;
	pvfs2_inode_t *pvfs2_inode = NULL;
	ssize_t length = 0;
	int fsuid;
	int fsgid;

	if (name == NULL || (size > 0 && buffer == NULL)) {
		gossip_err("pvfs2_inode_getxattr: bogus NULL pointers\n");
		return -EINVAL;
	}
	if (size < 0 ||
	    (strlen(name) + strlen(prefix)) >= PVFS_MAX_XATTR_NAMELEN) {
		gossip_err("Invalid size (%d) or key length (%d)\n",
			   (int)size,
			   (int)(strlen(name) + strlen(prefix)));
		return -EINVAL;
	}
	if (inode) {
		fsuid = from_kuid(&init_user_ns, current_fsuid());
		fsgid = from_kgid(&init_user_ns, current_fsgid());

		gossip_debug(GOSSIP_XATTR_DEBUG,
			     "getxattr on inode %llu, name %s "
			     "(uid %o, gid %o)\n",
			     llu(get_handle_from_ino(inode)),
			     name,
			     fsuid,
			     fsgid);
		pvfs2_inode = PVFS2_I(inode);
		/* obtain the xattr semaphore */
		down_read(&pvfs2_inode->xattr_sem);

		new_op = op_alloc(PVFS2_VFS_OP_GETXATTR);
		if (!new_op) {
			up_read(&pvfs2_inode->xattr_sem);
			return ret;
		}

		new_op->upcall.req.getxattr.refn = pvfs2_inode->refn;
		ret = snprintf((char *)new_op->upcall.req.getxattr.key,
			       PVFS_MAX_XATTR_NAMELEN,
			       "%s%s",
			       prefix,
			       name);
		/*
		 * NOTE: Although keys are meant to be NULL terminated
		 * textual strings, I am going to explicitly pass the
		 * length just in case we change this later on...
		 */
		new_op->upcall.req.getxattr.key_sz = ret + 1;

		ret = service_operation(new_op,
					"pvfs2_inode_getxattr",
					get_interruptible_flag(inode));

		/*
		 * Upon success, we need to get the value length
		 * from downcall and return that.
		 * and also copy the value out to the requester
		 */
		if (ret == 0) {
			ssize_t new_length;
			length = new_op->downcall.resp.getxattr.val_sz;
			new_length = length;

			/*
			 * Just return the length of the queried attribute
			 * after subtracting the \0.
			 */
			if (size == 0)
				ret = new_length;
			else
				/*
				 * check to see if key length is > provided
				 * buffer size
				 */
				if (new_length > size) {
					ret = -ERANGE;
				} else {
					/* No size problems */
					memset(buffer, 0, size);
					memcpy(buffer,
					     new_op->downcall.resp.getxattr.val,
					     new_length);
					ret = new_length;
					gossip_debug(GOSSIP_XATTR_DEBUG,
					     "pvfs2_inode_getxattr: inode %llu "
					     "key %s key_sz %d, val_len %d\n",
					     llu(get_handle_from_ino(inode)),
					     (char *)new_op->
						upcall.req.getxattr.key,
					     (int)new_op->
						upcall.req.getxattr.key_sz,
					     (int)ret);
				}

		} else if (ret == -ENOENT) {
			/* if no such keys exists we set this to be errno */
			ret = -ENODATA;
			gossip_debug(GOSSIP_XATTR_DEBUG,
				     "pvfs2_inode_getxattr: inode %llu key %s"
				     " does not exist!\n",
				     llu(get_handle_from_ino(inode)),
				     (char *)new_op->upcall.req.getxattr.key);
		}

		/* when request is serviced properly, free req op struct */
		op_release(new_op);
		up_read(&pvfs2_inode->xattr_sem);
	}
	return ret;
}

/*
 * tries to set an attribute for a given key on a file.
 * Returns a -ve number on error and 0 on success.
 * Key is text, but value can be binary!
 */
int pvfs2_inode_setxattr(struct inode *inode,
			 const char *prefix,
			 const char *name,
			 const void *value,
			 size_t size,
			 int flags)
{
	int ret = -ENOMEM;
	pvfs2_kernel_op_t *new_op = NULL;
	pvfs2_inode_t *pvfs2_inode = NULL;

	if (size < 0 ||
	    size >= PVFS_MAX_XATTR_VALUELEN ||
	    flags < 0) {
		gossip_err("pvfs2_inode_setxattr: bogus values of size(%d), flags(%d)\n",
			   (int)size,
			   flags);
		return -EINVAL;
	}

	if (name == NULL ||
	    (size > 0 && value == NULL)) {
		gossip_err("pvfs2_inode_setxattr: bogus NULL pointers!\n");
		return -EINVAL;
	}

	if (prefix) {
		if (strlen(name) + strlen(prefix) >= PVFS_MAX_XATTR_NAMELEN) {
			gossip_err
			    ("pvfs2_inode_setxattr: bogus key size (%d)\n",
			     (int)(strlen(name) + strlen(prefix)));
			return -EINVAL;
		}
	} else {
		if (strlen(name) >= PVFS_MAX_XATTR_NAMELEN) {
			gossip_err
			    ("pvfs2_inode_setxattr: bogus key size (%d)\n",
			     (int)(strlen(name)));
			return -EINVAL;
		}
	}

	/* This is equivalent to a removexattr */
	if (size == 0 && value == NULL) {
		gossip_debug(GOSSIP_XATTR_DEBUG,
			     "removing xattr (%s%s)\n",
			     prefix,
			     name);
		return pvfs2_inode_removexattr(inode, prefix, name, flags);
	}

	if (inode) {
		gossip_debug(GOSSIP_XATTR_DEBUG,
			     "setxattr on inode %llu, name %s\n",
			     llu(get_handle_from_ino(inode)),
			     name);
		if (IS_RDONLY(inode)) {
			gossip_err
			    ("pvfs2_inode_setxattr: Read-only file system\n");
			return -EROFS;
		}
		if (IS_IMMUTABLE(inode) || IS_APPEND(inode)) {
			gossip_err("pvfs2_inode_setxattr: Immutable inode or append-only inode; operation not permitted\n");
			return -EPERM;
		}
		pvfs2_inode = PVFS2_I(inode);

		down_write(&pvfs2_inode->xattr_sem);
		new_op = op_alloc(PVFS2_VFS_OP_SETXATTR);
		if (!new_op) {
			up_write(&pvfs2_inode->xattr_sem);
			return ret;
		}

		new_op->upcall.req.setxattr.refn = pvfs2_inode->refn;
		new_op->upcall.req.setxattr.flags = flags;
		/*
		 * NOTE: Although keys are meant to be NULL terminated textual
		 * strings, I am going to explicitly pass the length just in
		 * case we change this later on...
		 */
		ret = snprintf((char *)new_op->upcall.req.setxattr.keyval.key,
			       PVFS_MAX_XATTR_NAMELEN,
			       "%s%s",
			       prefix, name);
		new_op->upcall.req.setxattr.keyval.key_sz = ret + 1;
		memcpy(new_op->upcall.req.setxattr.keyval.val, value, size);
		new_op->upcall.req.setxattr.keyval.val[size] = '\0';
		/* For some reason, val_sz should include the \0 at the end
		 * as well.
		 */
		new_op->upcall.req.setxattr.keyval.val_sz = size + 1;

		gossip_debug(GOSSIP_XATTR_DEBUG,
			     "pvfs2_inode_setxattr: key %s, key_sz %d "
			     " value size %zd\n",
			     (char *)new_op->upcall.req.setxattr.keyval.key,
			     (int)new_op->upcall.req.setxattr.keyval.key_sz,
			     size + 1);

		ret = service_operation(new_op,
					"pvfs2_inode_setxattr",
					get_interruptible_flag(inode));

		gossip_debug(GOSSIP_XATTR_DEBUG,
			     "pvfs2_inode_setxattr: returning %d\n",
			     ret);

		/* when request is serviced properly, free req op struct */
		op_release(new_op);
		up_write(&pvfs2_inode->xattr_sem);
	}
	return ret;
}

int pvfs2_inode_removexattr(struct inode *inode,
			    const char *prefix,
			    const char *name,
			    int flags)
{
	int ret = -ENOMEM;
	pvfs2_kernel_op_t *new_op = NULL;
	pvfs2_inode_t *pvfs2_inode = NULL;

	if (!name) {
		gossip_err("pvfs2_inode_removexattr: xattr key is NULL\n");
		return -EINVAL;
	}

	if (prefix) {
		if ((strlen(name) + strlen(prefix)) >= PVFS_MAX_XATTR_NAMELEN) {
			gossip_err
			   ("pvfs2_inode_removexattr: Invalid key length(%d)\n",
			    (int)(strlen(name) + strlen(prefix)));
			return -EINVAL;
		}
	} else {
		if (strlen(name) >= PVFS_MAX_XATTR_NAMELEN) {
			gossip_err
			   ("pvfs2_inode_removexattr: Invalid key length(%d)\n",
			    (int)(strlen(name)));
			return -EINVAL;
		}
	}

	if (inode) {
		pvfs2_inode = PVFS2_I(inode);

		down_write(&pvfs2_inode->xattr_sem);
		new_op = op_alloc(PVFS2_VFS_OP_REMOVEXATTR);
		if (!new_op) {
			up_write(&pvfs2_inode->xattr_sem);
			return ret;
		}

		new_op->upcall.req.removexattr.refn = pvfs2_inode->refn;
		/*
		 * NOTE: Although keys are meant to be NULL terminated
		 * textual strings, I am going to explicitly pass the
		 * length just in case we change this later on...
		 */
		ret = snprintf((char *)new_op->upcall.req.removexattr.key,
			       PVFS_MAX_XATTR_NAMELEN,
			       "%s%s",
			       (prefix ? prefix : ""),
			       name);
		new_op->upcall.req.removexattr.key_sz = ret + 1;

		gossip_debug(GOSSIP_XATTR_DEBUG,
			     "pvfs2_inode_removexattr: key %s, key_sz %d\n",
			     (char *)new_op->upcall.req.removexattr.key,
			     (int)new_op->upcall.req.removexattr.key_sz);

		ret = service_operation(new_op,
					"pvfs2_inode_removexattr",
					get_interruptible_flag(inode));

		if (ret == -ENOENT) {
			/*
			 * Request to replace a non-existent attribute is an
			 * error
			 */
			if (flags & XATTR_REPLACE)
				ret = -ENODATA;
			else
				ret = 0;
		}
		gossip_debug(GOSSIP_XATTR_DEBUG,
			     "pvfs2_inode_removexattr: returning %d\n", ret);

		/* when request is serviced properly, free req op struct */
		op_release(new_op);
		up_write(&pvfs2_inode->xattr_sem);
	}
	return ret;
}

/*
 * Tries to get a specified object's keys into a user-specified
 * buffer of a given size.
 * Note that like the previous instances of xattr routines,
 * this also allows you to pass in a NULL pointer and 0 size
 * to probe the size for subsequent memory allocations.
 * Thus our return value is always the size of all the keys
 * unless there were errors in fetching the keys!
 */
int pvfs2_inode_listxattr(struct inode *inode, char *buffer, size_t size)
{
	ssize_t ret = -ENOMEM;
	ssize_t total = 0;
	int i = 0;
	int count_keys = 0;
	pvfs2_kernel_op_t *new_op = NULL;
	pvfs2_inode_t *pvfs2_inode = NULL;
	ssize_t length = 0;

	if (size > 0 && buffer == NULL) {
		gossip_err("pvfs2_inode_listxattr: bogus NULL pointers\n");
		return -EINVAL;
	}
	if (size < 0) {
		gossip_err("Invalid size (%d)\n", (int)size);
		return -EINVAL;
	}
	if (inode) {
		PVFS_ds_position token = PVFS_ITERATE_START;

		pvfs2_inode = PVFS2_I(inode);
		/* obtain the xattr semaphore */
		down_read(&pvfs2_inode->xattr_sem);

		new_op = op_alloc(PVFS2_VFS_OP_LISTXATTR);
		if (!new_op) {
			up_read(&pvfs2_inode->xattr_sem);
			return ret;
		}
		if (buffer && size > 0)
			memset(buffer, 0, size);

try_again:
		new_op->upcall.req.listxattr.refn = pvfs2_inode->refn;
		new_op->upcall.req.listxattr.token = token;
		new_op->upcall.req.listxattr.requested_count =
		    (size == 0) ? 0 : PVFS_MAX_XATTR_LISTLEN;
		ret = service_operation(new_op,
					"pvfs2_inode_listxattr",
					get_interruptible_flag(inode));
		if (ret == 0) {
		  if (size == 0) {
		    /*
		     * This is a bit of a big upper limit, but I
		     * did not want to spend too much time getting
		     * this correct, since users end up allocating
		     * memory rather than us...
		     */
		    total = new_op->downcall.resp.listxattr.returned_count *
			    PVFS_MAX_XATTR_NAMELEN;
		    goto done;
		  }
		  length = new_op->downcall.resp.listxattr.keylen;
		  if (length == 0) {
		    goto done;
		  } else {
		    int key_size = 0;
		    /*
		     * check to see how much can be fit in the
		     * buffer. fit only whole keys
		     */
		    for (i = 0;
			 i < new_op->downcall.resp.listxattr.returned_count;
			 i++) {
		      if (total + new_op->downcall.resp.listxattr.lengths[i] <=
			  size) {
			/* Since many dumb programs try to setxattr()
			 * on our reserved xattrs this is a feeble
			 * attempt at defeating those by not listing
			 * them in the output of listxattr.. sigh
			 */

			if (is_reserved_key(
			     new_op->downcall.resp.listxattr.key + key_size,
			     new_op->downcall.resp.listxattr.lengths[i]) == 0) {
			  gossip_debug(GOSSIP_XATTR_DEBUG,
			      "Copying key %d -> %s\n",
			      i,
			      new_op->downcall.resp.listxattr.key + key_size);
			  memcpy(buffer + total,
			  new_op->downcall.resp.listxattr.key + key_size,
				 new_op->downcall.resp.listxattr.lengths[i]);
			  total += new_op->downcall.resp.listxattr.lengths[i];
			  count_keys++;
			} else {
			  gossip_debug(GOSSIP_XATTR_DEBUG,
			       "[RESERVED] key %d -> %s\n",
			       i,
			       new_op->downcall.resp.listxattr.key + key_size);
			}
			key_size += new_op->downcall.resp.listxattr.lengths[i];
		      } else {
			goto done;
		      }
		    }
		    /*
		     * Since the buffer was large enough, we might have to
		     * continue fetching more keys!
		     */
		    token = new_op->downcall.resp.listxattr.token;
		    if (token != PVFS_ITERATE_END)
			goto try_again;
		  }
		}
done:
		gossip_debug(GOSSIP_XATTR_DEBUG,
			     "pvfs2_inode_listxattr: returning %d"
			     " [size of buffer %ld] (filled in %d keys)\n",
			     ret ? (int)ret : (int)total,
			     (long)size,
			     count_keys);
		/* when request is serviced properly, free req op struct */
		op_release(new_op);
		up_read(&pvfs2_inode->xattr_sem);
		if (ret == 0)
			ret = total;
	}
	return ret;
}

int pvfs2_remove_entry(struct inode *dir, struct dentry *dentry)
{
	int ret = -EINVAL;
	pvfs2_kernel_op_t *new_op = NULL;
	pvfs2_inode_t *parent = PVFS2_I(dir);
	struct inode *inode = dentry->d_inode;

	if (inode && parent && dentry) {
		gossip_debug(GOSSIP_UTILS_DEBUG,
			     "pvfs2_remove_entry: called on %s\n"
			     "  (inode %llu): Parent is %llu | fs_id %d\n",
			     dentry->d_name.name,
			     llu(get_handle_from_ino(inode)),
			     llu(parent->refn.handle),
			     parent->refn.fs_id);

		new_op = op_alloc(PVFS2_VFS_OP_REMOVE);
		if (!new_op)
			return -ENOMEM;

		if (parent && parent->refn.handle != PVFS_HANDLE_NULL
		    && parent->refn.fs_id != PVFS_FS_ID_NULL) {
			new_op->upcall.req.remove.parent_refn = parent->refn;
		} else {
			gossip_lerr("Critical error: i_ino cannot be relied on when using iget4/5\n");
			op_release(new_op);
			return -ENOMEM;
		}
		strncpy(new_op->upcall.req.remove.d_name,
			dentry->d_name.name,
			PVFS2_NAME_LEN);

		ret = service_operation(new_op,
					"pvfs2_remove_entry",
					get_interruptible_flag(inode));

		/* when request is serviced properly, free req op struct */
		op_release(new_op);
	}
	return ret;
}

int pvfs2_truncate_inode(struct inode *inode, loff_t size)
{
	int ret = -EINVAL;
	pvfs2_inode_t *pvfs2_inode = PVFS2_I(inode);
	pvfs2_kernel_op_t *new_op = NULL;

	gossip_debug(GOSSIP_UTILS_DEBUG,
		     "pvfs2: pvfs2_truncate_inode %llu: Handle is %llu | fs_id %d | size is %lu\n",
		     llu(get_handle_from_ino(inode)),
		     llu(pvfs2_inode->refn.handle),
		     pvfs2_inode->refn.fs_id,
		     (unsigned long)size);

	new_op = op_alloc(PVFS2_VFS_OP_TRUNCATE);
	if (!new_op)
		return -ENOMEM;

	new_op->upcall.req.truncate.refn = pvfs2_inode->refn;
	new_op->upcall.req.truncate.size = (PVFS_size) size;

	ret = service_operation(new_op,
				"pvfs2_truncate_inode",
				get_interruptible_flag(inode));

	/*
	 * the truncate has no downcall members to retrieve, but
	 * the status value tells us if it went through ok or not
	 */
	gossip_debug(GOSSIP_UTILS_DEBUG,
		     "pvfs2: pvfs2_truncate got return value of %d\n",
		     ret);

	op_release(new_op);

	return ret;
}

int pvfs2_unmount_sb(struct super_block *sb)
{
	int ret = -EINVAL;
	pvfs2_kernel_op_t *new_op = NULL;

	gossip_debug(GOSSIP_UTILS_DEBUG,
		     "pvfs2_unmount_sb called on sb %p\n",
		     sb);

	new_op = op_alloc(PVFS2_VFS_OP_FS_UMOUNT);
	if (!new_op)
		return -ENOMEM;
	new_op->upcall.req.fs_umount.id = PVFS2_SB(sb)->id;
	new_op->upcall.req.fs_umount.fs_id = PVFS2_SB(sb)->fs_id;
	strncpy(new_op->upcall.req.fs_umount.pvfs2_config_server,
		PVFS2_SB(sb)->devname,
		PVFS_MAX_SERVER_ADDR_LEN);

	gossip_debug(GOSSIP_UTILS_DEBUG,
		     "Attempting PVFS2 Unmount via host %s\n",
		     new_op->upcall.req.fs_umount.pvfs2_config_server);

	ret = service_operation(new_op, "pvfs2_fs_umount", 0);

	gossip_debug(GOSSIP_UTILS_DEBUG,
		     "pvfs2_unmount: got return value of %d\n", ret);
	if (ret)
		sb = ERR_PTR(ret);
	else
		PVFS2_SB(sb)->mount_pending = 1;

	op_release(new_op);
	return ret;
}

/*
 * NOTE: on successful cancellation, be sure to return -EINTR, as
 * that's the return value the caller expects
 */
int pvfs2_cancel_op_in_progress(uint64_t tag)
{
	int ret = -EINVAL;
	pvfs2_kernel_op_t *new_op = NULL;

	gossip_debug(GOSSIP_UTILS_DEBUG,
		     "pvfs2_cancel_op_in_progress called on tag %llu\n",
		     llu(tag));

	new_op = op_alloc(PVFS2_VFS_OP_CANCEL);
	if (!new_op)
		return -ENOMEM;
	new_op->upcall.req.cancel.op_tag = tag;

	gossip_debug(GOSSIP_UTILS_DEBUG,
		     "Attempting PVFS2 operation cancellation of tag %llu\n",
		     llu(new_op->upcall.req.cancel.op_tag));

	ret = service_operation(new_op, "pvfs2_cancel", PVFS2_OP_CANCELLATION);

	gossip_debug(GOSSIP_UTILS_DEBUG,
		     "pvfs2_cancel_op_in_progress: got return value of %d\n",
		     ret);

	op_release(new_op);
	return ret;
}

/*
 * this is called from super:pvfs2_destroy_inode.
 */
void pvfs2_inode_finalize(pvfs2_inode_t *pvfs2_inode)
{
	pvfs2_inode->refn.handle = PVFS_HANDLE_NULL;
	pvfs2_inode->refn.fs_id = PVFS_FS_ID_NULL;
	pvfs2_inode->last_failed_block_index_read = 0;
	pvfs2_inode->error_code = 0;
}

void pvfs2_op_initialize(pvfs2_kernel_op_t *op)
{
	if (op) {
		spin_lock(&op->lock);
		op->io_completed = 0;

		op->upcall.type = PVFS2_VFS_OP_INVALID;
		op->downcall.type = PVFS2_VFS_OP_INVALID;
		op->downcall.status = -1;

		op->op_state = OP_VFS_STATE_UNKNOWN;
		op->tag = 0;
		spin_unlock(&op->lock);
	}
}

void pvfs2_make_bad_inode(struct inode *inode)
{
	if (is_root_handle(inode)) {
		/*
		 * if this occurs, the pvfs2-client-core was killed but we
		 * can't afford to lose the inode operations and such
		 * associated with the root handle in any case.
		 */
		gossip_debug(GOSSIP_UTILS_DEBUG,
			     "*** NOT making bad root inode %llu\n",
			     llu(get_handle_from_ino(inode)));
	} else {
		gossip_debug(GOSSIP_UTILS_DEBUG,
			     "*** making bad inode %llu\n",
			     llu(get_handle_from_ino(inode)));
		make_bad_inode(inode);
	}
}

/* this code is based on linux/net/sunrpc/clnt.c:rpc_clnt_sigmask */
void mask_blocked_signals(sigset_t *orig_sigset)
{
	unsigned long sigallow = sigmask(SIGKILL);
	unsigned long irqflags = 0;
	struct k_sigaction *action = pvfs2_current_sigaction;

	sigallow |= ((action[SIGINT - 1].sa.sa_handler == SIG_DFL) ?
		     sigmask(SIGINT) :
		     0);
	sigallow |= ((action[SIGQUIT - 1].sa.sa_handler == SIG_DFL) ?
		     sigmask(SIGQUIT) :
		     0);

	spin_lock_irqsave(&pvfs2_current_signal_lock, irqflags);
	*orig_sigset = current->blocked;
	siginitsetinv(&current->blocked, sigallow & ~orig_sigset->sig[0]);
	recalc_sigpending();
	spin_unlock_irqrestore(&pvfs2_current_signal_lock, irqflags);
}

/* this code is based on linux/net/sunrpc/clnt.c:rpc_clnt_sigunmask */
void unmask_blocked_signals(sigset_t *orig_sigset)
{
	unsigned long irqflags = 0;

	spin_lock_irqsave(&pvfs2_current_signal_lock, irqflags);
	current->blocked = *orig_sigset;
	recalc_sigpending();
	spin_unlock_irqrestore(&pvfs2_current_signal_lock, irqflags);
}

PVFS_time pvfs2_convert_time_field(void *time_ptr)
{
	PVFS_time pvfs2_time;
	struct timespec *tspec = (struct timespec *)time_ptr;
	pvfs2_time = (PVFS_time) ((time_t) tspec->tv_sec);
	return pvfs2_time;
}

/* macro defined in include/pvfs2-types.h */
DECLARE_ERRNO_MAPPING_AND_FN();

int pvfs2_normalize_to_errno(PVFS_error error_code)
{
	if (error_code > 0) {
		gossip_err("pvfs2: error status receieved.\n");
		gossip_err("pvfs2: assuming error code is inverted.\n");
		error_code = -error_code;
	}

	/* convert any error codes that are in pvfs2 format */
	if (IS_PVFS_NON_ERRNO_ERROR(-error_code)) {
		if (PVFS_NON_ERRNO_ERROR_CODE(-error_code) == PVFS_ECANCEL) {
			/*
			 * cancellation error codes generally correspond to
			 * a timeout from the client's perspective
			 */
			error_code = -ETIMEDOUT;
		} else {
			/* assume a default error code */
			gossip_err("pvfs2: warning: got error code without errno equivalent: %d.\n",
				   error_code);
			error_code = -EINVAL;
		}
	} else if (IS_PVFS_ERROR(-error_code)) {
		error_code = -PVFS_ERROR_TO_ERRNO(-error_code);
	}
	return error_code;
}

#define NUM_MODES 11
int32_t PVFS_util_translate_mode(int mode)
{
	int ret = 0;
	int i = 0;
	static int modes[NUM_MODES] = {
		S_IXOTH, S_IWOTH, S_IROTH,
		S_IXGRP, S_IWGRP, S_IRGRP,
		S_IXUSR, S_IWUSR, S_IRUSR,
		S_ISGID, S_ISUID
	};
	static int pvfs2_modes[NUM_MODES] = {
		PVFS_O_EXECUTE, PVFS_O_WRITE, PVFS_O_READ,
		PVFS_G_EXECUTE, PVFS_G_WRITE, PVFS_G_READ,
		PVFS_U_EXECUTE, PVFS_U_WRITE, PVFS_U_READ,
		PVFS_G_SGID, PVFS_U_SUID
	};

	for (i = 0; i < NUM_MODES; i++)
		if (mode & modes[i])
			ret |= pvfs2_modes[i];

	return ret;
}
#undef NUM_MODES

static char *pvfs2_strtok(char *s, const char *toks)
{
	/* original string */
	static char *in_string_p;
	/* starting value of in_string_p during this iteration. */
	char *this_string_p;
	/* # of tokens */
	uint32_t toks_len = strlen(toks);
	/* index */
	uint32_t i;

	/* when s has a value, we are using a new input string */
	if (s)
		in_string_p = s;

	/* set new starting position */
	this_string_p = in_string_p;

	/*
	 * loop through the string until a token or end-of-string(null)
	 * is found.
	 */
	for (; *in_string_p; in_string_p++)
		/* Is character a token? */
		for (i = 0; i < toks_len; i++)
			if (*in_string_p == toks[i]) {
				/*token found => end-of-word */
				*in_string_p = 0;
				in_string_p++;
				return this_string_p;
			}

	if (*this_string_p == 0)
		return NULL;

	return this_string_p;
}

/*convert 64-bit debug mask into a readable string of keywords*/
static int proc_mask_to_debug(struct __keyword_mask_t *mask_map,
			      int num_mask_map,
			      uint64_t mask,
			      char *debug_string)
{
	unsigned int index = 0;
	unsigned int i;

	memset(debug_string, 0, PVFS2_MAX_DEBUG_STRING_LEN);

	for (i = 0; i < num_mask_map; i++) {
		if ((index + strlen(mask_map[i].keyword)) >=
		    PVFS2_MAX_DEBUG_STRING_LEN)
			return 0;

		switch (mask_map[i].mask_val) {
		case GOSSIP_NO_DEBUG:
			if (mask == GOSSIP_NO_DEBUG) {
				strcpy(debug_string, mask_map[i].keyword);
				return 0;
			}
			break;
		case GOSSIP_MAX_DEBUG:
			if (mask == GOSSIP_MAX_DEBUG) {
				strcpy(debug_string, mask_map[i].keyword);
				return 0;
			}
			break;
		default:
			if ((mask & mask_map[i].mask_val) !=
			    mask_map[i].mask_val)
				/*mask does NOT contain the mask value */
				break;

			if (index != 0) {
				/*
				 * add comma for second and subsequent mask
				 * keywords
				 */
				(debug_string[index]) = ',';
				index++;
			}

			/*add keyword and slide index */
			memcpy(&debug_string[index],
			       mask_map[i].keyword,
			       strlen(mask_map[i].keyword));
			index += strlen(mask_map[i].keyword);
		}
	}

	return 0;
}

static uint64_t proc_debug_to_mask(struct __keyword_mask_t *mask_map,
				   int num_mask_map,
				   const char *event_logging)
{
	uint64_t mask = 0;
	char *s = NULL;
	char *t = NULL;
	const char *toks = ", ";
	int i = 0;
	int negate = 0;
	int slen = 0;

	if (event_logging) {
		/* s = strdup(event_logging); */
		slen = strlen(event_logging);
		s = kmalloc(slen + 1, GFP_KERNEL);
		if (!s)
			return -ENOMEM;
		memset(s, 0, slen + 1);
		memcpy(s, event_logging, slen);

		/* t = strtok(s, toks); */
		t = pvfs2_strtok(s, toks);

		while (t) {
			if (*t == '-') {
				negate = 1;
				++t;
			}

			for (i = 0; i < num_mask_map; i++) {
				if (!strcmp(t, mask_map[i].keyword)) {

					if (negate)
						mask &= ~mask_map[i].mask_val;
					else
						mask |= mask_map[i].mask_val;

					break;
				}
			}
			/* t = strtok(NULL, toks); */
			t = pvfs2_strtok(NULL, toks);
		}
		kfree(s);
	}
	return mask;
}

/*
 * Based on human readable keywords, translate them into
 * a mask value appropriate for the debugging level desired.
 * The 'computed' mask is returned; 0 if no keywords are
 * present or recognized.  Unrecognized keywords are ignored when
 * mixed with recognized keywords.
 *
 * Prefix a keyword with "-" to turn it off.  All keywords
 * processed in specified order.
 */
uint64_t PVFS_proc_debug_eventlog_to_mask(const char *event_logging)
{
	return proc_debug_to_mask(s_keyword_mask_map,
				  num_keyword_mask_map,
				  event_logging);
}

uint64_t PVFS_proc_kmod_eventlog_to_mask(const char *event_logging)
{
	return proc_debug_to_mask(s_kmod_keyword_mask_map,
				  num_kmod_keyword_mask_map,
				  event_logging);
}

int PVFS_proc_kmod_mask_to_eventlog(uint64_t mask, char *debug_string)
{
	return proc_mask_to_debug(s_kmod_keyword_mask_map,
				  num_kmod_keyword_mask_map,
				  mask,
				  debug_string);
}

int PVFS_proc_mask_to_eventlog(uint64_t mask, char *debug_string)
{

	return proc_mask_to_debug(s_keyword_mask_map,
				  num_keyword_mask_map,
				  mask,
				  debug_string);
}
