/*
 * (C) 2001 Clemson University and The University of Chicago
 *
 * See COPYING in top-level directory.
 */

/*
 *  Linux VFS file operations.
 */

#include "protocol.h"
#include "pvfs2-kernel.h"
#include "pvfs2-bufmap.h"
#include <linux/fs.h>
#include <linux/pagemap.h>

#define wake_up_daemon_for_return(op)			\
do {							\
	spin_lock(&op->lock);                           \
	op->io_completed = 1;                           \
	spin_unlock(&op->lock);                         \
	wake_up_interruptible(&op->io_completion_waitq);\
} while (0)

/*
 * Copy to client-core's address space from the buffers specified
 * by the iovec upto total_size bytes.
 * NOTE: the iovector can either contain addresses which
 *       can futher be kernel-space or user-space addresses.
 *       or it can pointers to struct page's
 */
static int precopy_buffers(int buffer_index, const struct iovec *vec,
		unsigned long nr_segs, size_t total_size, int from_user)
{
	int ret = 0;

	/*
	 * copy data from application/kernel by pulling it out
	 * of the iovec.
	 */
	/* Are we copying from User Virtual Addresses? */
	if (from_user)
		ret = pvfs_bufmap_copy_iovec_from_user(
			buffer_index,
			vec,
			nr_segs,
			total_size);
	/* Are we copying from Kernel Virtual Addresses? */
	else
		ret = pvfs_bufmap_copy_iovec_from_kernel(
			buffer_index,
			vec,
			nr_segs,
			total_size);
	if (ret < 0)
		gossip_err("%s: Failed to copy-in buffers. Please make sure that the pvfs2-client is running. %ld\n",
			__func__,
			(long)ret);
	return ret;
}

/*
 * Copy from client-core's address space to the buffers specified
 * by the iovec upto total_size bytes.
 * NOTE: the iovector can either contain addresses which
 *       can futher be kernel-space or user-space addresses.
 *       or it can pointers to struct page's
 */
static int postcopy_buffers(int buffer_index,
			    const struct iovec *vec,
			    int nr_segs,
			    size_t total_size,
			    int to_user)
{
	int ret = 0;

	/*
	 * copy data to application/kernel by pushing it out to
	 * the iovec. NOTE; target buffers can be addresses or
	 * struct page pointers.
	 */
	if (total_size) {
		/* Are we copying to User Virtual Addresses? */
		if (to_user)
			ret = pvfs_bufmap_copy_to_user_iovec(
				buffer_index,
				vec,
				nr_segs,
				total_size);
		/* Are we copying to Kern Virtual Addresses? */
		else
			ret = pvfs_bufmap_copy_to_kernel_iovec(
				buffer_index,
				vec,
				nr_segs,
				total_size);
		if (ret < 0)
			gossip_err("%s: Failed to copy-out buffers.  Please make sure that the pvfs2-client is running (%ld)\n",
				__func__,
				(long)ret);
	}
	return ret;
}

/*
 * Post and wait for the I/O upcall to finish
 */
static ssize_t wait_for_direct_io(enum PVFS_io_type type, struct inode *inode,
		loff_t *offset, struct iovec *vec, unsigned long nr_segs,
		size_t total_size, loff_t readahead_size, int to_user)
{
	struct pvfs2_inode_s *pvfs2_inode = PVFS2_I(inode);
	struct pvfs2_khandle *handle = &pvfs2_inode->refn.khandle;
	struct pvfs2_kernel_op *new_op = NULL;
	int buffer_index = -1;
	ssize_t ret;

	new_op = op_alloc(PVFS2_VFS_OP_FILE_IO);
	if (!new_op) {
		ret = -ENOMEM;
		goto out;
	}
	/* synchronous I/O */
	new_op->upcall.req.io.async_vfs_io = PVFS_VFS_SYNC_IO;
	new_op->upcall.req.io.readahead_size = readahead_size;
	new_op->upcall.req.io.io_type = type;
	new_op->upcall.req.io.refn = pvfs2_inode->refn;

populate_shared_memory:
	/* get a shared buffer index */
	ret = pvfs_bufmap_get(&buffer_index);
	if (ret < 0) {
		gossip_debug(GOSSIP_FILE_DEBUG,
			     "%s: pvfs_bufmap_get failure (%ld)\n",
			     __func__, (long)ret);
		goto out;
	}
	gossip_debug(GOSSIP_FILE_DEBUG,
		     "%s(%pU): GET op %p -> buffer_index %d\n",
		     __func__,
		     handle,
		     new_op,
		     buffer_index);

	new_op->uses_shared_memory = 1;
	new_op->upcall.req.io.buf_index = buffer_index;
	new_op->upcall.req.io.count = total_size;
	new_op->upcall.req.io.offset = *offset;

	gossip_debug(GOSSIP_FILE_DEBUG,
		     "%s(%pU): copy_to_user %d nr_segs %lu, offset: %llu total_size: %zd\n",
		     __func__,
		     handle,
		     to_user,
		     nr_segs,
		     llu(*offset),
		     total_size);
	/*
	 * Stage 1: copy the buffers into client-core's address space
	 * precopy_buffers only pertains to writes.
	 */
	if (type == PVFS_IO_WRITE) {
		ret = precopy_buffers(buffer_index, vec, nr_segs,
				total_size, to_user);
		if (ret < 0)
			goto out;
	}

	gossip_debug(GOSSIP_FILE_DEBUG,
		     "%s(%pU): Calling post_io_request with tag (%llu)\n",
		     __func__,
		     handle,
		     llu(new_op->tag));

	/* Stage 2: Service the I/O operation */
	ret = service_operation(new_op,
				type == PVFS_IO_WRITE ? "file_write" : "file_read",
				get_interruptible_flag(inode));

	/*
	 * If service_operation() returns -EAGAIN #and# the operation was
	 * purged from pvfs2_request_list or htable_ops_in_progress, then
	 * we know that the client was restarted, causing the shared memory
	 * area to be wiped clean.  To restart a  write operation in this
	 * case, we must re-copy the data from the user's iovec to a NEW
	 * shared memory location. To restart a read operation, we must get
	 * a new shared memory location.
	 */
	if (ret == -EAGAIN && op_state_purged(new_op)) {
		gossip_debug(GOSSIP_WAIT_DEBUG,
			     "%s:going to repopulate_shared_memory.\n",
			     __func__);
		goto populate_shared_memory;
	}

	if (ret < 0) {
		handle_io_error(); /* defined in pvfs2-kernel.h */
		/*
		   don't write an error to syslog on signaled operation
		   termination unless we've got debugging turned on, as
		   this can happen regularly (i.e. ctrl-c)
		 */
		if (ret == -EINTR)
			gossip_debug(GOSSIP_FILE_DEBUG,
				     "%s: returning error %ld\n", __func__,
				     (long)ret);
		else
			gossip_err("%s: error in %s handle %pU, returning %zd\n",
				__func__,
				type == PVFS_IO_READ ?
					"read from" : "write to",
				handle, ret);
		goto out;
	}

	/*
	 * Stage 3: Post copy buffers from client-core's address space
	 * postcopy_buffers only pertains to reads.
	 */
	if (type == PVFS_IO_READ) {
		ret = postcopy_buffers(buffer_index, vec, nr_segs,
			       new_op->downcall.resp.io.amt_complete,
			       to_user);
		if (ret < 0) {
			/*
			 * put error codes in downcall so that handle_io_error()
			 * preserves it properly
			 */
			new_op->downcall.status = ret;
			handle_io_error();
			goto out;
		}
	}
	gossip_debug(GOSSIP_FILE_DEBUG,
	    "%s(%pU): Amount written as returned by the sys-io call:%d\n",
	    __func__,
	    handle,
	    (int)new_op->downcall.resp.io.amt_complete);

	ret = new_op->downcall.resp.io.amt_complete;

	/*
	   tell the device file owner waiting on I/O that this read has
	   completed and it can return now.  in this exact case, on
	   wakeup the daemon will free the op, so we *cannot* touch it
	   after this.
	 */
	wake_up_daemon_for_return(new_op);
	new_op = NULL;

out:
	if (buffer_index >= 0) {
		pvfs_bufmap_put(buffer_index);
		gossip_debug(GOSSIP_FILE_DEBUG,
			     "%s(%pU): PUT buffer_index %d\n",
			     __func__, handle, buffer_index);
		buffer_index = -1;
	}
	if (new_op) {
		op_release(new_op);
		new_op = NULL;
	}
	return ret;
}

/*
 * The reason we need to do this is to be able to support readv and writev
 * that are larger than (pvfs_bufmap_size_query()) Default is
 * PVFS2_BUFMAP_DEFAULT_DESC_SIZE MB. What that means is that we will
 * create a new io vec descriptor for those memory addresses that
 * go beyond the limit. Return value for this routine is negative in case
 * of errors and 0 in case of success.
 *
 * Further, the new_nr_segs pointer is updated to hold the new value
 * of number of iovecs, the new_vec pointer is updated to hold the pointer
 * to the new split iovec, and the size array is an array of integers holding
 * the number of iovecs that straddle pvfs_bufmap_size_query().
 * The max_new_nr_segs value is computed by the caller and returned.
 * (It will be (count of all iov_len/ block_size) + 1).
 */
static int split_iovecs(unsigned long max_new_nr_segs,		/* IN */
			unsigned long nr_segs,			/* IN */
			const struct iovec *original_iovec,	/* IN */
			unsigned long *new_nr_segs,		/* OUT */
			struct iovec **new_vec,			/* OUT */
			unsigned long *seg_count,		/* OUT */
			unsigned long **seg_array)		/* OUT */
{
	unsigned long seg;
	unsigned long count = 0;
	unsigned long begin_seg;
	unsigned long tmpnew_nr_segs = 0;
	struct iovec *new_iovec = NULL;
	struct iovec *orig_iovec;
	unsigned long *sizes = NULL;
	unsigned long sizes_count = 0;

	if (nr_segs <= 0 ||
	    original_iovec == NULL ||
	    new_nr_segs == NULL ||
	    new_vec == NULL ||
	    seg_count == NULL ||
	    seg_array == NULL ||
	    max_new_nr_segs <= 0) {
		gossip_err("Invalid parameters to split_iovecs\n");
		return -EINVAL;
	}
	*new_nr_segs = 0;
	*new_vec = NULL;
	*seg_count = 0;
	*seg_array = NULL;
	/* copy the passed in iovec descriptor to a temp structure */
	orig_iovec = kmalloc(nr_segs * sizeof(*orig_iovec),
			     PVFS2_BUFMAP_GFP_FLAGS);
	if (orig_iovec == NULL) {
		gossip_err(
		    "split_iovecs: Could not allocate memory for %lu bytes!\n",
		    (unsigned long)(nr_segs * sizeof(*orig_iovec)));
		return -ENOMEM;
	}
	new_iovec = kzalloc(max_new_nr_segs * sizeof(*new_iovec),
			    PVFS2_BUFMAP_GFP_FLAGS);
	if (new_iovec == NULL) {
		kfree(orig_iovec);
		gossip_err(
		    "split_iovecs: Could not allocate memory for %lu bytes!\n",
		    (unsigned long)(max_new_nr_segs * sizeof(*new_iovec)));
		return -ENOMEM;
	}
	sizes = kzalloc(max_new_nr_segs * sizeof(*sizes),
			PVFS2_BUFMAP_GFP_FLAGS);
	if (sizes == NULL) {
		kfree(new_iovec);
		kfree(orig_iovec);
		gossip_err(
		    "split_iovecs: Could not allocate memory for %lu bytes!\n",
		    (unsigned long)(max_new_nr_segs * sizeof(*sizes)));
		return -ENOMEM;
	}
	/* copy the passed in iovec to a temp structure */
	memcpy(orig_iovec, original_iovec, nr_segs * sizeof(*orig_iovec));
	begin_seg = 0;
repeat:
	for (seg = begin_seg; seg < nr_segs; seg++) {
		if (tmpnew_nr_segs >= max_new_nr_segs ||
		    sizes_count >= max_new_nr_segs) {
			kfree(sizes);
			kfree(orig_iovec);
			kfree(new_iovec);
			gossip_err
			    ("split_iovecs: exceeded the index limit (%lu)\n",
			    tmpnew_nr_segs);
			return -EINVAL;
		}
		if (count + orig_iovec[seg].iov_len <
		    pvfs_bufmap_size_query()) {
			count += orig_iovec[seg].iov_len;
			memcpy(&new_iovec[tmpnew_nr_segs],
			       &orig_iovec[seg],
			       sizeof(*new_iovec));
			tmpnew_nr_segs++;
			sizes[sizes_count]++;
		} else {
			new_iovec[tmpnew_nr_segs].iov_base =
			    orig_iovec[seg].iov_base;
			new_iovec[tmpnew_nr_segs].iov_len =
			    (pvfs_bufmap_size_query() - count);
			tmpnew_nr_segs++;
			sizes[sizes_count]++;
			sizes_count++;
			begin_seg = seg;
			orig_iovec[seg].iov_base +=
			    (pvfs_bufmap_size_query() - count);
			orig_iovec[seg].iov_len -=
			    (pvfs_bufmap_size_query() - count);
			count = 0;
			break;
		}
	}
	if (seg != nr_segs)
		goto repeat;
	else
		sizes_count++;

	*new_nr_segs = tmpnew_nr_segs;
	/* new_iovec is freed by the caller */
	*new_vec = new_iovec;
	*seg_count = sizes_count;
	/* seg_array is also freed by the caller */
	*seg_array = sizes;
	kfree(orig_iovec);
	return 0;
}

static long bound_max_iovecs(const struct iovec *curr, unsigned long nr_segs,
			     ssize_t *total_count)
{
	unsigned long i;
	long max_nr_iovecs;
	ssize_t total;
	ssize_t count;

	total = 0;
	count = 0;
	max_nr_iovecs = 0;
	for (i = 0; i < nr_segs; i++) {
		const struct iovec *iv = &curr[i];
		count += iv->iov_len;
		if (unlikely((ssize_t) (count | iv->iov_len) < 0))
			return -EINVAL;
		if (total + iv->iov_len < pvfs_bufmap_size_query()) {
			total += iv->iov_len;
			max_nr_iovecs++;
		} else {
			total =
			    (total + iv->iov_len - pvfs_bufmap_size_query());
			max_nr_iovecs += (total / pvfs_bufmap_size_query() + 2);
		}
	}
	*total_count = count;
	return max_nr_iovecs;
}

/*
 * Common entry point for read/write/readv/writev
 * This function will dispatch it to either the direct I/O
 * or buffered I/O path depending on the mount options and/or
 * augmented/extended metadata attached to the file.
 * Note: File extended attributes override any mount options.
 */
static ssize_t do_readv_writev(enum PVFS_io_type type, struct file *file,
		loff_t *offset, const struct iovec *iov, unsigned long nr_segs)
{
	struct inode *inode = file->f_mapping->host;
	struct pvfs2_inode_s *pvfs2_inode = PVFS2_I(inode);
	struct pvfs2_khandle *handle = &pvfs2_inode->refn.khandle;
	ssize_t ret;
	ssize_t total_count;
	unsigned int to_free;
	size_t count;
	unsigned long seg;
	unsigned long new_nr_segs = 0;
	unsigned long max_new_nr_segs = 0;
	unsigned long seg_count = 0;
	unsigned long *seg_array = NULL;
	struct iovec *iovecptr = NULL;
	struct iovec *ptr = NULL;

	total_count = 0;
	ret = -EINVAL;
	count = 0;
	to_free = 0;

	/* Compute total and max number of segments after split */
	max_new_nr_segs = bound_max_iovecs(iov, nr_segs, &count);
	if (max_new_nr_segs < 0) {
		gossip_lerr("%s: could not bound iovec %lu\n",
			    __func__,
			    max_new_nr_segs);
		goto out;
	}

	gossip_debug(GOSSIP_FILE_DEBUG,
		"%s-BEGIN(%pU): count(%d) after estimate_max_iovecs.\n",
		__func__,
		handle,
		(int)count);

	if (type == PVFS_IO_WRITE) {
		if (file->f_flags & O_APPEND) {
			/*
			 * Make sure generic_write_checks sees an uptodate
			 * inode size.
			 */
			ret = pvfs2_inode_getattr(inode, PVFS_ATTR_SYS_SIZE);
			if (ret != 0)
				goto out;
		} else if (file->f_pos > i_size_read(inode))
			pvfs2_i_size_write(inode, file->f_pos);
	

		ret = generic_write_checks(file,
					   offset,
					   &count,
					   S_ISBLK(inode->i_mode));
		if (ret != 0) {
			gossip_err("%s: failed generic argument checks.\n",
				   __func__);
			goto out;
		}

		gossip_debug(GOSSIP_FILE_DEBUG,
			     "%s(%pU): proceeding with offset : %llu, "
			     "size %d\n",
			     __func__,
			     handle,
			     llu(*offset),
			     (int)count);
	}

	if (count == 0) {
		ret = 0;
		goto out;
	}

	/*
	 * if the total size of data transfer requested is greater than
	 * the kernel-set blocksize of PVFS2, then we split the iovecs
	 * such that no iovec description straddles a block size limit
	 */

	gossip_debug(GOSSIP_FILE_DEBUG,
		     "%s: pvfs_bufmap_size:%d\n",
		     __func__,
		     pvfs_bufmap_size_query());

	if (count > pvfs_bufmap_size_query()) {
		/*
		 * Split up the given iovec description such that
		 * no iovec descriptor straddles over the block-size limitation.
		 * This makes us our job easier to stage the I/O.
		 * In addition, this function will also compute an array
		 * with seg_count entries that will store the number of
		 * segments that straddle the block-size boundaries.
		 */
		ret = split_iovecs(max_new_nr_segs,	/* IN */
				   nr_segs,		/* IN */
				   iov,			/* IN */
				   &new_nr_segs,	/* OUT */
				   &iovecptr,		/* OUT */
				   &seg_count,		/* OUT */
				   &seg_array);		/* OUT */
		if (ret < 0) {
			gossip_err("%s: Failed to split iovecs to satisfy larger than blocksize readv/writev request %zd\n",
				__func__,
				ret);
			goto out;
		}
		gossip_debug(GOSSIP_FILE_DEBUG,
			     "%s: Splitting iovecs from %lu to %lu"
			     " [max_new %lu]\n",
			     __func__,
			     nr_segs,
			     new_nr_segs,
			     max_new_nr_segs);
		/* We must free seg_array and iovecptr */
		to_free = 1;
	} else {
		new_nr_segs = nr_segs;
		/* use the given iovec description */
		iovecptr = (struct iovec *)iov;
		/* There is only 1 element in the seg_array */
		seg_count = 1;
		/* and its value is the number of segments passed in */
		seg_array = &nr_segs;
		/* We dont have to free up anything */
		to_free = 0;
	}
	ptr = iovecptr;

	gossip_debug(GOSSIP_FILE_DEBUG,
		     "%s(%pU) %zd@%llu\n",
		     __func__,
		     handle,
		     count,
		     llu(*offset));
	gossip_debug(GOSSIP_FILE_DEBUG,
		     "%s(%pU): new_nr_segs: %lu, seg_count: %lu\n",
		     __func__,
		     handle,
		     new_nr_segs, seg_count);

/* PVFS2_KERNEL_DEBUG is a CFLAGS define. */
#ifdef PVFS2_KERNEL_DEBUG
	for (seg = 0; seg < new_nr_segs; seg++)
		gossip_debug(GOSSIP_FILE_DEBUG,
			     "%s: %d) %p to %p [%d bytes]\n",
			     __func__,
			     (int)seg + 1,
			     iovecptr[seg].iov_base,
			     iovecptr[seg].iov_base + iovecptr[seg].iov_len,
			     (int)iovecptr[seg].iov_len);
	for (seg = 0; seg < seg_count; seg++)
		gossip_debug(GOSSIP_FILE_DEBUG,
			     "%s: %zd) %lu\n",
			     __func__,
			     seg + 1,
			     seg_array[seg]);
#endif
	seg = 0;
	while (total_count < count) {
		size_t each_count;
		size_t amt_complete;

		/* how much to transfer in this loop iteration */
		each_count =
		   (((count - total_count) > pvfs_bufmap_size_query()) ?
			pvfs_bufmap_size_query() :
			(count - total_count));

		gossip_debug(GOSSIP_FILE_DEBUG,
			     "%s(%pU): size of each_count(%d)\n",
			     __func__,
			     handle,
			     (int)each_count);
		gossip_debug(GOSSIP_FILE_DEBUG,
			     "%s(%pU): BEFORE wait_for_io: offset is %d\n",
			     __func__,
			     handle,
			     (int)*offset);

		ret = wait_for_direct_io(type, inode, offset, ptr,
				seg_array[seg], each_count, 0, 1);
		gossip_debug(GOSSIP_FILE_DEBUG,
			     "%s(%pU): return from wait_for_io:%d\n",
			     __func__,
			     handle,
			     (int)ret);

		if (ret < 0)
			goto out;

		/* advance the iovec pointer */
		ptr += seg_array[seg];
		seg++;
		*offset += ret;
		total_count += ret;
		amt_complete = ret;

		gossip_debug(GOSSIP_FILE_DEBUG,
			     "%s(%pU): AFTER wait_for_io: offset is %d\n",
			     __func__,
			     handle,
			     (int)*offset);

		/*
		 * if we got a short I/O operations,
		 * fall out and return what we got so far
		 */
		if (amt_complete < each_count)
			break;
	} /*end while */

	if (total_count > 0)
		ret = total_count;
out:
	if (to_free) {
		kfree(iovecptr);
		kfree(seg_array);
	}
	if (ret > 0) {
		if (type == PVFS_IO_READ) {
			file_accessed(file);
		} else {
			SetMtimeFlag(pvfs2_inode);
			inode->i_mtime = CURRENT_TIME;
			mark_inode_dirty_sync(inode);
		}
	}

	gossip_debug(GOSSIP_FILE_DEBUG,
		     "%s(%pU): Value(%d) returned.\n",
		     __func__,
		     handle,
		     (int)ret);

	return ret;
}

/*
 * Read data from a specified offset in a file (referenced by inode).
 * Data may be placed either in a user or kernel buffer.
 */
ssize_t pvfs2_inode_read(struct inode *inode,
			 char __user *buf,
			 size_t count,
			 loff_t *offset,
			 loff_t readahead_size)
{
	struct pvfs2_inode_s *pvfs2_inode = PVFS2_I(inode);
	size_t bufmap_size;
	struct iovec vec;
	ssize_t ret = -EINVAL;

	g_pvfs2_stats.reads++;

	vec.iov_base = buf;
	vec.iov_len = count;

	bufmap_size = pvfs_bufmap_size_query();
	if (count > bufmap_size) {
		gossip_debug(GOSSIP_FILE_DEBUG,
			     "%s: count is too large (%zd/%zd)!\n",
			     __func__, count, bufmap_size);
		return -EINVAL;
	}

	gossip_debug(GOSSIP_FILE_DEBUG,
		     "%s(%pU) %zd@%llu\n",
		     __func__,
		     &pvfs2_inode->refn.khandle,
		     count,
		     llu(*offset));

	ret = wait_for_direct_io(PVFS_IO_READ, inode, offset, &vec, 1,
			count, readahead_size, 0);
	if (ret > 0)
		*offset += ret;

	gossip_debug(GOSSIP_FILE_DEBUG,
		     "%s(%pU): Value(%zd) returned.\n",
		     __func__,
		     &pvfs2_inode->refn.khandle,
		     ret);

	return ret;
}

/*
 * NOTES on the aio implementation.
 * Conceivably, we could just make use of the
 * generic_aio_file_read/generic_aio_file_write
 * functions that stages the read/write through
 * the page-cache. But given that we are not
 * interested in staging anything thru the page-cache,
 * we are going to resort to another
 * design.
 *
 * The aio callbacks to be implemented at the f.s. level
 * are fairly straightforward. All we see at this level
 * are individual contiguous file block reads/writes.
 * This means that we can just make use of the current
 * set of I/O upcalls without too much modifications.
 * (All we need is an extra flag for sync/async)
 *
 * However, we do need to handle cancellations properly.
 * What this means is that the "ki_cancel" callback function must
 * be set so that the kernel calls us back with the kiocb structure
 * for proper cancellation. This way we can send appropriate upcalls
 * to cancel I/O operations if need be and copy status/results
 * back to user-space.
 */

/*
 * Using the iocb->private->op->tag field,
 * we should try and cancel the I/O
 * operation, and also update res->obj
 * and res->data to the values
 * at the time of cancellation.
 * This is called not only by the io_cancel()
 * system call, but also by the exit_mm()/aio_cancel_all()
 * functions when the process that issued
 * the aio operation is about to exit.
 */
static int pvfs2_aio_cancel(struct kiocb *iocb)
{
	struct pvfs2_kiocb_s *x = NULL;
	if (iocb == NULL) {
		gossip_err("pvfs2_aio_cancel: Invalid parameter %p!\n", iocb);
		return -EINVAL;
	}
	x = (struct pvfs2_kiocb_s *) iocb->private;
	if (x == NULL) {
		gossip_err("pvfs2_aio_cancel: cannot retrieve pvfs2_kiocb structure!\n");
		return -EINVAL;
	} else {
		struct pvfs2_kernel_op *op = NULL;
		/*
		 * Do some sanity checks
		 */
		if (x->kiocb != iocb) {
			gossip_err("pvfs2_aio_cancel: kiocb structures don't match %p %p!\n",
				x->kiocb,
				iocb);
			return -EINVAL;
		}
		op = x->op;
		if (op == NULL) {
			gossip_err("pvfs2_aio_cancel: cannot retreive pvfs2_kernel_op structure!\n");
			return -EINVAL;
		}
		get_op(op);
		/*
		 * This will essentially remove it from
		 * htable_in_progress or from the req list
		 * as the case may be.
		 */
		gossip_debug(GOSSIP_WAIT_DEBUG,
			     "*** %s: operation aio_cancel (tag %llu, op %p)\n",
			     __func__,
			     llu(op->tag), op);
		pvfs2_clean_up_interrupted_operation(op);
		/*
		 * However, we need to make sure that
		 * the client daemon is not transferring data
		 * as we speak! Thus we look at the reference
		 * counter to determine if that is indeed the case.
		 */
		do {
			int timed_out_or_signal = 0;

			DECLARE_WAITQUEUE(wait_entry, current);
			/* add yourself to the wait queue */
			add_wait_queue_exclusive(&op->io_completion_waitq,
						 &wait_entry);

			spin_lock(&op->lock);
			while (op->io_completed == 0) {
				set_current_state(TASK_INTERRUPTIBLE);
				/*
				 * We don't need to wait if client-daemon
				 * did not get a reference to op.
				 */
				if (!op_wait(op))
					break;
				/*
				 * There may be a window if the client-daemon
				 * has acquired a reference to op, but not a
				 * spin-lock on it yet before which the async
				 * canceller (i.e. this piece of code) acquires
				 * the same. Consequently we may end up with a
				 * race. To prevent that we use the aio_ref_cnt
				 * counter.
				 */
				spin_unlock(&op->lock);
				if (!signal_pending(current)) {
					int timeout =
					    MSECS_TO_JIFFIES(1000 *
							     op_timeout_secs);
					if (!schedule_timeout(timeout)) {
						gossip_debug(GOSSIP_FILE_DEBUG, "Timed out on I/O cancellation - aborting\n");
						timed_out_or_signal = 1;
						spin_lock(&op->lock);
						break;
					}
					spin_lock(&op->lock);
					continue;
				}
				gossip_debug(GOSSIP_FILE_DEBUG, "signal on Async I/O cancellation - aborting\n");
				timed_out_or_signal = 1;
				spin_lock(&op->lock);
				break;
			}
			set_current_state(TASK_RUNNING);
			remove_wait_queue(&op->io_completion_waitq,
					  &wait_entry);

		} while (0);

		/*
		 * Drop the buffer pool index
		 */
		if (x->buffer_index >= 0) {
			gossip_debug(GOSSIP_FILE_DEBUG,
				     "pvfs2_aio_cancel: put bufmap_index %d\n",
				     x->buffer_index);
			pvfs_bufmap_put(x->buffer_index);
			x->buffer_index = -1;
		}
		/*
		 * Put reference to op twice, once for the reader/writer
		 * that initiated the op and once for the cancel
		 */
		put_op(op);
		put_op(op);
		x->needs_cleanup = 0;
		/* x is itself deallocated by the destructor */
		return 0;
	}
}

static inline int
fill_default_kiocb(struct pvfs2_kiocb_s *x,
		   struct task_struct *tsk,
		   struct kiocb *iocb,
		   int rw,
		   int buffer_index,
		   struct pvfs2_kernel_op *op,
		   const struct iovec *iovec,
		   unsigned long nr_segs,
		   loff_t offset,
		   size_t count,
		   int (*aio_cancel) (struct kiocb *))
{
	x->tsk = tsk;
	x->kiocb = iocb;
	x->buffer_index = buffer_index;
	x->op = op;
	x->rw = rw;
	x->bytes_to_be_copied = count;
	x->offset = offset;
	x->bytes_copied = 0;
	x->needs_cleanup = 1;
	kiocb_set_cancel_fn(iocb, aio_cancel);
	/*
	 * Allocate a private pointer to store the
	 * iovector since the caller could pass in a
	 * local variable for the iovector.
	 */
	x->iov = kmalloc(nr_segs * sizeof(*x->iov), PVFS2_BUFMAP_GFP_FLAGS);
	if (x->iov == NULL)
		return -ENOMEM;
	memcpy(x->iov, iovec, nr_segs * sizeof(*x->iov));
	x->nr_segs = nr_segs;
	return 0;
}

static ssize_t pvfs2_file_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	loff_t pos = *(&iocb->ki_pos);
	ssize_t rc = 0;
	size_t count = iov_iter_count(iter);
	unsigned long nr_segs = iter->nr_segs;
	struct pvfs2_kernel_op *new_op;
	struct inode *inode = file->f_mapping->host;
	struct pvfs2_inode_s *pvfs2_inode = PVFS2_I(inode);
	struct pvfs2_kiocb_s *x;
	int buffer_index = -1;
	
	BUG_ON(iocb->private);

	gossip_debug(GOSSIP_FILE_DEBUG,"pvfs2_file_read_iter\n");

	g_pvfs2_stats.reads++;

	if (is_sync_kiocb(iocb)) {
		gossip_debug(GOSSIP_FILE_DEBUG,"read_iter: synchronous io\n");

		rc = do_readv_writev(PVFS_IO_READ,
				     file,
				     &pos,
				     iter->iov,
				     nr_segs);

		iocb->ki_pos = pos;
		goto out;
	}

	gossip_debug(GOSSIP_FILE_DEBUG,"asynchronous io\n");

	if (count == 0) {
		rc = 0;
		goto out;
	}

	if (count > pvfs_bufmap_size_query()) {
		/*
		 * TODO: Asynchronous I/O operation is not allowed to
		 * be greater than our block size
		 */
		gossip_lerr("%s: cannot transfer (%zd) "
			    "bytes (larger than block size %d)\n",
			    __func__,
			    count,
			    pvfs_bufmap_size_query());
		rc = -EINVAL;
		goto out;
	}

	gossip_debug(GOSSIP_FILE_DEBUG, "Posting asynchronous I/O operation\n");

	new_op = op_alloc(PVFS2_VFS_OP_FILE_IO);
	if (!new_op) {
		rc = -ENOMEM;
		goto out;
	}

	/* Increase ref count */
	get_op(new_op);
	new_op->upcall.req.io.async_vfs_io = PVFS_VFS_ASYNC_IO;
	new_op->upcall.req.io.io_type = PVFS_IO_READ;
	new_op->upcall.req.io.refn = pvfs2_inode->refn;
	rc = pvfs_bufmap_get(&buffer_index);
	if (rc < 0) {
		gossip_debug(GOSSIP_FILE_DEBUG,
			     "%s: pvfs_bufmap_get() failure %ld\n",
			     __func__,
			     (long)rc);
		goto out_put_op;
	}

	gossip_debug(GOSSIP_FILE_DEBUG,
		     "%s: pvfs_bufmap_get %d\n",
		     __func__,
		     buffer_index);
	new_op->upcall.req.io.buf_index = buffer_index;
	new_op->upcall.req.io.count = count;
	new_op->upcall.req.io.offset = pos;

	x = kiocb_alloc();
	if (x == NULL) {
		gossip_debug(GOSSIP_FILE_DEBUG,
			     "%s: pvfs_bufmap_put %d\n",
			     __func__,
			     buffer_index);
		rc = -ENOMEM;
		goto out_put_bufmap;
	}
	gossip_debug(GOSSIP_FILE_DEBUG, "kiocb_alloc: %p\n", x);

	/*
	 * We need to set the cancellation callbacks + other state information
	 * here if the asynchronous request is going to be successfully
	 * submitted.
	 */
	rc = fill_default_kiocb(x,
				current,
				iocb,
				PVFS_IO_READ,
				buffer_index,
				new_op,
				iter->iov,
				nr_segs,
				pos,
				count,
				&pvfs2_aio_cancel);
	if (rc != 0) {
		gossip_debug(GOSSIP_FILE_DEBUG,
			     "%s: pvfs_bufmap_put %d\n",
			     __func__,
			     buffer_index);
		goto out_kiocb_release;
	}

	new_op->priv = x;
	iocb->private = x;

	/*
	 * Add it to the list of ops to be serviced but don't wait for it to be
	 * serviced. Return immediately
	 */
	service_operation(new_op, __func__, PVFS2_OP_ASYNC);
	gossip_debug(GOSSIP_FILE_DEBUG,
		     "%s: queued operation [%llu for %zd]\n",
		     __func__,
		     llu(pos),
		     count);
	rc = -EIOCBQUEUED;
	goto out;

out_kiocb_release:
	kiocb_release(x);
out_put_bufmap:
	pvfs_bufmap_put(buffer_index);
out_put_op:
	put_op(new_op);
out:
	return rc;
}

static ssize_t pvfs2_file_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
        loff_t pos = *(&iocb->ki_pos);
	unsigned long nr_segs = iter->nr_segs;
	struct inode *inode = file->f_mapping->host;
	struct pvfs2_inode_s *pvfs2_inode = PVFS2_I(inode);
	struct pvfs2_kernel_op *new_op;
	struct pvfs2_kiocb_s *x;
	size_t count = iov_iter_count(iter);
	ssize_t rc;
	int buffer_index = -1;
	
	BUG_ON(iocb->private);

	gossip_debug(GOSSIP_FILE_DEBUG,"pvfs2_file_aio_write_iovec\n");

	g_pvfs2_stats.writes++;

	/* synchronous I/O */
	if (is_sync_kiocb(iocb)) {
		gossip_debug(GOSSIP_FILE_DEBUG,
			     "pvfs2_file_aio_write_iovec: syncronous.\n");
		rc = do_readv_writev(PVFS_IO_WRITE,
				     file,
				     &pos,
				     iter->iov,
				     nr_segs);

		iocb->ki_pos = pos;
		goto out;
	}

	gossip_debug(GOSSIP_FILE_DEBUG, "write_iter: asyncronous.\n");
	/* perform generic tests for sanity of write arguments */
	rc = generic_write_checks(file, &pos, &count, 0);
	if (rc) {
		gossip_err("%s: failed generic argument checks.\n", __func__);
		return rc;
	}

	if (count == 0) {
		rc = 0;
		goto out;
	}

	rc = -EINVAL;
	if (count > pvfs_bufmap_size_query()) {
		/*
		 * TODO: Asynchronous I/O operation is not allowed to
		 * be greater than our block size
		 */
		gossip_lerr("%s: cannot transfer (%zd) "
			    "bytes (larger than block size %d)\n",
			    __func__,
			    count,
			    pvfs_bufmap_size_query());
		rc = -EINVAL;
		goto out;
	}

	gossip_debug(GOSSIP_FILE_DEBUG, "Posting asynchronous I/O operation\n");

	new_op = op_alloc(PVFS2_VFS_OP_FILE_IO);
	if (!new_op) {
		rc = -ENOMEM;
		goto out;
	}
	/* Increase ref count */
	get_op(new_op);
	/* Asynchronous I/O */
	new_op->upcall.req.io.async_vfs_io = PVFS_VFS_ASYNC_IO;
	new_op->upcall.req.io.io_type = PVFS_IO_WRITE;
	new_op->upcall.req.io.refn = pvfs2_inode->refn;
	rc = pvfs_bufmap_get(&buffer_index);
	if (rc < 0) {
		gossip_debug(GOSSIP_FILE_DEBUG,
			     "%s: pvfs_bufmap_get() failure %ld\n",
			     __func__,
			     (long)rc);
		goto out_put_op;
	}
	gossip_debug(GOSSIP_FILE_DEBUG,
		     "%s: pvfs_bufmap_get %d\n",
		     __func__,
		     buffer_index);
	new_op->upcall.req.io.buf_index = buffer_index;
	new_op->upcall.req.io.count = count;
	new_op->upcall.req.io.offset = pos;

	/*
	 * copy the data from the application for writes.
	 * We could return -EIOCBRETRY here and have
	 * the data copied in the pvfs2_aio_retry routine,
	 * I dont see too much point in doing that
	 * since the app would have touched the
	 * memory pages prior to the write and
	 * hence accesses to the page won't block.
	 */
	rc = pvfs_bufmap_copy_iovec_from_user(
			buffer_index,
			iter->iov,
			nr_segs,
			count);
	if (rc < 0) {
		gossip_err("%s: Failed to copy user buffer %ld. "
			   "Make sure pvfs2-client-core is still running\n",
			   __func__,
			   (long)rc);
		gossip_debug(GOSSIP_FILE_DEBUG,
			     "%s: pvfs_bufmap_put %d\n",
			     __func__,
			     buffer_index);
		goto out_put_bufmap;
	}

	x = kiocb_alloc();
	if (x == NULL) {
		gossip_debug(GOSSIP_FILE_DEBUG,
			     "write_iter@kiocb_alloc: pvfs_bufmap_put %d\n",
			     buffer_index);
		rc = -ENOMEM;
		goto out_put_bufmap;
	}
	gossip_debug(GOSSIP_FILE_DEBUG, "kiocb_alloc: %p\n", x);

	/*
	 * We need to set the cancellation callbacks + other state information
	 * here if the asynchronous request is going to be successfully
	 * submitted.
	 */
	rc = fill_default_kiocb(x,
				current,
				iocb,
				PVFS_IO_WRITE,
				buffer_index,
				new_op,
				iter->iov,
				nr_segs,
				pos,
				count,
				&pvfs2_aio_cancel);
	if (rc != 0) {
		gossip_debug(GOSSIP_FILE_DEBUG,
			     "%s@fill_default_kiocb: pvfs_bufmap_put %d\n",
			     __func__,
			     buffer_index);
		goto out_kiocb_release;
	}

	/*
	 * We need to be able to retrieve this structure from
	 * the op structure as well, since the client-daemon
	 * needs to send notifications upon aio_completion.
	 */
	new_op->priv = x;
	iocb->private = x;

	/*
	 * Add it to the list of ops to be serviced but don't wait for it to
	 * be serviced.  Return immediately
	 */
	service_operation(new_op, __func__, PVFS2_OP_ASYNC);
	gossip_debug(GOSSIP_FILE_DEBUG,
		     "%s: queued operation [%llu for %zd]\n",
		     __func__,
		     llu(pos),
		     count);
	return -EIOCBQUEUED;

out_kiocb_release:
	kiocb_release(x);
out_put_bufmap:
	pvfs_bufmap_put(buffer_index);
out_put_op:
	put_op(new_op);
out:
	return rc;
}

/*
 * Perform a miscellaneous operation on a file.
 */
long pvfs2_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = -ENOTTY;
	uint64_t val = 0;
	unsigned long uval;

	gossip_debug(GOSSIP_FILE_DEBUG,
		     "pvfs2_ioctl: called with cmd %d\n",
		     cmd);

	/*
	 * we understand some general ioctls on files, such as the immutable
	 * and append flags
	 */
	if (cmd == FS_IOC_GETFLAGS) {
		val = 0;
		ret = pvfs2_xattr_get_default(file->f_dentry,
					      "user.pvfs2.meta_hint",
					      &val,
					      sizeof(val),
					      0);
		if (ret < 0 && ret != -ENODATA)
			return ret;
		else if (ret == -ENODATA)
			val = 0;
		uval = val;
		gossip_debug(GOSSIP_FILE_DEBUG,
			     "pvfs2_ioctl: FS_IOC_GETFLAGS: %llu\n",
			     (unsigned long long)uval);
		return put_user(uval, (int __user *)arg);
	} else if (cmd == FS_IOC_SETFLAGS) {
		ret = 0;
		if (get_user(uval, (int __user *)arg))
			return -EFAULT;
		/*
		 * PVFS_MIRROR_FL is set internally when the mirroring mode
		 * is turned on for a file. The user is not allowed to turn
		 * on this bit, but the bit is present if the user first gets
		 * the flags and then updates the flags with some new
		 * settings. So, we ignore it in the following edit. bligon.
		 */
		if ((uval & ~PVFS_MIRROR_FL) &
		    (~(FS_IMMUTABLE_FL | FS_APPEND_FL | FS_NOATIME_FL))) {
			gossip_err("pvfs2_ioctl: the FS_IOC_SETFLAGS only supports setting one of FS_IMMUTABLE_FL|FS_APPEND_FL|FS_NOATIME_FL\n");
			return -EINVAL;
		}
		val = uval;
		gossip_debug(GOSSIP_FILE_DEBUG,
			     "pvfs2_ioctl: FS_IOC_SETFLAGS: %llu\n",
			     (unsigned long long)val);
		ret = pvfs2_xattr_set_default(file->f_dentry,
					      "user.pvfs2.meta_hint",
					      &val,
					      sizeof(val),
					      0,
					      0);
	}

	return ret;
}

/*
 * Memory map a region of a file.
 */
static int pvfs2_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	gossip_debug(GOSSIP_FILE_DEBUG,
		     "pvfs2_file_mmap: called on %s\n",
		     (file ?
			(char *)file->f_dentry->d_name.name :
			(char *)"Unknown"));

	/* set the sequential readahead hint */
	vma->vm_flags |= VM_SEQ_READ;
	vma->vm_flags &= ~VM_RAND_READ;
//	return generic_file_mmap(file, vma);
	return generic_file_readonly_mmap(file, vma);
}

#define mapping_nrpages(idata) ((idata)->nrpages)

/*
 * Called to notify the module that there are no more references to
 * this file (i.e. no processes have it open).
 *
 * \note Not called when each file is closed.
 */
int pvfs2_file_release(struct inode *inode, struct file *file)
{
	gossip_debug(GOSSIP_FILE_DEBUG,
		     "pvfs2_file_release: called on %s\n",
		     file->f_dentry->d_name.name);

	pvfs2_flush_inode(inode);

	/*
	   remove all associated inode pages from the page cache and mmap
	   readahead cache (if any); this forces an expensive refresh of
	   data for the next caller of mmap (or 'get_block' accesses)
	 */
	if (file->f_dentry->d_inode &&
	    file->f_dentry->d_inode->i_mapping &&
	    mapping_nrpages(&file->f_dentry->d_inode->i_data))
		truncate_inode_pages(file->f_dentry->d_inode->i_mapping, 0);
	return 0;
}

/*
 * Push all data for a specific file onto permanent storage.
 */
int pvfs2_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	int ret = -EINVAL;
	struct pvfs2_inode_s *pvfs2_inode = PVFS2_I(file->f_dentry->d_inode);
	struct pvfs2_kernel_op *new_op = NULL;

	/* required call */
	filemap_write_and_wait_range(file->f_mapping, start, end);

	new_op = op_alloc(PVFS2_VFS_OP_FSYNC);
	if (!new_op)
		return -ENOMEM;
	new_op->upcall.req.fsync.refn = pvfs2_inode->refn;

	ret = service_operation(new_op,
			"pvfs2_fsync",
			get_interruptible_flag(file->f_dentry->d_inode));

	gossip_debug(GOSSIP_FILE_DEBUG,
		     "pvfs2_fsync got return value of %d\n",
		     ret);

	op_release(new_op);

	pvfs2_flush_inode(file->f_dentry->d_inode);
	return ret;
}

/*
 * Change the file pointer position for an instance of an open file.
 *
 * \note If .llseek is overriden, we must acquire lock as described in
 *       Documentation/filesystems/Locking.
 *
 * Future upgrade could support SEEK_DATA and SEEK_HOLE but would
 * require much changes to the FS
 */
loff_t pvfs2_file_llseek(struct file *file, loff_t offset, int origin)
{
	int ret = -EINVAL;
	struct inode *inode = file->f_dentry->d_inode;

	if (!inode) {
		gossip_err("pvfs2_file_llseek: invalid inode (NULL)\n");
		return ret;
	}

	if (origin == PVFS2_SEEK_END) {
		/*
		 * revalidate the inode's file size.
		 * NOTE: We are only interested in file size here,
		 * so we set mask accordingly.
		 */
		ret = pvfs2_inode_getattr(inode, PVFS_ATTR_SYS_SIZE);
		if (ret) {
			gossip_debug(GOSSIP_FILE_DEBUG,
				     "%s:%s:%d calling make bad inode\n",
				     __FILE__,
				     __func__,
				     __LINE__);
			pvfs2_make_bad_inode(inode);
			return ret;
		}
	}

	gossip_debug(GOSSIP_FILE_DEBUG,
		     "pvfs2_file_llseek: offset is %ld | origin is %d | "
		     "inode size is %lu\n",
		     (long)offset,
		     origin,
		     (unsigned long)file->f_dentry->d_inode->i_size);

	return generic_file_llseek(file, offset, origin);
}

int pvfs2_lock(struct file *f, int flags, struct file_lock *lock)
{
	return -ENOSYS;
}

/** PVFS2 implementation of VFS file operations */
const struct file_operations pvfs2_file_operations = {
	.llseek		= pvfs2_file_llseek,
	.read		= new_sync_read,
	.write		= new_sync_write,
	.read_iter	= pvfs2_file_read_iter,
	.write_iter	= pvfs2_file_write_iter,
	.lock		= pvfs2_lock,
	.unlocked_ioctl	= pvfs2_ioctl,
	.mmap		= pvfs2_file_mmap,
	.open		= generic_file_open,
	.release	= pvfs2_file_release,
	.fsync		= pvfs2_fsync,
};
