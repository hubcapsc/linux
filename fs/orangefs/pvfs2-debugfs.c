#include <linux/debugfs.h>
#include <linux/slab.h>

#include <asm/uaccess.h>

#include "pvfs2-debugfs.h"
#include "protocol.h"
#include "pvfs2-kernel.h"

#define ORANGEFS_KMOD_DEBUG_HELP_FILE "debug-help"
#define ORANGEFS_KMOD_DEBUG_FILE "kernel-debug"

extern char debug_help_string[];

static struct dentry *debug_dir;
static int orangefs_kmod_debug_disabled = 1;

/*
 * you can cat /sys/kernel/debug/orangefs/debug-help 
 * and see all the possible debug directives...
 */
static int orangefs_kmod_debug_help_open(struct inode *, struct file *);

static const struct file_operations debug_help_fops = {
        .open           = orangefs_kmod_debug_help_open,
        .read           = seq_read,
        .release        = seq_release,
        .llseek         = seq_lseek,
};

static void *help_start(struct seq_file *, loff_t *);
static void *help_next(struct seq_file *, void *, loff_t *);
static void help_stop(struct seq_file *, void *);
static int help_show(struct seq_file *, void *);

static const struct seq_operations help_debug_ops = {
	.start	= help_start,
	.next	= help_next,
	.stop	= help_stop,
	.show	= help_show,
};

/*
 * you can cat one or more of the kmod debug directives listed in 
 * /sys/kernel/debug/orangefs/debug-help into 
 * /sys/kernel/debug/orangefs/kernel-debug to enable their
 * related gossip statements.
 */
int orangefs_kmod_debug_open(struct inode *, struct file *);

/* used to protect data in ORANGEFS_KMOD_DEBUG_FILE. */
DEFINE_MUTEX(orangefs_debug_lock); 

static ssize_t orangefs_kmod_debug_read(struct file *,
				 char __user *,
				 size_t,
				 loff_t *);

static ssize_t orangefs_kmod_debug_write(struct file *,
				  const char __user *,
				  size_t,
				  loff_t *);

static const struct file_operations kernel_debug_fops = {
        .open           = orangefs_kmod_debug_open,
        .read           = orangefs_kmod_debug_read,
        .write		= orangefs_kmod_debug_write,
        .llseek         = generic_file_llseek,
};

/*
 * initialize kmod debug operations, create orangefs debugfs dir and
 * ORANGEFS_KMOD_DEBUG_HELP_FILE.
 */
int pvfs2_debugfs_init(void)
{

	int rc = -ENOMEM;
	struct dentry *ret;

	debug_dir = debugfs_create_dir("orangefs", NULL);
	if (!debug_dir)
		goto out;

	ret = debugfs_create_file(ORANGEFS_KMOD_DEBUG_HELP_FILE,
				  0444,
				  debug_dir,
				  debug_help_string,
				  &debug_help_fops);
	if (!ret)
		goto out;
	
	orangefs_kmod_debug_disabled = 0;
	rc = 0;

out:
	if (rc)
		pvfs2_debugfs_cleanup();

	return rc;
}

void pvfs2_debugfs_cleanup(void)
{
	debugfs_remove_recursive(debug_dir);
}

/* open ORANGEFS_KMOD_DEBUG_HELP_FILE */
static int orangefs_kmod_debug_help_open(struct inode *inode, struct file *file)
{
	int rc = -ENODEV;
	int ret;

	gossip_debug(GOSSIP_PROC_DEBUG,
		     "orangefs_kmod_debug_help_open: start\n");

	if (orangefs_kmod_debug_disabled)
		goto out;

	ret = seq_open(file, &help_debug_ops);
	if (ret)
		goto out;

	((struct seq_file *)(file->private_data))->private = inode->i_private;

	rc = 0;

out:
	gossip_debug(GOSSIP_PROC_DEBUG,
		     "orangefs_kmod_debug_help_open: rc:%d:\n",
		     rc);
	return rc;
}

/*
 * I think start always gets called again after stop. Start
 * needs to return NULL when it is done. The whole "payload"
 * in this case is a single (long) string, so by the second
 * time we get to start (pos = 1), we're done.
 */
static void *help_start(struct seq_file *m, loff_t *pos)
{
	void *payload = NULL;

	gossip_debug(GOSSIP_PROC_DEBUG, "help_start: start\n");

	if (*pos == 0)
		payload = m->private;

	return payload;
}

static void *help_next(struct seq_file *m, void *v, loff_t *pos)
{
	gossip_debug(GOSSIP_PROC_DEBUG, "help_next: start\n");

	return NULL;
}

static void help_stop(struct seq_file *m, void *p)
{
	gossip_debug(GOSSIP_PROC_DEBUG, "help_stop: start\n");
}

static int help_show(struct seq_file *m, void *v)
{
	gossip_debug(GOSSIP_PROC_DEBUG, "help_show: start\n");

	seq_puts(m, v);

	return 0;
}

/*
 * initialize the kmod debug keyword file.
 */
int pvfs2_kernel_debug_init(void)
{

	int rc = -ENOMEM;
	struct dentry *ret;
	char *init_string;

	gossip_debug(GOSSIP_PROC_DEBUG, "pvfs2_kernel_debug_init: start\n");

	init_string = kmalloc(PVFS2_MAX_DEBUG_STRING_LEN, GFP_KERNEL);
	if (!init_string) {
		gossip_debug(GOSSIP_PROC_DEBUG,
			     "pvfs2_kernel_debug_init: kmalloc failed!\n");
		goto out;
	}
	memset(init_string, 0, PVFS2_MAX_DEBUG_STRING_LEN);
	if (kernel_debug_string[PVFS2_MAX_DEBUG_STRING_LEN - 2]) {
		gossip_debug(GOSSIP_PROC_DEBUG,
			     "%s: kernel_debug_string corrupt!\n",
			     __func__);
		kfree(init_string);
		goto out;
	}
	strcpy(init_string, kernel_debug_string);
	strcat(init_string, "\n");

	ret = debugfs_create_file(ORANGEFS_KMOD_DEBUG_FILE,
				  0444,
				  debug_dir,
				  init_string,
				  &kernel_debug_fops);
	if (!ret)
		goto out;
	
	orangefs_kmod_debug_disabled = 0;
	rc = 0;

out:
	if (rc)
		pvfs2_debugfs_cleanup();

	gossip_debug(GOSSIP_PROC_DEBUG,
		     "pvfs2_kernel_debug_init: rc:%d:\n",
		     rc);
	return rc;
}

/* open ORANGEFS_KMOD_DEBUG_FILE */
int orangefs_kmod_debug_open(struct inode *inode, struct file *file)
{
	int rc = -ENODEV;

	gossip_debug(GOSSIP_PROC_DEBUG,
		     "%s: orangefs_kmod_debug_disabled: %d\n",
		     __func__,
		     orangefs_kmod_debug_disabled);

	if (orangefs_kmod_debug_disabled)
		goto out;

	rc = 0;
	mutex_lock(&orangefs_debug_lock);
	file->private_data = inode->i_private;
	mutex_unlock(&orangefs_debug_lock);

out:
	gossip_debug(GOSSIP_PROC_DEBUG,
		     "orangefs_kmod_debug_open: rc: %d\n",
		     rc);
	return rc;
	
}

static ssize_t orangefs_kmod_debug_read(struct file *file,
				 char __user *ubuf,
				 size_t count,
				 loff_t *ppos)
{
	char *buf;
	int sprintf_ret;
	ssize_t read_ret = -ENOMEM;;

	gossip_debug(GOSSIP_PROC_DEBUG, "orangefs_kmod_debug_read: start\n");

	buf = kmalloc(PVFS2_MAX_DEBUG_STRING_LEN, GFP_KERNEL);
	if (!buf) {
		gossip_debug(GOSSIP_PROC_DEBUG,
			     "orangefs_kmod_debug_read: kmalloc failed!\n");
		goto out;
	}

	mutex_lock(&orangefs_debug_lock);
	sprintf_ret = sprintf(buf, "%s", (char *)file->private_data);
	mutex_unlock(&orangefs_debug_lock);

	read_ret = simple_read_from_buffer(ubuf, count, ppos, buf, sprintf_ret);

	kfree(buf);

out:
	gossip_debug(GOSSIP_PROC_DEBUG,
		     "orangefs_kmod_debug_read: ret: %zu\n",
		     read_ret);

	return read_ret;
}

static ssize_t orangefs_kmod_debug_write(struct file *file,
				  const char __user *ubuf,
				  size_t count,
				  loff_t *ppos)
{
	char *buf;
	int rc = -EFAULT;
	size_t silly = 0;

	gossip_debug(GOSSIP_PROC_DEBUG, "orangefs_kmod_debug_write: start\n");

	/*
	 * Thwart users who try to jamb a ridiculous number
	 * of bytes into the kernel-debug file...
	 */
	if (count > PVFS2_MAX_DEBUG_STRING_LEN) {
		silly = count;
		count = PVFS2_MAX_DEBUG_STRING_LEN;
	}


	buf = kmalloc(PVFS2_MAX_DEBUG_STRING_LEN, GFP_KERNEL);
	if (!buf) {
		gossip_debug(GOSSIP_PROC_DEBUG,
			     "orangefs_kmod_debug_write: kmalloc failed!\n");
		goto out;
	}
	memset(buf, 0, PVFS2_MAX_DEBUG_STRING_LEN);

	if (copy_from_user(buf, ubuf, count - 1)) {
		gossip_debug(GOSSIP_PROC_DEBUG,
			     "%s: copy_from_user failed!\n",
			     __func__);
		goto out;
	}

	/*
	 * Map the keyword string from userspace into a valid debug mask.
	 * The mapping process will toss any invalid keywords.
	 */
	gossip_debug_mask = PVFS_proc_kmod_eventlog_to_mask(buf);

	/*
	 * Convert the error-checked mask back into a keyword string.
	 * PVFS_proc_kmod_mask_to_eventlog returns an irrelevant int,
	 * perhaps it should just be void?
	 */
	PVFS_proc_kmod_mask_to_eventlog(gossip_debug_mask, buf);
	buf[strlen(buf)] = '\n';

	mutex_lock(&orangefs_debug_lock);
	memset(file->f_inode->i_private, 0, PVFS2_MAX_DEBUG_STRING_LEN);
	sprintf((char *)file->f_inode->i_private, "%s", buf);
	mutex_unlock(&orangefs_debug_lock);

	*ppos += count;
	if (silly)
		rc = silly;
	else
		rc = count;

out:
	gossip_debug(GOSSIP_PROC_DEBUG,
		     "orangefs_kmod_debug_write: rc: %d\n",
		     rc);
	kfree(buf);
	return rc;
}
