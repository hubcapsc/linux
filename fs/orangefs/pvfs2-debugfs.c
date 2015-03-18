#include <linux/debugfs.h>
#include <linux/slab.h>

#include <asm/uaccess.h>

#include "pvfs2-debugfs.h"

#define INIT_STRING "none\n"
#define DEBUG_HELP "debug-help"
#define KERNEL_DEBUG "kernel-debug"
#define MAX_KERNEL_DEBUG_INPUT 512

static struct dentry *debug_dir;
extern char debug_help_string[];
static int debug_disabled = 1;

/*
 * you can cat /sys/kernel/debug/orangefs/debug-help 
 * and see all the possible debug directives...
 */
static int debug_help_open(struct inode *, struct file *);

static const struct file_operations debug_help_fops = {
        .open           = debug_help_open,
        .read           = seq_read,
        .release        = seq_release,
        .llseek         = seq_lseek,
};

/*
 * /sys/kernel/debug/orangefs/kernel-debug is initialized to "none".
 * you can turn on different levels of debug by catting in one
 * or more of the debug directives listed in debug-help. If you
 * cat in more than one debug directive, they should be comma
 * separated.
 */
char *kernel_debug_str;
DEFINE_MUTEX(kernel_debug_lock); /* used to protect kernel_debug_str. */
static int kernel_debug_disabled = 1;

int kernel_debug_open(struct inode *, struct file *);

static ssize_t kernel_debug_read(struct file *,
				 char __user *,
				 size_t,
				 loff_t *);

static ssize_t kernel_debug_write(struct file *,
				  const char __user *,
				  size_t,
				  loff_t *);

static const struct file_operations kernel_debug_fops = {
        .open           = kernel_debug_open,
        .read           = kernel_debug_read,
        .write		= kernel_debug_write,
        .llseek         = generic_file_llseek,
};

int pvfs2_debugfs_init(void)
{

	int rc = -ENOMEM;
	struct dentry *ret;

	debug_dir = debugfs_create_dir("orangefs", NULL);
	if (!debug_dir)
		goto out;

	ret = debugfs_create_file(DEBUG_HELP,
				  0444,
				  debug_dir,
				  debug_help_string,
				  &debug_help_fops);
	if (!ret)
		goto out;
	
	debug_disabled = 0;
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

/*
 * I think start always gets called again after stop. Start
 * needs to return NULL when it is done. The whole "payload"
 * in this case is a single (long) string, so by the second
 * time we get to start (pos = 1), we're done.
 */
static void *help_start(struct seq_file *m, loff_t *pos)
{
	void *payload = NULL;

	if (*pos == 0)
		payload = m->private;

	return payload;
}

static void *help_next(struct seq_file *m, void *v, loff_t *pos)
{
	return NULL;
}

static void help_stop(struct seq_file *m, void *p)
{
}

static int help_show(struct seq_file *m, void *v)
{
	seq_puts(m, v);

	return 0;
}

static const struct seq_operations help_debug_ops = {
	.start	= help_start,
	.next	= help_next,
	.stop	= help_stop,
	.show	= help_show,
};

static int debug_help_open(struct inode *inode, struct file *file)
{
	int rc = -ENODEV;
	int ret;

	if (debug_disabled)
		goto out;

	ret = seq_open(file, &help_debug_ops);
	if (ret)
		goto out;

	((struct seq_file *)(file->private_data))->private = inode->i_private;

	rc = 0;

out:
	return rc;
}

int pvfs2_kernel_debug_init(void)
{

	int rc = -ENOMEM;
	struct dentry *ret;
	char *init_string;

	init_string = kmalloc(strlen(INIT_STRING) + 1, GFP_KERNEL);
	if (!init_string)
		goto out;
	strcpy(init_string, INIT_STRING);

	ret = debugfs_create_file(KERNEL_DEBUG,
				  0444,
				  debug_dir,
				  init_string,
				  &kernel_debug_fops);
	if (!ret)
		goto out;
	
	kernel_debug_disabled = 0;
	rc = 0;

out:
	if (rc)
		pvfs2_debugfs_cleanup();

	return rc;
}

int kernel_debug_open(struct inode *inode, struct file *file)
{
	int rc = -ENODEV;

	if (kernel_debug_disabled)
		goto out;

	rc = 0;
	file->private_data = inode->i_private;

out:
	return rc;
	
}

static ssize_t kernel_debug_read(struct file *file,
				 char __user *ubuf,
				 size_t count,
				 loff_t *ppos)
{
	char *buf;
	int sprintf_ret;
	ssize_t read_ret = -ENOMEM;;

	buf = kmalloc(strlen(file->private_data) + 1, GFP_KERNEL);
	if (!buf)
		goto out;

	mutex_lock(&kernel_debug_lock);
	sprintf_ret = sprintf(buf, "%s", (char *)file->private_data);
	mutex_unlock(&kernel_debug_lock);

	read_ret = simple_read_from_buffer(ubuf, count, ppos, buf, sprintf_ret);

	kfree(buf);

out:
	return read_ret;
}

static ssize_t kernel_debug_write(struct file *file,
				  const char __user *ubuf,
				  size_t count,
				  loff_t *ppos)
{
	char *buf;
	int rc = -EFAULT;
	int sprintf_ret;

	/*
	 * Thwart users who try to jamb a ridiculous number
	 * of bytes into the kernel-debug file...
	 */
	if (count > MAX_KERNEL_DEBUG_INPUT)
		count = MAX_KERNEL_DEBUG_INPUT;

	buf = kmalloc(count + 1, GFP_KERNEL);
	if (!buf)
		goto out;
	memset(buf, 0, count + 1);

	if (copy_from_user(buf, ubuf, count-1))
		goto out;

	mutex_lock(&kernel_debug_lock);
	//kfree(file->private_data);
	kfree(file->f_inode->i_private);
	file->f_inode->i_private = kmalloc(strlen(buf) + 1, GFP_KERNEL);
	if (!(file->f_inode->i_private))
		goto out;
	buf[count-1] = '\n';
	sprintf_ret = sprintf((char *)file->f_inode->i_private, "%s", buf);
	mutex_unlock(&kernel_debug_lock);

	*ppos += count;
	rc = count;

out:
	return rc;
}
