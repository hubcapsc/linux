#include <linux/debugfs.h>
#include <linux/slab.h>

#include "pvfs2-debugfs.h"

static struct dentry *debug_dir;
extern char debug_help_string[];
static int debug_disabled = 1;

static int debug_help_open(struct inode *, struct file *);

static const struct file_operations debug_help_fops = {
        .open           = debug_help_open,
        .read           = seq_read,
        .release        = seq_release,
        .llseek         = seq_lseek,
};

int pvfs2_debugfs_init(void)
{
	int rc = -ENOMEM;
	struct dentry *ret;

	debug_dir = debugfs_create_dir("orangefs", NULL);
	if (!debug_dir)
		goto out;

	ret = debugfs_create_file("debug-help",
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
 * needs to return NULL when it is done.
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
