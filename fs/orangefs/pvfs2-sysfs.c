
/*
 * TODO:
 *
 * Documentation/ABI
 */

#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/module.h>
#include <linux/init.h>

#include "protocol.h"
#include "pvfs2-kernel.h"
#include "pvfs2-sysfs.h"

struct orangefs_obj {
	struct kobject kobj;
	int op_timeout_secs;
	int perf_counter_reset;
	int perf_history_size;
	int perf_time_interval_secs;
	int slot_timeout_secs;
};

struct acache_orangefs_obj {
	struct kobject kobj;
	int hard_limit;
	int reclaim_percentage;
	int soft_limit;
	int timeout_msecs;
};

struct capcache_orangefs_obj {
	struct kobject kobj;
	int hard_limit;
	int reclaim_percentage;
	int soft_limit;
	int timeout_secs;
};

struct ccache_orangefs_obj {
	struct kobject kobj;
	int hard_limit;
	int reclaim_percentage;
	int soft_limit;
	int timeout_secs;
};

struct orangefs_attribute {
	struct attribute attr;
	ssize_t (*show)(struct orangefs_obj *orangefs_obj,
			struct orangefs_attribute *attr,
			char *buf);
        ssize_t (*store)(struct orangefs_obj *orangefs_obj,
			 struct orangefs_attribute *attr,
			 const char *buf,
			 size_t count);
};

struct acache_orangefs_attribute {
	struct attribute attr;
	ssize_t (*show)(struct acache_orangefs_obj *acache_orangefs_obj,
			struct acache_orangefs_attribute *attr,
			char *buf);
        ssize_t (*store)(struct acache_orangefs_obj *acache_orangefs_obj,
			 struct acache_orangefs_attribute *attr,
			 const char *buf,
			 size_t count);
};

struct capcache_orangefs_attribute {
	struct attribute attr;
	ssize_t (*show)(struct capcache_orangefs_obj *capcache_orangefs_obj,
			struct capcache_orangefs_attribute *attr,
			char *buf);
        ssize_t (*store)(struct capcache_orangefs_obj *capcache_orangefs_obj,
			 struct capcache_orangefs_attribute *attr,
			 const char *buf,
			 size_t count);
};

struct ccache_orangefs_attribute {
	struct attribute attr;
	ssize_t (*show)(struct ccache_orangefs_obj *ccache_orangefs_obj,
			struct ccache_orangefs_attribute *attr,
			char *buf);
        ssize_t (*store)(struct ccache_orangefs_obj *ccache_orangefs_obj,
			 struct ccache_orangefs_attribute *attr,
			 const char *buf,
			 size_t count);
};

static ssize_t orangefs_attr_show(struct kobject *kobj,
				  struct attribute *attr,
				  char *buf)
{
	struct orangefs_attribute *attribute;
	struct orangefs_obj *orangefs_obj;

	attribute = container_of(attr, struct orangefs_attribute, attr);
	orangefs_obj = container_of(kobj, struct orangefs_obj, kobj);

	if (!attribute->show)
		return -EIO;

	return attribute->show(orangefs_obj, attribute, buf);
}

static ssize_t orangefs_attr_store(struct kobject *kobj,
				   struct attribute *attr,
				   const char *buf,
				   size_t len)
{
	struct orangefs_attribute *attribute;
	struct orangefs_obj *orangefs_obj;

	gossip_debug(GOSSIP_PROC_DEBUG,
		     "orangefs_attr_store: start\n");

	attribute = container_of(attr, struct orangefs_attribute, attr);
        orangefs_obj = container_of(kobj, struct orangefs_obj, kobj);

        if (!attribute->store)
                return -EIO;

	return attribute->store(orangefs_obj, attribute, buf, len);
}

static const struct sysfs_ops orangefs_sysfs_ops = {
	.show = orangefs_attr_show,
	.store = orangefs_attr_store,
};

static ssize_t acache_orangefs_attr_show(struct kobject *kobj,
					 struct attribute *attr,
					 char *buf)
{
	struct acache_orangefs_attribute *attribute;
	struct acache_orangefs_obj *acache_orangefs_obj;

	attribute = container_of(attr, struct acache_orangefs_attribute, attr);
	acache_orangefs_obj =
		container_of(kobj, struct acache_orangefs_obj, kobj);

	if (!attribute->show)
		return -EIO;

	return attribute->show(acache_orangefs_obj, attribute, buf);
}

static ssize_t acache_orangefs_attr_store(struct kobject *kobj,
					  struct attribute *attr,
					  const char *buf,
					  size_t len)
{
	struct acache_orangefs_attribute *attribute;
	struct acache_orangefs_obj *acache_orangefs_obj;

	gossip_debug(GOSSIP_PROC_DEBUG,
		     "acache_orangefs_attr_store: start\n");

	attribute = container_of(attr, struct acache_orangefs_attribute, attr);
        acache_orangefs_obj =
		container_of(kobj, struct acache_orangefs_obj, kobj);

        if (!attribute->store)
                return -EIO;

	return attribute->store(acache_orangefs_obj, attribute, buf, len);
}

static const struct sysfs_ops acache_orangefs_sysfs_ops = {
	.show = acache_orangefs_attr_show,
	.store = acache_orangefs_attr_store,
};

static ssize_t capcache_orangefs_attr_show(struct kobject *kobj,
					   struct attribute *attr,
					   char *buf)
{
	struct capcache_orangefs_attribute *attribute;
	struct capcache_orangefs_obj *capcache_orangefs_obj;

	attribute =
		container_of(attr, struct capcache_orangefs_attribute, attr);
	capcache_orangefs_obj =
		container_of(kobj, struct capcache_orangefs_obj, kobj);

	if (!attribute->show)
		return -EIO;

	return attribute->show(capcache_orangefs_obj, attribute, buf);
}

static ssize_t capcache_orangefs_attr_store(struct kobject *kobj,
					    struct attribute *attr,
					    const char *buf,
					    size_t len)
{
	struct capcache_orangefs_attribute *attribute;
	struct capcache_orangefs_obj *capcache_orangefs_obj;

	gossip_debug(GOSSIP_PROC_DEBUG,
		     "capcache_orangefs_attr_store: start\n");

	attribute =
		container_of(attr, struct capcache_orangefs_attribute, attr);
        capcache_orangefs_obj =
		container_of(kobj, struct capcache_orangefs_obj, kobj);

        if (!attribute->store)
                return -EIO;

	return attribute->store(capcache_orangefs_obj, attribute, buf, len);
}

static const struct sysfs_ops capcache_orangefs_sysfs_ops = {
	.show = capcache_orangefs_attr_show,
	.store = capcache_orangefs_attr_store,
};

static ssize_t ccache_orangefs_attr_show(struct kobject *kobj,
					   struct attribute *attr,
					   char *buf)
{
	struct ccache_orangefs_attribute *attribute;
	struct ccache_orangefs_obj *ccache_orangefs_obj;

	attribute =
		container_of(attr, struct ccache_orangefs_attribute, attr);
	ccache_orangefs_obj =
		container_of(kobj, struct ccache_orangefs_obj, kobj);

	if (!attribute->show)
		return -EIO;

	return attribute->show(ccache_orangefs_obj, attribute, buf);
}

static ssize_t ccache_orangefs_attr_store(struct kobject *kobj,
					    struct attribute *attr,
					    const char *buf,
					    size_t len)
{
	struct ccache_orangefs_attribute *attribute;
	struct ccache_orangefs_obj *ccache_orangefs_obj;

	gossip_debug(GOSSIP_PROC_DEBUG,
		     "ccache_orangefs_attr_store: start\n");

	attribute =
		container_of(attr, struct ccache_orangefs_attribute, attr);
        ccache_orangefs_obj =
		container_of(kobj, struct ccache_orangefs_obj, kobj);

        if (!attribute->store)
                return -EIO;

	return attribute->store(ccache_orangefs_obj, attribute, buf, len);
}

static const struct sysfs_ops ccache_orangefs_sysfs_ops = {
	.show = ccache_orangefs_attr_show,
	.store = ccache_orangefs_attr_store,
};

static void orangefs_release(struct kobject *kobj)
{
	struct orangefs_obj *orangefs_obj;

	gossip_debug(GOSSIP_PROC_DEBUG, "orangefs_release: start\n");

	orangefs_obj = container_of(kobj, struct orangefs_obj, kobj);
	kfree(orangefs_obj);
}

static ssize_t int_show(struct orangefs_obj *orangefs_obj,
			struct orangefs_attribute *attr,
			char *buf)
{
	ssize_t rc;

	gossip_debug(GOSSIP_PROC_DEBUG,
		     "int_show:start attr->attr.name:%s:\n", attr->attr.name);

	/*
	 * snprintf() returns the length the resulting string would be,
	 * assuming it all fit into buf.
	 *
	 * scnprintf() returns the length of the string actually created
	 * in buf.
	 */
	if (!strcmp(attr->attr.name, "op_timeout_secs")) {
		rc = scnprintf(buf, PAGE_SIZE, "%d\n", op_timeout_secs);
		goto out;
	} else if (!strcmp(attr->attr.name, "slot_timeout_secs")) {
		rc = scnprintf(buf, PAGE_SIZE, "%d\n", slot_timeout_secs);
		goto out;
	} else {
		rc = -EIO;
	}

out:

        return rc;
}

static ssize_t int_store(struct orangefs_obj *orangefs_obj,
			 struct orangefs_attribute *attr,
			 const char *buf,
			 size_t count)
{
	int rc = 0;

	gossip_debug(GOSSIP_PROC_DEBUG,
		     "int_store: start attr->attr.name:%s: buf:%s:\n",
		     attr->attr.name, buf);

	if (!strcmp(attr->attr.name, "op_timeout_secs")) {
		rc = sscanf(buf, "%d", &op_timeout_secs);
		goto out;
	} else if (!strcmp(attr->attr.name, "slot_timeout_secs")) {
		rc = sscanf(buf, "%d", &slot_timeout_secs);
		goto out;
	} else {
		goto out;
	}

out:
	if (!rc)
		rc = -EINVAL;
	else 
		rc = count;

	return rc;
}

int sysfs_service_op_show(char *kobj_id, char *buf, void *attr)
{
	struct pvfs2_kernel_op *new_op = NULL;
	int rc = 0;
	int val = 0;
	struct orangefs_attribute *orangefs_attr;
	struct acache_orangefs_attribute *acache_attr;
	struct capcache_orangefs_attribute *capcache_attr;
	struct ccache_orangefs_attribute *ccache_attr;

	gossip_debug(GOSSIP_PROC_DEBUG,
		     "sysfs_service_op_show: id:%s:\n",
		     kobj_id);

	new_op = op_alloc(PVFS2_VFS_OP_PARAM);
	if (!new_op)
		return -ENOMEM;

	new_op->upcall.req.param.type = PVFS2_PARAM_REQUEST_GET;

	if (!strcmp(kobj_id, "orangefs")) {
		orangefs_attr = (struct orangefs_attribute *)attr;

		if (!strcmp(orangefs_attr->attr.name, "perf_history_size"))
			new_op->upcall.req.param.op =
				PVFS2_PARAM_REQUEST_OP_PERF_HISTORY_SIZE;
		else if (!strcmp(orangefs_attr->attr.name,
				 "perf_time_interval_secs"))
			new_op->upcall.req.param.op =
				PVFS2_PARAM_REQUEST_OP_PERF_TIME_INTERVAL_SECS;
		else if (!strcmp(orangefs_attr->attr.name,
				 "perf_counter_reset"))
			new_op->upcall.req.param.op =
				PVFS2_PARAM_REQUEST_OP_PERF_RESET;

	} else if (!strcmp(kobj_id, "acache")) {
		acache_attr = (struct acache_orangefs_attribute *)attr;

		if (!strcmp(acache_attr->attr.name, "timeout_msecs"))
			new_op->upcall.req.param.op = 
				PVFS2_PARAM_REQUEST_OP_ACACHE_TIMEOUT_MSECS;

		if (!strcmp(acache_attr->attr.name, "hard_limit"))
			new_op->upcall.req.param.op = 
				PVFS2_PARAM_REQUEST_OP_ACACHE_HARD_LIMIT;

		if (!strcmp(acache_attr->attr.name, "soft_limit"))
			new_op->upcall.req.param.op = 
				PVFS2_PARAM_REQUEST_OP_ACACHE_SOFT_LIMIT;

		if (!strcmp(acache_attr->attr.name, "reclaim_percentage"))
			new_op->upcall.req.param.op = 
			  PVFS2_PARAM_REQUEST_OP_ACACHE_RECLAIM_PERCENTAGE;
	} else if (!strcmp(kobj_id, "capcache")) {
		capcache_attr = (struct capcache_orangefs_attribute *)attr;

		if (!strcmp(capcache_attr->attr.name, "timeout_secs"))
			new_op->upcall.req.param.op = 
				PVFS2_PARAM_REQUEST_OP_CAPCACHE_TIMEOUT_SECS;

		if (!strcmp(capcache_attr->attr.name, "hard_limit"))
			new_op->upcall.req.param.op = 
				PVFS2_PARAM_REQUEST_OP_CAPCACHE_HARD_LIMIT;

		if (!strcmp(capcache_attr->attr.name, "soft_limit"))
			new_op->upcall.req.param.op = 
				PVFS2_PARAM_REQUEST_OP_CAPCACHE_SOFT_LIMIT;

		if (!strcmp(capcache_attr->attr.name, "reclaim_percentage"))
			new_op->upcall.req.param.op = 
			  PVFS2_PARAM_REQUEST_OP_CAPCACHE_RECLAIM_PERCENTAGE;
	} else if (!strcmp(kobj_id, "ccache")) {
		ccache_attr = (struct ccache_orangefs_attribute *)attr;

		if (!strcmp(ccache_attr->attr.name, "timeout_secs"))
			new_op->upcall.req.param.op = 
				PVFS2_PARAM_REQUEST_OP_CCACHE_TIMEOUT_SECS;

		if (!strcmp(ccache_attr->attr.name, "hard_limit"))
			new_op->upcall.req.param.op = 
				PVFS2_PARAM_REQUEST_OP_CCACHE_HARD_LIMIT;

		if (!strcmp(ccache_attr->attr.name, "soft_limit"))
			new_op->upcall.req.param.op = 
				PVFS2_PARAM_REQUEST_OP_CCACHE_SOFT_LIMIT;

		if (!strcmp(ccache_attr->attr.name, "reclaim_percentage"))
			new_op->upcall.req.param.op = 
			  PVFS2_PARAM_REQUEST_OP_CCACHE_RECLAIM_PERCENTAGE;
	} else {
		gossip_err("sysfs_service_op_show: unknown kobj_id:%s:\n",
			   kobj_id);
		rc = -EINVAL;
		goto out;
	}


	/*
	 * The service_operation will return an errno return code on
	 * error, and zero on success.
	 */
	rc = service_operation(new_op, "pvfs2_param", PVFS2_OP_INTERRUPTIBLE);

out:
	if (!rc)
		val = (int)new_op->downcall.resp.param.value;
	else
		val = rc;


	op_release(new_op);

	return val;

}

static ssize_t service_orangefs_show(struct orangefs_obj *orangefs_obj,
				     struct orangefs_attribute *attr,
				     char *buf)
{
	int rc = 0;

	rc = sysfs_service_op_show("orangefs", buf, (void *) attr);

	/* rc should have an errno value if the service_op went bad. */
	if (rc > 0)
		rc = scnprintf(buf, PAGE_SIZE, "%d\n", rc);

	return rc;
}

static ssize_t
	service_acache_show(struct acache_orangefs_obj *acache_orangefs_obj,
			    struct acache_orangefs_attribute *attr,
			    char *buf)
{
	int rc = 0;

	rc = sysfs_service_op_show("acache", buf, (void *) attr);

	/* rc should have an errno value if the service_op went bad. */
	if (rc > 0)
		rc = scnprintf(buf, PAGE_SIZE, "%d\n", rc);

	return rc;
}

static ssize_t service_capcache_show(struct capcache_orangefs_obj
					*capcache_orangefs_obj,
				     struct capcache_orangefs_attribute *attr,
				     char *buf)
{
	int rc = 0;

	rc = sysfs_service_op_show("capcache", buf, (void *) attr);

	/* rc should have an errno value if the service_op went bad. */
	if (rc > 0)
		rc = scnprintf(buf, PAGE_SIZE, "%d\n", rc);

	return rc;
}

static ssize_t service_ccache_show(struct ccache_orangefs_obj
					*ccache_orangefs_obj,
				   struct ccache_orangefs_attribute *attr,
				   char *buf)
{
	int rc = 0;

	rc = sysfs_service_op_show("ccache", buf, (void *) attr);

	/* rc should have an errno value if the service_op went bad. */
	if (rc > 0)
		rc = scnprintf(buf, PAGE_SIZE, "%d\n", rc);

	return rc;
}

/*
 * pass attribute values back to userspace with a service operation.
 *
 * We have to do a memory allocation, an sscanf and a service operation.
 * And we have to evaluate what the user entered, to make sure the
 * value is within the range supported by the attribute. So, there's
 * a lot of return code checking and mapping going on here.
 *
 * We want to return 1 if we think everything went OK, and
 * EINVAL if not.
 */
int sysfs_service_op_store(char *kobj_id, const char *buf, void *attr)
{
	struct pvfs2_kernel_op *new_op = NULL;
	int val = 0;
	int rc = 0;
	struct orangefs_attribute *orangefs_attr;
	struct acache_orangefs_attribute *acache_attr;
	struct capcache_orangefs_attribute *capcache_attr;
	struct ccache_orangefs_attribute *ccache_attr;

	gossip_debug(GOSSIP_PROC_DEBUG,
		     "sysfs_service_op_store: id:%s:\n",
		     kobj_id);

	new_op = op_alloc(PVFS2_VFS_OP_PARAM);
        if (!new_op) {
                rc = -ENOMEM;
		goto out;
	}

	/*
	 * The value we want to send back to userspace is in buf.
	 */
	if (!(rc = sscanf(buf, "%d", &val))) goto out;

	if (!strcmp(kobj_id, "orangefs")) {
		orangefs_attr = (struct orangefs_attribute *)attr;

		if (!strcmp(orangefs_attr->attr.name, "perf_history_size")) {
			if (val > 0) {
				new_op->upcall.req.param.op =
				  PVFS2_PARAM_REQUEST_OP_PERF_HISTORY_SIZE;
			} else {
				rc = 0;
				goto out;
			}
		} else if (!strcmp(orangefs_attr->attr.name,
				   "perf_time_interval_secs")) {
			if (val > 0) {
		        	new_op->upcall.req.param.op =
					PVFS2_PARAM_REQUEST_OP_PERF_TIME_INTERVAL_SECS;
			} else {
				rc = 0;
				goto out;
			}
		} else if (!strcmp(orangefs_attr->attr.name,
				   "perf_counter_reset")) {
			if ((val == 0) || (val == 1)) {
				new_op->upcall.req.param.op =
					PVFS2_PARAM_REQUEST_OP_PERF_RESET;
			} else {
				rc = 0;
				goto out;
			}
		}
	} else if (!strcmp(kobj_id, "acache")) {
		acache_attr = (struct acache_orangefs_attribute *)attr;

		if (!strcmp(acache_attr->attr.name, "hard_limit")) {
			if (val > -1) {
				new_op->upcall.req.param.op =
				  PVFS2_PARAM_REQUEST_OP_ACACHE_HARD_LIMIT;
			} else {
				rc = 0;
				goto out;
			}
		} else if (!strcmp(acache_attr->attr.name, "soft_limit")) {
                        if (val > -1) {
                                new_op->upcall.req.param.op =
                                  PVFS2_PARAM_REQUEST_OP_ACACHE_SOFT_LIMIT;
                        } else {
                                rc = 0;
                                goto out;
                        }
		} else if (!strcmp(acache_attr->attr.name,
				   "reclaim_percentage")) {
			if ((val > -1) && (val < 101)) {
				new_op->upcall.req.param.op =
					PVFS2_PARAM_REQUEST_OP_ACACHE_RECLAIM_PERCENTAGE;
			} else {
				rc = 0;
				goto out;
			}
		} else if (!strcmp(acache_attr->attr.name, "timeout_msecs")) {
                        if (val > -1) {
                                new_op->upcall.req.param.op =
                                  PVFS2_PARAM_REQUEST_OP_ACACHE_TIMEOUT_MSECS;
                        } else {
                                rc = 0;
                                goto out;
                        }
                }
	} else if (!strcmp(kobj_id, "capcache")) {
		capcache_attr = (struct capcache_orangefs_attribute *)attr;

		if (!strcmp(capcache_attr->attr.name, "hard_limit")) {
			if (val > -1) {
				new_op->upcall.req.param.op =
				  PVFS2_PARAM_REQUEST_OP_CAPCACHE_HARD_LIMIT;
			} else {
				rc = 0;
				goto out;
			}
		} else if (!strcmp(capcache_attr->attr.name, "soft_limit")) {
                        if (val > -1) {
                                new_op->upcall.req.param.op =
                                  PVFS2_PARAM_REQUEST_OP_CAPCACHE_SOFT_LIMIT;
                        } else {
                                rc = 0;
                                goto out;
                        }
		} else if (!strcmp(capcache_attr->attr.name,
				   "reclaim_percentage")) {
			if ((val > -1) && (val < 101)) {
				new_op->upcall.req.param.op =
					PVFS2_PARAM_REQUEST_OP_CAPCACHE_RECLAIM_PERCENTAGE;
			} else {
				rc = 0;
				goto out;
			}
		} else if (!strcmp(capcache_attr->attr.name, "timeout_secs")) {
                        if (val > -1) {
                                new_op->upcall.req.param.op =
                                  PVFS2_PARAM_REQUEST_OP_CAPCACHE_TIMEOUT_SECS;
                        } else {
                                rc = 0;
                                goto out;
                        }
                }
	} else if (!strcmp(kobj_id, "ccache")) {
		ccache_attr = (struct ccache_orangefs_attribute *)attr;

		if (!strcmp(ccache_attr->attr.name, "hard_limit")) {
			if (val > -1) {
				new_op->upcall.req.param.op =
				  PVFS2_PARAM_REQUEST_OP_CCACHE_HARD_LIMIT;
			} else {
				rc = 0;
				goto out;
			}
		} else if (!strcmp(ccache_attr->attr.name, "soft_limit")) {
                        if (val > -1) {
                                new_op->upcall.req.param.op =
                                  PVFS2_PARAM_REQUEST_OP_CCACHE_SOFT_LIMIT;
                        } else {
                                rc = 0;
                                goto out;
                        }
		} else if (!strcmp(ccache_attr->attr.name,
				   "reclaim_percentage")) {
			if ((val > -1) && (val < 101)) {
				new_op->upcall.req.param.op =
					PVFS2_PARAM_REQUEST_OP_CCACHE_RECLAIM_PERCENTAGE;
			} else {
				rc = 0;
				goto out;
			}
		} else if (!strcmp(ccache_attr->attr.name, "timeout_secs")) {
                        if (val > -1) {
                                new_op->upcall.req.param.op =
                                  PVFS2_PARAM_REQUEST_OP_CCACHE_TIMEOUT_SECS;
                        } else {
                                rc = 0;
                                goto out;
                        }
                }
	} else {
		gossip_err("sysfs_service_op_store: unknown kobj_id:%s:\n",
			   kobj_id);
		rc = -EINVAL;
		goto out;
	}

        new_op->upcall.req.param.type = PVFS2_PARAM_REQUEST_SET;

	new_op->upcall.req.param.value = val;
	
	/*
	 * The service_operation will return a errno return code on
	 * error, and zero on success.
	 */
        rc = service_operation(new_op, "pvfs2_param", PVFS2_OP_INTERRUPTIBLE);

	if (rc < 0) {
		pr_info("sysfs_service_op_store: service op returned:%d:\n",
			rc);
		rc = 0;
	} else {
		rc = 1;
	}

out:
	/*
	 * if we got ENOMEM, then op_alloc probably failed...
	 */
	if (rc == -ENOMEM)
		rc = 0;
	else
		op_release(new_op);

	if (rc == 0)
		rc = -EINVAL;

	return rc;
}

static ssize_t
	service_orangefs_store(struct orangefs_obj *orangefs_obj,
			       struct orangefs_attribute *attr,
			       const char *buf,
			       size_t count)
{
	int rc = 0;

	rc = sysfs_service_op_store("orangefs", buf, (void *) attr);

	/* rc should have an errno value if the service_op went bad. */
	if (rc == 1)
		rc = count;

	return rc;
}

static ssize_t
	service_acache_store(struct acache_orangefs_obj *acache_orangefs_obj,
			     struct acache_orangefs_attribute *attr,
			     const char *buf,
			     size_t count)
{
	int rc = 0;

	rc = sysfs_service_op_store("acache", buf, (void *) attr);

	/* rc should have an errno value if the service_op went bad. */
	if (rc == 1)
		rc = count;

	return rc;
}

static ssize_t
	service_capcache_store(struct capcache_orangefs_obj
				*capcache_orangefs_obj,
			       struct capcache_orangefs_attribute *attr,
			       const char *buf,
			       size_t count)
{
	int rc = 0;

	rc = sysfs_service_op_store("capcache", buf, (void *) attr);

	/* rc should have an errno value if the service_op went bad. */
	if (rc == 1)
		rc = count;

	return rc;
}

static ssize_t service_ccache_store(struct ccache_orangefs_obj
					*ccache_orangefs_obj,
				    struct ccache_orangefs_attribute *attr,
				    const char *buf,
				    size_t count)
{
	int rc = 0;

	rc = sysfs_service_op_store("ccache", buf, (void *) attr);

	/* rc should have an errno value if the service_op went bad. */
	if (rc == 1)
		rc = count;

	return rc;
}

static struct orangefs_attribute op_timeout_secs_attribute =
	__ATTR(op_timeout_secs, 0664, int_show, int_store);

static struct orangefs_attribute slot_timeout_secs_attribute =
	__ATTR(slot_timeout_secs, 0664, int_show, int_store);

static struct orangefs_attribute perf_counter_reset_attribute =
	__ATTR(perf_counter_reset,
	       0664,
	       service_orangefs_show,
	       service_orangefs_store);

static struct orangefs_attribute perf_history_size_attribute =
	__ATTR(perf_history_size,
	       0664,
	       service_orangefs_show,
	       service_orangefs_store);

static struct orangefs_attribute perf_time_interval_secs_attribute =
	__ATTR(perf_time_interval_secs,
	       0664,
	       service_orangefs_show,
	       service_orangefs_store);

static struct attribute *orangefs_default_attrs[] = {
	&op_timeout_secs_attribute.attr,
	&slot_timeout_secs_attribute.attr,
	&perf_counter_reset_attribute.attr,
	&perf_history_size_attribute.attr,
	&perf_time_interval_secs_attribute.attr,
	NULL,
};

static struct kobj_type orangefs_ktype = {
	.sysfs_ops = &orangefs_sysfs_ops,
	.release = orangefs_release,
	.default_attrs = orangefs_default_attrs,
};

static struct acache_orangefs_attribute acache_hard_limit_attribute =
	__ATTR(hard_limit,
	       0664,
	       service_acache_show,
	       service_acache_store);

static struct acache_orangefs_attribute acache_reclaim_percent_attribute =
	__ATTR(reclaim_percentage,
	       0664,
	       service_acache_show,
	       service_acache_store);

static struct acache_orangefs_attribute acache_soft_limit_attribute =
	__ATTR(soft_limit,
	       0664,
	       service_acache_show,
	       service_acache_store);

static struct acache_orangefs_attribute acache_timeout_msecs_attribute =
	__ATTR(timeout_msecs,
	       0664,
	       service_acache_show,
	       service_acache_store);

static struct attribute *acache_orangefs_default_attrs[] = {
	&acache_hard_limit_attribute.attr,
	&acache_reclaim_percent_attribute.attr,
	&acache_soft_limit_attribute.attr,
	&acache_timeout_msecs_attribute.attr,
	NULL,
};

static struct kobj_type acache_orangefs_ktype = {
	.sysfs_ops = &acache_orangefs_sysfs_ops,
	.release = orangefs_release,
	.default_attrs = acache_orangefs_default_attrs,
};

static struct capcache_orangefs_attribute capcache_hard_limit_attribute =
	__ATTR(hard_limit,
	       0664,
	       service_capcache_show,
	       service_capcache_store);

static struct capcache_orangefs_attribute capcache_reclaim_percent_attribute =
	__ATTR(reclaim_percentage,
	       0664,
	       service_capcache_show,
	       service_capcache_store);

static struct capcache_orangefs_attribute capcache_soft_limit_attribute =
	__ATTR(soft_limit,
	       0664,
	       service_capcache_show,
	       service_capcache_store);

static struct capcache_orangefs_attribute capcache_timeout_secs_attribute =
	__ATTR(timeout_secs,
	       0664,
	       service_capcache_show,
	       service_capcache_store);

static struct attribute *capcache_orangefs_default_attrs[] = {
	&capcache_hard_limit_attribute.attr,
	&capcache_reclaim_percent_attribute.attr,
	&capcache_soft_limit_attribute.attr,
	&capcache_timeout_secs_attribute.attr,
	NULL,
};

static struct kobj_type capcache_orangefs_ktype = {
	.sysfs_ops = &capcache_orangefs_sysfs_ops,
	.release = orangefs_release,
	.default_attrs = capcache_orangefs_default_attrs,
};

static struct ccache_orangefs_attribute ccache_hard_limit_attribute =
	__ATTR(hard_limit,
	       0664,
	       service_ccache_show,
	       service_ccache_store);

static struct ccache_orangefs_attribute ccache_reclaim_percent_attribute =
	__ATTR(reclaim_percentage,
	       0664,
	       service_ccache_show,
	       service_ccache_store);

static struct ccache_orangefs_attribute ccache_soft_limit_attribute =
	__ATTR(soft_limit,
	       0664,
	       service_ccache_show,
	       service_ccache_store);

static struct ccache_orangefs_attribute ccache_timeout_secs_attribute =
	__ATTR(timeout_secs,
	       0664,
	       service_ccache_show,
	       service_ccache_store);

static struct attribute *ccache_orangefs_default_attrs[] = {
	&ccache_hard_limit_attribute.attr,
	&ccache_reclaim_percent_attribute.attr,
	&ccache_soft_limit_attribute.attr,
	&ccache_timeout_secs_attribute.attr,
	NULL,
};

static struct kobj_type ccache_orangefs_ktype = {
	.sysfs_ops = &ccache_orangefs_sysfs_ops,
	.release = orangefs_release,
	.default_attrs = ccache_orangefs_default_attrs,
};

static struct orangefs_obj *orangefs_obj;
static struct acache_orangefs_obj *acache_orangefs_obj;
static struct capcache_orangefs_obj *capcache_orangefs_obj;
static struct ccache_orangefs_obj *ccache_orangefs_obj;

int orangefs_sysfs_init(void)
{
	int rc;

	gossip_debug(GOSSIP_PROC_DEBUG, "orangefs_sysfs_init: start\n");

	/* create /sys/fs/orangefs. */
	orangefs_obj = kzalloc(sizeof(*orangefs_obj), GFP_KERNEL);
        if (!orangefs_obj) {
                rc = -EINVAL;
                goto out;
        }
	
	rc = kobject_init_and_add(&orangefs_obj->kobj,
				  &orangefs_ktype,
				  fs_kobj,
				  "orangefs");

	if (rc) {
		kobject_put(&orangefs_obj->kobj);
		rc = -EINVAL;
		goto out;
	}

	kobject_uevent(&orangefs_obj->kobj, KOBJ_ADD);

	/* create /sys/fs/orangefs/acache. */
	acache_orangefs_obj = kzalloc(sizeof(*acache_orangefs_obj), GFP_KERNEL);
        if (!acache_orangefs_obj) {
                rc = -EINVAL;
                goto out;
        }
	
	rc = kobject_init_and_add(&acache_orangefs_obj->kobj,
				  &acache_orangefs_ktype,
				  &orangefs_obj->kobj,
				  "acache");

	if (rc) {
                kobject_put(&orangefs_obj->kobj);
                rc = -EINVAL;
                goto out;
        }

        kobject_uevent(&acache_orangefs_obj->kobj, KOBJ_ADD);

	/* create /sys/fs/orangefs/capcache. */
        capcache_orangefs_obj =
		kzalloc(sizeof(*capcache_orangefs_obj), GFP_KERNEL);
        if (!capcache_orangefs_obj) {
                rc = -EINVAL;
                goto out;
        }

	rc = kobject_init_and_add(&capcache_orangefs_obj->kobj,
				  &capcache_orangefs_ktype,
				  &orangefs_obj->kobj,
				  "capcache");
        if (rc) {
                kobject_put(&orangefs_obj->kobj);
                rc = -EINVAL;
                goto out;
        }

        kobject_uevent(&capcache_orangefs_obj->kobj, KOBJ_ADD);

	/* create /sys/fs/orangefs/ccache. */
        ccache_orangefs_obj =
		kzalloc(sizeof(*ccache_orangefs_obj), GFP_KERNEL);
        if (!ccache_orangefs_obj) {
                rc = -EINVAL;
                goto out;
        }

	rc = kobject_init_and_add(&ccache_orangefs_obj->kobj,
				  &ccache_orangefs_ktype,
				  &orangefs_obj->kobj,
				  "ccache");
        if (rc) {
                kobject_put(&orangefs_obj->kobj);
                rc = -EINVAL;
                goto out;
        }

        kobject_uevent(&ccache_orangefs_obj->kobj, KOBJ_ADD);

out:
	return rc;
}

void orangefs_sysfs_exit(void)
{
	gossip_debug(GOSSIP_PROC_DEBUG, "orangefs_sysfs_exit: start\n");

	kobject_put(&orangefs_obj->kobj);
}
