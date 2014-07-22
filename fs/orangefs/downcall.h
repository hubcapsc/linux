/*
 * (C) 2001 Clemson University and The University of Chicago
 *
 * See COPYING in top-level directory.
 */

/*
 *  Definitions of downcalls used in Linux kernel module.
 */

#ifndef __DOWNCALL_H
#define __DOWNCALL_H

/*
 * Sanitized the device-client core interaction
 * for clean 32-64 bit usage
 */
struct pvfs2_io_response {
	int64_t amt_complete;
};

struct pvfs2_iox_response {
	int64_t amt_complete;
};

struct pvfs2_lookup_response {
	struct pvfs2_object_kref refn;
};

struct pvfs2_create_response {
	struct pvfs2_object_kref refn;
};

struct pvfs2_symlink_response {
	struct pvfs2_object_kref refn;
};

struct pvfs2_getattr_response {
	struct PVFS_sys_attr_s attributes;
	char link_target[PVFS2_NAME_LEN];
};

struct pvfs2_mkdir_response {
	struct pvfs2_object_kref refn;
};

/*
 * duplication of some system interface structures so that I don't have
 * to allocate extra memory
 */
struct pvfs2_dirent {
	char *d_name;
	int d_length;
	struct pvfs2_khandle khandle;
};

struct pvfs2_statfs_response {
	int64_t block_size;
	int64_t blocks_total;
	int64_t blocks_avail;
	int64_t files_total;
	int64_t files_avail;
};

struct pvfs2_fs_mount_response {
	int32_t fs_id;
	int32_t id;
	struct pvfs2_khandle root_khandle;
};

/* the getxattr response is the attribute value */
struct pvfs2_getxattr_response {
	int32_t val_sz;
	int32_t __pad1;
	char val[PVFS_MAX_XATTR_VALUELEN];
};

/* the listxattr response is an array of attribute names */
struct pvfs2_listxattr_response {
	int32_t returned_count;
	int32_t __pad1;
	uint64_t token;
	char key[PVFS_MAX_XATTR_LISTLEN * PVFS_MAX_XATTR_NAMELEN];
	int32_t keylen;
	int32_t __pad2;
	int32_t lengths[PVFS_MAX_XATTR_LISTLEN];
};

struct pvfs2_param_response {
	int64_t value;
};

#define PERF_COUNT_BUF_SIZE 4096
struct pvfs2_perf_count_response {
	char buffer[PERF_COUNT_BUF_SIZE];
};

#define FS_KEY_BUF_SIZE 4096
struct pvfs2_fs_key_response {
	int32_t fs_keylen;
	int32_t __pad1;
	char fs_key[FS_KEY_BUF_SIZE];
};

/*
 * this typedef is exposed to the client core (userspace).
 */
typedef struct pvfs2_downcall {
	int32_t type;
	int32_t status;
	/* currently trailer is used only by readdir */
	int64_t trailer_size;
	PVFS2_ALIGN_VAR(char *, trailer_buf);

	union {
		struct pvfs2_io_response io;
		struct pvfs2_iox_response iox;
		struct pvfs2_lookup_response lookup;
		struct pvfs2_create_response create;
		struct pvfs2_symlink_response sym;
		struct pvfs2_getattr_response getattr;
		struct pvfs2_mkdir_response mkdir;
		struct pvfs2_statfs_response statfs;
		struct pvfs2_fs_mount_response fs_mount;
		struct pvfs2_getxattr_response getxattr;
		struct pvfs2_listxattr_response listxattr;
		struct pvfs2_param_response param;
		struct pvfs2_perf_count_response perf_count;
		struct pvfs2_fs_key_response fs_key;
	} resp;
} pvfs2_downcall_t;

/*
 * this typedef is exposed to the client core (userspace).
 */
typedef struct pvfs2_readdir_response {
	uint64_t token;
	uint64_t directory_version;
	uint32_t  __pad2;
	uint32_t pvfs_dirent_outcount;
	struct pvfs2_dirent *dirent_array;
} pvfs2_readdir_response_t;

#endif /* __DOWNCALL_H */
