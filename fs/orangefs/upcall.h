/*
 * (C) 2001 Clemson University and The University of Chicago
 *
 * See COPYING in top-level directory.
 */

#ifndef __UPCALL_H
#define __UPCALL_H

/*
 * Sanitized this header file to fix
 * 32-64 bit interaction issues between
 * client-core and device
 */
struct pvfs2_io_request_t {
	int32_t async_vfs_io;
	int32_t buf_index;
	int32_t count;
	int32_t __pad1;
	int64_t offset;
	struct pvfs2_object_kref refn;
	enum PVFS_io_type io_type;
	int32_t readahead_size;
};

struct pvfs2_iox_request_t {
	int32_t buf_index;
	int32_t count;
	struct pvfs2_object_kref refn;
	enum PVFS_io_type io_type;
	int32_t __pad1;
};

struct pvfs2_lookup_request_t {
	int32_t sym_follow;
	int32_t __pad1;
	struct pvfs2_object_kref parent_refn;
	char d_name[PVFS2_NAME_LEN];
};

struct pvfs2_create_request_t {
	struct pvfs2_object_kref parent_refn;
	struct PVFS_sys_attr_s attributes;
	char d_name[PVFS2_NAME_LEN];
};

struct pvfs2_symlink_request_t {
	struct pvfs2_object_kref parent_refn;
	struct PVFS_sys_attr_s attributes;
	char entry_name[PVFS2_NAME_LEN];
	char target[PVFS2_NAME_LEN];
};

struct pvfs2_getattr_request_t {
	struct pvfs2_object_kref refn;
	uint32_t mask;
	uint32_t __pad1;
};

struct pvfs2_setattr_request_t {
	struct pvfs2_object_kref refn;
	struct PVFS_sys_attr_s attributes;
};

struct pvfs2_remove_request_t {
	struct pvfs2_object_kref parent_refn;
	char d_name[PVFS2_NAME_LEN];
};

struct pvfs2_mkdir_request_t {
	struct pvfs2_object_kref parent_refn;
	struct PVFS_sys_attr_s attributes;
	char d_name[PVFS2_NAME_LEN];
};

struct pvfs2_readdir_request_t {
	struct pvfs2_object_kref refn;
	uint64_t token;
	int32_t max_dirent_count;
	int32_t buf_index;
};

struct pvfs2_readdirplus_request_t {
	struct pvfs2_object_kref refn;
	uint64_t token;
	int32_t max_dirent_count;
	uint32_t mask;
	int32_t buf_index;
	int32_t __pad1;
};

struct pvfs2_rename_request_t {
	struct pvfs2_object_kref old_parent_refn;
	struct pvfs2_object_kref new_parent_refn;
	char d_old_name[PVFS2_NAME_LEN];
	char d_new_name[PVFS2_NAME_LEN];
};

struct pvfs2_statfs_request_t {
	int32_t fs_id;
	int32_t __pad1;
};

struct pvfs2_truncate_request_t {
	struct pvfs2_object_kref refn;
	int64_t size;
};

struct pvfs2_mmap_ra_cache_flush_request_t {
	struct pvfs2_object_kref refn;
};

struct pvfs2_fs_mount_request_t {
	char pvfs2_config_server[PVFS_MAX_SERVER_ADDR_LEN];
};

struct pvfs2_fs_umount_request_t {
	int32_t id;
	int32_t fs_id;
	char pvfs2_config_server[PVFS_MAX_SERVER_ADDR_LEN];
};

struct pvfs2_getxattr_request_t {
	struct pvfs2_object_kref refn;
	int32_t key_sz;
	int32_t __pad1;
	char key[PVFS_MAX_XATTR_NAMELEN];
};

struct pvfs2_setxattr_request_t {
	struct pvfs2_object_kref refn;
	struct PVFS_keyval_pair keyval;
	int32_t flags;
	int32_t __pad1;
};

struct pvfs2_listxattr_request_t {
	struct pvfs2_object_kref refn;
	int32_t requested_count;
	int32_t __pad1;
	uint64_t token;
};

struct pvfs2_removexattr_request_t {
	struct pvfs2_object_kref refn;
	int32_t key_sz;
	int32_t __pad1;
	char key[PVFS_MAX_XATTR_NAMELEN];
};

struct pvfs2_op_cancel_t {
	uint64_t op_tag;
};

struct pvfs2_fsync_request_t {
	struct pvfs2_object_kref refn;
};

enum pvfs2_param_request_type {
	PVFS2_PARAM_REQUEST_SET = 1,
	PVFS2_PARAM_REQUEST_GET = 2
};

enum pvfs2_param_request_op {
	PVFS2_PARAM_REQUEST_OP_ACACHE_TIMEOUT_MSECS = 1,
	PVFS2_PARAM_REQUEST_OP_ACACHE_HARD_LIMIT = 2,
	PVFS2_PARAM_REQUEST_OP_ACACHE_SOFT_LIMIT = 3,
	PVFS2_PARAM_REQUEST_OP_ACACHE_RECLAIM_PERCENTAGE = 4,
	PVFS2_PARAM_REQUEST_OP_PERF_TIME_INTERVAL_SECS = 5,
	PVFS2_PARAM_REQUEST_OP_PERF_HISTORY_SIZE = 6,
	PVFS2_PARAM_REQUEST_OP_PERF_RESET = 7,
	PVFS2_PARAM_REQUEST_OP_NCACHE_TIMEOUT_MSECS = 8,
	PVFS2_PARAM_REQUEST_OP_NCACHE_HARD_LIMIT = 9,
	PVFS2_PARAM_REQUEST_OP_NCACHE_SOFT_LIMIT = 10,
	PVFS2_PARAM_REQUEST_OP_NCACHE_RECLAIM_PERCENTAGE = 11,
	PVFS2_PARAM_REQUEST_OP_STATIC_ACACHE_TIMEOUT_MSECS = 12,
	PVFS2_PARAM_REQUEST_OP_STATIC_ACACHE_HARD_LIMIT = 13,
	PVFS2_PARAM_REQUEST_OP_STATIC_ACACHE_SOFT_LIMIT = 14,
	PVFS2_PARAM_REQUEST_OP_STATIC_ACACHE_RECLAIM_PERCENTAGE = 15,
	PVFS2_PARAM_REQUEST_OP_CLIENT_DEBUG = 16,
	PVFS2_PARAM_REQUEST_OP_CCACHE_TIMEOUT_SECS = 17,
	PVFS2_PARAM_REQUEST_OP_CCACHE_HARD_LIMIT = 18,
	PVFS2_PARAM_REQUEST_OP_CCACHE_SOFT_LIMIT = 19,
	PVFS2_PARAM_REQUEST_OP_CCACHE_RECLAIM_PERCENTAGE = 20
};

struct pvfs2_param_request_t {
	enum pvfs2_param_request_type type;
	enum pvfs2_param_request_op op;
	int64_t value;
	char s_value[PVFS2_MAX_DEBUG_STRING_LEN];
};

enum pvfs2_perf_count_request_type {
	PVFS2_PERF_COUNT_REQUEST_ACACHE = 1,
	PVFS2_PERF_COUNT_REQUEST_NCACHE = 2,
	PVFS2_PERF_COUNT_REQUEST_STATIC_ACACHE = 3,
};

struct pvfs2_perf_count_request_t {
	enum pvfs2_perf_count_request_type type;
	int32_t __pad1;
};

struct pvfs2_fs_key_request_t {
	int32_t fsid;
	int32_t __pad1;
};

/* typedef pvfs2_upcall_t exposed to client-core (userland) */
typedef struct pvfs2_upcall_s {
	int32_t type;
	uint32_t uid;
	uint32_t gid;
	int pid;
	int tgid;
	/* currently trailer is used only by readx/writex (iox) */
	int64_t trailer_size;
	PVFS2_ALIGN_VAR(char *, trailer_buf);

	union {
		struct pvfs2_io_request_t io;
		struct pvfs2_iox_request_t iox;
		struct pvfs2_lookup_request_t lookup;
		struct pvfs2_create_request_t create;
		struct pvfs2_symlink_request_t sym;
		struct pvfs2_getattr_request_t getattr;
		struct pvfs2_setattr_request_t setattr;
		struct pvfs2_remove_request_t remove;
		struct pvfs2_mkdir_request_t mkdir;
		struct pvfs2_readdir_request_t readdir;
		struct pvfs2_readdirplus_request_t readdirplus;
		struct pvfs2_rename_request_t rename;
		struct pvfs2_statfs_request_t statfs;
		struct pvfs2_truncate_request_t truncate;
		struct pvfs2_mmap_ra_cache_flush_request_t ra_cache_flush;
		struct pvfs2_fs_mount_request_t fs_mount;
		struct pvfs2_fs_umount_request_t fs_umount;
		struct pvfs2_getxattr_request_t getxattr;
		struct pvfs2_setxattr_request_t setxattr;
		struct pvfs2_listxattr_request_t listxattr;
		struct pvfs2_removexattr_request_t removexattr;
		struct pvfs2_op_cancel_t cancel;
		struct pvfs2_fsync_request_t fsync;
		struct pvfs2_param_request_t param;
		struct pvfs2_perf_count_request_t perf_count;
		struct pvfs2_fs_key_request_t fs_key;
	} req;
} pvfs2_upcall_t;

#endif /* __UPCALL_H */
