/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  Copyright (C) 2011       Sebastian Pipping <sebastian@pipping.org>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall kmre_fuse.c `pkg-config fuse3 --cflags --libs` -lulockmgr -o kmre_fuse
*/

#define FUSE_USE_VERSION 31

#define BUF_SIZE 4096

#define _GNU_SOURCE

#include "lock_file.h"
#include "groups.h"
#include "misc.h"

#include <fuse.h>
#include <fuse_lowlevel.h>

#ifdef HAVE_LIBULOCKMGR
#include <ulockmgr.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <grp.h>
#include <libgen.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif
#include <sys/file.h> /* flock(2) */

#include <sys/utsname.h>

#include <sys/syslog.h>
#include <regex.h>

#define LOG_IDENT "KMRE_kylin-kmre-fuse"

static int allow_delete = 0;

struct regex_pair
{
    regex_t reg;
    char* pattern;
};

struct regex_pair regex_list[] = {
    { {}, "^[-\\.]*[0-9][0-9]*[-\\.]+[0-9][0-9]*$" },
    { {}, "^moffice[0-9][0-9]*\\.tmp$" },
    { {}, "^\\.moffice_wr_check[0-9][0-9]*$" },
    { {}, "^[0-9a-fA-F][0-9a-fA-F]*-[0-9a-fA-F][0-9a-fA-F]*-[0-9a-fA-F][0-9a-fA-F]*-[0-9a-fA-F][0-9a-fA-F]*-[0-9a-fA-F][0-9a-fA-F]*$" },
};


static int initialized = 0;
static void initialize_regex_list()
{
    int i = 0;

    if (initialized) {
        return;
    }

    for (i = 0; i < (sizeof(regex_list) / sizeof(struct regex_pair)); i++) {
        regcomp(&(regex_list[i].reg), regex_list[i].pattern, REG_EXTENDED | REG_ICASE | REG_NEWLINE | REG_NOSUB);
    }

    initialized = 1;
}

static void finalize_regex_list()
{
    int i = 0;

    if (!initialized) {
        return;
    }

    for (i = 0; i < (sizeof(regex_list) / sizeof(struct regex_pair)); i++) {
        regfree(&(regex_list[i].reg));
    }

    initialized = 0;
}

static int regex_matched(const char* str)
{
    int i = 0;
    int status = 0;

    initialize_regex_list();

    for (i = 0; i < (sizeof(regex_list) / sizeof(struct regex_pair)); i++) {
        status = regexec(&(regex_list[i].reg), str, 1, NULL, 0);
        if (status == 0) {
            return 1;
        }
    }

    return 0;
}

static void *xmp_init(struct fuse_conn_info *conn,
              struct fuse_config *cfg)
{
    (void) conn;
    cfg->use_ino = 1;
    cfg->nullpath_ok = 1;

    /* Pick up changes from lower filesystem right away. This is
       also necessary for better hardlink support. When the kernel
       calls the unlink() handler, it does not know the inode of
       the to-be-removed entry and can therefore not invalidate
       the cache of the associated inode - resulting in an
       incorrect st_nlink value being reported for any remaining
       hardlinks to this inode. */
    cfg->entry_timeout = 0;
    cfg->attr_timeout = 0;
    cfg->negative_timeout = 0;
    cfg->hard_remove = 1;

    return NULL;
}

static int xmp_getattr(const char *path, struct stat *stbuf,
            struct fuse_file_info *fi)
{
    int res;

    (void) path;

    if(fi)
        res = fstat(fi->fh, stbuf);
    else
        res = lstat(path, stbuf);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_access(const char *path, int mask)
{
    int res;

    res = access(path, mask);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
    int res;

    res = readlink(path, buf, size - 1);
    if (res == -1)
        return -errno;

    buf[res] = '\0';
    return 0;
}

struct xmp_dirp {
    DIR *dp;
    struct dirent *entry;
    off_t offset;
};

static int xmp_opendir(const char *path, struct fuse_file_info *fi)
{
    int res;
    struct xmp_dirp *d = malloc(sizeof(struct xmp_dirp));
    if (d == NULL)
        return -ENOMEM;

    d->dp = opendir(path);
    if (d->dp == NULL) {
        res = -errno;
        free(d);
        return res;
    }
    d->offset = 0;
    d->entry = NULL;

    fi->fh = (unsigned long) d;
    return 0;
}

static inline struct xmp_dirp *get_dirp(struct fuse_file_info *fi)
{
    return (struct xmp_dirp *) (uintptr_t) fi->fh;
}

static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
               off_t offset, struct fuse_file_info *fi,
               enum fuse_readdir_flags flags)
{
    struct xmp_dirp *d = get_dirp(fi);

    (void) path;
    if (offset != d->offset) {
#ifndef __FreeBSD__
        seekdir(d->dp, offset);
#else
        /* Subtract the one that we add when calling
           telldir() below */
        seekdir(d->dp, offset-1);
#endif
        d->entry = NULL;
        d->offset = offset;
    }
    while (1) {
        struct stat st;
        off_t nextoff;
        enum fuse_fill_dir_flags fill_flags = 0;

        if (!d->entry) {
            d->entry = readdir(d->dp);
            if (!d->entry)
                break;
        }
#ifdef HAVE_FSTATAT
        if (flags & FUSE_READDIR_PLUS) {
            int res;

            res = fstatat(dirfd(d->dp), d->entry->d_name, &st,
                      AT_SYMLINK_NOFOLLOW);
            if (res != -1)
                fill_flags |= FUSE_FILL_DIR_PLUS;
        }
#endif
        if (!(fill_flags & FUSE_FILL_DIR_PLUS)) {
            memset(&st, 0, sizeof(st));
            st.st_ino = d->entry->d_ino;
            st.st_mode = d->entry->d_type << 12;
        }
        nextoff = telldir(d->dp);
#ifdef __FreeBSD__        
        /* Under FreeBSD, telldir() may return 0 the first time
           it is called. But for libfuse, an offset of zero
           means that offsets are not supported, so we shift
           everything by one. */
        nextoff++;
#endif
        if (filler(buf, d->entry->d_name, &st, nextoff, fill_flags))
            break;

        d->entry = NULL;
        d->offset = nextoff;
    }

    return 0;
}

static int xmp_releasedir(const char *path, struct fuse_file_info *fi)
{
    struct xmp_dirp *d = get_dirp(fi);
    (void) path;
    closedir(d->dp);
    free(d);
    return 0;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
    int res;

    if (S_ISFIFO(mode))
        res = mkfifo(path, mode);
    else
        res = mknod(path, mode, rdev);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
    int res;

    res = mkdir(path, mode);
    if (res == -1)
        return -errno;

    return 0;
}

static int is_path_allowed_to_delete(const char* path)
{
    char buf[4096] = {0};
    int len;

    if (!path) {
        return 0;
    }

    len = strlen(path);
    if (len == 0 || len > 4095) {
        return 0;
    }

    strcpy(buf, path);

    if (regex_matched(basename(buf))) {
        return 1;
    }

    return 0;
}

static int xmp_unlink(const char *path)
{
    int res;

    if (allow_delete || is_path_allowed_to_delete(path)) {
        res = unlink(path);
        if (res == -1)
            return -errno;
    }

    return 0;
}

static int xmp_rmdir(const char *path)
{
    int res;

    if (allow_delete) {
        res = rmdir(path);
        if (res == -1)
            return -errno;
    }

    return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
    int res;

    res = symlink(from, to);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_rename(const char *from, const char *to, unsigned int flags)
{
    int res;

    /* When we have renameat2() in libc, then we can implement flags */
    if (flags)
        return -EINVAL;

    res = rename(from, to);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_link(const char *from, const char *to)
{
    int res;

    res = link(from, to);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_chmod(const char *path, mode_t mode,
             struct fuse_file_info *fi)
{
    int res;

    if (!allow_delete) {
        return 0;
    }

    if(fi)
        res = fchmod(fi->fh, mode);
    else
        res = chmod(path, mode);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid,
             struct fuse_file_info *fi)
{
    int res;

    if (!allow_delete) {
        return 0;
    }

    if (fi)
        res = fchown(fi->fh, uid, gid);
    else
        res = lchown(path, uid, gid);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_truncate(const char *path, off_t size,
             struct fuse_file_info *fi)
{
    int res;

    if(fi)
        res = ftruncate(fi->fh, size);
    else
        res = truncate(path, size);

    if (res == -1)
        return -errno;

    return 0;
}

#ifdef HAVE_UTIMENSAT
static int xmp_utimens(const char *path, const struct timespec ts[2],
               struct fuse_file_info *fi)
{
    int res;

    /* don't use utime/utimes since they follow symlinks */
    if (fi)
        res = futimens(fi->fh, ts);
    else
        res = utimensat(0, path, ts, AT_SYMLINK_NOFOLLOW);
    if (res == -1)
        return -errno;

    return 0;
}
#endif

static int xmp_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    int fd;

    fd = open(path, fi->flags, mode);
    if (fd == -1)
        return -errno;

    fi->fh = fd;
    return 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
    int fd;

    fd = open(path, fi->flags);
    if (fd == -1)
        return -errno;

    fi->fh = fd;
    return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
            struct fuse_file_info *fi)
{
    int res;

    (void) path;
    res = pread(fi->fh, buf, size, offset);
    if (res == -1)
        res = -errno;

    return res;
}

static int xmp_read_buf(const char *path, struct fuse_bufvec **bufp,
            size_t size, off_t offset, struct fuse_file_info *fi)
{
    struct fuse_bufvec *src;

    (void) path;

    src = malloc(sizeof(struct fuse_bufvec));
    if (src == NULL)
        return -ENOMEM;

    *src = FUSE_BUFVEC_INIT(size);

    src->buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
    src->buf[0].fd = fi->fh;
    src->buf[0].pos = offset;

    *bufp = src;

    return 0;
}

static int xmp_write(const char *path, const char *buf, size_t size,
             off_t offset, struct fuse_file_info *fi)
{
    int res;

    (void) path;
    res = pwrite(fi->fh, buf, size, offset);
    if (res == -1)
        res = -errno;

    return res;
}

static int xmp_write_buf(const char *path, struct fuse_bufvec *buf,
             off_t offset, struct fuse_file_info *fi)
{
    struct fuse_bufvec dst = FUSE_BUFVEC_INIT(fuse_buf_size(buf));

    (void) path;

    dst.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
    dst.buf[0].fd = fi->fh;
    dst.buf[0].pos = offset;

    return fuse_buf_copy(&dst, buf, FUSE_BUF_SPLICE_NONBLOCK);
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
    int res;

    res = statvfs(path, stbuf);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_flush(const char *path, struct fuse_file_info *fi)
{
    int res;

    (void) path;
    /* This is called from every close on an open file, so call the
       close on the underlying filesystem.    But since flush may be
       called multiple times for an open file, this must not really
       close the file.  This is important if used on a network
       filesystem like NFS which flush the data/metadata on close() */
    res = close(dup(fi->fh));
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_release(const char *path, struct fuse_file_info *fi)
{
    (void) path;
    close(fi->fh);

    return 0;
}

static int xmp_fsync(const char *path, int isdatasync,
             struct fuse_file_info *fi)
{
    int res;
    (void) path;

#ifndef HAVE_FDATASYNC
    (void) isdatasync;
#else
    if (isdatasync)
        res = fdatasync(fi->fh);
    else
#endif
        res = fsync(fi->fh);
    if (res == -1)
        return -errno;

    return 0;
}

#ifdef HAVE_POSIX_FALLOCATE
static int xmp_fallocate(const char *path, int mode,
            off_t offset, off_t length, struct fuse_file_info *fi)
{
    (void) path;

    if (mode)
        return -EOPNOTSUPP;

    return -posix_fallocate(fi->fh, offset, length);
}
#endif

#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
static int xmp_setxattr(const char *path, const char *name, const char *value,
            size_t size, int flags)
{
    int res = lsetxattr(path, name, value, size, flags);
    if (res == -1)
        return -errno;
    return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
            size_t size)
{
    int res = lgetxattr(path, name, value, size);
    if (res == -1)
        return -errno;
    return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
    int res = llistxattr(path, list, size);
    if (res == -1)
        return -errno;
    return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
    int res = lremovexattr(path, name);
    if (res == -1)
        return -errno;
    return 0;
}
#endif /* HAVE_SETXATTR */

#ifdef HAVE_LIBULOCKMGR
static int xmp_lock(const char *path, struct fuse_file_info *fi, int cmd,
            struct flock *lock)
{
    (void) path;

    return ulockmgr_op(fi->fh, cmd, lock, &fi->lock_owner,
               sizeof(fi->lock_owner));
}
#endif

static int xmp_flock(const char *path, struct fuse_file_info *fi, int op)
{
    int res;
    (void) path;

    res = flock(fi->fh, op);
    if (res == -1)
        return -errno;

    return 0;
}

#ifdef HAVE_COPY_FILE_RANGE
static ssize_t xmp_copy_file_range(const char *path_in,
                   struct fuse_file_info *fi_in,
                   off_t off_in, const char *path_out,
                   struct fuse_file_info *fi_out,
                   off_t off_out, size_t len, int flags)
{
    ssize_t res;
    (void) path_in;
    (void) path_out;

    res = copy_file_range(fi_in->fh, &off_in, fi_out->fh, &off_out, len,
                  flags);
    if (res == -1)
        return -errno;

    return res;
}
#endif

static off_t xmp_lseek(const char *path, off_t off, int whence, struct fuse_file_info *fi)
{
    off_t res;
    (void) path;

    res = lseek(fi->fh, off, whence);
    if (res == -1)
        return -errno;

    return res;
}

static struct fuse_operations xmp_oper = {
    .init           = xmp_init,
    .getattr    = xmp_getattr,
    .access        = xmp_access,
    .readlink    = xmp_readlink,
    .opendir    = xmp_opendir,
    .readdir    = xmp_readdir,
    .releasedir    = xmp_releasedir,
    .mknod        = xmp_mknod,
    .mkdir        = xmp_mkdir,
    .symlink    = xmp_symlink,
    .unlink        = xmp_unlink,
    .rmdir        = xmp_rmdir,
    .rename        = xmp_rename,
    .link        = xmp_link,
    .chmod        = xmp_chmod,
    .chown        = xmp_chown,
    .truncate    = xmp_truncate,
#ifdef HAVE_UTIMENSAT
    .utimens    = xmp_utimens,
#endif
    .create        = xmp_create,
    .open        = xmp_open,
    .read        = xmp_read,
    .read_buf    = xmp_read_buf,
    .write        = xmp_write,
    .write_buf    = xmp_write_buf,
    .statfs        = xmp_statfs,
    .flush        = xmp_flush,
    .release    = xmp_release,
    .fsync        = xmp_fsync,
#ifdef HAVE_POSIX_FALLOCATE
    .fallocate    = xmp_fallocate,
#endif
#ifdef HAVE_SETXATTR
    .setxattr    = xmp_setxattr,
    .getxattr    = xmp_getxattr,
    .listxattr    = xmp_listxattr,
    .removexattr    = xmp_removexattr,
#endif
#ifdef HAVE_LIBULOCKMGR
    .lock        = xmp_lock,
#endif
    .flock        = xmp_flock,
#ifdef HAVE_COPY_FILE_RANGE
    .copy_file_range = xmp_copy_file_range,
#endif
    .lseek        = xmp_lseek,
};

static int _check_lockfile(const char* mountpoint)
{
    char lockfile_name[256] = {0};
    char lockfile_path[1024] = {0};

    slash_to_underline(mountpoint, lockfile_name);
    sprintf(lockfile_path, "%s/.kmre-%s", LOCKFILE_PREFIX, lockfile_name);

    mkdir(LOCKFILE_PREFIX, 0750);
    chmod(LOCKFILE_PREFIX, 0750);

    return test_lockfile(lockfile_path);
}

static int check_lockfile(int argc, char *argv[])
{
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct fuse_cmdline_opts opts;
    int res = 0;

    res = fuse_parse_cmdline(&args, &opts);
    if (res < 0)
        return -1;

    if (opts.mountpoint) {
        res = _check_lockfile(opts.mountpoint);
        free(opts.mountpoint);
    }

    fuse_opt_free_args(&args);

    return res;
}

static int run_fuse(uid_t uid, gid_t gid, gid_t* kGroups, int group_size, int argc, char *argv[])
{
    umask(0);
    int err = 0;
    struct fuse *fuse;
    struct fuse_session *se;
    struct fuse_cmdline_opts opts;
    int res;
    int i = 0;
    char* end_string = "modules=subdir,subdir=/var/log";
    int end_len = strlen(end_string);
    int ret;

    gid_t groups0[GROUPS_NUM];
    gid_t *groups = groups0;
    int ngroups = GROUPS_NUM;
    int groups_initialized = 0;
    int should_get_groups = 0;

    for (i = 0; i < argc; i++) {
        int str_len = strlen(argv[i]);
        if (str_len < end_len) {
            continue;
        }
        if (string_end_with(argv[i], str_len, end_string, end_len)) {
            should_get_groups = 1;
            break;
        }
    }

    if (should_get_groups) {
        if (get_groups_from_uid(uid, gid, groups, &ngroups) < 0) {
            if (ngroups > 0) {
                groups = malloc(ngroups * sizeof(gid_t));
                if (groups != NULL) {
                    if (get_groups_from_uid(uid, gid, groups, &ngroups) == 0) {
                        groups_initialized = 1;
                    }
                }
            }
        } else {
            groups_initialized = 1;
        }
    }

    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

    if (fuse_parse_cmdline(&args, &opts) != 0) {
        fprintf(stderr, "fuse_parse_cmdline failed.\n");
        syslog(LOG_ERR, "Failed to parse cmdline args.");
        res = -1;
        goto on_exit;
    }

    if (check_lockfile(argc, argv) < 0) {
        fprintf(stderr, "check_lockfile failed\n");
        syslog(LOG_ERR, "Failed to check lockfile. Maybe another process has already held the lock.");
        res = -1;
        goto on_exit;
    }

    fuse = fuse_new(&args, &xmp_oper, sizeof(xmp_oper), NULL);

    if (!fuse) {
        err = errno;
        fprintf(stderr, "fuse_new failed.\n");
        syslog(LOG_ERR, "Failed to allocate fuse.");
        res = -1;
        goto out1;
    }

    if (fuse_mount(fuse, opts.mountpoint) != 0) {
        res = -1;
        fprintf(stderr, "fuse_mount failed.\n");
        syslog(LOG_ERR, "Failed to mount fuse");
        goto out2;
    }

    if (fuse_daemonize(opts.foreground) != 0) {
        res = -1;
        fprintf(stderr, "fuse_daemonize failed.\n");
        syslog(LOG_ERR, "Failed to daemonize fuse.");
        goto out3;
    }

    se = fuse_get_session(fuse);
    if (fuse_set_signal_handlers(se) != 0) {
        res = -1;
        fprintf(stderr, "fuse_set_signal_handlers failed.\n");
        syslog(LOG_ERR, "Failed to set signal handlers for fuse.");
        goto out3;
    }

    if (should_get_groups && groups_initialized) {
        ret = setgroups(ngroups, groups);
        if (ret < 0) {
            ret = setgroups(group_size, kGroups);
        }
    } else {
        ret = setgroups(group_size, kGroups);
    }
    if (ret < 0) {
        err = errno;
        fprintf(stderr, "cannot setgroups: %s\n", strerror(err));
        syslog(LOG_ERR, "Failed to set groups: %s.", strerror(err));
        res = -1;
        goto out3;
    }

    if (setgid(gid) < 0) {
        err = errno;
        fprintf(stderr, "cannot setgid: %s\n", strerror(err));
        syslog(LOG_ERR, "Failed to set uid: %s.", strerror(err));
        res = -1;
        goto out3;
    }
    if (setuid(uid) < 0) {
        err = errno;
        fprintf(stderr, "cannot setuid: %s\n", strerror(err));
        syslog(LOG_ERR, "Failed to set gid: %s.", strerror(err));
        res = -1;
        goto out3;
    }

    syslog(LOG_DEBUG, "kylin-kmre-fuse is running.");
    if (opts.singlethread) {
        res = fuse_loop(fuse);
    } else {
#if FUSE_USE_VERSION < 32
        res = fuse_loop_mt(fuse, opts.clone_fd);
#else
        struct fuse_loop_config loop_config;
        loop_config.clone_fd = opts.clone_fd;
        loop_config.max_idle_threads = opts.max_idle_threads;
        res = fuse_loop_mt(fuse, &loop_config);
#endif
    }

    if (res) {
        res = -1;
    }

    syslog(LOG_DEBUG, "kylin-kmre-fuse is going to exit.");
    closelog();

    fuse_remove_signal_handlers(se);
out3:
    fuse_unmount(fuse);
out2:
#if FUSE_VERSION < FUSE_MAKE_VERSION(3, 10)
    fuse_destroy(fuse);
#endif
out1:
    free(opts.mountpoint);
    fuse_opt_free_args(&args);
on_exit:

    if (groups != groups0) {
        if (groups) {
            free(groups);
        }
    }

    if (res == -1)
        return 1;

    return 0;
}


int main(int argc, char** argv) {
    int arg_count = 0;
    int ret = 0;
    int i = 0;
    int uid = -1;
    int gid = -1;
    char* endstr = NULL;

    char** args = NULL;

    openlog(LOG_IDENT, LOG_NDELAY | LOG_NOWAIT | LOG_PID, LOG_USER);
    syslog(LOG_DEBUG, "kylin-kmre-fuse is starting.");

    initialize_regex_list();
    args = (char**) calloc(argc + 1, sizeof(char*));
    args[0] = argv[0];

    for (i = 0; i < argc; ++i) {
        endstr = NULL;
        if (strcmp(argv[i], "-u") == 0) {
            if (i + 1 >= argc) {
                break;
            }
            uid = strtol(argv[i + 1], &endstr, 10);
            if (endstr == argv[i + 1] || *endstr != '\0') {
                uid = -1;
            }
            ++i; // skip uid
        } else if (strcmp(argv[i], "-g") == 0) {
            if (i + 1 >= argc) {
                break;
            }
            gid = strtol(argv[i + 1], &endstr, 10);
            if (endstr == argv[i + 1] || *endstr != '\0') {
                gid = -1;
            }
            ++i; // skip gid
        } else if (strcmp(argv[i], "--allow-delete") == 0) {
            allow_delete = 1;
        } else {
            args[arg_count++] = argv[i];
        }
    }

    if (uid < 0 || gid < 0) {
        ret = -1;
        goto out;
    }

    ret = run_fuse(uid, gid, (gid_t*)&gid, 1, arg_count, args);

out:
    if (args) {
        free(args);
    }

    finalize_regex_list();

    return ret;
}
