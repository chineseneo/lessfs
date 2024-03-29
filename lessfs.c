/*
 *   Lessfs: A data deduplicating filesystem.
 *   Copyright (C) 2008 Mark Ruijter <mruijter@lessfs.com>
 *
 *   This program is free software.
 *   You can redistribute lessfs and/or modify it under the terms of either
 *   (1) the GNU General Public License; either version 3 of the License,
 *   or (at your option) any later version as published by
 *   the Free Software Foundation; or (2) obtain a commercial license
 *   by contacting the Author.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#define FUSE_USE_VERSION 26
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef LFATAL
#include "lib_log.h"
#endif

#ifndef VERSION
#define VERSION "0"
#endif

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <malloc.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>
#include <libgen.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <tcutil.h>
#include <tchdb.h>
#include <tcbdb.h>
#include <stdlib.h>
#include <stdbool.h>
#ifdef LZO
#include "lib_lzo.h"
#else
#include "lib_qlz.h"
#endif
#include "lib_tc.h"
#include "lib_net.h"
#include "file_io.h"

#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif
#include "lib_safe.h"
#include "lib_cfg.h"
#include "lib_str.h"
#include "retcodes.h"
#ifdef ENABLE_CRYPTO
#include "lib_crypto.h"
#endif
#ifdef SHA3
#include "lib_BMW_SHA3api_ref.h"
#endif

#ifdef i386
#define ITERATIONS 30
#else
#define ITERATIONS 500
#endif
#include "commons.h"

void segvExit()
{
    LFATAL("Exit caused by segfault!, exitting\n");
    tc_close(0);
    exit(EXIT_OK);
}

void normalExit()
{
    LFATAL("Exit signal received, exitting\n");
    sync_flush_dtaq();
    sync_flush_dbu();
    sync_flush_dbc();
    sync_flush_dbb();
    tc_close(0);
    exit(EXIT_OK);
}

void libSafeExit()
{
    tc_close(0);
    LFATAL("Exit signal received from lib_safe, exitting\n");
    exit(EXIT_OK);
}

int check_path_sanity(const char *path)
{
    char *name;
    char *p;
    char *q;
    int retcode = 0;

    FUNC;

    name = s_strdup((char *) path);
    p = name;
    q = p;
    while (1) {
        p = strrchr(q, '/');
        if (p == NULL)
            break;
        q = p;
        q++;
        p[0] = 0;
        if (q) {
            if (strlen(q) > 255) {
                LDEBUG("check_path_sanity : error q>255");
                retcode = -ENAMETOOLONG;
            }
        }
        q = p--;
    }
    free(name);
    EFUNC;
    return (retcode);
}

void dbsync()
{
    tcbdbsync(dbdirent);
    tchdbsync(dbr);
    tchdbsync(dbu);
	tchdbsync(dbc);
    tchdbsync(dbb);
    tchdbsync(dbp);
    if (NULL != config->blockdatabs) {
        tchdbsync(dbdta);
    } else {
        fsync(fdbdta);
    }
}

/*
 * print the time use
 */
void printTimeStamp(struct timeval start, const char *func)
{
	struct timeval end;
	float timeSpan;

	gettimeofday(&end, 0);
	timeSpan = 1000000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec);
	timeSpan /= 1000000;
	LDEBUG("%s: time use=%f", func, timeSpan);
}

/*
 * search in the database for path and get the stat of the file or dir
 *
 */
static int lessfs_getattr(const char *path, struct stat *stbuf)	
{
    int res;
    int c;

    FUNC;
    LDEBUG("lessfs_getattr %s", path);
    res = check_path_sanity(path);
    if (res == -ENAMETOOLONG)
        return (res);

    open_lock();
getattrwait:
    get_global_lock();
    for (c = 0; c < max_threads; c++) {
        if (tdta[c]->inode != 0 ) {
            release_global_lock();
            goto getattrwait;
        }
    }
    res = dbstat(path, stbuf);
    LDEBUG("%s: file=%s inode=%llu", __FUNCTION__, path, stbuf->st_ino);
    LDEBUG("lessfs_getattr : st_nlinks=%u", stbuf->st_nlink);
    LDEBUG("lessfs_getattr : %s size %llu : result %i",path,
           (unsigned long long) stbuf->st_size, res);
    release_global_lock();
    release_open_lock();
    return (res);
}

/*
 * do nothing
 *
 */
static int lessfs_access(const char *path, int mask)
{
    int res = 0;
    FUNC;
// Empty stub
    return (res);
}

/*
 * search in the database for path and get the stat of the file or dir
 *
 */
static int lessfs_readlink(const char *path, char *buf, size_t size)
{
    int res = 0;

    FUNC;

    LDEBUG("%s: path = %s, size = %llu", __FUNCTION__, path, 
		(unsigned long long)size);
    get_global_lock();
    res = fs_readlink(path, buf, size);
    release_global_lock();
    return (res);
}


static int lessfs_readdir(const char *path, void *buf,
                          fuse_fill_dir_t filler, off_t offset,
                          struct fuse_file_info *fi)
{
    int retcode;
    LDEBUG("%s: path = %s, offset = %llu", __FUNCTION__, path, (unsigned long long)offset);
    get_global_lock();
    retcode = fs_readdir(path, buf, filler, offset, fi);
    release_global_lock();
    return (retcode);
}

static int lessfs_mknod(const char *path, mode_t mode, dev_t rdev)
{
    int retcode = 0;
    char *dname;
    struct stat stbuf;
    time_t thetime;

    FUNC;
    LDEBUG("%s: path = %s", __FUNCTION__, path);
    get_global_lock();
    thetime = time(NULL);
    dname = s_dirname((char *) path);
    retcode = dbstat(dname, &stbuf);
    LDEBUG("lessfs_mknod : dbstat returns %i", retcode);
    if (0 != retcode)
        return retcode;
    dbmknod(path, mode, NULL, rdev);
    stbuf.st_ctim.tv_sec = thetime;
    stbuf.st_ctim.tv_nsec=0;
    stbuf.st_mtim.tv_sec = thetime;
    stbuf.st_mtim.tv_nsec=0;
    retcode = update_stat(dname, &stbuf);
    LDEBUG("lessfs_mknod : update_stat returns %i", retcode);
    free(dname);
    release_global_lock();
    return (retcode);
}

static int lessfs_mkdir(const char *path, mode_t mode)
{
    int ret;
    LDEBUG("%s: path = %s", __FUNCTION__, path);
    get_global_lock();
    ret = fs_mkdir(path, mode);
    release_global_lock();
    return (ret);
}

static int lessfs_unlink(const char *path)
{
    int res;
    FUNC;
    LDEBUG("%s: path = %s", __FUNCTION__, path);
    get_global_lock();
    sync_flush_dtaq();
    sync_flush_dbu();
    sync_flush_dbc();
    sync_flush_dbb();
    if (NULL != config->blockdatabs) {
        res = db_unlink_file(path);
    } else {
        res = file_unlink_file(path);
    }
    if ( config->relax == 0 ) dbsync();
    release_global_lock();
    EFUNC;
    return res;
}

static int lessfs_rmdir(const char *path)
{
    int res;
    LDEBUG("%s: path = %s", __FUNCTION__, path);
    get_global_lock();
    res = fs_rmdir(path);
    release_global_lock();
    return (res);

}

static int lessfs_symlink(const char *from, const char *to)
{
    int res = 0;

    FUNC;
    LDEBUG("%s: from = %s, to = %s", __FUNCTION__, from, to);
    get_global_lock();
    res = fs_symlink((char *) from, (char *) to);
    release_global_lock();
    return (res);
}

static int lessfs_rename(const char *from, const char *to)
{
    int res = 0;
    struct stat stbuf;

    FUNC;
    LDEBUG("%s: from = %s, to = %s", __FUNCTION__, from, to);
    LDEBUG("lessfs_rename : from %s , to %s", from, to);
    get_global_lock();
    res = dbstat(from, &stbuf);
    if (res == 0) {
        update_filesize_onclose(stbuf.st_ino);
        if (stbuf.st_nlink > 1 && !S_ISDIR(stbuf.st_mode)) {
            res = fs_rename_link(from, to, stbuf);
        } else {
            res = fs_rename(from, to, stbuf);
        }
    }
    release_global_lock();
    return (res);
}

/*
 * create a new link,
 * add info of link name and dir inode and link dest inode into dbl
 */
static int lessfs_link(const char *from, const char *to)
{
    int res = 0;

    FUNC;
    LDEBUG("%s: from = %s, to = %s", __FUNCTION__, from, to);
    get_global_lock();
    res = fs_link((char *) from, (char *) to);
    release_global_lock();
    return (res);
}

/*
 * change the mode of a file,
 * if the meta exists in dbcache, rewrite the dbcache
 * if not, rewrite the dbp
 */
static int lessfs_chmod(const char *path, mode_t mode)
{
    int res;
    time_t thetime;
    struct stat stbuf;
    DBT *data;
    MEMDDSTAT *memddstat;
    DBT *ddbuf;

    FUNC;
    LDEBUG("%s: path = %s", __FUNCTION__, path);
    get_global_lock();
    thetime = time(NULL);
    res = dbstat(path, &stbuf);
    if ( res != 0 ) return(res);
    data = search_memhash(dbcache, &stbuf.st_ino,
                          sizeof(unsigned long long));
    if (NULL != data) {
        memddstat = (MEMDDSTAT *) data->data;
        memddstat->stbuf.st_ctim.tv_sec = thetime;
        memddstat->stbuf.st_ctim.tv_nsec=0;
        memddstat->stbuf.st_mode = mode;
        memddstat->updated = 1;
        ddbuf = create_mem_ddbuf(memddstat);
        mbin_write_dbdata(dbcache, &stbuf.st_ino,
                          sizeof(unsigned long long), (void *) ddbuf->data,
                          ddbuf->size);
        DBTfree(ddbuf);
        DBTfree(data);
    } else {
        stbuf.st_mode = mode;
        stbuf.st_ctim.tv_sec = thetime;
        stbuf.st_ctim.tv_nsec=0;
        res = update_stat((char *) path, &stbuf);
    }
    release_global_lock();
    return (res);
}

/*
 * change the uid and gid of a file,
 * if the meta exists in dbcache, rewrite the dbcache
 * if not, rewrite the dbp
 */
static int lessfs_chown(const char *path, uid_t uid, gid_t gid)
{
    int res;
    time_t thetime;
    struct stat stbuf;
    DBT *data;
    MEMDDSTAT *memddstat;
    DBT *ddbuf;

    FUNC;
    get_global_lock();
    thetime = time(NULL);
    res = dbstat(path, &stbuf);
    if ( res != 0 ) return(res);
    data = search_memhash(dbcache, &stbuf.st_ino,
                          sizeof(unsigned long long));
    if (NULL != data) {
        memddstat = (MEMDDSTAT *) data->data;
        memddstat->stbuf.st_ctim.tv_sec = thetime;
        memddstat->stbuf.st_ctim.tv_nsec=0;
        memddstat->stbuf.st_uid = uid;
        memddstat->stbuf.st_gid = gid;
        memddstat->updated = 1;
        ddbuf = create_mem_ddbuf(memddstat);
        mbin_write_dbdata(dbcache, &stbuf.st_ino,
                          sizeof(unsigned long long), (void *) ddbuf->data,
                          ddbuf->size);
        DBTfree(ddbuf);
        DBTfree(data);
    } else {
        if (-1 != uid)
           stbuf.st_uid = uid;
        if (-1 != gid)
           stbuf.st_gid = gid;
        stbuf.st_ctim.tv_sec = thetime;
        stbuf.st_ctim.tv_nsec=0;
        res = update_stat((char *) path, &stbuf);
    }
    release_global_lock();
    return (res);
}

/*
 * truncate a file, if the new size is bigger, update size and fill empty bytes
 * if the new size is smaller, update size and delete the extra blocks
 */
static int lessfs_truncate(const char *path, off_t size)
{
    int res = 0;
    struct stat *stbuf;
    char *bname;
    DBT *data;
	
    get_global_lock();
    LDEBUG("%s: path = %s, from %llu to %llu", __FUNCTION__, path, stbuf->st_size, 
		size);
    bname = s_basename((char *) path);
    stbuf = s_malloc(sizeof(struct stat));
    res = dbstat(path, stbuf);
    if (res != 0)
        return (res);
    if (S_ISDIR(stbuf->st_mode)) {
        return (-EISDIR);
    }
    /* Flush the blockcache before we continue. */
    data = try_block_cache(stbuf->st_ino, 0, 1);
    if (data != NULL) die_syserr(); 
    release_global_lock();
    wait_io_pending(stbuf->st_ino);
    sync_flush_dtaq();

    if ( size < stbuf->st_size || size == 0 ) {
       if (NULL != config->blockdatabs) {
           res = db_fs_truncate(stbuf, size, bname);
       } else {
           res = file_fs_truncate(stbuf, size, bname);
       }
    } else {
       LDEBUG("lessfs_truncate : %s only change size to %llu",path,size);
       update_filesize_cache(stbuf, size);
    }
    free(stbuf);
    free(bname);
    release_global_lock();
    return (res);
}

/*
 * update the access time and modify time of an inode,
 * rewrite the dbcache entry if it exists,
 * or rewrite the dbp entry
 */
static int lessfs_utimens(const char *path, const struct timespec ts[2])
{
    int res = 0;
    struct stat stbuf;
    DDSTAT *ddstat;
    DBT *ddbuf;
    DBT *data;
    MEMDDSTAT *memddstat;

    FUNC;
    get_global_lock();
    res = dbstat(path, &stbuf);
    if ( res != 0 ) {
       release_global_lock();
       return(res);
    }
    data = search_memhash(dbcache, &stbuf.st_ino,
                          sizeof(unsigned long long));
    if (NULL != data) {
        memddstat = (MEMDDSTAT *) data->data;
        memddstat->stbuf.st_atim.tv_sec = ts[0].tv_sec;
        memddstat->stbuf.st_atim.tv_nsec = ts[0].tv_nsec;
        memddstat->stbuf.st_mtim.tv_sec = ts[1].tv_sec;
        memddstat->stbuf.st_mtim.tv_nsec = ts[1].tv_nsec;
        memddstat->updated = 1;
        ddbuf = create_mem_ddbuf(memddstat);
        mbin_write_dbdata(dbcache, &stbuf.st_ino,
                          sizeof(unsigned long long), (void *) ddbuf->data,
                          ddbuf->size);
        DBTfree(ddbuf);
        DBTfree(data);
    } else {
        data =
            search_dbdata(dbp, &stbuf.st_ino, sizeof(unsigned long long));
        if (data == NULL) {
#ifdef x86_64
            die_dataerr("Failed to find file %lu", stbuf.st_ino);
#else
            die_dataerr("Failed to find file %llu", stbuf.st_ino);
#endif
        }
        ddstat = value_to_ddstat(data);
        ddstat->stbuf.st_atim.tv_sec = ts[0].tv_sec;
        ddstat->stbuf.st_atim.tv_nsec = ts[0].tv_nsec;
        ddstat->stbuf.st_mtim.tv_sec = ts[1].tv_sec;
        ddstat->stbuf.st_mtim.tv_nsec = ts[1].tv_nsec;
        ddbuf = create_ddbuf(ddstat->stbuf, ddstat->filename);
        bin_write_dbdata(dbp, &stbuf.st_ino, sizeof(unsigned long long),
                         (void *) ddbuf->data, ddbuf->size);
        DBTfree(data);
        DBTfree(ddbuf);
        ddstatfree(ddstat);
    }
    release_global_lock();
    return (res);
}

/*
 * open a file, get the stat of the file into dbcache
 * if file is opened, increase the opens flag
 * if not, initialize new memddstat and set opens 1, access time the current time
 */
static int lessfs_open(const char *path, struct fuse_file_info *fi)
{
    struct stat stbuf;
    char *bname;
    DBT *ddbuf;
    DBT *dataptr;
    unsigned long long blocknr = 0;
    MEMDDSTAT *memddstat;
    unsigned long long inode;

    int res = 0;

    FUNC;
    LDEBUG("lessfs_open : %s strlen %i : uid %u", path,
           strlen((char *) path), fuse_get_context()->uid);

    open_lock();
    get_global_lock();
    res = dbstat(path, &stbuf);
    release_global_lock();
    if (res == -ENOENT) {
        fi->fh = 0;
        stbuf.st_mode = fi->flags;
        stbuf.st_uid = fuse_get_context()->uid;
        stbuf.st_gid = fuse_get_context()->gid;
    } else {
        fi->fh = stbuf.st_ino;
        inode = stbuf.st_ino;
        wait_io_pending(inode);
        bname = s_basename((char *) path);
//  Check if we have already something in cache for this inode
        dataptr = search_memhash(dbcache, &stbuf.st_ino, 
        						sizeof(unsigned long long));
        if (dataptr == NULL) {
            blocknr--;          /* Invalid block in cache */
//  Initialize the cache
            memddstat = s_malloc(sizeof(MEMDDSTAT));
            memcpy(&memddstat->stbuf, &stbuf, sizeof(struct stat));
            memcpy(&memddstat->filename, bname, strlen(bname) + 1);
            memddstat->blocknr = blocknr;
            memddstat->updated = 0;
            memddstat->opened = 1;
            memddstat->deduplicated = 0;
            memddstat->lzo_compressed_size = 0;
            memddstat->stbuf.st_atim.tv_sec=time(NULL);
            memddstat->stbuf.st_atim.tv_nsec=0;
            LDEBUG("lessfs_open : initial open memddstat->opened = %u",
                   memddstat->opened);
            ddbuf = create_mem_ddbuf(memddstat);
            mbin_write_dbdata(dbcache, &inode, sizeof(unsigned long long),
                              (void *) ddbuf->data, ddbuf->size);
            DBTfree(ddbuf);
            memddstatfree(memddstat);
        } else {
            memddstat = (MEMDDSTAT *) dataptr->data;
            memddstat->opened++;
            memddstat->stbuf.st_atim.tv_sec=time(NULL);
            memddstat->stbuf.st_atim.tv_nsec=0;
            LDEBUG("lessfs_open : repeated open ddstat->opened = %u",
                   memddstat->opened);
            ddbuf = create_mem_ddbuf(memddstat);
            mbin_write_dbdata(dbcache, &inode, sizeof(unsigned long long),
                              (void *) ddbuf->data, ddbuf->size);
            DBTfree(ddbuf);
            DBTfree(dataptr);
        }
        free(bname);
        release_global_lock();
    }
    release_open_lock();
    return (res);
}

/*
 * read file data into buf
 * @param buf the buffer to store the read data
 * @param size the length of data to read at one time
 */
static int lessfs_read(const char *path, char *buf, size_t size,
                       off_t offset, struct fuse_file_info *fi)
{
    unsigned long long blocknr;
    size_t done = 0;
    size_t got = 0;
    size_t block_offset = 0;
    char *tmpbuf = NULL;
    MEMDDSTAT *memddstat;
	OFFHASH *offhash;

    FUNC;
    LDEBUG("%s: path = %s, size = %llu, offset = %llu", __FUNCTION__, 
		path, (unsigned long long)size, (unsigned long long)offset);

    get_global_lock();
// Change this to creating a buffer that is allocated once.
    tmpbuf = s_malloc(BLKSIZE + 1);
    memset(buf, 0, size);
    blocknr = get_blocknr(fi->fh, offset);
	offhash = get_offhash(fi->fh, blocknr);
    block_offset = (done + offset) - offhash->offset;
redo:
    memset(tmpbuf, 0, BLKSIZE + 1);
    LDEBUG("lessfs_read called offset : %llu, size bytes %llu",
           (unsigned long long) offset, (unsigned long long) size);
    while (done < size) {
        LDEBUG("blocknr to read :%llu", (unsigned long long) blocknr);
        if (NULL != config->blockdatabs) {
            got = readBlock(blocknr, path, tmpbuf, fi->fh);
        } else
            got = file_read_block(blocknr, path, tmpbuf, fi->fh);
        if (got > 0) {
            if ((got - block_offset) + done >= size) {
                memcpy(buf + done, tmpbuf + block_offset, size - done);
                done = size;
                break;
            }
            memcpy(buf + done, tmpbuf + block_offset, got - block_offset);
            done = done + got - block_offset;
        } 
		else if (got == 0) {
	        done += (size - done) < BLKSIZE? (size - done) : BLKSIZE;
	        LDEBUG("lessfs_read : sparse block %llu-%llu offset %llu size %llu",
                fi->fh,blocknr,(unsigned long long) offset,(unsigned long long) size);
    	}
		blocknr++;
		block_offset = 0;
    }
    free(tmpbuf);
    release_global_lock();
    return (done);
}

/*
 *write data of which the length is size and starts from offset to the data base.
 *size is specified in FUSE with the args in lessfs mount.
 */
static int lessfs_write(const char *path, const char *buf, size_t size,
                        off_t offset, struct fuse_file_info *fi)
{
	if (dedup == 0) {
		int len;
		char *ext = getextension(&len, path);
		if (ext == NULL) {
			len = 5;
			ext = malloc(len);
			memcpy(ext, "none\0", len);
		}
		int ratio = check_ratio(ext, len);
		if (0 < ratio) {
			return sb_write(path, buf, size, offset, fi);
		}
		else
			return fsp_write(path, buf, size, offset, fi);
	}
	if (dedup == 1)
		return fsp_write(path, buf, size, offset, fi);
	else
		return sb_write(path, buf, size, offset, fi);
}

int fsp_write(const char *path, const char *buf, size_t size,
                        off_t offset, struct fuse_file_info *fi)
{
	  unsigned long long blocknr;
	  off_t offsetfile;
	  unsigned int offsetblock;
	  DBT *blocktiger;
	  DBT *data;
	  OFFHASH *offhash;
	  size_t bsize;
	  size_t done = 0;
	  int res;
	  INOBNO inobno;
	
	  FUNC;
	  tiger_lock();
	  bsize = size;
	  blocknr = offset / BLKSIZE;
	
	  offsetblock = offset - (blocknr * BLKSIZE);
	  offsetfile = offset - offsetblock;
	  if ((offsetblock + bsize) > BLKSIZE) {
		  bsize = BLKSIZE - offsetblock;
	  }
	  blkdta->inode = fi->fh;
	  inobno.inode = fi->fh;
	  //notice that the offset printed is the offsetblock rather than offset itself...	  
	  LDEBUG("lessfs_write : %s - %llu-%llu size %llu offset %u",path,
		  inobno.inode,blocknr,(unsigned long long)size,offsetblock);
	wagain:
	  inobno.blocknr = blocknr;
	  /*  When I/O for this inode - blocknr is pending this operation will be an update */
	  wait_inode_block_pending(inobno.inode, inobno.blocknr);
	  memset((char *) blkdta->blockdata, 0, BLKSIZE);
	  LDEBUG("lessfs_write -> try_block_cache : inode %llu blocknr %llu",
			 fi->fh, blocknr);
	  data = try_block_cache(inobno.inode, inobno.blocknr, 2);
	  if (NULL != data) {
	
		  memcpy((char *) blkdta->blockdata, data->data, data->size);
		  memcpy((char *) blkdta->blockdata + offsetblock, buf + done,
				 bsize);
		  add_blk_to_cache(inobno.inode, inobno.blocknr, offsetblock + bsize, 
						   (unsigned char *) blkdta->blockdata, offsetfile);
		  DBTfree(data);
		  res = 2;
	  } else
		  res = 0;
	  if (2 != res) {
		  blocktiger = check_block_exists(inobno);
		  if (NULL != blocktiger) {
			  LDEBUG("lessfs_write -> update_block : inode %llu blocknr %llu",
				   fi->fh, blocknr);
			  offhash = (OFFHASH *) blocktiger->data;
			  if (NULL != config->blockdatabs) {
				  db_update_block(buf + done, blocknr, offsetblock, bsize,
								  blkdta->inode, offhash->stiger, offsetfile);
			  } else {
				  file_update_block(buf + done, blocknr, offsetblock, bsize,
									blkdta->inode, offhash->stiger, offsetfile);
			  }
			  DBTfree(blocktiger);
			  release_global_lock();
		  } else {
			  LDEBUG
				  ("lessfs_write -> add_block : inode %llu blocknr %llu",
				   fi->fh, blocknr);
			  blkdta->blocknr = blocknr;
			  blkdta->offsetblock = offsetblock;
			  blkdta->bsize = bsize;
			  blkdta->offsetfile = offsetfile;
			  blkdta->buf = (unsigned char *)buf + done;
			  if (1 == res) {
				  blkdta->sparse = 1;
			  } else {
				  blkdta->sparse = 0;
			  }
			  release_worker_lock();
			  release_global_lock();
			  write_lock();
		  }
	  } else
		  release_global_lock();
	  done = done + bsize;
	  bsize = (size - done) > BLKSIZE? BLKSIZE : size - done;
	  if (done < size) {
		  blocknr++;
		  offsetblock = 0;
		  offsetfile += BLKSIZE;
		  goto wagain;
	  }
	  release_tiger_lock();
	  LDEBUG("lessfs_write : inode %llu blocknr %llu", fi->fh, blocknr);
	  EFUNC;
	  return (done);
}

int sb_write(const char *path, const char *buf, size_t size, off_t offset, 
	struct fuse_file_info *fi)
{
	unsigned long long inode;
	size_t doublesize, bufsize, patchsize, done;
	BUFCACHE *cache;
	unsigned char *addbuf;

	tiger_lock();
	done = 0;
	inode = fi->fh;
	doublesize = BLKSIZE * 2;
	addbuf = s_malloc(doublesize);

	get_global_lock();
	while(done < size){
		if (offset == 0 || NULL == (cache = try_buf_cache(inode))){
			if (size >= done + doublesize){
				//deal with the buf
				if (0 != (patchsize = sb_addblock(buf + done, offset + done, 
					doublesize, inode))){
					memcpy(addbuf, buf + (done + doublesize - patchsize), 
						patchsize);
					add_buf_to_bufcache(addbuf, patchsize, inode, 
						offset + (done + doublesize - patchsize));
				}
				done += doublesize;
				continue;
			}
			else{
				memcpy(addbuf, buf + done, size - done);
				add_buf_to_bufcache(addbuf, size - done, inode, offset + done);
				done = size;
			}
		}
		else{
			bufsize = cache->bufsize;
			if (size >= done + doublesize - bufsize){
				memcpy(cache->buf + bufsize, buf + done, doublesize - bufsize);
				//deal with the buf
				if (0 != (patchsize = sb_addblock(cache->buf, cache->offset, 
					doublesize, inode))){
					memcpy(addbuf, cache->buf + (doublesize - patchsize), 
						patchsize);
					add_buf_to_bufcache(addbuf, patchsize, inode, 
						cache->offset + (doublesize - patchsize));
				}
				done += doublesize - bufsize;
				if (NULL != cache)
					free(cache);
				continue;
			}
			else{
				memcpy(cache->buf + bufsize, buf + done, size - done);
				add_buf_to_bufcache(cache->buf, bufsize + (size - done), inode, 
					cache->offset);
				done = size;
				if (NULL != cache)
					free(cache);
			}
		}
	}
	free(addbuf);
	release_global_lock();
	release_tiger_lock();
	return done;
}

int sb_addblock(unsigned char *buf, off_t offset, unsigned int bufsize, 
	unsigned long long inode)
{
	int head, tail, fragsize;
	unsigned long long checksumusage, stigerusage;
	int blksize = BLKSIZE;
	unsigned char *fullbuf, *fragbuf;
	unsigned int key, offsetbuf;
	unsigned char *stiger;
	INOBNO inobno;
	bool sparse = 0;
	
#ifndef SHA3
    word64 res[3];
#endif

	head = 0;
	tail = bufsize;
	inobno.inode = inode;
	if (0 == (inobno.blocknr = try_blocknr_cache(inode)))
		inobno.blocknr = get_blocknr(inode, offset);
	fullbuf = s_malloc(blksize);
	while (head <= tail - blksize){
		memcpy(fullbuf, buf + head, blksize);
		//check the buf
		key = (head == 0)? checksum(fullbuf, blksize) : 
			rolling_checksum(key, blksize, buf[head - 1], buf[head + blksize - 1]);
		if (0 != (checksumusage = checksum_exists(key))){
#ifdef SHA3
            stiger=sha_binhash(fullbuf, blksize);
#else
            binhash(fullbuf, blksize, res);
            stiger = (unsigned char *)&res;
#endif
			if (0 != (stigerusage = getInUse(stiger))){
#ifdef SHA3
				free(stiger);
#endif
				if (head > 0){
					fragbuf = s_malloc(head);
					memcpy(fragbuf, buf, head);
					
			        if (NULL != config->blockdatabs) {
			            db_commit_block(fragbuf, inobno, head, offset);
			        } else {
			            file_commit_block(fragbuf, inobno, offset);
			        }
					free(fragbuf);
					inobno.blocknr++;
					offset += head;
				}
				add_blk_to_cache(inode, inobno.blocknr, blksize, fullbuf, offset);
				free(fullbuf);
				return tail - head - blksize;
			}
#ifdef SHA3
			free(stiger);
#endif
		}
		head++;
	}
	
	//add the two blocks	
	if (head != 0){
		memcpy(fullbuf, buf, blksize);
		fragsize = bufsize - blksize;
		if (dedup == 2 && fragsize == blksize) {
			add_blk_to_cache(inobno.inode, inobno.blocknr, blksize, fullbuf, offset);
			free(fullbuf);
			return blksize;
		}
		if (NULL != config->blockdatabs) {
			db_commit_block(fullbuf, inobno, blksize, offset);
		} else {
			file_commit_block(fullbuf, inobno, offset);
		}
		inobno.blocknr++;
		offset += blksize;
		offsetbuf = blksize;
	} else {
		fragsize = bufsize;
		offsetbuf = 0;
	}
	memcpy(fullbuf, buf + offsetbuf, fragsize);
	add_blk_to_cache(inode, inobno.blocknr, fragsize, fullbuf, offset);
	free(fullbuf);
	return 0;
}

/*
 * get the stat of the filesystem, thus get the fs stat of database file
 */
static int lessfs_statfs(const char *path, struct statvfs *stbuf)
{
    int res;
    char *blockdatadir;

    if (NULL != config->blockdatabs) {
        res = statvfs(config->blockdata, stbuf);
    } else {
        blockdatadir = s_dirname(config->blockdata);
        res = statvfs(blockdatadir, stbuf);
        free(blockdatadir);
    }
    if (res == -1)
        return -errno;
    return 0;
}

/*
 * close one file, if it is opened multiple times, reduce the opens, if only one time, 
 * flush the block data and update filesize and show the compress info and delete meta buffer
 */
static int lessfs_release(const char *path, struct fuse_file_info *fi)
{
    DBT *dataptr;
    MEMDDSTAT *memddstat;
    DBT *ddbuf;
    DBT *data;
	BUFCACHE *cache;
	size_t patchsize;
	unsigned long long inode, blocknr, offset, dedupblocknr;
	char *ext;
	int len;
	double ratio;

    FUNC;
// Finish pending i/o for this inode.
    open_lock();
    wait_io_pending(fi->fh);
	inode = fi->fh;
    dataptr = search_memhash(dbcache, &fi->fh, sizeof(unsigned long long));
    if (dataptr != NULL) {
        memddstat = (MEMDDSTAT *) dataptr->data;
        if (memddstat->opened == 1) {
			if (NULL != (cache = try_buf_cache(inode))){
				if (0 != (patchsize = sb_addblock(cache->buf, cache->offset, 
					cache->bufsize, cache->inode))){
					offset = cache->offset + cache->bufsize - patchsize;
					if (0 == (blocknr = try_blocknr_cache(inode)))
						blocknr = get_blocknr(inode, offset);
					add_blk_to_cache(inode, blocknr, patchsize, cache->buf + 
						cache->bufsize - patchsize,	offset);
				}
				free(cache);
			}
// Flush blocks in cache that where not written yet, if any.
            data = try_block_cache(fi->fh, 0, 1);
            if (data != NULL)
                die_syserr();
            sync_flush_dtaq();
			if (NULL != (data = search_dbdata(dbp, &inode, 
												sizeof(unsigned long long)))) {
				DDSTAT *ddstat = value_to_ddstat(data);
				if (ddstat->stbuf.st_size == 0) {
					if (NULL == (ext = getextension(&len, path))){
						len = 5;
						ext = malloc(len);
						memcpy(ext, "none\0", len);
					}
					dedupblocknr = memddstat->deduplicated;
					blocknr = get_blocknr(inode, memddstat->stbuf.st_size);
					blocknr = (blocknr == 0)? 1:blocknr;
					ratio = (double)dedupblocknr / (double)blocknr;
					update_ratio(ext, len, ratio);
					free(ext);
				}
				free(ddstat);
				DBTfree(data);
			}
// Update the filesize when needed.
            update_filesize_onclose(fi->fh);
#ifdef x86_64
            LDEBUG
                ("File %s size %lu bytes : lzo compressed bytes %llu and %llu duplicate blocks",
                 path, memddstat->stbuf.st_size,
                 memddstat->lzo_compressed_size, memddstat->deduplicated);
#else
            LDEBUG
                ("File %s size %llu bytes : lzo compressed bytes %llu and %llu duplicate blocks",
                 path, memddstat->stbuf.st_size,
                 memddstat->lzo_compressed_size, memddstat->deduplicated);
#endif
            LDEBUG("File %s compression ratio : 1 : %f", path,
                   (float) memddstat->stbuf.st_size /
                   memddstat->lzo_compressed_size);
            LDEBUG("lessfs_release : Delete cache for %llu", fi->fh);
            mdelete_key(dbcache, &fi->fh, sizeof(unsigned long long));
            if ( NULL == config->blockdatabs) fdatasync(fdbdta);
        }
		else {
            memddstat->opened--;
            ddbuf = create_mem_ddbuf(memddstat);
            LDEBUG("lessfs_release : %llu is now %u open", fi->fh, memddstat->opened);
            mbin_write_dbdata(dbcache, &fi->fh, sizeof(unsigned long long),
                              (void *) ddbuf->data, ddbuf->size);
            DBTfree(ddbuf);
        }
        DBTfree(dataptr);
    }
    (void) path;
    (void) fi;
    release_global_lock();
    release_open_lock();
    return 0;
}

/*
 * sync the cached data and database of one file
 * fi contains the file handle
 */
static int lessfs_fsync(const char *path, int isdatasync,
                        struct fuse_file_info *fi)
{
    DBT *data;
    FUNC;
    (void) path;
    (void) isdatasync;
    open_lock();
    wait_io_pending(fi->fh);
    /* Living on the edge, wait for pending I/O but do not flush the caches. */
    if (config->relax < 2) {
        sync_flush_dtaq();
        data = try_block_cache(fi->fh, 0, 1);
        if (data != NULL)
            die_syserr();
        update_filesize_onclose(fi->fh);
    }
    sync_flush_dbu();
    sync_flush_dbc();
    sync_flush_dbb();
    /* When config->relax == 1 dbsync is not called but the caches within lessfs
       are flushed making this a safer option. */
    if (config->relax == 0)
        dbsync();
    release_global_lock();
    release_open_lock();
    return 0;
}

/*
 * unmount the file system - sync all databases and cleanup and close db
 */
static void lessfs_destroy(void *unused __attribute__ ((unused)))
{
    FUNC;
    sync_flush_dbu();
    sync_flush_dbc();
    sync_flush_dbb();
    clear_dirty();
    tc_close(0);
    
#ifdef ENABLE_CRYPTO
    if (config->encryptdata){
       free(config->passwd);
       free(config->iv);
    }
#endif
    free(config);
    free((char *) blkdta->blockdata);
    free(blkdta);
    return;
}

int check_free_space(char *dbpath)
{
    float dfull;
    int mf;
    char *minfree;
    struct statfs sb;

    if (-1 == statfs(dbpath, &sb))
        die_dataerr("Failed to stat : %s", dbpath);
    dfull = (float) sb.f_blocks / (float) sb.f_bfree;
    dfull = 100 / dfull;
    minfree = getenv("MINSPACEFREE");
    if (NULL != minfree) {
        mf = atoi(minfree);
        if (mf > 100 || mf < 1)
            mf = 10;
    } else {
        mf = 10;
    }
    if (dfull <= mf) {
        return (-1);
    }
    return (0);
}

void freeze_nospace(char *dbpath)
{
    LFATAL
        ("Filesystem for database %s has insufficient space to continue, freezing I/O",
         dbpath);
    get_global_lock();
    sync_flush_dbu();
    sync_flush_dbc();
    sync_flush_dbb();
    sync_flush_dtaq(); 
    tc_close(1);
    LFATAL("All IO is now suspended until space comes available.");
    LFATAL
        ("If no other options are available it should be safe to kill lessfs.");
    while (1) {
        if (0 == check_free_space(dbpath)) {
            tc_open(1,0);
            release_global_lock();
            break;
        }
        sleep(1);
    }
    LFATAL("Resuming IO : sufficient space available.");
}


void *flush_dbu_worker(void *arg)
{
   int sleeptime=config->flushtime;
   int done;
   while(1)
   {
      LDEBUG("flush_dbu_worker : call sync_flush_dbc"); 
      done=sync_flush_dbu();
      if ( done == 0 ){
         sleeptime=config->flushtime;
      } else {
         sleeptime=sleeptime/2;
      }
      sleep(sleeptime);
   } 
}

void *flush_dbc_worker(void *arg)
{
   int sleeptime=config->flushtime;
   int done;
   while(1)
   {
      LDEBUG("flush_dbc_worker : call sync_flush_dbu"); 
      done=sync_flush_dbc();
      if ( done == 0 ){
         sleeptime=config->flushtime;
      } else {
         sleeptime=sleeptime/2;
      }
      sleep(sleeptime);
   } 
}

void *flush_dbr_worker(void *arg)
{
   int sleeptime=config->flushtime;
   int done;
   while(1)
   {
      LDEBUG("flush_dbr_worker : call sync_flush_dbr"); 
      done=sync_flush_dbr();
      if ( done == 0 ){
         sleeptime=config->flushtime;
      } else {
         sleeptime=sleeptime/2;
      }
      sleep(sleeptime);
   } 
}

void *flush_dbb_worker(void *arg)
{
   int sleeptime=config->flushtime;
   int done;
   while(1)
   {
      LDEBUG("flush_dbb_worker : call sync_flush_dbb"); 
      done=sync_flush_dbb();
      if ( done == 0 ){
         sleeptime=config->flushtime;
      } else {
         sleeptime=sleeptime/2;
      }
      sleep(sleeptime);
   }
}

/* This thread does general housekeeping.
   For now it checks that there is enough diskspace free for
   the databases. If not it syncs the database, 
   closes them and freezes I/O. */
void *housekeeping_worker(void *arg)
{
    char *dbpath;
    LDEBUG("%s: inspectdiskinterval = %d", __FUNCTION__, config->inspectdiskinterval);

    while (1) {
        dbpath = as_sprintf("%s/fileblock.tch", config->fileblock);
        if (0 != check_free_space(dbpath))
            freeze_nospace(dbpath);
        free(dbpath);
        dbpath = as_sprintf("%s/blockusage.tch", config->blockusage);
        if (0 != check_free_space(dbpath))
            freeze_nospace(dbpath);
        free(dbpath);
        dbpath = as_sprintf("%s/metadata.tcb", config->meta);
        if (0 != check_free_space(dbpath))
            freeze_nospace(dbpath);
        free(dbpath);
        if (NULL != config->blockdatabs) {
            dbpath = as_sprintf("%s/blockdata.tch", config->blockdata);
            if (0 != check_free_space(dbpath))
                freeze_nospace(dbpath);
            free(dbpath);
        } else {
            if (0 != check_free_space(config->blockdata))
                freeze_nospace(config->blockdata);
        }
        dbpath = as_sprintf("%s/symlink.tch", config->symlink);
        if (0 != check_free_space(dbpath))
            freeze_nospace(dbpath);
        free(dbpath);
        dbpath = as_sprintf("%s/dirent.tcb", config->dirent);
        if (0 != check_free_space(dbpath))
            freeze_nospace(dbpath);
        free(dbpath);
        dbpath = as_sprintf("%s/hardlink.tcb", config->hardlink);
        if (0 != check_free_space(dbpath))
            freeze_nospace(dbpath);
        free(dbpath);
        sleep(config->inspectdiskinterval);
    }
    return NULL;
}

void show_lock_status(int csocket)
{
   timeoutWrite(3, csocket,
      "---------------------\n",
      strlen
      ("---------------------\n"));
   timeoutWrite(3, csocket,
      "normally unset\n\n",
      strlen
      ("normally unset\n\n"));
   if ( 0 != try_global_lock()) {
      timeoutWrite(3, csocket,
      "global_lock : 1 (set)\n",
      strlen
      ("global_lock : 1 (set)\n"));
   } else {
      release_global_lock();
      timeoutWrite(3, csocket,
         "global_lock : 0 (not set)\n",
         strlen
         ("global_lock : 0 (not set)\n"));
   }
   if ( 0 != try_open_lock()) {
      timeoutWrite(3, csocket,
      "open_lock : 1 (set)\n",
      strlen
      ("open_lock : 1 (set)\n"));
   } else {
      release_open_lock();
      timeoutWrite(3, csocket,
         "open_lock : 0 (not set)\n",
         strlen
         ("open_lock : 0 (not set)\n"));
   }
   if ( 0 != try_tiger_lock()) {
      timeoutWrite(3, csocket,
      "tiger_lock : 1 (set)\n",
      strlen
      ("tiger_lock : 1 (set)\n"));
   } else {
      release_tiger_lock();
      timeoutWrite(3, csocket,
         "tiger_lock : 0 (not set)\n",
         strlen
         ("tiger_lock : 0 (not set)\n"));
   }
   if ( 0 != try_dbb_lock()) {
      timeoutWrite(3, csocket,
      "dbb_lock : 1 (set)\n",
      strlen
      ("dbb_lock : 1 (set)\n"));
   } else {
      release_dbb_lock();
      timeoutWrite(3, csocket,
         "dbb_lock : 0 (not set)\n",
         strlen
         ("dbb_lock : 0 (not set)\n"));
   }
   if ( 0 != try_dbu_lock()) {
      timeoutWrite(3, csocket,
      "dbu_lock : 1 (set)\n",
      strlen
      ("dbu_lock : 1 (set)\n"));
   } else {
      release_dbu_lock();
      timeoutWrite(3, csocket,
         "dbu_lock : 0 (not set)\n",
         strlen
         ("dbu_lock : 0 (not set)\n"));
   }
   if ( 0 != try_moddb_lock()) {
      timeoutWrite(3, csocket,
      "moddb_lock : 1 (set)\n",
      strlen
      ("moddb_lock : 1 (set)\n"));
   } else {
      release_moddb_lock();
      timeoutWrite(3, csocket,
         "moddb_lock : 0 (not set)\n",
         strlen
         ("moddb_lock : 0 (not set)\n"));
   }
   timeoutWrite(3, csocket,
      "---------------------\n",
      strlen
      ("---------------------\n"));
   timeoutWrite(3, csocket,
      "normally set\n\n",
      strlen
      ("normally set\n\n"));
   if ( 0 != try_worker_lock()) {
      timeoutWrite(3, csocket,
      "worker_lock : 1 (set)\n",
      strlen
      ("worker_lock : 1 (set)\n"));
   } else {
      release_worker_lock();
      timeoutWrite(3, csocket,
         "worker_lock : 0 (not set)\n",
         strlen
         ("worker_lock : 0 (not set)\n"));
   }
   if ( 0 != try_write_lock()) {
      timeoutWrite(3, csocket,
      "write_lock : 1 (set)\n",
      strlen
      ("write_lock : 1 (set)\n"));
   } else {
      release_write_lock();
      timeoutWrite(3, csocket,
         "write_lock : 0 (not set)\n",
         strlen
         ("write_lock : 0 (not set)\n"));
   }
   if ( 0 != try_qempty_lock()) {
      timeoutWrite(3, csocket,
      "qempty_lock : 1 (set)\n",
      strlen
      ("qempty_lock : 1 (set)\n"));
   } else {
      release_qempty_lock();
      timeoutWrite(3, csocket,
         "qemptu_lock : 0 (not set)\n",
         strlen
         ("qempty_lock : 0 (not set)\n"));
   }
   if ( 0 != try_qdta_lock()) {
      timeoutWrite(3, csocket,
      "qdta_lock : 1 (set)\n\n",
      strlen
      ("qdta_lock : 1 (set)\n\n"));
   } else {
      release_qdta_lock();
      timeoutWrite(3, csocket,
         "qdta_lock : 0 (not set)\n\n",
         strlen
         ("qdta_lock : 0 (not set)\n\n"));
   }
}

void *ioctl_worker(void *arg)
{
    int msocket;
    int csocket;
    const char *port;
    const char *proto = "tcp";
    struct sockaddr_un client_address;
    socklen_t client_len;
    char buf[1028];
    char *addr;
    int err = 0;
    char *result;
    char *message = NULL;
    bool isfrozen = 0;

    msocket = -1;
    while (1) {
        addr = getenv("LISTEN_IP");
        port = getenv("LISTEN_PORT");
        if (NULL == port)
            port = "100";
        if (NULL == addr)
            LWARNING
                ("The administration session is not limited to localhost, this is not recommended.");
        msocket = serverinit(addr, port, proto);
        if (msocket != -1)
            break;
        sleep(1);
        close(msocket);
    }

    client_len = sizeof(client_address);
    while (1) {
        csocket =
            accept(msocket, (struct sockaddr *) &client_address,
                   &client_len);
        while (1) {
            result = NULL;
            if (-1 == timeoutWrite(3, csocket, ">", 1))
                break;
            if (-1 == readnlstring(10, csocket, buf, 1024)) {
                result = "timeout";
                err = 1;
                break;
            }
            if (0 == strncmp(buf, "\r", strlen("\r")))
                continue;
            if (0 == strncmp(buf, "quit\r", strlen("quit\r"))
                || 0 == strncmp(buf, "exit\r", strlen("exit\r"))) {
                err = 0;
                result = "bye";
                break;
            }
            if (0 == strncmp(buf, "freeze\r", strlen("freeze\r"))) {
                if (0 == isfrozen) {
                    result = "All i/o is now suspended.";
                    err = 0;
                    get_global_lock();
                    dbsync();
                    isfrozen = 1;
                } else {
                    result = "i/o is already suspended.";
                    err = 1;
                }
            }
            if (0 == strncmp(buf, "defrost\r", strlen("defrost\r"))) {
                if (1 == isfrozen) {
                    result = "Resuming i/o.";
                    err = 0;
                    release_global_lock();
                    isfrozen = 0;
                } else {
                    result = "i/o is not suspended.";
                    err = 1;
                }
            }
            if (0 == strncmp(buf, "defrag\r", strlen("defrag\r"))) {
                result = "Resuming i/o after defragmentation.";
                err = 1;
                if (-1 ==
                    timeoutWrite(3, csocket,
                                 "Suspending i/o for defragmentation\n",
                                 strlen
                                 ("Suspending i/o for defragmentation\n")))
                    break;
                err = 0;
                get_global_lock();
                tc_defrag();
                tc_close(1);
                tc_open(1,0);
                release_global_lock();
            }
            if (0 == strncmp(buf, "help\r", strlen("help\r"))
                || 0 == strncmp(buf, "h\r", strlen("h\r"))) {
                result =
                    "valid commands: defrag defrost freeze help lockstatus quit|exit";
                err = 0;
            }
            if (0 == strncmp(buf, "lockstatus\r", strlen("lockstatus\r"))) {
                show_lock_status(csocket);
                result = "lockstatus listed";
                err=0;
            } 
            if (NULL == result) {
                err = -1;
                result = "unknown command";
            }
            if (err == 0) {
                message = as_sprintf("+OK %s\n", result);
                if (-1 ==
                    timeoutWrite(3, csocket, message, strlen(message)))
                    break;
            } else {
                message = as_sprintf("-ERR %s\n", result);
                if (-1 ==
                    timeoutWrite(3, csocket, message, strlen(message)))
                    break;
            }
            free(message);
            message = NULL;
        }
        if (message)
            free(message);
        if (err == 0) {
            message = as_sprintf("+OK %s\n", result);
            timeoutWrite(3, csocket, message, strlen(message));
        } else {
            message = as_sprintf("-ERR %s\n", result);
            timeoutWrite(3, csocket, message, strlen(message));
        }
        free(message);
        message = NULL;
        close(csocket);
    }
    return NULL;
}


void *init_data_writer(void *arg)
{
    get_qempty_lock();
    while (1) {
        get_qdta_lock();
        LDEBUG("init_data_writer : got qdta lock");
        sync_flush_dtaq();
        release_qempty_lock();
        LDEBUG("init_data_writer : released qempty lock");
    }
    pthread_exit(NULL);
}


// Flush data every flushtime seconds.
void *lessfs_flush(void *arg)
{
    while (1) {
        sleep(config->flushtime);
        LDEBUG("lessfs_flush: flush_dta_queue");
        get_global_lock();
        flush_dta_queue();
        /* Make sure that the meta data is updated every once in a while */
        if ( config->relax > 0 ) {
           tcbdbsync(dbdirent);
           tcbdbsync(dbl);
           tchdbsync(dbp);
           tchdbsync(dbs);
           if ( config->blockdatabs == NULL ) {
              tcbdbsync(freelist);
           }
        }
        release_global_lock();
    }
    pthread_exit(NULL);
}


void *init_worker(void *arg)
{
    int count;
    int c;
#ifndef SHA3
    word64 res[max_threads][3];
#endif


    memcpy(&count, arg, sizeof(int));
    get_global_lock();
    if (NULL == tdta) {
        tdta = malloc(max_threads * sizeof(BLKDTA));
        for (c = 0; c < max_threads; c++) {
            tdta[c] = s_malloc(sizeof(BLKDTA));
            tdta[c]->blockfiller = s_malloc(BLKSIZE + 1);
            tdta[c]->inode = 0;
        }
    }
    release_global_lock();

    tdta[count]->blockdata = s_malloc(BLKSIZE);
    while (1) {
        memset((char *) tdta[count]->blockdata, 0, BLKSIZE);
        worker_lock();

        memcpy((char *) tdta[count]->blockdata, blkdta->buf, blkdta->bsize);
        memcpy(&tdta[count]->bsize, &blkdta->bsize, sizeof(size_t));
        tdta[count]->inode = blkdta->inode;
        memcpy(&tdta[count]->blocknr, &blkdta->blocknr, sizeof(unsigned long long));
        memcpy(&tdta[count]->sparse, &blkdta->sparse, sizeof(bool));
        memcpy(&tdta[count]->offsetblock, &blkdta->offsetblock, sizeof(off_t));
		memcpy(&tdta[count]->offsetfile, &blkdta->offsetfile, sizeof(off_t));
        release_write_lock();
        memset(tdta[count]->blockfiller, 0, BLKSIZE + 1);
        memmove(tdta[count]->blockfiller + tdta[count]->offsetblock,
                tdta[count]->blockdata, tdta[count]->bsize);
        if (tdta[count]->bsize + tdta[count]->offsetblock < BLKSIZE) {
            tdta[count]->stiger = NULL;
        } else {
#ifdef SHA3
            tdta[count]->stiger=sha_binhash(tdta[count]->blockfiller, BLKSIZE);
#else
            binhash(tdta[count]->blockfiller, BLKSIZE,res[count]);
            tdta[count]->stiger = (unsigned char *)&res[count];
#endif
        }
        tdta[count]->compressed = NULL;
// See if we can obtain a general lock, 
// if not we don't wait idle but start with compressing the block
        if (0 != try_global_lock()) {
// Do not start to compress if we are not going to use it.
// Better to start with addBlock as soon as we can.
            if (tdta[count]->bsize + tdta[count]->offsetblock == BLKSIZE) {
#ifdef LZO
                tdta[count]->compressed =
                    lzo_compress(tdta[count]->blockfiller, BLKSIZE);
#else
                tdta[count]->compressed =
                    clz_compress(tdta[count]->blockfiller, BLKSIZE);
#endif
            }
            get_global_lock();
        }
        if (NULL != config->blockdatabs) {
            LDEBUG("write to tc backend");
            addBlock(tdta[count]);
        } else {
            LDEBUG("write to file_io backend");
            add_file_block(tdta[count]);
        }
        tdta[count]->inode = 0;
        release_global_lock();
#ifdef SHA3
        if (NULL != tdta[count]->stiger)
            free(tdta[count]->stiger);
#endif
    }
    free((char *) tdta[count]->blockdata);
    free(tdta[count]->blockfiller);
    free(tdta[count]);
    tdta[count] = NULL;
    pthread_exit(NULL);
}

/* Write the hash for string LESSFS_DIRTY to DBU
   When this hash is present during mount the filesystem
   has not been unmounted cleanly previously.*/
void mark_dirty()
{
    unsigned char *stiger;
    char *brand;
    INUSE finuse;
    time_t thetime;
    unsigned long long inuse;
#ifndef SHA3
    word64 res[3];
#endif

    brand=as_sprintf("LESSFS_DIRTY");
#ifdef SHA3
    stiger=sha_binhash((unsigned char *)brand, strlen(brand));
#else
    binhash((unsigned char *)brand, strlen(brand), res);
    stiger=(unsigned char *)&res;
#endif
    thetime = time(NULL);
    inuse=thetime;
    if ( config->blockdatabs != NULL ) {
        update_inuse(stiger,inuse);
    } else {
        finuse.inuse=BLKSIZE;
        finuse.size=inuse;
        finuse.offset=0;
        file_update_inuse(stiger,&finuse);
    }
    sync_flush_dbu();
    free(brand);
#ifdef SHA3
    free(stiger);
#endif
    tchdbsync(dbu); 
    return;
}

/* Return 1 when filesystem is dirty */
int check_dirty()
{
    unsigned char *stiger;
    char *brand;
    unsigned long long inuse;
    INUSE *finuse;
    int dirty=0;
#ifndef SHA3
    word64 res[3];
#endif


    brand=as_sprintf("LESSFS_DIRTY");
#ifdef SHA3
    stiger=sha_binhash((unsigned char *)brand, strlen(brand));
#else
    binhash((unsigned char *)brand, strlen(brand), res);
    stiger=(unsigned char *)&res;
#endif
    if ( NULL == config->blockdatabs ) {
      finuse=file_get_inuse(stiger);
      if ( NULL != finuse ) {
         free(finuse);
         dirty=1;
      }
    } else {
      inuse=getInUse(stiger);
      if ( 0 != inuse ) dirty=1;
    }
#ifdef SHA3
    free(stiger);
#endif
    free(brand);
    return(dirty);
}

void check_blocksize()
{
    int blksize;

    blksize=get_blocksize();
    if ( blksize != BLKSIZE ) die_dataerr("Not allowed to mount lessfs with blocksize %u when previously used with blocksize %i",BLKSIZE,blksize);
    return;
}

static void *lessfs_init()
{
    unsigned int count = 0;
    unsigned int *cnt;
#ifndef SHA3
    word64 res[3]; 
#endif
    int ret;
    unsigned char *stiger;
    char *hashstr;
    INUSE *inuse;

    pthread_spin_init(&moddb_spinlock, 0);
    pthread_spin_init(&dbu_spinlock, 0);
    pthread_spin_init(&dbc_spinlock, 0);
    pthread_spin_init(&dbr_spinlock, 0);
    pthread_spin_init(&dbb_spinlock, 0);

#ifdef LZO
    initlzo();
#endif
    blkdta = s_malloc(sizeof(BLKDTA));
    blkdta->blockdata = s_malloc(BLKSIZE);
    if (NULL != getenv("MAX_THREADS"))
        max_threads = atoi(getenv("MAX_THREADS"));

    pthread_t worker_thread[max_threads];
    pthread_t ioctl_thread;
    pthread_t data_thread;
    pthread_t housekeeping_thread;
    pthread_t flush_thread;
    pthread_t flush_dbu_thread;
    pthread_t flush_dbc_thread;
    pthread_t flush_dbr_thread;
    pthread_t flush_dbb_thread;

    LDEBUG("lessfs_init : worker_lock");
    worker_lock();
    LDEBUG("lessfs_init : write_lock");
    write_lock();
    LDEBUG("lessfs_init : qdta_lock");
    get_qdta_lock();
    for (count = 0; count < max_threads; count++) {
        cnt = s_malloc(sizeof(int));
        memcpy(cnt, &count, sizeof(int));
        ret =
            pthread_create(&(worker_thread[count]), NULL, init_worker,
                           (void *) cnt);
        if (ret != 0)
            die_syserr();
    }
    ret = pthread_create(&ioctl_thread, NULL, ioctl_worker, (void *) NULL);
    if (ret != 0)
        die_syserr();
    ret =
        pthread_create(&data_thread, NULL, init_data_writer,
                       (void *) NULL);
    if (ret != 0)
        die_syserr();
    ret = pthread_create(&flush_thread, NULL, lessfs_flush, (void *) NULL);
    if (ret != 0)
        die_syserr();
    ret = pthread_create(&flush_dbu_thread, NULL, flush_dbu_worker, (void *) NULL);
    if (ret != 0)
        die_syserr();
    ret = pthread_create(&flush_dbc_thread, NULL, flush_dbc_worker, (void *) NULL);
    if (ret != 0)
        die_syserr();
    ret = pthread_create(&flush_dbr_thread, NULL, flush_dbr_worker, (void *) NULL);
    if (ret != 0)
        die_syserr();
    ret = pthread_create(&flush_dbb_thread, NULL, flush_dbb_worker, (void *) NULL);
    if (ret != 0)
        die_syserr();
    ret =
        pthread_create(&housekeeping_thread, NULL, housekeeping_worker,
                       (void *) NULL);
    if (ret != 0)
        die_syserr();

    check_blocksize();
	read_dbc();	
	read_dbr();	
	read_dbu();	
	read_dbb();
    if ( check_dirty()){
       LFATAL("Lessfs has not been unmounted cleanly, you are advised to run lessfsck.");
    } else {
       mark_dirty();
    }
#ifdef SHA3
    hashstr=as_sprintf("BMW%i",config->hashlen);
    stiger=sha_binhash((unsigned char *)hashstr, strlen(hashstr));
#else
    hashstr=as_sprintf("TGR%i",config->hashlen);
    binhash((unsigned char *)hashstr, strlen(hashstr), res);
    stiger=(unsigned char *)&res;
#endif
    if ( NULL == config->blockdatabs ) {
       if ( NULL == (inuse=file_get_inuse(stiger)))  {
           die_dataerr("Invalid hashsize or hash found, do not change hash or hashsize after formatting lessfs.");
       } else free(inuse);
    } else {
       if ( 0 == getInUse(stiger))
           die_dataerr("Invalid hashsize or hash found, do not change hash or hashsize after formatting lessfs.");
    }
    free(hashstr);
#ifdef SHA3
    free(stiger);
#endif
    return NULL;
}

static struct fuse_operations lessfs_oper = {
    .getattr = lessfs_getattr,
    .access = lessfs_access,
    .readlink = lessfs_readlink,
    .readdir = lessfs_readdir,
    .mknod = lessfs_mknod,
    .mkdir = lessfs_mkdir,
    .symlink = lessfs_symlink,
    .unlink = lessfs_unlink,
    .rmdir = lessfs_rmdir,
    .rename = lessfs_rename,
    .link = lessfs_link,
    .chmod = lessfs_chmod,
    .chown = lessfs_chown,
    .truncate = lessfs_truncate,
    .utimens = lessfs_utimens,
    .open = lessfs_open,
    .read = lessfs_read,
    .write = lessfs_write,
    .statfs = lessfs_statfs,
    .release = lessfs_release,
    .fsync = lessfs_fsync,
    .destroy = lessfs_destroy,
    .init = lessfs_init,
};

void usage(char *appName)
{
    char **argv = (char **) malloc(2 * sizeof(char *));
    argv[0] = appName;
    argv[1] = (char *) malloc(3 * sizeof(char));
    memcpy(argv[1], "-h\0", 3);
    fuse_main(2, argv, &lessfs_oper, NULL);
    FUNC;
    printf("\n"
           "-------------------------------------------------------\n"
           "lessfs %s\n"
           "\n"
           "Usage: %s [/path_to_config.cfg] [mount_point] <FUSE OPTIONS>\n"
           "\n"
           "Example :\nmklessfs /etc/lessfs.cfg \nlessfs   /etc/lessfs.cfg /mnt\n\n"
           "A high performance example with big_writes.\n(Requires kernel 2.6.26 or higher and a recent version of fuse.)\n"
           "lessfs /etc/lessfs.cfg /fuse -o use_ino,readdir_ino,default_permissions,\\\n       allow_other,big_writes,max_read=131072,max_write=131072\n"
           "-------------------------------------------------------\n",
           VERSION, appName);
    exit(EXIT_USAGE);
}

int verify_kernel_version()
{
    struct utsname un;
    char *begin;
    char *end;
    int count;

    uname(&un);
    begin = un.release;

    for (count = 0; count < 3; count++) {
        end = strchr(begin, '.');
        if (NULL != end) {
            end[0] = 0;
            end++;
        }
        if (count == 0 && atoi(begin) < 2)
            return (-1);
        if (count == 0 && atoi(begin) > 2)
            break;
        if (count == 1 && atoi(begin) < 6)
            return (-2);
        if (count == 1 && atoi(begin) > 6)
            break;
        if (count == 2 && atoi(begin) < 26)
            return (-3);
        begin = end;
    }
    return (0);
}

int get_opts(int argc, char *argv[])
{
    int c;

    while ((c = getopt (argc, argv, "fsb")) != -1)
		switch (c)
        {
        case 'f':
			return 1;
        case 's':
			return 2;
        case 'b':
			return 3;
        default:
			usage(argv[0]);
    }
    return 0;
}

int main(int argc, char *argv[])
{
    int res;
    char *p, *maxwrite, *maxread;
    char **argv_new = (char **) malloc(argc * sizeof(char *));
    int argc_new;
	char *opt;
	int pos = 1;
    struct rlimit lessfslimit;

    FUNC;
    if ((argc == 2) && (strcmp(argv[1], "-h") == 0)) {
        usage(argv[0]);
    }

    if (argc < 3) {
        usage(argv[0]);
    }
	if (0 != (dedup = get_opts(argc, argv)))
		pos = 2;
	argc_new = argc - pos;
    if (-1 == r_env_cfg(argv[pos]))
        usage(argv[0]);
    argv_new[0] = argv[0];
    int i;
    for (i = 1; i < argc - pos; i++) {
        argv_new[i] = argv[i + pos];
        if (NULL != strstr(argv[i + 1], "big_writes")) {
            maxwrite = strstr(argv[i + 1], "max_write=");
            maxread = strstr(argv[i + 1], "max_read=");
            if (NULL != maxwrite && NULL != maxread) {
                p = strchr(maxwrite, '=');
                p++;
                BLKSIZE = atoi(p);
				printf("Block size is: %u", BLKSIZE);
                p = strchr(maxread, '=');
                p++;
                if (atoi(p) != BLKSIZE) {
                    LFATAL
                        ("lessfs : Supplied values for max_read and max_write must match.");
                    fprintf(stderr,
                            "Supplied values for max_read and max_write must match.\n");
                    exit(EXIT_SYSTEM);
                }
                if (BLKSIZE > 4096 && 0 != verify_kernel_version()) {
                    LFATAL
                        ("The kernel used is to old for larger then 4k blocksizes, kernel >= 2.6.26 is required.");
                    exit(EXIT_SYSTEM);
                }
            } else {
                LFATAL
                    ("lessfs : big_writes specified without max_write or max_read.");
                fprintf(stderr,
                        "big_writes specified without max_write or max_read.\n");
                exit(EXIT_SYSTEM);
            }
        }
    }
// Enable dumping of core for debugging.
    if (NULL != getenv("COREDUMPSIZE")) {
        lessfslimit.rlim_cur = lessfslimit.rlim_max =
            atoi(getenv("COREDUMPSIZE"));
        if (0 != setrlimit(RLIMIT_CORE, &lessfslimit)) {
            fprintf(stderr, "Failed to set COREDUMPSIZE to %i : error %s",
                    atoi(getenv("COREDUMPSIZE")), strerror(errno));
            exit(EXIT_SYSTEM);
        }
    } else {
        signal(SIGSEGV, segvExit);
    }
    LDEBUG("lessfs : blocksize is set to %u", BLKSIZE);
    signal(SIGHUP, normalExit);
    signal(SIGTERM, normalExit);
    signal(SIGALRM, normalExit);
    signal(SIGINT, normalExit);
    signal(SIGUSR1, libSafeExit);
    if (NULL != getenv("DEBUG"))
        debug = atoi(getenv("DEBUG"));
    parseconfig(0);
    res = fuse_main(argc_new, argv_new, &lessfs_oper, NULL);
    free(argv_new);
    return (res);
}
