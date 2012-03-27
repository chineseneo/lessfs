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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifndef LFATAL
#include "lib_log.h"
#endif

#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/types.h>
#include <fuse.h>

#include <fcntl.h>
#include <pthread.h>

#include <tcutil.h>
#include <tcbdb.h>
#include <tchdb.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <aio.h>

#include "lib_safe.h"
#include "lib_cfg.h"
#include "retcodes.h"
#ifdef LZO
#include "lib_lzo.h"
#else
#include "lib_qlz.h"
#endif
#include "lib_tc.h"
#include "lib_crypto.h"
#include "file_io.h"
#ifdef SHA3
#include "lib_BMW_SHA3api_ref.h"
#endif

extern char *logname;
extern char *function;
extern int debug;
extern int BLKSIZE;
extern int max_threads;
extern BLKDTA **tdta;
extern char *passwd;

TCHDB *dbb = NULL;
TCHDB *dbu = NULL;
TCHDB *dbc = NULL;
TCHDB *dbp = NULL;
TCBDB *dbl = NULL;              // Hardlink
TCHDB *dbs = NULL;              // Symlink
TCHDB *dbdta = NULL;
TCBDB *dbdirent = NULL;
TCBDB *freelist = NULL;         // Free list for file_io
TCMDB *dbcache;
TCMDB *dbdtaq;
TCMDB *blkcache;                // A cache that has the tiger hash as key and the fs data as value.
TCMDB *bufcache; 
TCMDB *dbum;
TCMDB *dbcm;
TCMDB *dbbm;
int fdbdta = 0;

unsigned long long nextoffset = 0;
unsigned int dbu_qcount = 0;
unsigned int dbc_qcount = 0;
unsigned int dbb_qcount = 0;
int written = 0;
static pthread_mutex_t global_lock_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t worker_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t write_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t tiger_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t open_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t qdta_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t qempty_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_spinlock_t moddb_spinlock;
pthread_spinlock_t dbu_spinlock;
pthread_spinlock_t dbc_spinlock;
pthread_spinlock_t dbb_spinlock;

#ifdef i386
#define ITERATIONS 30
#else
#define ITERATIONS 500
#endif

u_int32_t db_flags, env_flags;

#define die_dataerr(f...) { LFATAL(f); exit(EXIT_DATAERR); }
#define die_syserr() { LFATAL("Fatal system error : %s",strerror(errno)); exit(EXIT_SYSTEM); }

#ifdef SHA3
unsigned char *sha_binhash(unsigned char *buf, int size)
{
   unsigned char *rethash;
   int hashbitlen=BMWLEN;
   if ( NULL == ((rethash=Hash (hashbitlen, (BitSequence *)buf, size)))) die_dataerr("sha_binhash : failure");
   loghash("sha_binhash ",rethash);
   return rethash;
}
#else
void binhash(unsigned char *buf, int size, word64 res[3])
{
    tiger((unsigned char *) buf, size, res);
    return;
}
#endif

unsigned int checksum(char *buf, int len){
	return adler32_checksum(buf, len);
}

unsigned int rolling_checksum(unsigned int csum, int len, char c1, char c2){
	return adler32_rolling_checksum(csum, len, c1, c2);
}

void logiv(char *msg, unsigned char *bhash)
{
    char *ascii_hash = NULL;
    int n;
    char *p1, *p2;


    for (n = 0; n < 8; n++) {
        p1 = as_sprintf("%02X", bhash[n]);
        if (n == 0) {
            ascii_hash = s_strdup(p1);
        } else {
            p2 = s_strdup(ascii_hash);
            free(ascii_hash);
            ascii_hash = as_sprintf("%s%s", p2, p1);
            free(p2);
        }
        free(p1);
    }
    LDEBUG("%s : %s", msg, ascii_hash);
    free(ascii_hash);
}


#ifdef DEBUG
void loghash(char *msg, unsigned char *bhash)
{
    char *ascii_hash = NULL;
    int n;
    char *p1, *p2;

    for (n = 0; n < config->hashlen ; n++) {
        p1 = as_sprintf("%02X", bhash[n]);
        if (n == 0) {
            ascii_hash = s_strdup(p1);
        } else {
            p2 = s_strdup(ascii_hash);
            free(ascii_hash);
            ascii_hash = as_sprintf("%s%s", p2, p1);
            free(p2);
        }
        free(p1);
    }
    LDEBUG("%s : %s", msg, ascii_hash);
    free(ascii_hash);
}
# else
void loghash(char *msg, unsigned char *bhash)
{
}
# endif


void log_fatal_hash(char *msg, unsigned char *bhash)
{
    char *ascii_hash = NULL;
    int n;
    char *p1, *p2;

    for (n = 0; n < config->hashlen ; n++) {
        p1 = as_sprintf("%02X", bhash[n]);
        if (n == 0) {
            ascii_hash = s_strdup(p1);
        } else {
            p2 = s_strdup(ascii_hash);
            free(ascii_hash);
            ascii_hash = as_sprintf("%s%s", p2, p1);
            free(p2);
        }
        free(p1);
    }
    LFATAL("%s : %s", msg, ascii_hash);
    free(ascii_hash);
}

TCHDB *hashdb_open(char *dbpath, int cacherow,
                   unsigned long long bucketsize)
{
    TCHDB *hdb;
    int ecode;

    FUNC;
    LDEBUG("%s: dbpath = %s, bucketsize = %llu", __FUNCTION__, dbpath, bucketsize);
    hdb = tchdbnew();
    if (cacherow > 0) {
        tchdbsetcache(hdb, cacherow);
    }

    if (config->defrag == 1) {
        if (!tchdbsetdfunit(hdb, 1)) {
            ecode = tchdbecode(hdb);
            die_dberr("Error on setting defragmentation : %s", tchdberrmsg(ecode));
        }
    }
    tchdbtune(hdb, bucketsize, 0, 0, HDBTLARGE);
    if (!tchdbopen(hdb, dbpath, HDBOWRITER | HDBOCREAT)) {
        ecode = tchdbecode(hdb);
        fprintf(stderr, "Error while opening database : %s : %s\n", dbpath, 
			tchdberrmsg(ecode));
        die_dberr("open error: %s", tchdberrmsg(ecode));
    }
    EFUNC;
    return hdb;
}

void tc_defrag()
{
    sync_flush_dtaq();
    if (!tchdboptimize(dbb, atol(config->fileblockbs), 0, 0, HDBTLARGE))
        LDEBUG("fileblock.tch not optimized");
    if (!tchdboptimize(dbu, atol(config->blockusagebs), 0, 0, HDBTLARGE))
        LDEBUG("blockusage.tch not optimized");
    if (!tchdboptimize(dbc, atol(config->checksumusagebs), 0, 0, HDBTLARGE))
        LDEBUG("blockusage.tch not optimized");
    if (!tchdboptimize(dbp, atol(config->metabs), 0, 0, HDBTLARGE))
        LDEBUG("metadata.tcb not optimized");
    if (!tchdboptimize(dbs, atol(config->symlinkbs), 0, 0, HDBTLARGE))
        LDEBUG("symlink.tch not optimized");
    if (NULL != config->blockdatabs) {
        if (!tchdboptimize
            (dbdta, atol(config->blockdatabs), 0, 0, HDBTLARGE))
            LDEBUG("blockdata.tch not optimized");
    } else {
        if (!tcbdboptimize(freelist, 0, 0, atol(config->freelistbs), -1, -1, BDBTLARGE))
            LDEBUG("freelist.tcb not optimized");
    }
    if (!tcbdboptimize
        (dbdirent, 0, 0, atol(config->direntbs), -1, -1, BDBTLARGE))
        LDEBUG("dirent.tcb not optimized");
    if (!tcbdboptimize
        (dbl, 0, 0, atol(config->hardlinkbs), -1, -1, BDBTLARGE))
        LDEBUG("hardlink.tcb not optimized");
}


void tc_open(bool defrag, bool createpath)
{
    char *dbpath;
    int ecode;
    struct stat stbuf;
    char *sp;

    FUNC;
    LDEBUG("%s: defrag = %d, createpath = %d", __FUNCTION__, defrag, createpath);
    dbpath = as_sprintf("%s/fileblock.tch", config->fileblock);
    if ( createpath ) mkpath(config->fileblock,0744);
    LDEBUG("Open database %s", dbpath);
    dbb = hashdb_open(dbpath, 2621440, atol(config->fileblockbs));
    free(dbpath);

    dbpath = as_sprintf("%s/blockusage.tch", config->blockusage);
    if ( createpath ) mkpath(config->blockusage,0744);
    LDEBUG("Open database %s", dbpath);
    dbu = hashdb_open(dbpath, 2621440, atol(config->blockusagebs));
    free(dbpath);

    dbpath = as_sprintf("%s/chechsumusage.tch", config->checksumusage);
    if ( createpath ) mkpath(config->checksumusage,0744);
    LDEBUG("Open database %s", dbpath);
    dbc = hashdb_open(dbpath, 2621440, atol(config->checksumusagebs));
    free(dbpath);

    dbpath = as_sprintf("%s/metadata.tcb", config->meta);
    if ( createpath ) mkpath(config->meta,0744);
    LDEBUG("Open database %s", dbpath);
    dbp = hashdb_open(dbpath, 1000, atol(config->metabs));
    free(dbpath);

    if (NULL != config->blockdatabs) {
        dbpath = as_sprintf("%s/blockdata.tch", config->blockdata);
        if ( createpath ) mkpath(config->blockdata,0744);
        LDEBUG("Open database %s", dbpath);
        dbdta = hashdb_open(dbpath, 10, atol(config->blockdatabs));
        free(dbpath);
    } else {
        sp=s_dirname(config->blockdata);
        if ( createpath ) mkpath(sp,0744);
        free(sp);
        freelist = tcbdbnew();
        tcbdbtune(freelist, 0, 0, atol(config->freelistbs), -1, -1,
                  BDBTLARGE);
        /* The dirent database is a B-TREE DB with cursors */
        dbpath = as_sprintf("%s/freelist.tcb", config->freelist);
        if ( createpath ) mkpath(config->freelist,0744);
        if (config->defrag == 1) {
            if (!tcbdbsetdfunit(freelist, 1)) {
                ecode = tcbdbecode(freelist);
                die_dberr("set defrag error: %s", tcbdberrmsg(ecode));
            }
        }
        LDEBUG("Open database %s", dbpath);
        if (!tcbdbopen(freelist, dbpath, BDBOWRITER | BDBOCREAT)) {
            ecode = tcbdbecode(freelist);
            die_dberr("open error: %s", tcbdberrmsg(ecode));
        }
        free(dbpath);
    }

    dbpath = as_sprintf("%s/symlink.tch", config->symlink);
    if ( createpath ) mkpath(config->symlink,0744);
    LDEBUG("Open database %s", dbpath);
    dbs = hashdb_open(dbpath, 10, atol(config->symlinkbs));
    free(dbpath);

    dbdirent = tcbdbnew();
    tcbdbtune(dbdirent, 0, 0, atol(config->direntbs), -1, -1, BDBTLARGE);
    /* The dirent database is a B-TREE DB with cursors */
    dbpath = as_sprintf("%s/dirent.tcb", config->dirent);
    if ( createpath ) mkpath(config->dirent,0744);
    if (config->defrag == 1) {
        if (!tcbdbsetdfunit(dbdirent, 1)) {
            ecode = tcbdbecode(dbdirent);
            die_dberr("set defrag error: %s", tcbdberrmsg(ecode));
        }
    }
    LDEBUG("Open database %s", dbpath);
    if (!tcbdbopen(dbdirent, dbpath, BDBOWRITER | BDBOCREAT)) {
        ecode = tcbdbecode(dbdirent);
        die_dberr("open error: %s", tcbdberrmsg(ecode));
    }
    free(dbpath);

    dbl = tcbdbnew();
    tcbdbtune(dbl, 0, 0, atol(config->hardlinkbs), -1, -1, BDBTLARGE);
    /* The dbl database is a B-TREE DB with cursors */
    dbpath = as_sprintf("%s/hardlink.tcb", config->hardlink);
    if ( createpath ) mkpath(config->hardlink,0744);
    LDEBUG("Open database %s", dbpath);

    if (config->defrag == 1) {
        if (!tcbdbsetdfunit(dbl, 1)) {
            ecode = tcbdbecode(dbl);
            die_dberr("set defrag error: %s", tcbdberrmsg(ecode));
        }
    }
    if (!tcbdbopen(dbl, dbpath, BDBOWRITER | BDBOCREAT)) {
        ecode = tcbdbecode(dbdirent);
        die_dberr("open error: %s", tcbdberrmsg(ecode));
    }
    free(dbpath);

    if (!defrag) {
        dbbm = tcmdbnew();
        dbum = tcmdbnew();
        dbcm = tcmdbnew();
        dbcache = tcmdbnew();
        dbdtaq = tcmdbnew();
        blkcache = tcmdbnew();
		bufcache = tcmdbnew();
		
        if (NULL == config->blockdatabs) {
            if (-1 ==
                (fdbdta =
                 s_open2(config->blockdata, O_CREAT | O_RDWR, S_IRWXU)))
                die_syserr();
            if (-1 == (stat(config->blockdata, &stbuf)))
                die_syserr();
            nextoffset = stbuf.st_size;
        }
    }
    LDEBUG("All databases are open");
    EFUNC;
}

void hashdb_close(TCHDB * hdb)
{
    int ecode;

    FUNC;
    /* close the database */
    if (!tchdbclose(hdb)) {
        ecode = tchdbecode(hdb);
        die_dberr("close error: %s", tchdberrmsg(ecode));
    }
    /* delete the object */
    tchdbdel(hdb);
}

void tc_close(bool defrag)
{
    int ecode;

    FUNC;
    hashdb_close(dbb);
    hashdb_close(dbp);
    hashdb_close(dbu);
    hashdb_close(dbc);
    hashdb_close(dbs);
    if (NULL != config->blockdatabs) {
        hashdb_close(dbdta);
    } else {
       /* close the B-TREE database */
       if (!tcbdbclose(freelist)) {
           ecode = tcbdbecode(freelist);
           die_dberr("close error: %s", tchdberrmsg(ecode));
       }
       /* delete the object */
       tcbdbdel(freelist);
    }

    /* close the B-TREE database */
    if (!tcbdbclose(dbdirent)) {
        ecode = tcbdbecode(dbdirent);
        die_dberr("close error: %s", tchdberrmsg(ecode));
    }
    /* delete the object */
    tcbdbdel(dbdirent);

    /* close the B-TREE database */
    if (!tcbdbclose(dbl)) {
        ecode = tcbdbecode(dbl);
        die_dberr("close error: %s", tchdberrmsg(ecode));
    }
    /* delete the object */
    tcbdbdel(dbl);

    if (!defrag) {
        tcmdbdel(dbcache);
        tcmdbdel(dbbm);
        tcmdbdel(dbum);
        tcmdbdel(dbcm);
        tcmdbdel(dbdtaq);
        tcmdbdel(blkcache);
		tcmdbdel(bufcache);
        if (NULL == config->blockdatabs) {
            close(fdbdta);
        }
    }
    EFUNC;
}

void get_global_lock()
{
    FUNC;
    pthread_mutex_lock(&global_lock_mutex);
    EFUNC;
    return;
}

void get_qdta_lock()
{
    FUNC;
    pthread_mutex_lock(&qdta_mutex);
    EFUNC;
    return;
}

void get_qempty_lock()
{
    FUNC;
    pthread_mutex_lock(&qempty_mutex);
    EFUNC;
    return;
}

void get_moddb_lock()
{
    FUNC;
    pthread_spin_lock(&moddb_spinlock);
    EFUNC;
    return;
}

void get_dbu_lock()
{
    FUNC;
    pthread_spin_lock(&dbu_spinlock);
    EFUNC;
    return;
}

void get_dbc_lock()
{
    FUNC;
    pthread_spin_lock(&dbc_spinlock);
    EFUNC;
    return;
}

void get_dbb_lock()
{
    FUNC;
    pthread_spin_lock(&dbb_spinlock);
    EFUNC;
    return;
}

void worker_lock()
{
    FUNC;
    pthread_mutex_lock(&worker_mutex);
    EFUNC;
    return;
}

void write_lock()
{
    FUNC;
    pthread_mutex_lock(&write_mutex);
    EFUNC;
    return;
}

void open_lock()
{
    FUNC;
    pthread_mutex_lock(&open_mutex);
    EFUNC;
    return;
}

void tiger_lock()
{
    FUNC;
    pthread_mutex_lock(&tiger_mutex);
    EFUNC;
    return;
}

void release_write_lock()
{
    pthread_mutex_unlock(&write_mutex);
    return;
}

void release_moddb_lock()
{
    pthread_spin_unlock(&moddb_spinlock);
    return;
}

void release_dbu_lock()
{
    pthread_spin_unlock(&dbu_spinlock);
    return;
}

void release_dbc_lock()
{
    pthread_spin_unlock(&dbc_spinlock);
    return;
}

void release_dbb_lock()
{
    pthread_spin_unlock(&dbb_spinlock);
    return;
}

int try_moddb_lock()
{
    int res;
    res=pthread_spin_trylock(&moddb_spinlock);
    return(res);
}


int try_dbu_lock()
{
    int res;
    res=pthread_spin_trylock(&dbu_spinlock);
    return(res);
} 

int try_dbb_lock()
{
    int res;
    res=pthread_spin_trylock(&dbb_spinlock);
    return(res);
} 

void release_open_lock()
{
    pthread_mutex_unlock(&open_mutex);
    return;
}

void release_tiger_lock()
{
    pthread_mutex_unlock(&tiger_mutex);
    return;
}

void release_global_lock()
{
    FUNC;
    pthread_mutex_unlock(&global_lock_mutex);
    return;
}

void release_qdta_lock()
{
    FUNC;
    pthread_mutex_unlock(&qdta_mutex);
    EFUNC;
    return;
}

void release_qempty_lock()
{
    FUNC;
    pthread_mutex_unlock(&qempty_mutex);
    EFUNC;
    return;
}

int try_open_lock()
{
    int res;
    res = pthread_mutex_trylock(&open_mutex);
    return (res);
}

int try_tiger_lock()
{
    int res;
    res = pthread_mutex_trylock(&tiger_mutex);
    return (res);
}

int try_qdta_lock()
{
    int res;
    res = pthread_mutex_trylock(&qdta_mutex);
    return (res);
}

int try_global_lock()
{
    int res;
    res = pthread_mutex_trylock(&global_lock_mutex);
    return (res);
}

int try_qempty_lock()
{
    int res;
    FUNC;
    res = pthread_mutex_trylock(&qempty_mutex);
    EFUNC;
    return (res);
}

int try_worker_lock()
{
    int res;
    FUNC;
    res = pthread_mutex_trylock(&worker_mutex);
    EFUNC;
    return (res);
}

int try_write_lock()
{
    int res;
    FUNC;
    res = pthread_mutex_trylock(&write_mutex);
    EFUNC;
    return (res);
}

void release_worker_lock()
{
    pthread_mutex_unlock(&worker_mutex);
    return;
}

/*
 * use the filename and stbuf to create a struct DBT, which will be written to dbp as the value
 * the key of the entry will be the inode
 */
DBT *create_ddbuf(struct stat stbuf, char *filename)
{
    DBT *ddbuf;
    int len;
#ifdef ENABLE_CRYPTO
    DBT *encrypted;
#endif

    FUNC;
    LDEBUG("%s: filename = %s, inode=%llu", __FUNCTION__, filename, stbuf.st_ino);
    if (NULL != filename) {
        len = sizeof(struct stat) + strlen((char *) filename) + 1;
    } else
        len = sizeof(struct stat) + 1;

    ddbuf = s_malloc(sizeof(DBT));
    ddbuf->size = len;
    ddbuf->data = s_malloc(ddbuf->size);
    memcpy(ddbuf->data, &stbuf, sizeof(struct stat));
    if (NULL != filename) {
        memcpy(ddbuf->data + sizeof(struct stat), (char *) filename,
               strlen((char *) filename) + 1);
    } else
        memset(ddbuf->data + sizeof(struct stat), 0, 1);

#ifdef ENABLE_CRYPTO
    if (config->encryptmeta && config->encryptdata) {
        encrypted = encrypt(ddbuf->data, ddbuf->size);
        DBTfree(ddbuf);
        EFUNC;
        return encrypted;
    }
#endif
    EFUNC;
    return ddbuf;
}

/*
 * use the struct memddstat to create a struct DBT, which will be written to dbcache as the value
 * the key of the entry will be the inode
 */
DBT *create_mem_ddbuf(MEMDDSTAT * ddstat)
{
    DBT *ddbuf;

    LDEBUG("%s: filename=%s, blocknr=%llu", __FUNCTION__, ddstat->filename, 
		ddstat->blocknr);
    ddbuf = s_malloc(sizeof(DBT));
    ddbuf->data = s_malloc(sizeof(MEMDDSTAT));
    ddbuf->size = sizeof(MEMDDSTAT);
    memcpy(ddbuf->data, ddstat, sizeof(MEMDDSTAT));
    return ddbuf;
}

/*
 * use the struct memddstat to create a struct DBT, which will be written to dbcache as the value
 * the key of the entry will be the inode
 */
DBT *offhash_to_ddbuf(OFFHASH *offhash)
{
    DBT *data;
	int len;

    LDEBUG("%s: offset=%llu", __FUNCTION__, (unsigned long long) offhash->offset);

    data = s_malloc(sizeof(DBT));
	data->size = sizeof(OFFHASH);
    data->data = s_malloc(data->size);
    memcpy(data->data, offhash, sizeof(OFFHASH));
    return data;
}

/*
 * convert the struct DBT to struct ddstat, DBT was the value of one entry in dbp
 */
DDSTAT *value_to_ddstat(DBT * vddstat)
{
    DDSTAT *ddbuf;
    int filelen;
    DBT *decrypted;

    FUNC;
    decrypted = vddstat;
#ifdef ENABLE_CRYPTO
    if (config->encryptmeta && config->encryptdata) {
        decrypted = decrypt(vddstat);
    }
#endif
    filelen = decrypted->size - sizeof(struct stat);
    ddbuf = s_malloc(sizeof(DDSTAT));
    memcpy(&ddbuf->stbuf, decrypted->data, sizeof(struct stat));
    if (1 == filelen) {
        memset(&ddbuf->filename, 0, MAX_POSIX_FILENAME_LEN);
    } else {
        memcpy(ddbuf->filename, decrypted->data + sizeof(struct stat),
               filelen + 1);
    }
    LDEBUG("value_to_ddstat : return %llu", ddbuf->stbuf.st_ino);
#ifdef ENABLE_CRYPTO
    if (config->encryptmeta && config->encryptdata) {
        DBTfree(decrypted);
    }
#endif
    EFUNC;
    return ddbuf;
}

/*
 * create a file, dir, or symbolic link
 */
void dbmknod(const char *path, mode_t mode, char *linkdest, dev_t rdev)
{
    unsigned long long inode;

	//path = to , linkdest = from
    FUNC;
    LDEBUG("dbmknod : %s", path);
    inode = get_next_inode();
    write_file_ent(path, inode, mode, linkdest, rdev);
    EFUNC;
    return;
}

/*
 * the db entry of a new file or dir or symbolic link is created here
 * for regular file, write dbp and dbdirent;
 * for symbolic link, write dbp and dbs;
 * for dir, write dbp and twice write dbdirent.
 */
void write_file_ent(const char *filename, unsigned long long inode,
                    mode_t mode, char *linkdest, dev_t rdev)
{
    struct stat stbuf;
    struct stat dirstat;
    time_t thetime;
    char *bname;
    char *parentdir;
    int res = 0;
    DBT *ddbuf;
    bool isdot = 0;
    bool isrootdir = 0;

    FUNC;
    LDEBUG("%s: filename=%s, inode=%llu, linkdest=%s", __FUNCTION__, filename, 
		inode, linkdest);
    bname = s_basename((char *) filename);
    parentdir = s_dirname((char *) filename);
    if (0 == strcmp(filename, "/"))
        isrootdir = 1;
    LDEBUG("write_file_ent: parentdir = %s", parentdir);
    write_nfi(inode + 1);

//Write stat structure to create an empty file.
    stbuf.st_ino = inode;
    stbuf.st_dev = 999988;
    stbuf.st_mode = mode;
    if (S_ISDIR(mode)) {
      stbuf.st_nlink = 2;
    } else stbuf.st_nlink = 1;
    if (!isrootdir) {
        if ( 0 == strcmp(filename,"/lost+found")){
           stbuf.st_uid = 0;
           stbuf.st_gid = 0;
        } else {
           stbuf.st_uid = fuse_get_context()->uid;
           stbuf.st_gid = fuse_get_context()->gid;
        }
    } else {
        stbuf.st_uid = 0;
        stbuf.st_gid = 0;
    }
    stbuf.st_rdev = rdev;
    if (S_ISDIR(mode)) {
        stbuf.st_size = 4096;
        stbuf.st_blocks = 1;
    } else {
        stbuf.st_size = 0;
        stbuf.st_blocks = 0;
    }
    if (S_ISLNK(mode)) {
        stbuf.st_size = 3;
        stbuf.st_blocks = 1;
    }
    stbuf.st_blksize = BLKSIZE;
    thetime = time(NULL);
    stbuf.st_atim.tv_sec = thetime;
    stbuf.st_atim.tv_nsec=0;
    stbuf.st_mtim.tv_sec = thetime;
    stbuf.st_mtim.tv_nsec=0;
    stbuf.st_ctim.tv_sec = thetime;
    stbuf.st_ctim.tv_nsec=0;

	//write dbp entry - file stat
    ddbuf = create_ddbuf(stbuf, bname);
    LDEBUG("write_file_ent : write dbp inode %llu", inode);
    bin_write_dbdata(dbp, &inode, sizeof(inode), ddbuf->data, ddbuf->size);
    DBTfree(ddbuf);

	//write dbs entry - for symbolic link
    if (NULL != linkdest) {
        bin_write_dbdata(dbs, &inode, sizeof(unsigned long long), linkdest,
                         strlen(linkdest));
    }
    if (0 == strcmp(bname, "."))
        isdot = 1;
    if (0 == strcmp(bname, ".."))
        isdot = 1;
  recurse:
    if (S_ISDIR(mode) && isdot != 1) {
        btbin_write_dup(dbdirent, &stbuf.st_ino, sizeof(stbuf.st_ino),
                        &inode, sizeof(inode));
    } else {
        res = dbstat(parentdir, &dirstat);
        btbin_write_dup(dbdirent, &dirstat.st_ino, sizeof(dirstat.st_ino),
                        &inode, sizeof(inode));
    }
    if (S_ISDIR(mode) && !isdot && !isrootdir) {
        // Create the link inode to the previous directory
        LDEBUG("Create the link inode to the previous directory");
        isdot = 1;
        // Only if !isrootdir. Nothing lower the root.
        goto recurse;
    }
    free(parentdir);
    free(bname);
    EFUNC;
}

/*
 * mark in the dbp the next inode
 * the entry will be made up with (nextinode : "NFI")
 */
void write_nfi(unsigned long long nextinode)
{
    LDEBUG("%s: nextinode=%llu", __FUNCTION__, nextinode);
    bin_write_dbdata(dbp, (unsigned char *) "NFI", strlen("NFI"),
                     (unsigned char *) &nextinode, sizeof(nextinode));
    return;
}

/*
 * the first time initialization of the file system.
 * the hash of the hash function name will be stored in the dbp for later check
 * if encrypto switch is on, the password will be hashed and stored in dbp for later check
 * get the stat of the database dir,
 * use NFI and the mode of the stat to create the root dir of the file system
 */
void formatfs()
{
    struct stat stbuf;
    unsigned long long nextinode = 0;
    unsigned char *stiger;
    char *blockdatadir;
#ifdef ENABLE_CRYPTO
    CRYPTO crypto;
#endif
    char *hashstr;
    INUSE inuse;
#ifndef SHA3
    word64 res[3];
#endif

    FUNC;
    if (NULL == dbp) {
        tc_open(0,0);
    }
#ifdef SHA3
        hashstr=as_sprintf("BMW%i",config->hashlen);
        stiger=sha_binhash((unsigned char *)hashstr, strlen(hashstr));
#else
        hashstr=as_sprintf("TGR%i",config->hashlen);
        binhash((unsigned char *)hashstr, strlen(hashstr), res);
        stiger=(unsigned char *)&res;
#endif
    free(hashstr);
    if ( config->blockdatabs != NULL ) {
        update_inuse(stiger,1);
    } else {
        inuse.inuse=0;
        inuse.size=0;
        inuse.offset=0;
        file_update_inuse(stiger,&inuse);
    }
    sync_flush_dbu();   
#ifdef SHA3
    free(stiger);
#endif 
    
#ifdef ENABLE_CRYPTO
    if (config->encryptdata) {
#ifdef SHA3
        stiger=sha_binhash(config->passwd, strlen((char *) config->passwd));
#else
        binhash(config->passwd, strlen((char *) config->passwd), res);
        stiger=(unsigned char *)&res;
#endif
        loghash("store passwd as hash", stiger);
        memcpy(&crypto.passwd, stiger, config->hashlen);
        memcpy(&crypto.iv, config->iv, 8);
        bin_write_dbdata(dbp, &nextinode, sizeof(unsigned long long),
                         &crypto, sizeof(CRYPTO));
#ifdef SHA3
        free(stiger);
#endif 
    }
#endif
    nextinode = 1;
    if (NULL == config->blockdatabs) {
        blockdatadir = s_dirname(config->blockdata);
        stat(blockdatadir, &stbuf);
        free(blockdatadir);
    } else {
        stat(config->blockdata, &stbuf);
    }
    write_nfi(nextinode);
    fs_mkdir("/", stbuf.st_mode);
    tc_close(0);
    return;
}

/*
 * get one by one the ancestor dir name and search for the ancestor dir inode level by level, 
 * deeper and deeper...the last dir inode will be found and returned
 */
int get_dir_inode(char *dname, struct stat *stbuf)
{
    char *p;
    int depth = 0;
    DDSTAT *filestat = NULL;
    int res = 0;
    unsigned long long inode = 1;

    FUNC;
    while (1) {
        p = strchr(dname, '/');
        if (NULL == p)
            break;
        p[0] = 0;
		//get the root dir stat
        if (depth == 0) {
            filestat =
                dnode_bname_to_inode(&inode, sizeof(unsigned long long), "/");
        } else {
        //get the non-root dir stat
            ddstatfree(filestat);
            inode = stbuf->st_ino;
            filestat =
                dnode_bname_to_inode(&inode, sizeof(unsigned long long), dname);
            if (NULL == filestat) {
                res = -ENOENT;
                break;
            }
        }
		//get the stat of the found ancestor dir inode
        memcpy(stbuf, &filestat->stbuf, sizeof(struct stat));
        LDEBUG("After memcpy %llu", stbuf->st_ino);

		//move pointer p to the next char, and depth increase, and dname updates
        p++;
        depth++;
        dname = p;
        if (NULL == p)
            break;
    }
    if (res == 0) {
        ddstatfree(filestat);
        LDEBUG("return stbuf.st_ino=%llu", stbuf->st_ino);
    }
    EFUNC;
    return (res);
}

/*
 * return 1 when found or 0 when not found in cache
 */
int get_realsize_fromcache(unsigned long long inode, struct stat *stbuf)
{
    int result = 0;
    DBT *data;
    MEMDDSTAT *mddstat;

    
	//search the inode in the dbcache
    data = search_memhash(dbcache, &inode, sizeof(unsigned long long));
    if (data == NULL) {
        LDEBUG("inode %llu not found use size from database.", inode);
        return (result);
    }
    result++;
    mddstat = (MEMDDSTAT *) data->data;
    memcpy(stbuf, &mddstat->stbuf, sizeof(struct stat));
    LDEBUG("get_realsize_fromcache : return stbuf from cache : size %llu",
           stbuf->st_size);
    DBTfree(data);
    return (result);
}

/*
 * search the dbdirent for the stat info of a file or dir, 
 * get the stat of the file or dir
 */
int dbstat(const char *filename, struct stat *stbuf)
{
    int retcode = 0;
    char *dname = NULL;
    char *bname = NULL;
    char *dupdname = NULL;
    char *mdupdname = NULL;
    DDSTAT *filestat = NULL;

    FUNC;
	//get dir name and file name
    dname = s_dirname((char *) filename);
    bname = s_basename((char *) filename);
    dupdname = s_strdup((char *) filename);
    mdupdname = dupdname;

// Walk the directory
    retcode = get_dir_inode(dupdname, stbuf);
    if (0 == retcode) {
        if (0 != strcmp(bname, dname)) {        /* This is the rootdir */
            // Now find the file within the directory
            filestat =
                dnode_bname_to_inode(&stbuf->st_ino,
                                     sizeof(unsigned long long), bname);
            if (NULL != filestat) {
                if (0 == strcmp(bname, filestat->filename)) {
					//try to get the file stat from cache, because it's newer
                    if (0 ==
                        get_realsize_fromcache(filestat->stbuf.st_ino,
                                               stbuf)) {
                        //file stat doesn't exist in cache, get it from dbp
                        memcpy(stbuf, &filestat->stbuf,
                               sizeof(struct stat));
                    }
                } else {
                    retcode = -ENOENT;
                }
                ddstatfree(filestat);
            } else {
                retcode = -ENOENT;
            }
        }
    } else
        retcode = -ENOENT;

    free(mdupdname);
    free(bname);
    free(dname);
    if (retcode == -ENOENT)
        LDEBUG("dbstat : File %s not found.", filename);
    EFUNC;
    return (retcode);
}

/*
 * Free the stuct ddstat when not NULL 
 */
void ddstatfree(DDSTAT * ddstat)
{
    if (NULL != ddstat) {
        LDEBUG("ddstatfree really free");
        free(ddstat);
        ddstat = NULL;
    }
}

/*
 * Convert the value to struct memddstat
 */
MEMDDSTAT *value_tomem_ddstat(char *value, int size)
{
    LDEBUG("%s: size=%d", __FUNCTION__, size);
    MEMDDSTAT *memddstat;
    memddstat = s_malloc(size);
    memcpy(memddstat, value, size);
    return memddstat;
}

/*
 * Convert the value to struct offhash
 */
OFFHASH *buf_to_offhash(DBT *data)
{
    OFFHASH *offhash;
	
	offhash = s_malloc(data->size);
	memcpy(offhash, data->data, data->size);
	DBTfree(data);
    return offhash;
}

/*
 * Convert the value to struct bufcache
 */
BUFCACHE *buf_to_bufcache(DBT *data)
{
    BUFCACHE *cache;
	
	cache = s_malloc(data->size);
	memcpy(cache, data->data, data->size);
	DBTfree(data);
    return cache;
}

/*
 * Free the stuct memddstat when not NULL 
 */
void memddstatfree(MEMDDSTAT * ddstat)
{
    if (NULL != ddstat) {
        LDEBUG("memddstatfree really free");
        free(ddstat);
    }
    ddstat = NULL;
    return;
}

/*
 * Free the struct compr if it is not empty
 */
void comprfree(compr * compdata)
{
    if (compdata) {
        if (compdata->data)
            free(compdata->data);
        free(compdata);
    }
}

/*
 * read a block from the blkcache, 
 * if not found, read it from the dbdtaq and dbdta, 
 * and decrypt the block or decompress the block when needed,
 * at last, get the original block data and return
 */
unsigned long long readBlock(unsigned long long blocknr, const char *filename, 
	char *blockdata, unsigned long long inode)
{
    int ret = 0;
    DBT *data;
    DBT *tdata;
    DBT *decrypted = NULL;
    DBT *cachedata;
    unsigned char *stiger;
    unsigned char *dtiger=NULL;
    compr *uncompdata = NULL;
    INOBNO inobno;
	OFFHASH *offhash;
    BLKCACHE *blk;
#ifndef SHA3
    word64 res[3];
#endif

    FUNC;
    LDEBUG("%s: filename=%s, inode=%llu, blocknr=%llu", __FUNCTION__, filename, 
		inode, blocknr);
    inobno.inode = inode;
    inobno.blocknr = blocknr;
    data = try_block_cache(inode, blocknr, 0);
    if (NULL != data) {
        LDEBUG("readBlock : block %llu - %llu found in cache", inode,
               blocknr);
        memcpy(blockdata, data->data, data->size);
        ret = data->size;
        DBTfree(data);
        return (ret);
    }
	//block was not found in cache
	//find block in dbb and blkcache, actually the blkcache has been checked before
    tdata = check_block_exists(inobno);
    if (NULL == tdata) return (0);
	offhash = (OFFHASH *) tdata->data;
    stiger = offhash->stiger;
// First try the cache
    get_moddb_lock();
    decrypted = search_memhash(dbdtaq, stiger, config->hashlen);
    if (NULL == decrypted) {
        LDEBUG("readBlock hash not found in dbdtaq");
#ifndef ENABLE_CRYPTO
        decrypted = search_dbdata(dbdta, stiger, config->hashlen);
        if (NULL == decrypted) {
#else
        data = search_dbdata(dbdta, stiger, config->hashlen);
        if (NULL == data) {
#endif
            LDEBUG("readBlock hash not found in dbdta");
            cachedata =
                search_memhash(blkcache, &inobno.inode,
                               sizeof(unsigned long long));
            if (NULL != cachedata) {
                blk = (BLKCACHE *) cachedata->data;
#ifdef SHA3
                dtiger=sha_binhash(blk->blockdata, BLKSIZE);
#else
                binhash(blk->blockdata, BLKSIZE, res);
                dtiger=(unsigned char *) &res;
#endif
                if (0 == memcmp(dtiger, stiger, config->hashlen)) {
                    decrypted = s_malloc(sizeof(DBT));
                    decrypted->data = s_malloc(BLKSIZE);
                    decrypted->size = BLKSIZE;
                    memcpy(decrypted->data, blk->blockdata, BLKSIZE);
                } else {
                    LFATAL
                        ("readBlock - unable to find dbdta block for inode %llu - %llu",
                         inobno.inode, inobno.blocknr);
                    log_fatal_hash
                        ("readBlock - unable to find dbdta block hash :",
                         stiger);
                    die_dataerr("No data found to read.");
                }
#ifdef SHA3
                free(dtiger);
#endif
                DBTfree(cachedata);
            } else {
                LFATAL
                    ("readBlock : unable to find dbdta block for inode %llu - %llu",
                     inobno.inode, inobno.blocknr);
                log_fatal_hash
                    ("readBlock : unable to find dbdta block hash :",
                     stiger);
                die_dataerr("No data found to read.");
            }
#ifndef ENABLE_CRYPTO
        }
#else
        } else {
            if (config->encryptdata) {
                decrypted = decrypt(data);
                DBTfree(data);
            } else
                decrypted = data;
        }
#endif
    }
    release_moddb_lock();
    if (decrypted->size != BLKSIZE) {
#ifdef LZO
        uncompdata = lzo_decompress(decrypted->data, decrypted->size);
#else
        uncompdata = clz_decompress(decrypted->data, decrypted->size);
#endif
        memcpy(blockdata, uncompdata->data, uncompdata->size);
        ret = uncompdata->size;
        comprfree(uncompdata);
    } else {
        memcpy(blockdata, decrypted->data, decrypted->size);
        ret = decrypted->size;
    }
    DBTfree(decrypted);
    DBTfree(tdata);
    EFUNC;
    return (ret);
}

/*
 * this happens when deleting a block of which the inuse is 1 
 * delete the inuse entry in dbum and dbu
 */
void delete_inuse(unsigned char *stiger)
{
	LDEBUG("%s: hash=%s", __FUNCTION__, stiger);
    get_dbu_lock();
        tcmdbout(dbum, stiger, config->hashlen);
        tchdbout(dbu, stiger, config->hashlen);
    release_dbu_lock();
}

/*
 * this happens when deleting the block of a file, 
 * the inode and blocknr of the block will be given, 
 * and delete the ino-blocknr entry in dbbm and dbb
 */
void delete_dbb(INOBNO *inobno)
{
    LDEBUG("%s: inode=%llu, blocknr=%llu", __FUNCTION__, inobno->inode, 
		inobno->blocknr);
    get_dbb_lock();
        tcmdbout(dbbm, inobno, sizeof(INOBNO));
        tchdbout(dbb, inobno, sizeof(INOBNO));
    release_dbb_lock();
}

/*
 * this happens when the reference times of a block is needed,
 * Return the number of times this block is referenced
 */
unsigned long long getInUse(unsigned char *tigerstr)
{
    unsigned long long counter;
    DBT *data;

    if (NULL == tigerstr)
        return (0);

    get_dbu_lock();
    data = search_memhash(dbum, tigerstr, config->hashlen);
    if ( NULL == data ) {
        data = search_dbdata(dbu, tigerstr, config->hashlen);
    }
    if (NULL == data) {
        LDEBUG("getInuse nothing found return 0.");
        release_dbu_lock();
        return (0);
    }
    release_dbu_lock();
    memcpy(&counter, data->data, sizeof(counter));
    DBTfree(data);
    LDEBUG("%s: hash=%s inuse=%llu", __FUNCTION__, tigerstr, counter);
    return counter;
}

unsigned long long checksum_exists(unsigned int key)
{
	unsigned long long counter;
	DBT *data;

	get_dbc_lock();
	data = search_memhash(dbcm, (void *) &key, sizeof(unsigned int));
	if (data == NULL) {
		data = search_dbdata(dbc, (void *) &key, sizeof(unsigned int));
	}
	if (data == NULL) {
		release_dbc_lock();
		return 0;
	}
	release_dbc_lock();
	memcpy(&counter, data->data, data->size);
	DBTfree(data);
	return counter;
}

/*
 * free the struct DBT if it is not empty
 */
void DBTfree(DBT * data)
{
    if (data) {
        if (data->data)
            if (data->data)
                free(data->data);
        free(data);
    }
    data = NULL;
}

/*
 * this happens when the inuse of one block is changed,
 * the change should be add to the dbum, 
 * and before that, make sure the queue is not full
 */
void update_inuse(unsigned char *hashdata, 
                 unsigned long long inuse)
{
    LDEBUG("%s: hash=%s, inuse=%llu", __FUNCTION__, hashdata, inuse);
    if (inuse > 0) {
        if ( dbu_qcount > METAQSIZE ) {
            sync_flush_dbu();
        }
        get_dbu_lock();
        mbin_write_dbdata(dbum, hashdata, config->hashlen, (unsigned char *) &inuse,
                         sizeof(unsigned long long));
        dbu_qcount++;
        release_dbu_lock();
    }
    return;
}

/*
 */
void update_checksum_inuse(unsigned int key, unsigned long long inuse)
{
    LDEBUG("%s: hash=%d, inuse=%llu", __FUNCTION__, key, inuse);
    if (inuse > 0) {
        if ( dbc_qcount > METAQSIZE ) {
            sync_flush_dbc();
        }
        get_dbc_lock();
        mbin_write_dbdata(dbcm, (void *) &key, sizeof(unsigned int), 
			(unsigned char *) &inuse, sizeof(unsigned long long));
        dbc_qcount++;
        release_dbc_lock();
    }
    return;
}

/*
 * this happens when a new inode-blocknr entry should be added to db,
 * or an old one should be replaced.
 * make sure the queue of dbb is not full, and add the new dbb entry to the queue
 */
void write_dbb_to_cache(INOBNO *inobno, OFFHASH *offhash)
{ 
    LDEBUG("%s: inode=%llu, blocknr=%llu, hash=%s", __FUNCTION__, 
		inobno->inode, inobno->blocknr, stiger);
    if ( dbb_qcount > METAQSIZE ) {
         sync_flush_dbb();
    }
    get_dbb_lock(); 
    mbin_write_dbdata(dbbm, inobno, sizeof(INOBNO), (void *) offhash, 
						sizeof(OFFHASH));
    dbb_qcount++;
    release_dbb_lock();
}

/*
 * write binary data as the value to a B+ tree db, in the position of cursor
 * not changing the key
 */
void btbin_curwrite_dbdata(TCBDB * db, BDBCUR * cur, char *data,
                           int datalen)
{
    int ecode;
    FUNC;
    if (!tcbdbcurput(cur, data, datalen, BDBCPAFTER)) {
        ecode = tcbdbecode(db);
        die_dberr("tcbdbput2 failed : %s", tcbdberrmsg(ecode));
    }
    if ( 0 == config->relax ) tcbdbsync(db);
    EFUNC;
}

/*
 * write ascii key and data as the key and value to a B+ tree db, 
 * the entry with the same key will be replaced
 */
void btasc_write_dbdata(TCBDB * db, char *keydata, char *dataData)
{
    int ecode;
    FUNC;
    if (!tcbdbputdup2(db, (char *) keydata, (char *) dataData)) {
        ecode = tcbdbecode(db);
        die_dberr("tcbdbput failed : %s", tcbdberrmsg(ecode));
    }
    if ( 0 == config->relax ) tcbdbsync(db);
    EFUNC;
}

/*
 * write binary key as the key and binary data as the value to a B+ tree db,
 * different entries with the same key is permitted
 */
void btbin_write_dup(TCBDB * db, void *keydata, int keylen,
                     void *dataData, int datalen)
{
    int ecode;
    FUNC;
    if (!tcbdbputdup(db, keydata, keylen, dataData, datalen)) {
        ecode = tcbdbecode(db);
        die_dberr("tcbdbputdup failed : %s", tcbdberrmsg(ecode));
    }
    if ( 0 == config->relax ) tcbdbsync(db);
    EFUNC;
}

/*
 * write ascii data as the value to a B+ tree db, in the position of cursor
 * not changing the key
 */
void btasc_curwrite_dbdata(TCBDB * db, BDBCUR * cur, unsigned char *data)
{
    int ecode;
    FUNC;

    if (!tcbdbcurput2(cur, (const char *) data, BDBCPAFTER)) {
        ecode = tcbdbecode(db);
        die_dberr("tcbdbput2 failed : %s", tcbdberrmsg(ecode));
    }
    if ( 0 == config->relax ) tcbdbsync(db);
    EFUNC;
}

/*
 * write binary key and data as the key and value to a B+ tree db, 
 * the entry with the same key will be replaced
 */
void btbin_write_dbdata(TCBDB * db, void *keydata, int keylen,
                        void *dataData, int datalen)
{
    int ecode;
    FUNC;
    if (!tcbdbput(db, keydata, keylen, dataData, datalen)) {
        ecode = tcbdbecode(db);
        die_dberr("tcbdbput failed : %s", tchdberrmsg(ecode));
    }
    if ( 0 == config->relax ) tcbdbsync(db);
    EFUNC;
}

/*
 * write binary key and data as the key and value to an on-memory hash db, 
 * the entry with the same key will be replaced
 */
void mbin_write_dbdata(TCMDB * db, void *keydata, int keylen,
                       void *dataData, int datalen)
{
    FUNC;
	//write into an on-memory hash database
    tcmdbput(db, keydata, keylen, dataData, datalen);
    EFUNC;
}

/*
 * write binary key and data as the key and value to an on-memory B+ tree db, 
 * the entry with the same key will be replaced
 */
void nbin_write_dbdata(TCNDB * db, void *keydata, int keylen,
                       void *dataData, int datalen)
{
    FUNC;
	//write into an on-memory tree database object
    tcndbput(db, keydata, keylen, dataData, datalen);
    EFUNC;
}

/*
 * write binary key and data as the key and value to a hash db, 
 * the entry with the same key will be replaced
 */
void bin_write_dbdata(TCHDB * db, void *keydata, int keylen,
                      void *dataData, int datalen)
{
    int ecode;
    if (!tchdbputasync(db, keydata, keylen, dataData, datalen)) {
        ecode = tchdbecode(db);
        die_dberr("tchdbputasync failed : %s", tchdberrmsg(ecode));
    }
}

/*
 * write ascii key and data as the key and value to a hash db, 
 * the entry with the same key will be replaced
 */
void asc_write_dbdata(TCHDB * db, unsigned char *keydata,
                      unsigned char *dataData)
{
    int ecode;
    FUNC;
    if (!tchdbputasync
        (db, keydata, strlen((char *) keydata), dataData,
         strlen((char *) dataData))) {
        ecode = tchdbecode(db);
        die_dberr("tchdbputasync failed : %s", tchdberrmsg(ecode));
    }
    EFUNC;
}

/* 
 * Search in directory with dir inode and the entry file name for the inode of the entry
 * the filename of hard link is empty, the inode will be found in dbl where bname equals link name
 * Return the inode of file bname
 */
DDSTAT *dnode_bname_to_inode(void *dinode, int dlen, char *bname)
{
    BDBCUR *cur;
    char *dbkey;
    int dbsize;
    char *dbvalue;
    DBT *statdata;
    DDSTAT *filestat = NULL;
    char *filename;
    DINOINO dinoino;
    unsigned long long keynode;
    unsigned long long valnode;

    FUNC;

	unsigned long long key;
	memcpy(&key, dinode, sizeof(key));
	//cur==cursor
    cur = tcbdbcurnew(dbdirent);
    if (!tcbdbcurjump(cur, (char *) dinode, dlen)
        && tcbdbecode(dbdirent) != TCESUCCESS) {
        tcbdbcurdel(cur);
        return NULL;
    }

    /* traverse records */
	//make sure that the search is in the current dir
    while ((dbkey = tcbdbcurkey(cur, &dbsize)) != NULL) {
        if (0 != memcmp(dbkey, dinode, dlen)) {
            free(dbkey);
            break;
        }
		//get the inode of the entry
        dbvalue = tcbdbcurval(cur, &dbsize);
        if (dbvalue) {
            memcpy(&valnode, dbvalue, sizeof(valnode));
            memcpy(&keynode, dbkey, sizeof(keynode));
			//dir inode == entry inode
            if (keynode == valnode && keynode != 1) {
                free(dbvalue);
                free(dbkey);
                tcbdbcurnext(cur);
                continue;
            }
			//search for stat of entry inode in dbp
            statdata =
                search_dbdata(dbp, &valnode, sizeof(unsigned long long));
            if (NULL == statdata) {
                LDEBUG("Unable to find file existing in dbp.\n");
                free(dbvalue);
                free(dbkey);
                return NULL;  
            } 
            filestat = value_to_ddstat(statdata);
            DBTfree(statdata);
            free(dbvalue);
			
			//if the filename is NULL, this is a hardlink
            if (0 != filestat->filename[0]) {
                LDEBUG("compare bname %s with filestat->filename %s",
                       bname, filestat->filename);
                if (0 == strcmp(bname, filestat->filename)) {
                    free(dbkey);
                    break;
                }
            } else {
            	//get the filename of a hard link from the dbl
                memcpy(&dinoino.dirnode, dinode,
                       sizeof(unsigned long long));
                dinoino.inode = filestat->stbuf.st_ino;
				//in the btsearch_keyval, the bname will be matched, so if matched successfully, 
				//this is the inode that we are looking for
                filename = btsearch_keyval(dbl, &dinoino, sizeof(DINOINO), bname,
                                    strlen(bname));
                if (NULL != filename) {
                    memcpy(&filestat->filename, filename,
                           strlen(filename) + 1);
                    free(filename);
                    free(dbkey);
                    break;
                }
            }
            ddstatfree(filestat);
            filestat = NULL;
        }
        free(dbkey);
        tcbdbcurnext(cur);
    }
    tcbdbcurdel(cur);
    if (NULL != filestat) {
        LDEBUG("dnode_bname_to_inode : filestat->filename=%s inode %llu",
               filestat->filename, filestat->stbuf.st_ino);
    } else {
        LDEBUG("dnode_bname_to_inode : return NULL");
    }
    return filestat;
}

/* 
 * search in hash database db for the key
 * and return the value as DBT
 */
DBT *search_dbdata(TCHDB * db, void *key, int len)
{
    DBT *data;
    int size;

    data = s_malloc(sizeof(DBT));
    data->data = tchdbget(db, key, len, &size);
    data->size = (unsigned long) size;
    if (NULL == data->data) {
        LDEBUG("search_dbdata : return NULL");
        free(data);
        data = NULL;
    } else
        LDEBUG("search_dbdata : return %lu bytes", data->size);
    return data;
}

/* 
 * Search in dbp for the value "NFI", and return the key
 * this is the next empty inode
 */
unsigned long long get_next_inode()
{
    DBT *data;
    unsigned long long nextinode = 0;
    FUNC;

    data = search_dbdata(dbp, (unsigned char *) "NFI", strlen("NFI"));	//the next inode is named "NFI", maybe for Next Found Inode
    if (NULL != data) {
        memcpy(&nextinode, data->data, sizeof(nextinode));
        DBTfree(data);
    }
    LDEBUG("Found next inode number: %llu", nextinode);
    EFUNC;
    return (nextinode);
}

/* 
 * Search in memory hash database db for key and return the value as DBT
 */
DBT *search_memhash(TCMDB * db, void *key, int len)
{
    DBT *data;
    int size;

    FUNC;
    data = s_malloc(sizeof(DBT));
    data->data = tcmdbget(db, key, len, &size);
    data->size = (unsigned long) size;
    if (NULL == data->data) {
        LDEBUG("search_memhash : return NULL");
        free(data);
        data = NULL;
    } else
        LDEBUG("search_memhash : return %lu bytes", data->size);
    EFUNC;
    return data;
}

/* 
 * add to the dbdtaq the stiger as the key and data as the value
 */
void qdta(unsigned char *stiger, DBT * data)
{
    LDEBUG("%s: hash=%s, datasize=%lu", __FUNCTION__, stiger, data->size);
    get_moddb_lock();
    loghash("qdta", stiger);
    mbin_write_dbdata(dbdtaq, stiger, config->hashlen, data->data, data->size);
    release_moddb_lock();
}

/* 
 * for uncompleted block, add it to the blkcache, 
 * for completed block, if new, add to dbdtaq, add dbu and dbb, if not, update dbu and add dbb
 */
void addBlock(BLKDTA * blkdta)
{
    unsigned long long inuse;
    INOBNO inobno;
	OFFHASH *offhash;
    DBT *cachedata = NULL;

    inobno.inode = blkdta->inode;
    inobno.blocknr = blkdta->blocknr;

    LDEBUG("%s: inode=%llu, blocknr=%llu, hash=%s", __FUNCTION__, blkdta->inode, 
		blkdta->blocknr, blkdta->stiger);
    if (blkdta->bsize + blkdta->offsetblock < BLKSIZE) {
// Flush the blockcache before overwriting.
        cachedata = try_block_cache(blkdta->inode, blkdta->blocknr, 0);
        if (cachedata)
            DBTfree(cachedata);
        add_blk_to_cache(blkdta->inode, blkdta->blocknr, blkdta->blockfiller, 
			blkdta->offsetfile);
        LDEBUG
            ("addBlock : wrote with add_blk_to_cache  : inode %llu - %llu size %i",
             inobno.inode, inobno.blocknr, blkdta->bsize);
        update_filesize(blkdta->inode, blkdta->bsize, blkdta->offsetblock,
                        blkdta->blocknr, blkdta->sparse, 0, 0);
        return;
    }

    inuse = getInUse(blkdta->stiger);
    if (inuse == 0) {
        if (NULL == blkdta->compressed) {
#ifdef LZO
            blkdta->compressed =
                lzo_compress(blkdta->blockfiller, BLKSIZE);
#else
            blkdta->compressed =
                clz_compress(blkdta->blockfiller, BLKSIZE);
#endif
        }
        LDEBUG("Compressed %i bytes to %lu bytes", BLKSIZE, 
			blkdta->compressed->size);
        loghash("addBlk call qdta for hash :", blkdta->stiger);
        qdta(blkdta->stiger, (DBT *) blkdta->compressed);
        loghash("addBlock queued with qdta", blkdta->stiger);
        update_filesize(blkdta->inode, blkdta->bsize, blkdta->offsetblock,
                        blkdta->blocknr, blkdta->sparse,
                        blkdta->compressed->size, 0);
    } else {
        update_filesize(blkdta->inode, blkdta->bsize, blkdta->offsetblock,
                        blkdta->blocknr, blkdta->sparse, 0, 1);
    }
    if (NULL != blkdta->compressed)
        comprfree(blkdta->compressed);
    inuse++;
    update_inuse(blkdta->stiger, inuse);
	offhash = s_malloc(sizeof(OFFHASH));
	offhash->offset = blkdta->offsetfile;
	memcpy(offhash->stiger, blkdta->stiger, config->hashlen);
    write_dbb_to_cache(&inobno, offhash);
	free(offhash);
    return;
}

/*
 * get the meta data of inode from dbcache
 */
MEMDDSTAT *inode_meta_from_cache(unsigned long long inode)
{
    DBT *dataptr;
    MEMDDSTAT *ddstat = NULL;
    LDEBUG("%s: inode=%llu", __FUNCTION__, inode);
    dataptr = search_memhash(dbcache, &inode, sizeof(unsigned long long));
    if (dataptr == NULL) {
        LDEBUG("inode %llu not found to update.", inode);
        return NULL;
    }
    ddstat = value_tomem_ddstat((char *) dataptr->data, dataptr->size);
    DBTfree(dataptr);
    return ddstat;
}

/*
 * sync the block data in memory and update filesize in dbp
 * the file is already closed, so the dbcache has no records
 */
void update_filesize_onclose(unsigned long long inode)
{
    MEMDDSTAT *memddstat;

	//get the meta data of inode from dbcache
    memddstat = inode_meta_from_cache(inode);
    if (NULL == memddstat) {
        LDEBUG("inode %llu not found to update.", inode);
        return;
    }
	//if found, flush the data, and update filesize
    flush_dta_queue();
    hash_update_filesize(memddstat, inode);
    LDEBUG("%s: inode=%llu, filesize=%llu", __FUNCTION__, inode, 
		memddstat->stbuf.st_size);
    memddstatfree(memddstat);
    return;
}

/*
 * check the dbcache and then dbp for meta data and update the filesize it
 */
int update_filesize_cache(struct stat *stbuf, off_t size)
{
    DBT *data;
    MEMDDSTAT *memddstat;
    DDSTAT *ddstat;
    DBT *ddbuf;
    time_t thetime;

    LDEBUG("%s: from %llu to %llu", __FUNCTION__, stbuf->st_size, size);

    thetime = time(NULL);
    // Truncate filesize.
    data = search_dbdata(dbp, &stbuf->st_ino, sizeof(unsigned long long));
    if (NULL == data) {
        LDEBUG("fs_truncate : no inode found to truncate");
        return (-ENOENT);
    }
    ddstat = value_to_ddstat(data);
    DBTfree(data);
    data = search_memhash(dbcache, &stbuf->st_ino,
                          sizeof(unsigned long long));
    if (NULL != data) {
        memddstat = (MEMDDSTAT *) data->data;
        memcpy(&memddstat->stbuf, stbuf, sizeof(struct stat));
        memddstat->stbuf.st_size = size;
        memddstat->stbuf.st_ctim.tv_sec = thetime;
        memddstat->stbuf.st_ctim.tv_nsec=0;
        memddstat->stbuf.st_mtim.tv_sec = thetime;
        memddstat->stbuf.st_mtim.tv_nsec=0;
        memddstat->updated = 1;
        ddbuf = create_mem_ddbuf(memddstat);
        mbin_write_dbdata(dbcache, &stbuf->st_ino, sizeof(unsigned long long), 
							(void *) ddbuf->data, ddbuf->size);
        DBTfree(ddbuf);
        DBTfree(data);
    } else {
        ddstatfree(ddstat);
        data =
            search_dbdata(dbp, &stbuf->st_ino, sizeof(unsigned long long));
        if (NULL == data) {
            return (-ENOENT);
        }
        ddstat = value_to_ddstat(data);
        ddstat->stbuf.st_mtim.tv_sec = thetime;
        ddstat->stbuf.st_mtim.tv_nsec=0;
        ddstat->stbuf.st_ctim.tv_sec = thetime;
        ddstat->stbuf.st_ctim.tv_nsec=0;
        ddstat->stbuf.st_size = size;
        DBTfree(data);
        data = create_ddbuf(ddstat->stbuf, ddstat->filename);
        bin_write_dbdata(dbp, &stbuf->st_ino, sizeof(unsigned long long),
                         (void *) data->data, data->size);
        DBTfree(data);
    }
    ddstatfree(ddstat);
    return(0);
}

/*
 * update filesize when new block is added
 */
void update_filesize(unsigned long long inode, unsigned long long fsize,
	unsigned int offsetblock, unsigned long long blocknr, bool sparse, 
	unsigned int compressed, unsigned int deduplicated)
{
    DBT *dataptr;
    DBT *tigerdata;
    MEMDDSTAT *memddstat;
    DBT *ddbuf;
    int addblocks;
    INOBNO inobno;

    FUNC;
    LDEBUG("%s : inode %llu fsize %llu offset %u blocknet %llu bool %c", 
		__FUNCTION__, inode, fsize, offsetblock, blocknr, sparse);
    dataptr = search_memhash(dbcache, &inode, sizeof(unsigned long long));
	//if the file stat does not exist in dbcache, nothing is to be updated
    if (dataptr == NULL)
        return;
    memddstat = (MEMDDSTAT *) dataptr->data;
    memddstat->updated++;
    memddstat->lzo_compressed_size = memddstat->lzo_compressed_size + compressed;
    memddstat->deduplicated = memddstat->deduplicated + deduplicated;
    memddstat->blocknr = blocknr;
    memddstat->stbuf.st_mtim.tv_sec = time(NULL);
    memddstat->stbuf.st_mtim.tv_nsec = 0;

	//stat contains the info of the number of blocks the file is made up
    addblocks = fsize / 512;
    LDEBUG("update_filesize : addblocks = %i", addblocks);
    if ((memddstat->stbuf.st_blocks + addblocks) * 512 <
        memddstat->stbuf.st_size + fsize)
        addblocks++;
    // The file has not grown in size. block is being updated in the file.
    if (!sparse && ((blocknr * BLKSIZE) + offsetblock + fsize) <=
        memddstat->stbuf.st_size) {
        inobno.inode = inode;
        inobno.blocknr = blocknr;
        tigerdata = check_block_exists(inobno);
        if (NULL != tigerdata) {
            LDEBUG
                ("update_filesize : The file has not grown in size and the block exists. This is an updated block.");
            ddbuf = create_mem_ddbuf(memddstat);
            mbin_write_dbdata(dbcache, &inode, sizeof(unsigned long long),
                              (void *) ddbuf->data, ddbuf->size);
            DBTfree(ddbuf);
            DBTfree(dataptr);
            DBTfree(tigerdata);
            return;
        } 
    }
    // The file size has grown or the block is sparse.
    if (!sparse) {
        if (memddstat->stbuf.st_size < (blocknr * BLKSIZE) + fsize + offsetblock){
            memddstat->stbuf.st_size = fsize + offsetblock + (blocknr * BLKSIZE);
        }
        if (memddstat->stbuf.st_size > (512 * memddstat->stbuf.st_blocks)) {
            memddstat->stbuf.st_blocks = memddstat->stbuf.st_blocks + addblocks;
            LDEBUG
                ("update_filesize : The file is not sparse and we need to add %i blocks",
                 addblocks);
        }
    } else {
        LDEBUG("update_filesize : The file adds a sparse block : add %i blocks",
             addblocks);
        memddstat->stbuf.st_blocks = memddstat->stbuf.st_blocks + addblocks;
    }
    ddbuf = create_mem_ddbuf(memddstat);
    mbin_write_dbdata(dbcache, &inode, sizeof(unsigned long long),
                      (void *) ddbuf->data, ddbuf->size);
    DBTfree(ddbuf);
// Do not flush data until cachesize is reached
    if (memddstat->updated > config->cachesize) {
        flush_dta_queue();
        hash_update_filesize(memddstat, inode);
        memddstat->updated = 0;
        ddbuf = create_mem_ddbuf(memddstat);
        mbin_write_dbdata(dbcache, &inode, sizeof(unsigned long long),
                          (void *) ddbuf->data, ddbuf->size);
        DBTfree(ddbuf);
    }
    DBTfree(dataptr);
    EFUNC;
    return;
}

/*
 * release the lock to start the dbdtaq flush
 */
void flush_dta_queue()
{
    FUNC;
    release_qdta_lock();	//when the qdta_lock is released, the init_data_writer will work
    get_qempty_lock();
    EFUNC;
}

/*
 * update dbp with ddstat
 */
void hash_update_filesize(MEMDDSTAT * ddstat, unsigned long long inode)
{
    DBT *ddbuf;
    LDEBUG("%s: inode=%llu, filename=%s", __FUNCTION__, inode, ddstat->filename);
// Wait until the data queue is written before we update the filesize
	//inode with more than one link does not have file name in dbp
    if (ddstat->stbuf.st_nlink > 1) {
        ddbuf = create_ddbuf(ddstat->stbuf, NULL);
    } else {
        ddbuf = create_ddbuf(ddstat->stbuf, ddstat->filename);
    }
	//update meta data of inode
    bin_write_dbdata(dbp, &inode, sizeof(unsigned long long), (void *) ddbuf->data,
        ddbuf->size);
    DBTfree(ddbuf);
    return;
}

/*
 * search for block in dbdta, dbdtaq and blkcache, to delete the block
 */
void delete_data_cache_or_db(unsigned char *chksum,
                             unsigned long long inode)
{
    DBT *data;
#ifndef SHA3
    word64 res[3];
#endif
    BLKCACHE *blk;
    unsigned char *dtiger=NULL;
    LDEBUG("%s: inode=%llu, hash=%s", __FUNCTION__, inode, chksum);
    get_moddb_lock();
    if (!tchdbout(dbdta, chksum, config->hashlen)) {
        loghash
            ("delete_data_cache_or_db : hash not found in dbdta, try cache",
             chksum);
        if (!tcmdbout(dbdtaq, chksum, config->hashlen)) {
            data =
                search_memhash(blkcache, &inode,
                               sizeof(unsigned long long));
            if (NULL != data) {
                blk = (BLKCACHE *) data->data;
#ifdef SHA3
                dtiger=sha_binhash(blk->blockdata, BLKSIZE);
#else
                binhash(blk->blockdata, BLKSIZE, res);
                dtiger=(unsigned char *)&res;
#endif
                loghash
                    ("delete_data_cache_or_db : dtiger deleted from cache",
                     dtiger);
                if (0 == memcmp(dtiger, chksum, config->hashlen)) {
                    loghash
                        ("delete_data_cache_or_db : deleted hash form blkcache",
                         dtiger);
                    mdelete_key(blkcache, &inode,
                                sizeof(unsigned long long));
                } else
                    die_dataerr("Weird scenes inside the coal mine.");
#ifdef SHA3
                free(dtiger);
#endif
                DBTfree(data);
            } else {
                die_dataerr("Weird scenes inside the coal mine.");
            }
        }
    } else
        loghash("delete_data_cache_or_db : deleted hash", chksum);
    release_moddb_lock();
    return;
}

/*
 * 
 * 
 * 
 */
/* delete = 1 Do delete dbdata
   delete = 0 Do not delete dbdta */
unsigned int db_commit_block(unsigned char *dbdata, INOBNO inobno, 
									off_t offset)
{
    unsigned char *stiger=NULL;
    compr *compressed;
    unsigned long long inuse;
    unsigned int ret = 0;
	OFFHASH *offhash;
#ifndef SHA3 
    word64 res[3];
#endif

    FUNC;
    LDEBUG("%s: inode=%llu, blocknr=%llu", __FUNCTION__,
		inobno.inode, inobno.blocknr);
//get hash of block
#ifdef SHA3
    stiger=sha_binhash(dbdata, BLKSIZE);
#else
    binhash(dbdata, BLKSIZE, res);
    stiger=(unsigned char *)&res;
#endif
//compress the block
#ifdef LZO
    compressed = lzo_compress((unsigned char *) dbdata, BLKSIZE);
#else
    compressed = clz_compress((unsigned char *) dbdata, BLKSIZE);
#endif
    ret = compressed->size;
    inuse = getInUse(stiger);
    if (0 == inuse) {
        loghash("commit_block : write hash with qdta", stiger);
        qdta(stiger, (DBT *) compressed);
    } else
        loghash("commit_block : only updated inuse for hash ", stiger);
    inuse++;
    update_inuse(stiger, inuse);
    comprfree(compressed);
	offhash = s_malloc(sizeof(OFFHASH));
	offhash->offset = offset;
	memcpy(offhash->stiger, stiger, config->hashlen);
    write_dbb_to_cache(&inobno, offhash);
#ifdef SHA3
    free(stiger);
#endif
	free(offhash);
    return (ret);
}

/*
 * 
 * 
 * 
 */
void add_blk_to_cache(unsigned long long inode, unsigned long long blocknr,
                      unsigned char *data, off_t offset)
{
    BLKCACHE blk;

    FUNC;
    LDEBUG("%s: inode=%llu, blocknr=%llu", __FUNCTION__, inode, blocknr);
    blk.blocknr = blocknr;
	blk.offset = offset;
    memcpy(&blk.blockdata, data, BLKSIZE);
    mbin_write_dbdata(blkcache, &inode, sizeof(unsigned long long),
                      (void *) &blk, sizeof(BLKCACHE));
    EFUNC;
    return;
}

void add_buf_to_bufcache(unsigned char *buf, size_t bufsize, 
	unsigned long long inode, off_t offset)
{
	BUFCACHE cache;

	FUNC;
	cache.bufsize = bufsize;
	cache.inode = inode;
	cache.offset = offset;
	memcpy(&cache.buf, buf, BLKSIZE * 2);
    mbin_write_dbdata(bufcache, &inode, sizeof(unsigned long long),
                      (void *) &cache, sizeof(BUFCACHE));
	EFUNC;
	return;
}

BUFCACHE *try_buf_cache(unsigned long long inode)
{
	DBT *data;
	BUFCACHE *cache = NULL;
	
	FUNC;
	if (NULL != 
		(data = search_memhash(bufcache, &inode, sizeof(unsigned long long)))) {
		cache = buf_to_bufcache(data);
	}
	EFUNC;
	return cache;
}

/*
 * 
 * 
 * 
 */
/* mode = 0 -> update the block and delete dbdta
   mode = 1 -> flush the inode
   mode = 2 -> dbdta has not been written so don't delete
*/
DBT *try_block_cache(unsigned long long inode, unsigned long long blocknr,
                     unsigned int mode)
{
    DBT *retdata = NULL;
    DBT *data;
    INOBNO inobno;
    BLKCACHE *blk;

    FUNC;
    LDEBUG("%s: inode=%llu, blocknr=%llu, mode=%d", __FUNCTION__, inode, blocknr,
		mode);
    data = search_memhash(blkcache, &inode, sizeof(unsigned long long));
    if (data != NULL) {
        blk = (BLKCACHE *) data->data;
        if ((blocknr == blk->blocknr) && (mode != 1)) {
            retdata = s_malloc(sizeof(DBT));
            retdata->size = BLKSIZE;
            retdata->data = s_malloc(BLKSIZE);
            memcpy(retdata->data, blk->blockdata, BLKSIZE);
        } else {
			//didn't get the block of same block number
			//so this previous block number should be flushed
			//then the record in block cache will be deleted
            inobno.inode = inode;
            inobno.blocknr = blk->blocknr;
            if (NULL != config->blockdatabs) {
                db_commit_block(blk->blockdata, inobno, blk->offset);
            } else {
                file_commit_block(blk->blockdata, inobno, blk->offset);
            }
			//delete the found block in cache
            mdelete_key(blkcache, &inode, sizeof(unsigned long long));
        }
        DBTfree(data);
    }
    return retdata;
}

unsigned long long try_blocknr_cache(unsigned long long inode)
{
	DBT *data;
	BLKCACHE *blk;
	INOBNO inobno;
	unsigned long long blocknr;

	data = search_memhash(blkcache, &inode, sizeof(unsigned long long));
	if (data != NULL) {
		blk = (BLKCACHE *) data->data;
		blocknr = blk->blocknr;
		inobno.inode = inode;
		inobno.blocknr = blocknr;
        if (NULL != config->blockdatabs) {
            db_commit_block(blk->blockdata, inobno, blk->offset);
        } else {
            file_commit_block(blk->blockdata, inobno, blk->offset);
        }
		mdelete_key(blkcache, &inode, sizeof(unsigned long long));
		DBTfree(data);
		return blocknr + 1;
	}
	return 0;
}

/*
 * 
 * 
 * 
 */
void db_update_block(const char *blockdata, unsigned long long blocknr,
                     		unsigned int offsetblock,  unsigned long long size, 
                     		unsigned long long inode,  unsigned char *chksum, 
                     		off_t offset)
{
    DBT *data;
    DBT *cachedata;
    unsigned char *dbdata;
    INOBNO inobno;
    compr *uncompdata;
    BLKCACHE *blk;
    unsigned char *dtiger=NULL;
    unsigned long long inuse;
#ifdef ENABLE_CRYPTO
    DBT *encrypted;
#endif
#ifndef SHA3
    word64 res[3];
#endif

    FUNC;
    LDEBUG("%s: inode=%llu, blocknr=%llu, offsetblock=%d, size=%llu", __FUNCTION__, inode, 
		blocknr, offsetblock, size);
    inobno.inode = inode;
    inobno.blocknr = blocknr;

    dbdata = s_malloc(BLKSIZE);
    memset(dbdata, 0, BLKSIZE);
    data = try_block_cache(inode, blocknr, 0);
    if (NULL != data) {
        memcpy(dbdata, data->data, data->size);
        memcpy(dbdata + offsetblock, blockdata, size);
        add_blk_to_cache(inode, blocknr, dbdata, offset);
        update_filesize(inode, size, offsetblock, blocknr, 0, 0, 0);
        free(dbdata);
        DBTfree(data);
        return;
    } else
        LDEBUG("update_block: block not found in cache.");

	// We don't need the old blockdata when we overwrite it completely anyway.
	// size < BLKSIZE means that this is a small block which needs to be stored into blkcache
    if (offsetblock > 0 || size < BLKSIZE) {
        get_moddb_lock();
		//try to find the existing block in dtaq and dta.
        data = search_memhash(dbdtaq, chksum, config->hashlen);
        if (NULL == data) {
            LDEBUG("updateBlock : Not in dbdtaq");
#ifdef ENABLE_CRYPTO
			//get encrypted data
            encrypted = search_dbdata(dbdta, chksum, config->hashlen);
            if (NULL == encrypted) {
#else
            data = search_dbdata(dbdta, chksum, config->hashlen);
            if (NULL == data) {
#endif
                LDEBUG("updateBlock : Not in dbdta");
                cachedata =
                    search_memhash(blkcache, &inobno.inode,
                                   sizeof(unsigned long long));
                if (NULL != cachedata) {
                    blk = (BLKCACHE *) cachedata->data;
#ifdef SHA3
                    dtiger=sha_binhash(blk->blockdata, BLKSIZE);
#else
                    binhash(blk->blockdata, BLKSIZE, res);
                    dtiger=(unsigned char *)&res;
#endif
                    if (0 == memcmp(dtiger, chksum, config->hashlen)) {
                        data = s_malloc(sizeof(DBT));
                        data->data = s_malloc(BLKSIZE);
                        data->size = BLKSIZE;
                        memcpy(data->data, blk->blockdata, BLKSIZE);
                        DBTfree(cachedata);
                    } else {
                        LDEBUG("updateBlock : Not in dbcache, out of luck.");
                        loghash("updateBlock : No data found to read ",  chksum);
                        die_dataerr
                            ("No data found to read, this should never happen: inode :%llu: blocknr :%llu",
                             inode, blocknr);
                    }
#ifdef SHA3
                    free(dtiger);
#endif
                } else {
                    loghash("updateBlock : No data found to read ",
                            chksum);
                    die_dataerr
                        ("No data found to read, this should never happen: inode :%llu: blocknr :%llu",
                         inode, blocknr);
                }
#ifndef ENABLE_CRYPTO
            }
#else
            } else {
                if (config->encryptdata) {
                    data = decrypt(encrypted);
                    DBTfree(encrypted);
                } else
                    data = encrypted;
            }
#endif
        }
        release_moddb_lock();
        if (data->size < BLKSIZE) {	//this means the data block is compressed
#ifdef LZO
            uncompdata = lzo_decompress(data->data, data->size);
#else
            LDEBUG("uncomp data");
            uncompdata = clz_decompress(data->data, data->size);
            LDEBUG("done uncomp data");
#endif
            LDEBUG("got uncompsize : %lu", uncompdata->size);
            memcpy(dbdata, uncompdata->data, uncompdata->size);
            comprfree(uncompdata);
        } else {
            LDEBUG("Got data->size %lu", data->size);
            memcpy(dbdata, data->data, data->size);
        }
        DBTfree(data);
    }
	//if offset block > 0, this is appending.
    memcpy(dbdata + offsetblock, blockdata, size);
    add_blk_to_cache(inode, blocknr, dbdata, offset);
    inuse = getInUse(chksum);
    if (inuse <= 1) {
        delete_inuse(chksum);
        delete_data_cache_or_db(chksum, inode);
    } else {
        inuse--;
        update_inuse(chksum, inuse);
    }
    update_filesize(inode, size, offsetblock, blocknr, 0, 0, 0);
    free(dbdata);
    EFUNC;
    return;
}

/*
 * 
 * 
 * 
 */
int btdelete_curkey(TCBDB * db, void *key, int keylen, void *kvalue,
                    int kvallen)
{
    BDBCUR *cur;
    char *value;
    int vsize;
    int ksize;
    char *dbkey;
    int ret = 1;

    FUNC;
    cur = tcbdbcurnew(db);
    if (!tcbdbcurjump(cur, key, keylen)) {
        tcbdbcurdel(cur);
        return (-ENOENT);
    }
    /* traverse records */
    while ((dbkey = tcbdbcurkey(cur, &ksize)) != NULL) {
        if (0 != memcmp(dbkey, key, ksize)) {
            free(dbkey);
            break;
        }
        value = tcbdbcurval(cur, &vsize);
        if (value) {
            if (kvallen == vsize) {
                if (0 == memcmp(value, kvalue, kvallen)) {
                    ret = 0;
                    if (!tcbdbcurout(cur)) {
                        die_dataerr
                            ("Failed to delete key, this should never happen!");
                        ret = -ENOENT;
                    }
                    free(value);
                    free(dbkey);
                    break;
                }
            }
            free(value);
        }
        free(dbkey);
        tcbdbcurnext(cur);
    }
    tcbdbcurdel(cur);
    return (ret);
}

/*
 * 
 * 
 * 
 */
void *btsearch_keyval(TCBDB * db, void *key, int keylen, void *val,
                      int vallen)
{
    BDBCUR *cur;
    char *dbkey;
    char *dbvalue;
    void *ret = NULL;
    int size;

    FUNC;
    cur = tcbdbcurnew(db);
    if (!tcbdbcurjump(cur, key, keylen) && tcbdbecode(db) != TCESUCCESS) {
        tcbdbcurdel(cur);
        return ret;
    }
    /* traverse records */
    while ((dbkey = tcbdbcurkey(cur, &size)) != NULL) {
        if (0 != memcmp(dbkey, key, keylen)) {
            free(dbkey);
            break;
        }
        dbvalue = tcbdbcurval(cur, &size);
        if (NULL != dbvalue) {
            if (NULL != val) {
                if (vallen == size) {
                    if (0 == memcmp(val, dbvalue, size)) {
                        ret = s_malloc(size + 1);
                        memset(ret, 0, size + 1);
                        memcpy(ret, dbvalue, size);
                        free(dbvalue);
                        free(dbkey);
                        break;
                    }
                }
            } else {
                ret = s_malloc(size + 1);
                memset(ret, 0, size + 1);
                memcpy(ret, dbvalue, size);
                free(dbvalue);
                free(dbkey);
                break;
            }
            free(dbvalue);
        }
        free(dbkey);
        tcbdbcurnext(cur);
    }
    tcbdbcurdel(cur);
    EFUNC;
    return ret;
}

/* 
 * count the hard link of which the key is dinoino, this shows how many hard links of an inode is in
 * one dir. Return 0, 1 or 2 if more then 2 we stop counting 
 */
int count_dirlinks(void *linkstr, int len)
{
    BDBCUR *cur;
    char *key;
    int size;
    int count = 0;

    cur = tcbdbcurnew(dbl);
    if (!tcbdbcurjump(cur, linkstr, len)
        && tcbdbecode(dbdirent) != TCESUCCESS) {
        tcbdbcurdel(cur);
        return (-ENOENT);
    }
    /* traverse records */
    while ((key = tcbdbcurkey(cur, &size)) != NULL) {
        if (len == size) {
            if (0 == memcmp(key, linkstr, len)) {
                count++;
            }
        }
        free(key);
        tcbdbcurnext(cur);
        if ( count > 1 ) break;
    }
    tcbdbcurdel(cur);
    return (count);
}

/*
 * 
 * 
 * 
 */
void delete_key(TCHDB * db, void *keydata, int len)
{
    int ecode;

    if (!tchdbout(db, keydata, len)) {
        ecode = tchdbecode(db);
        die_dataerr("Delete of key failed :%s", tchdberrmsg(ecode));
    }
}

/*
 * 
 * 
 * 
 */
void mdelete_key(TCMDB * db, void *keydata, int len)
{
    //FUNC;
    tcmdbout(db, keydata, len);
    //EFUNC;
}

/*
 * 
 * 
 * 
 */
void ndelete_key(TCNDB * db, void *keydata, int len)
{
    //FUNC;
    tcndbout(db, keydata, len);
    //EFUNC;
}

/*
 * 
 * 
 * 
 */
DBT *check_block_exists(INOBNO inobno)
{
    DBT *data = NULL;
    DBT *cachedata = NULL;
    BLKCACHE *blk;
	OFFHASH *offhash;
#ifdef SHA3
    BitSequence *hashval;
#else
    word64 res[3];
#endif

    FUNC;
    LDEBUG("%s: inode=%llu, blocknr=%llu", __FUNCTION__, inobno.inode, 
		inobno.blocknr);
    get_dbb_lock();
    data = search_memhash(dbbm, &inobno, sizeof(INOBNO));
    if ( NULL == data ) {
       data = search_dbdata(dbb, &inobno, sizeof(INOBNO));
    }
    release_dbb_lock();
    if (NULL == data) {
        cachedata = search_memhash(blkcache, &inobno.inode,
			sizeof(unsigned long long));
        if (cachedata != NULL) {
            blk = (BLKCACHE *) cachedata->data;
            if ((inobno.blocknr == blk->blocknr)) {
				offhash = s_malloc(sizeof(OFFHASH));
				offhash->offset = blk->offset;
#ifdef SHA3
                memcpy(offhash->stiger, sha_binhash(blk->blockdata, BLKSIZE), 
                	config->hashlen);
#else
                binhash(blk->blockdata, BLKSIZE, res);
                memcpy(offhash->stiger,&res,config->hashlen);
#endif
                data = offhash_to_ddbuf(offhash);
				free(offhash);
				offhash = NULL;
            } else {
                LDEBUG("check_block_exists : %llu-%llu not found",
                       inobno.inode, inobno.blocknr);
            }
            DBTfree(cachedata);
        } else {
            LDEBUG("check_block_exists : %llu-%llu not found",
                   inobno.inode, inobno.blocknr);
            return NULL;
        }
    }
    return data;
}

/*
 * 
 * 
 * 
 */
void wait_io_pending(unsigned long long inode)
{
    int c;

    FUNC;
  iowait:
    get_global_lock();
    for (c = 0; c < max_threads; c++) {
        if (0 == tdta[c]->inode)
            continue;
        if (tdta[c]->inode == inode) {
            release_global_lock();
            goto iowait;
        }
    }
    EFUNC;
    return;
}

/*
 * 
 * 
 * 
 */
void wait_inode_block_pending(unsigned long long inode,
                              unsigned long long blocknr)
{
    int c;

    FUNC;
  iobp:
    get_global_lock();
    for (c = 0; c < max_threads; c++) {
        if (0 == tdta[c]->inode)
            continue;
        if (tdta[c]->inode == inode) {
            if (tdta[c]->blocknr == blocknr) {
                release_global_lock();
                LDEBUG("wait_inode_block_pending : loop");
                goto iobp;
            }
        }
    }
    EFUNC;
    return;
}

/*
 * 
 * 
 * 
 */
int inode_block_pending(unsigned long long inode,
                        unsigned long long blocknr)
{
    int c;
    int pending = 0;

    FUNC;
    for (c = 0; c < max_threads; c++) {
        if (0 == tdta[c]->inode)
            continue;
        if (tdta[c]->inode == inode) {
            if (tdta[c]->blocknr == blocknr)
                pending = 1;
            break;
        }
    }
    EFUNC;
    return (pending);
}

/*
 * 
 * 
 * 
 */
int db_unlink_file(const char *path)
{
    int res = 0;
    int haslinks = 0;
    int dir_links = 0;
    struct stat st;
    struct stat dirst;
    char *dname;
    char *bname;
    unsigned char *stiger;
    unsigned long long inode;
    unsigned long long counter = 0;
    unsigned long long inuse;
    unsigned long long done = 0;
    time_t thetime;
    void *vdirnode;
    DBT *bdata;
    DBT *ddbuf;
    DBT *dataptr;
    DDSTAT *ddstat;
    DINOINO dinoino;
    INOBNO inobno;
    char *filename;

    FUNC;

	/* st is the stat of the file to be unlinked,
	 * inode refers to the file to be unlinked,
	 * haslinks refers to the nlinks of the inode,
	 * dirst refers to the dir inode of the file to be unlinked
	 */
    LDEBUG("unlink_file %s", path);
    res = dbstat(path, &st);
    if (res == -ENOENT)
        return (res);
    inode = st.st_ino;
    haslinks = st.st_nlink;
    thetime = time(NULL);
    dname = s_dirname((char *) path);
    /* Change ctime and mtime of the parentdir Posix std posix behavior */
    res = update_parent_time(dname,0);
    bname = s_basename((char *) path);
    res = dbstat(dname, &dirst);
	
    LDEBUG("%s: path=%s, inode=%llu, has %d links, dir inode is %llu, size=%llu", 
		__FUNCTION__, path, inode, haslinks, dirst.st_ino, st.st_size);
	
    if (S_ISLNK(st.st_mode) && haslinks == 1) {
        LDEBUG("unlink symlink %s inode %llu", path, inode);
        delete_key(dbs, &inode, sizeof(unsigned long long));
        LDEBUG("unlink symlink done %s", path);
    }

	// this is not hard link, reduce the reference of the blocks
	// and delete dbb, dbp, dbdirent data entry
	if (haslinks == 1)
	{
	    inobno.inode = inode;
	    inobno.blocknr = counter;

	    while (done < st.st_size) {
			//search for dbb entry
	        get_dbb_lock();
	        bdata = search_memhash(dbbm, &inobno, sizeof(INOBNO));
	        if ( NULL == bdata ) {
				bdata = search_dbdata(dbb, &inobno, sizeof(INOBNO));
	        }
	        release_dbb_lock();
			//sparse block
	        if (bdata == NULL) {
	            LDEBUG("%llu is sparse", counter);
	            done = done + BLKSIZE;
	            counter++;
	            inobno.blocknr = counter;
	            continue;
	        }
			//get the hash of the inode-blocknr
	        stiger = s_malloc(bdata->size);
	        memcpy(stiger, bdata->data, bdata->size);
	        loghash("search inuse for ", stiger);
	        inuse = getInUse(stiger);
	        LDEBUG("inuse=%llu", inuse);
			//delete dbu entry
			//not hard link
	        if (inuse == 1) {
	            loghash("unlink_file delete dbu,dbdta for ", stiger);
	            delete_inuse(stiger);
	            delete_key(dbdta, stiger, config->hashlen);
	        } else {
	            if (inuse > 1)
	                inuse--;
	            loghash("update_inuse dbu,dbdta for ", stiger);
	            update_inuse(stiger, inuse);
	        }
	        free(stiger);
	        DBTfree(bdata);
			//delete dbb entry
			//not hard link
	        LDEBUG("unlink_file : delete inode %llu - %llu", inobno.inode,
					inobno.blocknr);
	        delete_dbb(&inobno);
	        counter++;
	        inobno.blocknr = counter;
	        done = done + BLKSIZE;
	    }
        if (0 !=
            (res = btdelete_curkey(dbdirent, 
             				&dirst.st_ino, sizeof(unsigned long long), 
             				&inode, sizeof(unsigned long long)))) {
            free(bname);
            free(dname);
            return (res);
        }
        delete_key(dbp, (unsigned char *) &inode, sizeof(unsigned long long));
	}
	else {
		//update dbp of the inode(reduce nlinks and change time),
		//and delete the hard link info of the inode in dbl
        dataptr = search_dbdata(dbp, 
            				(unsigned char *) &inode, sizeof(unsigned long long));
        if (dataptr == NULL) {
            die_dataerr("Failed to find file %llu", inode);
        }
        ddstat = value_to_ddstat(dataptr);
        ddstat->stbuf.st_nlink--;
        ddstat->stbuf.st_ctim.tv_sec = thetime;
        ddstat->stbuf.st_ctim.tv_nsec=0;
        ddstat->stbuf.st_mtim.tv_sec = thetime;
        ddstat->stbuf.st_mtim.tv_nsec=0;
        dinoino.dirnode = dirst.st_ino;
        dinoino.inode = ddstat->stbuf.st_ino;
        dir_links = count_dirlinks(&dinoino, sizeof(DINOINO));
		//delete dbl entry
        res = btdelete_curkey(dbl, 
        					&dinoino, sizeof(DINOINO), 
        					bname, strlen(bname));
        btdelete_curkey(dbl, 
					&ddstat->stbuf.st_ino, sizeof(unsigned long long), 
					&dinoino, sizeof(DINOINO));
		
		// the last hard link of the inode is unlinked, 
		// Restore to regular file settings and clean up.
        if (ddstat->stbuf.st_nlink == 1) {
            vdirnode = btsearch_keyval(dbl, 
								&ddstat->stbuf.st_ino, sizeof(unsigned long long), 
								NULL, 0);
            memcpy(&dinoino, vdirnode, sizeof(DINOINO));
            free(vdirnode);
            filename = (char *) btsearch_keyval(dbl, 
												&dinoino, sizeof(DINOINO),
                                         		NULL, 0);
            memcpy(&ddstat->filename, filename, strlen(filename) + 1);
            free(filename);
            LDEBUG("unlink_file: Restore %s to regular file settings and clean up.",
                 ddstat->filename);
            btdelete_curkey(dbl, 
							&dinoino, sizeof(DINOINO), 
							ddstat->filename, strlen(ddstat->filename));
            btdelete_curkey(dbl, 
							&ddstat->stbuf.st_ino, sizeof(unsigned long long), 
							&dinoino, sizeof(DINOINO));
            res = 0;
        }
        if (dir_links == 1) {
            if (0 != 
				(res = btdelete_curkey(dbdirent, 
										&dirst.st_ino, sizeof(unsigned long long), 
										&inode, sizeof(unsigned long long)))) {
                die_dataerr("unlink_file : Failed to delete record.");
            }
        }
		// if the file has no hard link, the filename is not NULL
        ddbuf = create_ddbuf(ddstat->stbuf, ddstat->filename);
        bin_write_dbdata(dbp, &inode, sizeof(unsigned long long), 
						(void *) ddbuf->data, ddbuf->size);
        DBTfree(dataptr);
        DBTfree(ddbuf);
        ddstatfree(ddstat);
    }
    free(bname);
    free(dname);
    EFUNC;
    return (res);
}

/*
 * create a directory, including the current dir, the sub /. dir and the sub /.. dir
 * and update parent metadata
 *
 */
int fs_mkdir(const char *path, mode_t mode)
{
    unsigned long long inode;
    char *rdir;
    char *pdir;
    int rootdir = 0;
    int res;

    FUNC;
    LDEBUG("%s: path=%s, mode=%i", __FUNCTION__, path, mode);
    if (0 == strcmp("/", path))
        rootdir = 1;
    inode = get_next_inode();
    write_file_ent(path, inode, S_IFDIR | mode, NULL, 0);
    if (rootdir) {
        rdir = as_sprintf("%s.", path);
    } else {
        rdir = as_sprintf("%s/.", path);
    }
    inode = get_next_inode();
    write_file_ent(rdir, inode, S_IFDIR | 0755, NULL, 0);
    free(rdir);
    if (rootdir) {
        rdir = as_sprintf("%s..", path);
    } else {
        rdir = as_sprintf("%s/..", path);
    }
    inode = get_next_inode();
    write_file_ent(rdir, inode, S_IFDIR | 0755, NULL, 0);
    free(rdir);
    /* Change ctime and mtime of the parentdir Posix std posix behavior */
    pdir = s_dirname((char *) path);
    res = update_parent_time(pdir,1);
    free(pdir);
    return (res);
}

/*
 * get the untruncated data from the last block and form a new one
 * delete the old block
 */
void partial_truncate_block(struct stat *stbuf, unsigned long long blocknr,
                            unsigned int offset)
{
    unsigned char *blockdata;
    compr *uncompdata;
    INOBNO inobno;
    DBT *data;
    DBT *encrypted;
	OFFHASH *offhash;
    unsigned char *stiger;
    unsigned long long inuse;
	off_t offsetfile;


    FUNC;
    LDEBUG("%s: %llu-%llu, offset=%d", __FUNCTION__, stbuf->st_ino, blocknr, offset);
    inobno.inode = stbuf->st_ino;
    inobno.blocknr = blocknr;
    get_dbb_lock();
    data = search_memhash(dbbm, &inobno, sizeof(INOBNO));
    if ( NULL == data ) {
       data = search_dbdata(dbb, &inobno, sizeof(INOBNO));
    }
    release_dbb_lock();
    if (NULL == data) {
        LDEBUG("Deletion of non existent block.");
        return;
    }
	offhash = (OFFHASH *) data->data;
    stiger = s_malloc(data->size);
    memcpy(stiger, offhash->stiger, config->hashlen);
	offsetfile = offhash->offset;
    DBTfree(data);
    data = search_memhash(dbdtaq, stiger, config->hashlen);
    if ( NULL == data ) {
#ifdef ENABLE_CRYPTO
    if (config->encryptdata){
      encrypted=search_dbdata(dbdta, stiger, config->hashlen);
      data = decrypt(encrypted);
      DBTfree(encrypted);
    } else data = search_dbdata(dbdta, stiger, config->hashlen);
#else
       data = search_dbdata(dbdta, stiger, config->hashlen);
#endif
    }
    if ( NULL == data ) {
        die_dataerr("Hmmm, did not expect this to happen.");
    }
    inuse = getInUse(stiger);
    if (inuse == 1) {
        loghash("partial_truncate_block : delete hash", stiger);
        delete_inuse(stiger);
        delete_data_cache_or_db(stiger,inobno.inode);
    } else {
        if (inuse > 1)
            inuse--;
        update_inuse(stiger, inuse);
    }
    delete_dbb(&inobno);
    blockdata = s_malloc(BLKSIZE);
    memset(blockdata, 0, BLKSIZE);
    if (data->size != BLKSIZE) {
#ifdef LZO
        uncompdata = lzo_decompress(data->data, data->size);
#else
        uncompdata = clz_decompress(data->data, data->size);
#endif
        memcpy(blockdata, uncompdata->data, offset);
        comprfree(uncompdata);
    } else {
        memcpy(blockdata, data->data, offset);
    }
    db_commit_block(blockdata, inobno, offsetfile);
    free(stiger);
    DBTfree(data);
    free(blockdata);
    return;
}

/*
 * if the new size is bigger, just change the size of meta data
 * else the extra data block should be deleted
 */
int db_fs_truncate(struct stat *stbuf, off_t size, char *bname)
{
    unsigned int offsetblock;
    unsigned long long blocknr;
	unsigned long long inode;
    unsigned long long lastblocknr;
    unsigned long long inuse;
    unsigned char *stiger;
    off_t oldsize;
    DBT *data;
	OFFHASH *offhash, *oldoffhash;
    INOBNO inobno;
    time_t thetime;

    FUNC;
    LDEBUG("%s: filename=%s, from %llu to %llu", __FUNCTION__, bname, 
		stbuf->st_size, size);
    thetime = time(NULL);
	inode = stbuf->st_ino;
    if (-1 == (blocknr = get_blocknr(inode, (off_t)size - 1)))
		die_dataerr("%s: get blocknr failed.", __FUNCTION__);
	if (NULL == (offhash = get_offhash(inode, blocknr)))
		die_dataerr("%s: offhash of %llu-%llu not found.", __FUNCTION__, inode, 
			blocknr);
	
    offsetblock = size - offhash->offset;
    oldsize = stbuf->st_size;
    if (-1 == (lastblocknr = get_blocknr(inode, (off_t)oldsize - 1)))
		die_dataerr("%s: get blocknr failed.", __FUNCTION__);
    
    // Truncate filesize.
    update_filesize_cache(stbuf, size);
    LDEBUG("lessfs_truncate : truncate new block %llu, oldblock %llu",
           blocknr, lastblocknr);
    while (lastblocknr >= blocknr) {
        if ( offsetblock != 0 && lastblocknr == blocknr ) break;
        LDEBUG
            ("lessfs_truncate : Enter loop lastblocknr %llu : blocknr %llu",
             lastblocknr, blocknr);
        inobno.inode = stbuf->st_ino;
        inobno.blocknr = lastblocknr;
        get_dbb_lock();
        data = search_memhash(dbbm, &inobno, sizeof(INOBNO));
        if ( NULL == data ) {
           data = search_dbdata(dbb, &inobno, sizeof(INOBNO));
        }
        release_dbb_lock();
        if (NULL == data) {
            LDEBUG
                ("Deletion of non existent block inode : %llu, blocknr %llu",
                 inobno.inode, inobno.blocknr);
            if (lastblocknr > 0)
                lastblocknr--;
            else
                break;
// Need to continue in case of a sparse file.
            continue;
        }
		offhash = (OFFHASH *) data->data;
        stiger = s_malloc(data->size);
        memcpy(stiger, offhash->stiger, config->hashlen);
        LDEBUG("lessfs_truncate Search to delete blocknr %llu:", lastblocknr);
        loghash("lessfs_truncate tiger :", stiger);
        DBTfree(data);
        inuse = getInUse(stiger);
        if (inuse == 1) {
            sync_flush_dtaq();
            loghash("truncate : delete hash", stiger);
            delete_data_cache_or_db(stiger,inobno.inode);
            delete_inuse(stiger);
        } else {
            if (inuse > 1)
                inuse--;
            update_inuse(stiger, inuse);
        }
        delete_dbb(&inobno);
        if (lastblocknr > 0)
            lastblocknr--;
        free(stiger);
    }
    LDEBUG("offsetblock = %u", offsetblock);
    if (0 != offsetblock)
        partial_truncate_block(stbuf, lastblocknr, offsetblock);
    return (0);
}

/*
 * move data from dbdtaq to dbdta, and delete the data in dbdtaq.
 * if the encrypt data switch is on, the data will be encrypted before written to dbdta
 * this is used in tc backend
 */
void db_sync_flush_dtaq()
{
    unsigned char *kdata;
    unsigned char *vdata;
    int ksize;
    int vsize;
#ifdef ENABLE_CRYPTO
    DBT *encrypted;
#endif

    /* traverse records */
    tcmdbiterinit(dbdtaq);
    while ((kdata = tcmdbiternext(dbdtaq, &ksize)) != NULL) {
        get_moddb_lock();
        vdata = tcmdbget(dbdtaq, kdata, ksize, &vsize);
        if (NULL == vdata) {
            LDEBUG("sync_flush_dtaq : no more value for key");
            release_moddb_lock();
            continue;
        }
        loghash("sync_flush_dtaq : flush to disk", kdata);
#ifdef ENABLE_CRYPTO
        if (config->encryptdata) {
            encrypted = encrypt(vdata, vsize);
            bin_write_dbdata(dbdta, kdata, ksize,
                             encrypted->data, encrypted->size);
            DBTfree(encrypted);
        } else {
            bin_write_dbdata(dbdta, kdata, ksize, vdata, vsize);
        }
#else
        bin_write_dbdata(dbdta, kdata, ksize, vdata, vsize);
#endif
        mdelete_key(dbdtaq, kdata, ksize);
        release_moddb_lock();
        free(kdata);
        free(vdata);
    }
    LDEBUG("sync_flush_dtaq : released qempty lock");
    return;
}

/*
 * flush the data in dbum to dbu, and clear dbum
 */
int sync_flush_dbu()
{
    unsigned char *kdata;
    unsigned char *vdata;
    int ksize;
    int vsize;
    int ret=0;

    FUNC;

    tcmdbiterinit(dbum);
    while ((kdata = tcmdbiternext(dbum, &ksize)) != NULL) {
        get_dbu_lock();
           vdata = tcmdbget(dbum, kdata, ksize, &vsize);
           if (NULL == vdata) {
               release_dbu_lock();
               continue;
           }
           bin_write_dbdata(dbu, kdata, ksize, vdata, vsize);
           mdelete_key(dbum, kdata, ksize);
           dbu_qcount--;
        release_dbu_lock();
        ret=1;
        free(kdata);
        free(vdata);
    }
    EFUNC;
    return(ret);
}

/*
 * flush the data in dbum to dbu, and clear dbum
 */
int sync_flush_dbc()
{
    unsigned char *kdata;
    unsigned char *vdata;
    int ksize;
    int vsize;
    int ret=0;

    FUNC;

    tcmdbiterinit(dbcm);
    while ((kdata = tcmdbiternext(dbcm, &ksize)) != NULL) {
        get_dbc_lock();
           vdata = tcmdbget(dbcm, kdata, ksize, &vsize);
           if (NULL == vdata) {
               release_dbc_lock();
               continue;
           }
           bin_write_dbdata(dbc, kdata, ksize, vdata, vsize);
           mdelete_key(dbcm, kdata, ksize);
           dbc_qcount--;
        release_dbc_lock();
        ret=1;
        free(kdata);
        free(vdata);
    }
    EFUNC;
    return(ret);
}

/*
 * flush the data in dbbm to dbb, and clear dbbm
 */
int sync_flush_dbb()
{
    unsigned char *kdata;
    unsigned char *vdata;
    int ksize;
    int vsize;
    int ret=0;

    FUNC;
    tcmdbiterinit(dbbm);
    while ((kdata = tcmdbiternext(dbbm, &ksize)) != NULL) {
        get_dbb_lock();
           vdata = tcmdbget(dbbm, kdata, ksize, &vsize);
           if (NULL == vdata) {
               release_dbb_lock();
               continue;
           }
           bin_write_dbdata(dbb, kdata, ksize, vdata, vsize);
           mdelete_key(dbbm, kdata, ksize);
           dbb_qcount--;
        release_dbb_lock();
        ret=1;
        free(kdata);
        free(vdata);
    }
    EFUNC;
    return(ret);
}

/*
 * flush data from dbdtaq to dbdta
 */
void sync_flush_dtaq()
{
    if (NULL != config->blockdatabs) {
        db_sync_flush_dtaq();
    } else {
        file_sync_flush_dtaq();
    }
    return;
}

/*
 * update the ctime and mtime and number of links of the inode
 */
int update_parent_time(char *path, int linkcount)
{
    int res;
    struct stat stbuf;
    time_t thetime;

    FUNC;
    LDEBUG("%s: path=%s", __FUNCTION__, path);
    thetime = time(NULL);
    /* Change ctime and mtime of the parentdir Posix std posix behavior */
    res = dbstat(path, &stbuf);
    if (0 != res)
        return (res);
    stbuf.st_ctim.tv_sec = thetime;
    stbuf.st_ctim.tv_nsec=0;
    stbuf.st_mtim.tv_sec = thetime;
    stbuf.st_mtim.tv_nsec=0;
    stbuf.st_nlink=stbuf.st_nlink+linkcount;
    res = update_stat(path, &stbuf);
    EFUNC;
    return (res);
}

/*
 * 
 * 
 * 
 */
int fs_rmdir(const char *path)
{
    int res;
    char *dotstr;
    char *dotdotstr;
    char *dname;
    unsigned long long dirnode;
    unsigned long long keynode;
    unsigned long long pathnode;
    unsigned long long dirnodes;

    FUNC;
    LDEBUG("%s: path=%s", __FUNCTION__, path);

    pathnode = get_inode(path);
    dirnodes = has_nodes(pathnode);
    if (0 != dirnodes) {
        LDEBUG("fs_rmdir : Cannot remove directory %s with %llu files",
               path, dirnodes);
        EFUNC;
        return -ENOTEMPTY;
    }

    dname = s_dirname((char *) path);
    dotstr = as_sprintf("%s/.", path);
    dotdotstr = as_sprintf("%s/..", path);

    keynode = get_inode(dotstr);
    LDEBUG("inode for %s is %llu", dotstr, keynode);
    delete_key(dbp, &keynode, sizeof(unsigned long long));
    btdelete_curkey(dbdirent, &pathnode, sizeof(unsigned long long),
                    &keynode, sizeof(unsigned long long));

    keynode = get_inode(dotdotstr);
    delete_key(dbp, &keynode, sizeof(unsigned long long));
    btdelete_curkey(dbdirent, &pathnode, sizeof(unsigned long long),
                    &keynode, sizeof(unsigned long long));

    dirnode = get_inode(dname);
    delete_key(dbp, &pathnode, sizeof(unsigned long long));
    btdelete_curkey(dbdirent, &dirnode, sizeof(unsigned long long),
                    &pathnode, sizeof(unsigned long long));
    btdelete_curkey(dbdirent, &pathnode, sizeof(unsigned long long),
                    &pathnode, sizeof(unsigned long long));
    free(dotstr);
    free(dotdotstr);
    res = update_parent_time(dname,-1);
    free(dname);
    return (res);
}

/*
 * find and return the inode information of a file or dir
 */
unsigned long long get_inode(const char *path)
{
    struct stat stbuf;

    FUNC;
    LDEBUG("%s: path=%s", __FUNCTION__, path);
    if (0 != dbstat(path, &stbuf)) {
        LDEBUG("get_inode : nothing found for %s", path);
        return (0);
    }
    EFUNC;
    return (stbuf.st_ino);
}

/*
 * find and return the blocknr 
 */
unsigned long long get_blocknr(unsigned long long inode, off_t offset)
{
	unsigned long long blocknr;
	DBT *data;
	OFFHASH *offhash;
	INOBNO inobno;

	blocknr = 0;
	inobno.inode = inode;
	inobno.blocknr = blocknr;
	while(1){
		if (offset == 0)
			return blocknr;
		data = check_block_exists(inobno);
		if (NULL == data){
			if (offhash->offset + BLKSIZE <= offset)
				return blocknr;
			else return --blocknr;
		}
		free(offhash);
		offhash = buf_to_offhash(data);
		if (offhash->offset == offset)
			return blocknr;
		if (offhash->offset > offset)
			return --blocknr;
		blocknr++;
		inobno.blocknr = blocknr;
		DBTfree(data);
		data = NULL;
	}
}

/*
 * find and return the blocknr 
 */
OFFHASH *get_offhash(unsigned long long inode, unsigned long long blocknr)
{
	DBT *data;
	INOBNO inobno;

	inobno.inode = inode;
	inobno.blocknr = blocknr;
	if (NULL != (data = check_block_exists(inobno)))
		return buf_to_offhash(data);
	return NULL;
}

/*
 * Return 0 when the directory is empty, 1 when it contains files
 * search for the sub entry of one dir and return 1 when meet non dot dirs
 */
unsigned long long has_nodes(unsigned long long inode)
{
    unsigned long long res = 0;
    BDBCUR *cur;
    unsigned long long filenode;
    char *filenodestr;
    DBT *filedata;
    bool dotdir = 0;
    char *key;
    DDSTAT *ddstat;
    int size;
    unsigned long long keyval;

    FUNC;
    cur = tcbdbcurnew(dbdirent);
    if (!tcbdbcurjump(cur, &inode, sizeof(unsigned long long))
        && tcbdbecode(dbdirent) != TCESUCCESS) {
        tcbdbcurdel(cur);
        return (-ENOENT);
    }
    while ((key = tcbdbcurkey(cur, &size)) != NULL) {
        memcpy(&keyval, key, sizeof(unsigned long long));
        if (keyval != inode) {
            free(key);
            break;
        }
        filenodestr = (char *) tcbdbcurval(cur, &size);
        memcpy(&filenode, filenodestr, sizeof(unsigned long long));
        filedata =
            search_dbdata(dbp, &filenode, sizeof(unsigned long long));
        if (NULL != filedata) {
            ddstat = value_to_ddstat(filedata);
            DBTfree(filedata);
            LDEBUG("Compare : %llu %llu", filenode, inode);
            if (filenode == inode)
                dotdir = 1;
            if (NULL != ddstat->filename) {
                if (0 == strcmp(ddstat->filename, "."))
                    dotdir = 1;
                if (0 == strcmp(ddstat->filename, ".."))
                    dotdir = 1;
            }
			//the dir has node which is not dor dir. res increases
            if (!dotdir) {
                LDEBUG
                    ("has_nodes : Found file in directory %s filenode %llu inode %llu",
                     ddstat->filename, filenode, inode);
                res++;
            }
            ddstatfree(ddstat);
        }
        free(key);
        free(filenodestr);
        dotdir = 0;
        if ( 0 != res ) break;
        tcbdbcurnext(cur);
    }
    tcbdbcurdel(cur);
    LDEBUG("inode %llu contains files", inode);
    EFUNC;
    return (res);
}

/*
 * get the dest of the hard link and fill it into buf
 */
void fs_read_hardlink(struct stat stbuf, DDSTAT * ddstat, void *buf,
                      fuse_fill_dir_t filler, struct fuse_file_info *fi)
{
    BDBCUR *cur;
    char *linkkey;
    int ksize;
    DINOINO dinoino;
    char *filename;

    FUNC;
    cur = tcbdbcurnew(dbl);
	//get dir inode and entry inode
    dinoino.dirnode = stbuf.st_ino;
    dinoino.inode = ddstat->stbuf.st_ino;
    if (!tcbdbcurjump(cur, &dinoino, sizeof(DINOINO))
        && tcbdbecode(dbl) != TCESUCCESS)
        die_dataerr("Unable to find linkname, run fsck.");
	//
    while ((linkkey = tcbdbcurkey(cur, &ksize)) != NULL) {
        if (0 != memcmp(linkkey, &dinoino, sizeof(DINOINO))) {
            LDEBUG("fs_read_hardlink : linkkey != dinoino");
            free(linkkey);
            break;
        }
		//get the dest of the dirinoino link
        filename = (char *) tcbdbcurval(cur, &ksize);
        memcpy(&ddstat->filename, filename, strlen(filename) + 1);
        free(filename);
        LDEBUG("fs_read_hardlink : fil_fuse_info %s size %i",
               ddstat->filename, ksize);
		//fill the dest of this link to the fuse buf
        fil_fuse_info(ddstat, buf, filler, fi);
        ddstat->filename[0] = 0;
        free(linkkey);
        tcbdbcurnext(cur);
    }
    tcbdbcurdel(cur);
    EFUNC;
    return;
}


/*
 * append to the buf of fuse using the entry name, to get the info of the parent dir
 */
void fil_fuse_info(DDSTAT * ddstat, void *buf, fuse_fill_dir_t filler,
                   struct fuse_file_info *fi)
{
    struct stat st;
    char *bname;

    memcpy(&st, &ddstat->stbuf, sizeof(struct stat));
    bname = s_basename(ddstat->filename);
    if (NULL != bname) {
        // Don't show the directory
        if (0 != strcmp(bname, "/")) {
            LDEBUG("Fill filler with %s", bname);
			//fill the buf with the basename
            filler(buf, bname, &st, 0);
        }
    }
    free(bname);
}

/*
 * 
 * 
 * 
 */
int fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
               off_t offset, struct fuse_file_info *fi)
{
    int retcode = 0;
    BDBCUR *cur;
    int size, res;
    int ksize;
    char *key;
    struct stat stbuf;
    unsigned long long keynode;
    unsigned long long filenode;
    char *filenodestr;
    DBT *filedata;
    DDSTAT *ddstat;
    FUNC;

    (void) offset;
    (void) fi;
    LDEBUG("Called fs_readdir with path %s", (char *) path);

    res = dbstat(path, &stbuf);
    if (0 != res)
        return -ENOENT;
	//locate the inode of the dir
    cur = tcbdbcurnew(dbdirent);
    if (!tcbdbcurjump(cur, &stbuf.st_ino, sizeof(unsigned long long))
        && tcbdbecode(dbdirent) != TCESUCCESS) {
        tcbdbcurdel(cur);
        return (-ENOENT);
    }
	//search for the entries of the dbdirent until the dir inode is different
    while ((key = tcbdbcurkey(cur, &ksize)) != NULL) {
        memcpy(&keynode, key, sizeof(unsigned long long));
        if (stbuf.st_ino != keynode) {
            free(key);
            break;
        }
		//get one entry of the dir
        filenodestr = tcbdbcurval(cur, &size);
        memcpy(&filenode, filenodestr, sizeof(unsigned long long));
		//when the entry inode is same with the dir inode, continue to next
        if (filenode == keynode) {
            free(filenodestr);
            free(key);
            tcbdbcurnext(cur);
            continue;
        }
		//get the file info of this entry
        LDEBUG("GOT filenode %llu", filenode);
        filedata = search_dbdata(dbp, &filenode, sizeof(unsigned long long));
        if (NULL != filedata) {
			//get file stat
            ddstat = value_to_ddstat(filedata);
            DBTfree(filedata);
			//about the hard link
            if (ddstat->filename[0] == 0) {
                fs_read_hardlink(stbuf, ddstat, buf, filler, fi);
            } else {
                fil_fuse_info(ddstat, buf, filler, fi);
            }
            ddstatfree(ddstat);
        }
        free(key);
        free(filenodestr);
        tcbdbcurnext(cur);
    }
    tcbdbcurdel(cur);
    LDEBUG("fs_readdir: return");
    return (retcode);
}

/*
 * when the inode became a link destination, 
 * the file name of the inode will be deleted, and be stored in dbl
 */
int fs_link(char *from, char *to)
{
    int res = 0;
    unsigned long long inode;
    unsigned long long todirnode;
    unsigned long long fromdirnode;
    struct stat stbuf;
    struct stat tobuf;
    struct stat frombuf;
    char *bfrom;
    char *bto;
    char *todir;
    char *fromdir;
    DBT *ddbuf;
    DBT *symdata;
    time_t thetime;
    DINOINO dinoino;
    DBT *data;
    MEMDDSTAT *memddstat;

    FUNC;
    LDEBUG("%s: from=%s, to=%s", __FUNCTION__, from , to);
    res = dbstat(from, &stbuf);

    if (res != 0)
        return (res);
	//get the stat of the from dir and to dir
    fromdir = s_dirname(from);
    res = dbstat(fromdir, &frombuf);
    todir = s_dirname(to);
    res = dbstat(todir, &tobuf);
    if (res != 0) {
        free(todir);
        free(fromdir);
        return -ENOENT;
    }
    bfrom = s_basename(from);
    bto = s_basename(to);

/* Update inode nrlinks */
	//get the inode of from dir and to dir
    todirnode = tobuf.st_ino;
    fromdirnode = frombuf.st_ino;
	//get the inode of the from file
    inode = stbuf.st_ino;
    // Update nr of links. stbuf refers to the from inode stat
    stbuf.st_nlink++;
    thetime = time(NULL);

/* from dir is the dir of the from inode, to dir is the dir of the to node*/

    data = search_memhash(dbcache, &stbuf.st_ino,
                          sizeof(unsigned long long));
    if (NULL != data) {
        memddstat = (MEMDDSTAT *) data->data;
        memddstat->stbuf.st_ctim.tv_sec = thetime;
        memddstat->stbuf.st_ctim.tv_nsec=0;
        memddstat->stbuf.st_mtim.tv_sec = thetime;
        memddstat->stbuf.st_mtim.tv_nsec=0;
        memddstat->stbuf.st_nlink++;
        memddstat->updated = 1;
        //memset(&memddstat->filename,0,2);
        ddbuf = create_mem_ddbuf(memddstat);
        mbin_write_dbdata(dbcache, &stbuf.st_ino,
                          sizeof(unsigned long long), (void *) ddbuf->data,
                          ddbuf->size);
        DBTfree(ddbuf);
        DBTfree(data);
    } 
    stbuf.st_ctim.tv_sec = thetime;
    stbuf.st_ctim.tv_nsec=0;
	//here NULL deleted the filename of the inode
    ddbuf = create_ddbuf(stbuf, NULL);
    LDEBUG("fs_link : update links on %llu to %i", inode, stbuf.st_nlink);
    bin_write_dbdata(dbp, &inode, sizeof(unsigned long long),
                     ddbuf->data, ddbuf->size);
    DBTfree(ddbuf);
/* Link dest filename inode to dest directory if it does not exist*/
    if (0 ==
        bt_entry_exists(dbdirent, &todirnode, sizeof(unsigned long long),
                        &inode, sizeof(unsigned long long))) {
        LDEBUG("fs_link : write link %llu : %llu", todirnode, inode);
        btbin_write_dup(dbdirent, &todirnode, sizeof(unsigned long long),
                        &inode, sizeof(unsigned long long));
    }

/* Link some more, hardlink a symlink. */
    if (S_ISLNK(stbuf.st_mode)) {
        LDEBUG("fs_link : hardlink a symlink");
        symdata = search_dbdata(dbs, &inode, sizeof(unsigned long long));
        if (NULL == symdata)
            die_dataerr("Unable to read symlink");
        DBTfree(symdata);
    }
	//dinoino is set: destdir inode - sourcefile inode
	//this is for the search in destdir for dest filename
    dinoino.dirnode = tobuf.st_ino;
    dinoino.inode = stbuf.st_ino;
    LDEBUG("A. fs_link : write link %llu-%llu : %s", tobuf.st_ino,
           stbuf.st_ino, bto);
    btbin_write_dup(dbl, &dinoino, sizeof(DINOINO), bto, strlen(bto));
    btbin_write_dup(dbl, &stbuf.st_ino, sizeof(unsigned long long),
                    &dinoino, sizeof(DINOINO));

	//dinoino is set: sourcedir inode - sourcefile inode
	//this is for the search in sourcedir for source filename
	//only the first time link will this part run
    dinoino.dirnode = frombuf.st_ino;
    dinoino.inode = stbuf.st_ino;
    if (stbuf.st_nlink == 2) {
        btbin_write_dup(dbl, &dinoino, sizeof(DINOINO), bfrom, strlen(bfrom));
        btbin_write_dup(dbl, &stbuf.st_ino, sizeof(unsigned long long),
                        &dinoino, sizeof(DINOINO));
    }
    res = update_parent_time(todir,0);
    free(todir);
    free(fromdir);
    free(bfrom);
    free(bto);
    EFUNC;
    return (res);
}

/*
 * 
 * 
 * 
 */
int bt_entry_exists(TCBDB * db, void *parent, int parentlen, void *value,
                    int vallen)
{
    int res = 0;
    BDBCUR *cur;
    char *dbvalue;
    char *key;
    int ksize;

    FUNC;
    cur = tcbdbcurnew(dbdirent);
    if (!tcbdbcurjump(cur, parent, parentlen)
        && tcbdbecode(db) != TCESUCCESS) {
        tcbdbcurdel(cur);
        return (res);
    }
    while ((key = tcbdbcurkey(cur, &ksize)) != NULL) {
        if (ksize != parentlen) {
            free(key);
            break;
        }
        if (0 != memcmp(key, parent, parentlen)) {
            free(key);
            break;
        }
        dbvalue = tcbdbcurval2(cur);
        if (dbvalue) {
            if (0 == memcmp(value, dbvalue, vallen))
                res = 1;
            free(dbvalue);
        }
        free(key);
        tcbdbcurnext(cur);
        if ( res == 1 ) break;
    }
    tcbdbcurdel(cur);
    LDEBUG("bt_entry_exists : returns %i", res);
    EFUNC;
    return (res);
}

/*
 * 
 * 
 * 
 */
int fs_symlink(char *from, char *to)
{
    int res = 0;
    char *todir;

    todir = s_dirname(to);
    dbmknod(to, 0777 | S_IFLNK, from, 0);
    res = update_parent_time(todir,0);
    free(todir);
    return (res);
}

/*
 * 
 * 
 * 
 */
int fs_readlink(const char *path, char *buf, size_t size)
{
    int res = 0;
    DBT *data;
    unsigned long long inode;

    FUNC;
    LDEBUG("%s: path=%s, size=%llu", __FUNCTION__, path, (unsigned long long)size);
    inode = get_inode(path);
    if (0 == inode)
        return (-ENOENT);

    data = search_dbdata(dbs, &inode, sizeof(unsigned long long));
    if (NULL == data) {
        res = -ENOENT;
    } else {
        if (size - 1 > data->size) {
            memcpy(buf, data->data, data->size + 1);
        } else {
            memcpy(buf, data->data, size - 1);
        }
        DBTfree(data);
    }
    return (res);
}

/*
 * delete the original link and create a new one with the new file name
 * 
 * 
 */
int fs_rename_link(const char *from, const char *to, struct stat stbuf)
{
    unsigned long long fromnode;
    unsigned long long tonode;
    unsigned long long inode;
    char *fromdir;
    char *todir;
    char *bfrom;
    char *bto;
    struct stat st;
    int res = 0;
    DINOINO dinoino;

    FUNC;
	//stbuf refers to the from inode
    LDEBUG("%s: from=%s, to=%s", __FUNCTION__, from , to);
    if (0 == strcmp(from, to))
        return (0);
    if (-ENOENT != dbstat(to, &st)) {
    	LDEBUG("%s: to inode exist as inode %llu, delete it", __FUNCTION__, 
			st.st_ino);
        if (NULL != config->blockdatabs) {
            db_unlink_file(to);
        } else {
            file_unlink_file(to);
        }
    }
    fromdir = s_dirname((char *) from);
    todir = s_dirname((char *) to);
    bfrom = s_basename((char *) from);
    bto = s_basename((char *) to);
	//inode refers to from inode
    inode = stbuf.st_ino;

    fromnode = get_inode(fromdir);
    tonode = get_inode(todir);
    if (0 == fromnode)
        die_dataerr("Unable to find directory %s for file %s", fromdir,
                    from);
    if (0 == tonode)
        die_dataerr("Unable to find directory %s for file %s", todir, to);

	if (fromnode == tonode)
	{
		dinoino.dirnode = fromnode;
		dinoino.inode = stbuf.st_ino;
	    btdelete_curkey(dbl, &dinoino, sizeof(DINOINO), bfrom, strlen(bfrom));
	    btbin_write_dup(dbl, &dinoino, sizeof(DINOINO), bto, strlen(bto));
	}
	else{
		//delete the hard link in from_dir, 
	    dinoino.dirnode = fromnode;
	    dinoino.inode = stbuf.st_ino;
		btdelete_curkey(dbl, &inode, sizeof(unsigned long long), &dinoino, 
			sizeof(DINOINO));
	    btdelete_curkey(dbl, &dinoino, sizeof(DINOINO), bfrom, strlen(bfrom));
	    if (count_dirlinks(&dinoino, sizeof(DINOINO)) < 1) {
	        btdelete_curkey(dbdirent, &fromnode, sizeof(unsigned long long),
	                        &inode, sizeof(unsigned long long));
	    }
	    dinoino.dirnode = tonode;
	    dinoino.inode = stbuf.st_ino;
	    btbin_write_dup(dbl, &inode, sizeof(unsigned long long), &dinoino, 
			sizeof(DINOINO));
	    btbin_write_dup(dbl, &dinoino, sizeof(DINOINO), bto, strlen(bto));
	    if (count_dirlinks(&dinoino, sizeof(DINOINO)) < 1) {
	        btbin_write_dup(dbdirent, &tonode, sizeof(unsigned long long),
	                    &inode, sizeof(unsigned long long));
	    }
	}
    free(fromdir);
    free(bfrom);
    free(bto);
    free(todir);
    EFUNC;
    return (res);
}

/*
 * 
 * 
 * 
 */
void update_cache(unsigned long long inode, struct stat *stbuf)
{
    DBT *dataptr;
    MEMDDSTAT *memddstat;
    DBT *ddbuf;

    FUNC;
    LDEBUG("%s: inode=%llu", __FUNCTION__, inode);
    dataptr = search_memhash(dbcache, &inode, sizeof(unsigned long long));
    if (dataptr == NULL) {
        return;
    }
    memddstat = (MEMDDSTAT *) dataptr->data;
    memcpy(&memddstat->stbuf, &stbuf, sizeof(struct stat));
    ddbuf = create_mem_ddbuf(memddstat);
    memddstat->updated = 0;
    mbin_write_dbdata(dbcache, &inode, sizeof(unsigned long long),
                      (void *) ddbuf->data, ddbuf->size);
    DBTfree(ddbuf);
    hash_update_filesize(memddstat, inode);
    DBTfree(dataptr);
    EFUNC;
    return;
}

/*
 * 
 * 
 * 
 */
int fs_rename(const char *from, const char *to, struct stat stbuf)
{
    DBT *dataptr;
    DDSTAT *ddstat;
    DBT *ddbuf;
    int res = 0;
    unsigned long long inode;
    time_t thetime;
    char *bto;
    char *bfrom;
    char *fromdir;
    char *todir;
    unsigned long long fromdirnode;
    unsigned long long todirnode;
    unsigned long long tonode;
    struct stat st;
    unsigned long long dirnodes;

    FUNC;
    
    LDEBUG("%s: from=%s, to=%s", __FUNCTION__, from , to);
    todir = s_dirname((char *) to);
    todirnode = get_inode(todir);
    tonode = get_inode(to);
    bto = s_basename((char *) to);
    bfrom = s_basename((char *) from);

	//to node exists
    if (-ENOENT != dbstat(to, &st)) {
		//to node is dir, rm the dir if it is empty, and do nothing if it is not
        if (S_ISDIR(st.st_mode)) {
            LDEBUG("fs_rename bto %s bfrom %s", bto, bfrom);
            dirnodes = has_nodes(tonode);
            if (0 != dirnodes) {
                if (0 != strcmp(bto, bfrom)) {
                    LDEBUG
                        ("fs_rename : Cannot rename directory %llu with %llu files",
                         todirnode, dirnodes);
                    free(todir);
                    free(bfrom);
                    free(bto);
                    EFUNC;
                    return -ENOTEMPTY;
                }
				else
				{
					LDEBUG("%s: from dir is same as to dir, nothing to do");
					return 0;
				}
            }
            fs_rmdir(to);
        } else {
        	//to node is file or link, unlink the file
            LDEBUG("fs_rename : destination file %s exists, unlink_file.",
                   to);
            if (NULL != config->blockdatabs) {
                db_unlink_file(to);
            } else {
                file_unlink_file(to);
            }
        }
    }
    free(bfrom);

	//inode refers to the from inode
    inode = stbuf.st_ino;
    fromdir = s_dirname((char *) from);
    fromdirnode = get_inode(fromdir);
    LDEBUG("fs_rename : bto = %s", bto);
    dataptr = search_dbdata(dbp, &inode, sizeof(unsigned long long));
    if (dataptr == NULL) {
        die_dataerr("Failed to find file %llu", inode);
    }
    ddstat = value_to_ddstat(dataptr);
    thetime = time(NULL);
    ddstat->stbuf.st_ctim.tv_sec = thetime;
    ddstat->stbuf.st_ctim.tv_nsec=0;
    ddbuf = create_ddbuf(ddstat->stbuf, (char *) bto);
    bin_write_dbdata(dbp, &inode,
                     sizeof(unsigned long long), (void *) ddbuf->data,
                     ddbuf->size);
    if (fromdirnode != todirnode) {
        LDEBUG("fs_rename : rename inode %llu : %llu to another path %llu",
               inode, fromdirnode, todirnode);
        btdelete_curkey(dbdirent, &fromdirnode, sizeof(unsigned long long),
                        &inode, sizeof(unsigned long long));
        btbin_write_dup(dbdirent, &todirnode, sizeof(unsigned long long),
                        &inode, sizeof(unsigned long long));
    }
    DBTfree(dataptr);
    DBTfree(ddbuf);
    ddstatfree(ddstat);
    free(bto);
    free(fromdir);
    free(todir);
    EFUNC;
    return (res);
}

/*
 * find the stat of file, update the stat, and write it again
 */
int update_stat(char *path, struct stat *stbuf)
{
    DDSTAT *ddstat;
    DBT *ddbuf;
    DBT *dataptr;
    unsigned long long inode;

    FUNC;
    LDEBUG("%s: path=%s", __FUNCTION__, path);
    inode = stbuf->st_ino;
    dataptr = search_dbdata(dbp, &inode, sizeof(unsigned long long));
    if (dataptr == NULL) {
        return (-ENOENT);
    }
    ddstat = value_to_ddstat(dataptr);
    memcpy(&ddstat->stbuf, stbuf, sizeof(struct stat));
    ddbuf = create_ddbuf(ddstat->stbuf, ddstat->filename);
    bin_write_dbdata(dbp, &inode,
                     sizeof(unsigned long long), (void *) ddbuf->data,
                     ddbuf->size);
    DBTfree(dataptr);
    DBTfree(ddbuf);
    ddstatfree(ddstat);
    EFUNC;
    return (0);
}

/*
 * 
 * 
 * 
 */
void parseconfig(int mklessfs)
{
    char *cache, *flushtime;
    unsigned int cs = 0;
    unsigned long calc;
#ifdef ENABLE_CRYPTO
    unsigned long long pwl = 0;
    unsigned char *stiger;

#ifndef SHA3
    word64 res[3];
#endif

    DBT *ivdb;
    CRYPTO *crypto;

#endif
    char *iv;
    char *dbpath;
    struct stat stbuf;

    FUNC;
    LDEBUG("%s: mklessfs=%d", __FUNCTION__, mklessfs);
    config = s_malloc(sizeof(struct configdata));
    // BLOCKDATA_IO_TYPE tokyocabinet (default), file_io
    config->blockdata = read_val("BLOCKDATA_PATH");
    iv = getenv("BLOCKDATA_IO_TYPE");
    if (NULL == iv) {
        config->blockdata_io_type = "tokyocabinet";
        config->blockdatabs = read_val("BLOCKDATA_BS");
        LINFO("The selected data store is tokyocabinet.");
    } else {
        if (0 == strncasecmp(iv, "file_io", strlen("file_io"))) {
            config->blockdata_io_type = "file_io";
            config->blockdatabs = NULL;
            config->freelist = read_val("FREELIST_PATH");
            config->freelistbs = read_val("FREELIST_BS");
            LINFO("The selected data store is file_io.");
        } else
            config->blockdatabs = read_val("BLOCKDATA_BS");
    }
    config->blockusage = read_val("BLOCKUSAGE_PATH");
    config->blockusagebs = read_val("BLOCKUSAGE_BS");
	config->checksumusage = read_val("CHECKSUMUSAGE_PATH");
	config->checksumusagebs = read_val("CHECKSUMUSAGE_BS");
    config->dirent = read_val("DIRENT_PATH");
    config->direntbs = read_val("DIRENT_BS");
    config->fileblock = read_val("FILEBLOCK_PATH");
    config->fileblockbs = read_val("FILEBLOCK_BS");
    config->meta = read_val("META_PATH");
    config->metabs = read_val("META_BS");
    config->hardlink = read_val("HARDLINK_PATH");
    config->hardlinkbs = read_val("HARDLINK_BS");
    config->symlink = read_val("SYMLINK_PATH");
    config->symlinkbs = read_val("SYMLINK_BS");
    config->encryptdata = 0;
    config->encryptmeta = 1;
    config->hashlen = 24;
    iv = getenv("HASHLEN");
    if (NULL != iv ) {
       if ( atoi(iv) >= 20 && atoi(iv) <= 32 ) {
           config->hashlen=atoi(iv);
       } else {
           LFATAL("The hash length is invalid.");
           exit(EXIT_USAGE);
       }
    }
    LINFO("Lessfs uses a %i bytes long hash.", config->hashlen);
    iv = getenv("SYNC_RELAX");
    if (NULL == iv) {
        config->relax = 0;
    } else {
        config->relax = atoi(iv);
        if (0 != config->relax) {
            LINFO
                ("Lessfs fsync does not sync the databases to the disk when fsync is called on an inode");
        }
    }
    iv = getenv("INSPECT_DISK_INTERVAL");
    if (NULL == iv) {
        config->inspectdiskinterval = 1;
    } else {
        config->inspectdiskinterval = atoi(iv);
    }
    iv = getenv("DYNAMIC_DEFRAGMENTATION");
    config->defrag = 0;
    if (NULL != iv) {
        if (0 == strcasecmp("on", iv)) {
            config->defrag = 1;
        }
    }
    if (config->defrag)
        LINFO("Automatic defragmentation is enabled.");
    cache = read_val("CACHESIZE");
    if (NULL != cache)
        cs = atoi(cache);
    if (cs <= 0)
        cs = 1;
    calc=cs;
    config->cachesize = (calc * 1024 * 1024) / MAX_FUSE_BLKSIZE;
    flushtime = read_val("COMMIT_INTERVAL");
    cs = atoi(flushtime);
    if (cs <= 0)
        cs = 30;
    config->flushtime = cs;
    LINFO("cache %u data blocks", config->cachesize);

#ifdef SHA3
    LINFO("The Blue Midnight Wish hash has been selected.");
#else
    LINFO("The tiger hash has been selected.");
#endif
    if (mklessfs == 1) {
        dbpath = as_sprintf("%s/fileblock.tch", config->fileblock);
        if (-1 != stat(dbpath, &stbuf)) {
            fprintf(stderr,
                    "Data %s already exists, please remove it and try again\n",
                    dbpath);
            exit(EXIT_DATAERR);
        }
    }
    if (mklessfs == 2 ) {
        drop_databases();
        if (NULL == dbp)
           tc_open(0,1);
    } else {
        if (NULL == dbp)
           tc_open(0,0);
    }
    if (mklessfs == 0) {
#ifdef ENABLE_CRYPTO
        iv = read_val("ENCRYPT_DATA");
        if (NULL != iv) {
            if (0 == strcasecmp(iv, "ON")) {
                config->encryptdata = 1;
                iv = getenv("ENCRYPT_META");
                LINFO("Data encryption is on");
                if (NULL != iv) {
                    if (0 != strcasecmp(iv, "ON")) {
                        LINFO("Metadata encryption is off");
                        config->encryptmeta = 0;
                    }
                }
            }
        }
        if (config->encryptdata) {
            if (config->encryptdata) {
                if (NULL == config->blockdatabs) {
                    fprintf(stderr,"Encryption is not supported with file_io\n");
                    die_dataerr
                        ("Encryption is not supported with file_io");
                }
            }
            if ( NULL == getenv("PASSWORD")){
               config->passwd =
                   (unsigned char *) s_strdup(getpass("Password: "));
            } else config->passwd = s_strdup(getenv("PASSWORD"));
            unsetenv("PASSWORD"); /* Eat it after receiving..*/
#ifdef SHA3
            stiger=sha_binhash(config->passwd, strlen((char *) config->passwd));
#else
            binhash(config->passwd, strlen((char *) config->passwd), res);
            stiger=(unsigned char *)&res;
#endif
            ivdb = search_dbdata(dbp, &pwl, sizeof(unsigned long long));
            if (NULL == ivdb) {
                tc_close(0);
                die_dataerr
                    ("The filesystem has not been formatted with encryption support.");
            }
            config->iv = s_malloc(8);
            crypto = (CRYPTO *) ivdb->data;
            memcpy(config->iv, crypto->iv, 8);
            //config->passwd is plain, crypto->passwd is hashed.
            checkpasswd(crypto->passwd);
#ifdef SHA3
            free(stiger);
#endif
            DBTfree(ivdb);
        }
#endif
        if (0 == get_next_inode())
            die_dataerr
                ("Please format lessfs with mklessfs before mounting!");
    }
    return;
}

#ifdef ENABLE_CRYPTO
/*
 * if the crypto switch is on, compare the hashed passwd and the stored passwd,
 * if match, continue, if not, exit program
 */
void checkpasswd(char *cryptopasswd)
{
    unsigned char *stiger;
#ifndef SHA3
    word64 res[3];
#endif

    FUNC;
    LDEBUG("%s: passwd=%s", __FUNCTION__, cryptopasswd);
#ifdef SHA3
    stiger=sha_binhash(config->passwd, strlen((char *) config->passwd));
#else
    binhash(config->passwd, strlen((char *) config->passwd),res);
    stiger=(unsigned char *)&res;
#endif
    if (0 != memcmp(cryptopasswd, stiger, config->hashlen)) {
        sleep(5);
        fprintf(stderr, "Invalid password entered.\n");
        exit(EXIT_PASSWD);
    }
#ifdef SHA3
    free(stiger);
#endif
    EFUNC;
    return;
}
#endif

/*
 * when mounted, the mark "LESSFS_DIRTY" will be written to dbu in func mark_dirty
 * now clear the mark of dirty in dbu, this indicates the file system is not mounted
 */
void clear_dirty()
{
    unsigned char *stiger;
    char *brand;
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
    tchdbout(dbu,stiger,config->hashlen);
#ifdef SHA3
    free(stiger);
#endif
    free(brand);
    return;
}

/*
 * check dbu for the entry with key "LESSFS_BLOCKSIZE", if it does not exist, 
 * write the current blocksize to dbu
 * the value(inuse info) is the blocksize that this filesystem uses
 * 
 */
int get_blocksize()
{
    unsigned char *stiger;
    char *brand;
    INUSE *finuse;
    int blksize=4096;
    unsigned long long inuse;
#ifndef SHA3
    word64 res[3];
#endif

    brand=as_sprintf("LESSFS_BLOCKSIZE");
#ifdef SHA3
    stiger=sha_binhash((unsigned char *)brand, strlen(brand));
#else
    binhash((unsigned char *)brand, strlen(brand), res);
    stiger=(unsigned char *)&res;
#endif
    if ( config->blockdatabs != NULL ) {
    	inuse=getInUse(stiger);
	  	LDEBUG("%s: stiger=%s, inuse=%llu", __FUNCTION__, stiger, inuse);
      	if ( 0 == inuse ) {
         	brand_blocksize();
		 	LINFO("%s: BLKSIZE = %d", __FUNCTION__, BLKSIZE);
         	blksize=BLKSIZE;
      	} else {
         	blksize=inuse;
      	}
    } else {
      	finuse=file_get_inuse(stiger);
      	if ( NULL == finuse ) {
         	brand_blocksize();
         	blksize=BLKSIZE;
      	} else {
         	blksize=finuse->inuse;
      	}
    }
#ifdef SHA3
    free(stiger);
#endif
    free(brand);
    return(blksize);
}

/*
 * Add the hash for string LESSFS_BLOCKSIZE to lessfs so that we know the blocksize for
 * lessfsck and when someone is foolish enough to remount with a different blocksize
 */
void brand_blocksize()
{
    unsigned char *stiger;
    char *brand;
    INUSE inuse;
#ifndef SHA3
    word64 res[3];
#endif

    brand=as_sprintf("LESSFS_BLOCKSIZE");
#ifdef SHA3
    stiger=sha_binhash((unsigned char *)brand, strlen(brand));
#else
    binhash((unsigned char *)brand, strlen(brand), res);
    stiger=(unsigned char *)&res;
#endif
    if ( config->blockdatabs != NULL ) {
        update_inuse(stiger,BLKSIZE);
    } else {
        inuse.inuse=BLKSIZE;
        inuse.size=0;
        inuse.offset=0;
        file_update_inuse(stiger,&inuse);
    }
#ifdef SHA3
    free(stiger);
#endif
    free(brand);
    return;
}

/*
 * delete all database files
 */
void drop_databases()
{
   char *dbpath;
   struct stat stbuf;
   
   dbpath = as_sprintf("%s/fileblock.tch", config->fileblock);
   if (-1 != stat(dbpath, &stbuf) ) unlink(dbpath);
   free(dbpath);
   dbpath = as_sprintf("%s/blockusage.tch", config->blockusage);
   if (-1 != stat(dbpath, &stbuf) ) unlink(dbpath);
   free(dbpath);
   dbpath = as_sprintf("%s/metadata.tcb", config->meta);
   if (-1 != stat(dbpath, &stbuf) ) unlink(dbpath);
   free(dbpath);
   dbpath = as_sprintf("%s/symlink.tch", config->symlink);
   if (-1 != stat(dbpath, &stbuf) ) unlink(dbpath);
   free(dbpath);
   dbpath = as_sprintf("%s/dirent.tcb", config->dirent);
   if (-1 != stat(dbpath, &stbuf) ) unlink(dbpath);
   free(dbpath);
   dbpath = as_sprintf("%s/hardlink.tcb", config->hardlink);
   if (-1 != stat(dbpath, &stbuf) ) unlink(dbpath);
   free(dbpath);
   if (NULL != config->blockdatabs) {
      dbpath = as_sprintf("%s/blockdata.tch", config->blockdata);
      if (-1 != stat(dbpath, &stbuf) ) unlink(dbpath);
      free(dbpath);
   } else {
      dbpath = as_sprintf("%s/freelist.tcb", config->freelist);
      if (-1 != stat(dbpath, &stbuf) ) unlink(dbpath);
      free(dbpath);
      unlink(config->blockdata);
   }
}
