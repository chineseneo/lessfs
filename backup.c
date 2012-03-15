#include <Python.h>
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
#include <sys/param.h>
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

#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include "lessfs.c"

#ifdef i386
#define ITERATIONS 30
#else
#define ITERATIONS 500
#endif
#define BTHREADS 100

PyObject* wrap_OpenDB(PyObject* self, PyObject* args) 
{
	int result;
	char *confPath;

	if (! PyArg_ParseTuple(args, "s", &confPath))
		return NULL;
	result = OpenDB(confPath);
	return Py_BuildValue("i", result);
}

PyObject* wrap_CloseDB(PyObject* self, PyObject* args) 
{
	int result;

	if (! PyArg_ParseTuple(args, ""))
		return NULL;
	result = CloseDB();
	return Py_BuildValue("i", result);
}

PyObject* wrap_BackUp(PyObject* self, PyObject* args) 
{
	int result;
	char *content, *filename;
	long filesize;

	if (! PyArg_ParseTuple(args, "ssl", &content, &filename, &filesize))
		return NULL;
	result = BackUp(content, filename, filesize);
	return Py_BuildValue("i", result);
}

PyObject* wrap_ShowFiles(PyObject* self, PyObject* args) 
{
	int result;
	char *path;
	FILEINFO *buf = (FILEINFO *)s_malloc(sizeof(FILEINFO));
	buf->filename = NULL;
	buf->date = NULL;
	buf->next = NULL;

	if (! PyArg_ParseTuple(args, "s", &path))
		return NULL;
	result = ShowFiles(buf, path);
	buf = ((FILEINFO *)buf)->next;
	PyObject* dict = PyDict_New();
	while(buf != NULL)
	{
		PyDict_SetItem(dict, PyString_FromString(buf->filename), 
			PyString_FromString(buf->date));
		buf = buf->next;
	}

	return dict;
}

PyObject* wrap_ReadFile(PyObject* self, PyObject* args) 
{
	char *path, *buf;
	unsigned long long size;

	if (! PyArg_ParseTuple(args, "s", &path))
		return NULL;
	buf = ReadFile(&size, path);
	return Py_BuildValue("s", buf);
}


static PyMethodDef BackUpMethods[] = {
    {"BackUp",  wrap_BackUp, METH_VARARGS,
     "Backup the file"},
    {"OpenDB",  wrap_OpenDB, METH_VARARGS,
     "Open the database"},
    {"CloseDB",  wrap_CloseDB, METH_VARARGS,
     "Close the database"},
    {"ShowFiles",  wrap_ShowFiles, METH_VARARGS,
     "show the file under one dir"},
    {"ReadFile",  wrap_ReadFile, METH_VARARGS,
     "read the content of one file"},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

PyMODINIT_FUNC initbackup(void)
{
    (void) Py_InitModule("backup", BackUpMethods);
}


int OpenDB(char *confPath)
{
    LINFO("%s", __FUNCTION__);
	if (-1 == r_env_cfg(confPath))
		return -1;
	parseconfig(0);
	lessfs_init();
	return 0;
}

int CloseDB()
{
    LINFO("%s", __FUNCTION__);
	lessfs_destroy(NULL);
	return 0;
}

int BackUpWrite(char *content, char *path, long filesize)
{
	struct fuse_file_info * fi;
	
	fi = malloc(sizeof(struct fuse_file_info));
	fi->fh=get_inode(path);
	lessfs_open(path, fi);
    lessfs_write(NULL, content, filesize, 0, fi);
	lessfs_release(path, fi);
	return 0;
}

int BackUpMeta(char *path)
{
	lessfs_mknod(path, 0755 | S_IFREG, 0);
	return 0;
}

int BackUp(char *content, char *filename, long filesize)
{
	char *path = (char *)malloc(strlen(filename) + 1);
	strcpy(path, "/");
	strcpy(path + 1, filename);
	if (0 != BackUpMeta(path))
		return -1;
	if (0 != BackUpWrite(content, path, filesize))
		return -1;
	return 0;
}

int FillDir(void *buf, const char *name, const struct stat *stbuf, off_t off)
{
	FILEINFO *tail;
	char *date = ctime(&stbuf->st_ctime);
	FILEINFO *file = (FILEINFO *)s_malloc(sizeof(FILEINFO));
	file->filename = (char *)s_malloc(strlen(name));
	strcpy(file->filename, name);
	file->date = (char *)s_malloc(strlen(date));
	strcpy(file->date, date);
	file->next = NULL;
	tail = (FILEINFO *)buf;
	while (tail->next != NULL)
	{
		tail = tail->next;
	}
	tail->next = file;
	
	return 0;
}

int ShowFiles(FILEINFO *buf, char *path)
{
	lessfs_readdir(path, (void *)buf, FillDir, 0, NULL);
	return 0;
}

char *ReadFile(unsigned long long *size, char *path)
{
	struct fuse_file_info * fi;
	struct stat stbuf;
	char *buf;
	
	fi = malloc(sizeof(struct fuse_file_info));
	fi->fh = get_inode(path);
	if(fi->fh == 0)
		return NULL;
	lessfs_open(path, fi);
	if(get_realsize_fromcache(fi->fh, &stbuf) == 0)
		return NULL;
	*size = stbuf.st_size;
	printf("%s: filesize is %llu", __FUNCTION__, *size);
	buf = (char *)s_malloc(*size);
    lessfs_read(path, buf, *size, 0, fi);
	printf("%s: bufsize is %d", __FUNCTION__, strlen(buf));
	lessfs_release(path, fi);
	return buf;
}

