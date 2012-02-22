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
