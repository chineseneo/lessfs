prefix=@prefix@
exec_prefix=@exec_prefix@
libdir=@libdir@
includedir=@includedir@

ARCH := $(shell uname -m)
LIBS=$(CRYPTO_LIBS) $(DEPS_LIBS) $(LZO_LIBS)
bin_PROGRAMS=lessfs
sbin_PROGRAMS=mklessfs defrag_lessfs listdb lessfsck test
man1_MANS=lessfs.1
lessfs_SOURCES=lib_lzo.c lessfs.c lib_sboxes.c lib_tiger.c lib_BMW.c lib_crypto.c lib_safe.c lib_tc.c file_io.c lib_cfg.c lib_str.c lib_net.c lib_qlz.c lib_log.h
lessfs_CFLAGS=-D__USE_LARGEFILE64 -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -DOPTIMIZE_FOR_ALPHA -D${ARCH} -D SYSLOG
mklessfs_SOURCES=lib_lzo.c file_io.c mklessfs.c lib_sboxes.c lib_BMW.c lib_crypto.c lib_tiger.c lib_safe.c lib_tc.c lib_cfg.c lib_str.c lib_net.c lib_qlz.c
mklessfs_CFLAGS=-D__USE_LARGEFILE64 -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -DOPTIMIZE_FOR_ALPHA -D${ARCH} -D SYSLOG
defrag_lessfs_SOURCES=lib_lzo.c file_io.c defrag_lessfs.c lib_crypto.c lib_BMW.c lib_sboxes.c lib_tiger.c lib_safe.c lib_tc.c lib_cfg.c lib_str.c lib_net.c lib_qlz.c
defrag_lessfs_CFLAGS=-D__USE_LARGEFILE64 -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -DOPTIMIZE_FOR_ALPHA -D${ARCH}
listdb_SOURCES=lib_lzo.c file_io.c listdb.c lib_sboxes.c lib_crypto.c lib_tiger.c lib_BMW.c lib_safe.c lib_tc.c lib_cfg.c lib_str.c lib_net.c lib_qlz.c
listdb_CFLAGS=-D__USE_LARGEFILE64 -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -DOPTIMIZE_FOR_ALPHA -D${ARCH}
lessfsck_SOURCES=lib_lzo.c file_io.c lessfsck.c lib_sboxes.c lib_crypto.c lib_tiger.c lib_BMW.c lib_safe.c lib_tc.c lib_cfg.c lib_str.c lib_net.c lib_qlz.c
lessfsck_CFLAGS=-D__USE_LARGEFILE64 -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -DOPTIMIZE_FOR_ALPHA -D${ARCH}
test_SOURCES=lib_lzo.c file_io.c test.c lib_sboxes.c lib_crypto.c lib_tiger.c lib_BMW.c lib_safe.c lib_tc.c lib_cfg.c lib_str.c lib_net.c lib_qlz.c
test_CFLAGS=-D__USE_LARGEFILE64 -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -DOPTIMIZE_FOR_ALPHA -D${ARCH}

Name: lessfs
Description: lessfs a data deduplicating filesystem
Version: @VERSION@

pkgconfigdir = @pkgconfigdir@
$(pkgconfig_DATA): config.status
