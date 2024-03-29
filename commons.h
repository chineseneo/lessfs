extern pthread_spinlock_t moddb_spinlock;
extern pthread_spinlock_t dbu_spinlock;
extern pthread_spinlock_t dbc_spinlock;
extern pthread_spinlock_t dbr_spinlock;
extern pthread_spinlock_t dbb_spinlock;
extern unsigned int dbu_qcount;
extern unsigned int dbb_qcount;

struct configdata *config;

char *logname;
char *function=__FILE__;
int debug = 5;
int BLKSIZE = 4096;
int dedup = 0;
#define MAX_THREADS 1
int max_threads = MAX_THREADS;
BLKDTA **tdta = NULL;

extern TCHDB *dbp;
extern TCHDB *dbu;
extern TCHDB *dbc;
extern TCHDB *dbr;
extern TCHDB *dbb;
extern TCHDB *dbdta;
extern TCHDB *dbs;
extern TCBDB *dbdirent;
extern TCBDB *freelist;
extern TCBDB *dbl;
extern TCMDB *dbcache;
extern TCMDB *dbdtaq;
extern TCMDB *blkcache;
extern TCMDB *bufcache;
extern TCMDB *dbccache;
extern TCMDB *dbrcache;
extern TCMDB *dbucache;
extern TCMDB *dbbcache;
extern TCMDB *dbum;
extern TCMDB *dbcm;
extern TCMDB *dbrm;
extern TCMDB *dbbm;
extern int fdbdta;

BLKDTA *blkdta;
