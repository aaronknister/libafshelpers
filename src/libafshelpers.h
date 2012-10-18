#include <afs/param.h>
#include <afs/prs_fs.h>

#include <afs/afs_args.h>
#include <rx/xdr.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>

#include <sys/socket.h>
#include <resolv.h>
#include <afs/venus.h>
#include <afs/afsutil.h>

#define AFS_PIOCTL_MAXSIZE	2048
#define MAX_PTS_NAME		64

typedef struct {
	char pts_name[MAX_PTS_NAME];
	int rights;
} afshelper_fs_acl_entry;

typedef struct {
	int count;
	afshelper_fs_acl_entry *entries;
} afshelper_fs_acl;

typedef struct {
	afshelper_fs_acl *pos_acls;
	afshelper_fs_acl *neg_acls;
} afshelper_fs_acl_container;

char * afshelpers_helpers_nextLine(char *);
