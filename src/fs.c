#include <src/libafshelpers.h>

afs_int32 afshelper_fs_isafs(char *path, afs_int32 follow) {
	struct ViceIoctl vi;
	afs_int32 code;
	char space[AFS_PIOCTL_MAXSIZE];

	vi.in_size = 0;
	vi.out_size = AFS_PIOCTL_MAXSIZE;
	vi.out = space;

	code = pioctl(path, VIOC_FILE_CELL_NAME, &vi, follow);
	
	if (code) {
		if ((errno == EINVAL) || (errno == ENOENT) || (errno == ENOSYS))
			return 0;
	}
	return 1;
}

const int _store_acl_entry(afshelper_fs_acl *acl,int isNegAcl, const char * pts_name, int rights) {
	afshelper_fs_acl_entry aclEntry;

	strncpy(aclEntry.pts_name,pts_name,MAX_PTS_NAME);
	aclEntry.rights=rights;

	if ( ! isNegAcl ) {
		/* Increment the number of acl entries s on the acl struct */
		acl->count++;
		/* Reallocate the memory for the entries in the acl struct to make room */
		acl->entries=realloc(acl->entries,(sizeof(afshelper_fs_acl_entry) * (acl->count)));
		/* Copy the ACL entry into the acl struct's list of entries */
		memcpy(&(acl->entries[acl->count - 1]),&aclEntry,sizeof(aclEntry));
	} else {
		/* Increment the number of acl entries s on the acl struct */
		acl->count++;
		/* Reallocate the memory for the entries in the acl struct to make room */
		acl->entries=realloc(acl->entries,(sizeof(afshelper_fs_acl_entry) * (acl->count)));
		/* Copy the ACL entry into the acl struct's list of entries */
		memcpy(&(acl->entries[acl->count - 1]),&aclEntry,sizeof(aclEntry));
	}
}

void afshelper_fs_acl_container_init(afshelper_fs_acl_container *acl_container) {
	/* Initialize the pointer to null */
	acl_container->pos_acls=NULL;
	acl_container->neg_acls=NULL;
}

int afshelper_fs_acl_container_free(afshelper_fs_acl_container *acl_container) {
	/* Free allocated memory */
	if ( acl_container->pos_acls != NULL ) {
		if ( acl_container->pos_acls->entries != NULL ) {
			free(acl_container->pos_acls->entries);
		}
		free(acl_container->pos_acls);
	}
	if ( acl_container->neg_acls !=NULL ) {
		if ( acl_container->neg_acls->entries != NULL ) {
			free(acl_container->neg_acls->entries);
		}
		free(acl_container->neg_acls);
	}


	return 0;
}

int afshelper_fs_acl_lookup(afshelper_fs_acl_container *acl_container, char *pts_name) {
	int i;
	int posRights=0;
	int negRights=0;

	if ( acl_container->pos_acls ) {
		for (i=0; i < acl_container->pos_acls->count; i++ ) {
			if (!strcmp(pts_name,acl_container->pos_acls->entries[i].pts_name)) {
				posRights=acl_container->pos_acls->entries[i].rights;
				break;
			}
		}
	}
	
	if ( acl_container->neg_acls ) {
		for (i=0; i < acl_container->neg_acls->count; i++ ) {
			if (!strcmp(pts_name,acl_container->neg_acls->entries[i].pts_name)) {
				negRights=acl_container->neg_acls->entries[i].rights;
				break;
			}
		}
	}

	return (posRights ^ negRights);
}
	

int afshelper_fs_acl_get(char *path, afs_int32 follow, afshelper_fs_acl_container *acl_container) {
	/* Take an AFS path and return an afshelper_acl struct of afshelper_acl_entry's. */
	afs_int32 ret;
	struct ViceIoctl vi;
        char space[AFS_PIOCTL_MAXSIZE];
        char * rest;
        char *aclList;
        int i;
        char aclPtEntry[MAX_PTS_NAME];
        int aclRights;
        int pacls=0;
        int nacls=0;
        int posRightsMask;
        int negRightsMask;
        int efctvRightsMask;
	afshelper_fs_acl pos_acl;
	afshelper_fs_acl neg_acl;

	/* Set the ViceIoctl struct to be passed into the pioctl call */
        vi.out_size = vi.in_size = AFS_PIOCTL_MAXSIZE;
	memset(space,0,sizeof(space));
        vi.in = vi.out = space;

	/* Perform a system call to AFS to get the acl vi for the given path */
        ret=pioctl(path,VIOCGETAL,&vi,follow);
	if ( ret ) {
		return 1;
	}

	/* Look up the number of positive and negative ACLs */
	sscanf(vi.out,"%d\n%d\n%*s",&pacls,&nacls);

	/* Set the acl list to the output from pioctl */
        aclList=vi.out;
	/* Get the next line of the acl output */
	aclList=afshelpers_helpers_nextLine(aclList);

	pos_acl.entries=realloc(NULL,sizeof(afshelper_fs_acl_entry));
	pos_acl.count=0;
	neg_acl.entries=realloc(NULL,sizeof(afshelper_fs_acl_entry));
	neg_acl.count=0;

	/* For each positive ACL, store the acl entry in the acl entry struct */
        for(i=0; i < pacls; i++ ) {
                aclList=afshelpers_helpers_nextLine(aclList);
                sscanf(aclList,"%s\t%d\n",aclPtEntry,&aclRights);

		_store_acl_entry(&pos_acl,0,aclPtEntry,aclRights);
        }

	/* For each negative ACL, store the acl entry in the acl entry struct */
        for(i=0; i < nacls; i++ ) {
                aclList=afshelpers_helpers_nextLine(aclList);
                sscanf(aclList,"%s\t%d\n",aclPtEntry,&aclRights);

		_store_acl_entry(&neg_acl,1,aclPtEntry,aclRights);
        }

	/* Allocate memory for the list of positive acls and copy over the positive ACL structs */
	acl_container->pos_acls=malloc(sizeof(pos_acl));
	memcpy(acl_container->pos_acls,&pos_acl,sizeof(pos_acl));
	/* Allocate memory for the list of negative acls and copy over the negative ACL structs */
	acl_container->neg_acls=malloc(sizeof(neg_acl));
	memcpy(acl_container->neg_acls,&neg_acl,sizeof(pos_acl));

	return 0;
}

int afshelper_fs_acl_ptentry_rights_on_path(char *path, char *ptentry, afs_int32 follow) {
	afshelper_fs_acl_container acl_container;
	int ret;
	int efctvRights;

	afshelper_fs_acl_container_init(&acl_container);
	afshelper_fs_acl_get(path,follow,&acl_container);
	efctvRights = afshelper_fs_acl_lookup(&acl_container, ptentry);
	afshelper_fs_acl_container_free(&acl_container);

	return efctvRights;
}
