#include <src/libafshelpers.h>


int main() {
	char path[]="/afs/umbc.edu/users/a/a/aaronk";
	int ret;
	int efctv_rights;
	afshelper_fs_acl_container acl_container;

	afshelper_fs_acl_container_init(&acl_container);
	//memset(&acl_container,0,sizeof(acl_container));

	ret=afshelper_fs_acl_get(path, 0, &acl_container);

	printf("ret: %d\n",ret);

	printf("test2: %s\n",acl_container.pos_acls->entries[0].pts_name);
	printf("test2: %s\n",acl_container.pos_acls->entries[1].pts_name);
	printf("test2: %s\n",acl_container.pos_acls->entries[2].pts_name);

	efctv_rights=afshelper_fs_acl_lookup(&acl_container,"aaronk");
	printf("effective rights: %d\n",efctv_rights);
	printf("any interesting rights: %d\n",efctv_rights & 86);

/*
	efctv_rights=afshelper_fs_acl_lookup(&acl_container,"system:anyuser");
	printf("system:anyuser - effective rights: %d\n",efctv_rights);
	printf("system:anyuser - any interesting rights: %d\n",efctv_rights & 86);
*/
	afshelper_fs_acl_container_free(&acl_container);
	printf("here2\n");

	efctv_rights=afshelper_fs_acl_ptentry_rights_on_path("/afs/umbc.edu/users/a/a/aaronk/home","aaronk",0);
	printf("efctv_rights: %d\n",efctv_rights);

	return ret;
}
