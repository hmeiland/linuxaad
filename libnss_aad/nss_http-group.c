#include "nss_http.h"

static pthread_mutex_t NSS_HTTP_MUTEX = PTHREAD_MUTEX_INITIALIZER;
#define NSS_HTTP_LOCK()    do { pthread_mutex_lock(&NSS_HTTP_MUTEX); } while (0)
#define NSS_HTTP_UNLOCK()  do { pthread_mutex_unlock(&NSS_HTTP_MUTEX); } while (0)

static json_t *ent_json_root = NULL;
static int ent_json_idx = 0;


// -1 Failed to parse
// -2 Buffer too small
static int
pack_group_struct(json_t *grouproot, json_t *membersroot, struct group *result, char *buffer, size_t buflen)
{

    char *next_buf = buffer;
    size_t bufleft = buflen;
    json_t *j_gr_name, *j_gr_gid, *j_gr_mem, *j_mem_name;

    if (!json_is_object(grouproot)) return -1;

    json_t *passwd_object = json_object_get(grouproot, "value");
    if (!json_is_array(passwd_object)) return -1;
    if (json_array_size(passwd_object) < 1) return -1;
    for(int i = 0; i < json_array_size(passwd_object); i++)
    {
      json_t *entry_data = json_array_get(passwd_object, i);
      json_t *extension_object = json_object_get(entry_data, "extj8xolrvw_linux");

      j_gr_name = json_object_get(extension_object, "group");
      j_gr_gid = json_object_get(extension_object, "gid");
      j_gr_mem = json_object_get(extension_object, "members");
    }

    //json_t *j_member;

    if (!json_is_string(j_gr_name)) return -1;
    if (!json_is_integer(j_gr_gid)) return -1;
    if (!json_is_string(j_gr_mem)) return -1;

    //printf("%s\n", json_string_value(j_gr_mem));

    memset(buffer, '\0', buflen);

    if (bufleft <= j_strlen(j_gr_name)) return -2;
    result->gr_name = strncpy(next_buf, json_string_value(j_gr_name), bufleft);
    next_buf += strlen(result->gr_name) + 1;
    bufleft  -= strlen(result->gr_name) + 1;

    if (bufleft <= 1) return -2;
    result->gr_passwd = strncpy(next_buf, "x\0", 2);
    next_buf += 2;
    bufleft -= 2;

    // Yay, ints are so easy!
    result->gr_gid = json_integer_value(j_gr_gid);

    //starting to get the members
    if (!json_is_object(membersroot)) return -1;
    json_t *members_object = json_object_get(membersroot, "value");
    if (!json_is_array(members_object)) return -1;
    if (json_array_size(members_object) < 1) return -1;

    // Carve off some space for array of members.
    result->gr_mem = (char **)next_buf;
    next_buf += (json_array_size(members_object) +1) * sizeof(char *);
    bufleft  -= (json_array_size(members_object) +1) * sizeof(char *);

    for(int i = 0; i < json_array_size(members_object); i++)
    {
      json_t *entry_data = json_array_get(members_object, i);
      json_t *extension_object = json_object_get(entry_data, "extj8xolrvw_linux");

      j_mem_name = json_object_get(extension_object, "user");
      if (!json_is_string(j_mem_name)) return -1;

      //printf("%s\n", json_string_value(j_mem_name));

      if (bufleft <= j_strlen(j_mem_name)) return -2;
      strncpy(next_buf, json_string_value(j_mem_name), bufleft);
      result->gr_mem[i] = next_buf;
      next_buf += strlen(result->gr_mem[i]) + 1;
      bufleft  -= strlen(result->gr_mem[i]) + 1;
    }

    return 0;
}


enum nss_status
_nss_aad_setgrent_locked(int stayopen)
{
    char url[512];
    json_t *json_root;
    json_error_t json_error;

    printf("nss_status\n");

    snprintf(url, 512, "http://" NSS_HTTP_SERVER ":" NSS_HTTP_PORT "/group");

    char *response = nss_http_request(url, "bla");
    if (!response) {
        return NSS_STATUS_UNAVAIL;
    }

    json_root = json_loads(response, 0, &json_error);

    if (!json_root) {
        return NSS_STATUS_UNAVAIL;
    }

    if (!json_is_array(json_root)) {
        json_decref(json_root);
        return NSS_STATUS_UNAVAIL;
    }

    ent_json_root = json_root;
    ent_json_idx = 0;

    return NSS_STATUS_SUCCESS;
}


// Called to open the group file
enum nss_status
_nss_aad_setgrent(int stayopen)
{
    enum nss_status ret;
    NSS_HTTP_LOCK();
    ret = _nss_aad_setgrent_locked(stayopen);
    NSS_HTTP_UNLOCK();
    return ret;
}


enum nss_status
_nss_aad_endgrent_locked(void)
{
    if (ent_json_root){
        while (ent_json_root->refcount > 0) json_decref(ent_json_root);
    }
    ent_json_root = NULL;
    ent_json_idx = 0;
    return NSS_STATUS_SUCCESS;
}


// Called to close the group file
enum nss_status
_nss_aad_endgrent(void)
{
    enum nss_status ret;
    NSS_HTTP_LOCK();
    ret = _nss_aad_endgrent_locked();
    NSS_HTTP_UNLOCK();
    return ret;
}


enum nss_status
_nss_aad_getgrent_r_locked(struct group *result, char *buffer, size_t buflen, int *errnop)
{
    enum nss_status ret = NSS_STATUS_SUCCESS;

    if (ent_json_root == NULL) {
        ret = _nss_aad_setgrent_locked(0);
    }

    if (ret != NSS_STATUS_SUCCESS) return ret;

    int pack_result = pack_group_struct(
        json_array_get(ent_json_root, ent_json_idx), NULL, result, buffer, buflen
    );

    if (pack_result == -1) {
        *errnop = ENOENT;
        return NSS_STATUS_UNAVAIL;
    }

    if (pack_result == -2) {
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    // Return notfound when there's nothing else to read.
    if (ent_json_idx >= json_array_size(ent_json_root)) {
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }

    ent_json_idx++;
    return NSS_STATUS_SUCCESS;
}


// Called to look up next entry in group file
enum nss_status
_nss_aad_getgrent_r(struct group *result, char *buffer, size_t buflen, int *errnop)
{
    enum nss_status ret;
    NSS_HTTP_LOCK();
    ret = _nss_aad_getgrent_r_locked(result, buffer, buflen, errnop);
    NSS_HTTP_UNLOCK();
    return ret;
}


// Find a group by gid
enum nss_status
_nss_aad_getgrgid_r_locked(gid_t gid, struct group *result, char *buffer, size_t buflen, int *errnop)
{
    char url[512];
    json_t *json_root;
    json_error_t json_error;
    
    printf("_nss_aad_getgrgid_r_locked\n");

    snprintf(url, 512, "http://" NSS_HTTP_SERVER ":" NSS_HTTP_PORT "/group?gid=%d", gid);

    char *response = nss_http_request(url, "bla");
    if (!response) {
        *errnop = ENOENT;
        return NSS_STATUS_UNAVAIL;
    }

    json_root = json_loads(response, 0, &json_error);

    if (!json_root) {
        *errnop = ENOENT;
        return NSS_STATUS_UNAVAIL;
    }

    int pack_result = pack_group_struct(json_root, NULL, result, buffer, buflen);

    if (pack_result == -1) {
        json_decref(json_root);
        *errnop = ENOENT;
        return NSS_STATUS_UNAVAIL;
    }

    if (pack_result == -2) {
        json_decref(json_root);
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    json_decref(json_root);

    return NSS_STATUS_SUCCESS;
}


enum nss_status
_nss_aad_getgrgid_r(gid_t gid, struct group *result, char *buffer, size_t buflen, int *errnop)
{
    enum nss_status ret;
    NSS_HTTP_LOCK();
    ret = _nss_aad_getgrgid_r_locked(gid, result, buffer, buflen, errnop);
    NSS_HTTP_UNLOCK();
    return ret;
}


enum nss_status
_nss_aad_getgrnam_r_locked(const char *name, struct group *result, char *buffer, size_t buflen, int *errnop)
{
    char graph_url[512], token_url[512], token_postfield[512], auth_header[2048], members_url[512];
    const char *access_token;
    json_t *json_root, *j_gr_id, *group_root, *members_root;
    json_error_t json_error;

    char *client_id = nss_read_config("client_id");
    char *secret = nss_read_config("secret");
    char *authority = nss_read_config("authority");

    snprintf(token_url, 512, "%s/oauth2/v2.0/token", authority);
    snprintf(token_postfield, 512, "client_id=%s&scope=https%%3A%%2F%%2Fgraph.microsoft.com%%2F.default&client_secret=%s&grant_type=client_credentials", client_id, secret);

    char *token = nss_http_token_request(token_url, token_postfield);

    json_root = json_loads(token, 0, &json_error);
    json_t *access_token_object = json_object_get(json_root, "access_token");
    access_token = json_string_value(access_token_object);

    if (json_is_string(access_token_object)) {
      snprintf(auth_header, 2048, "%s %s\n", "Authorization: Bearer", access_token);
      //printf("auth header is %s\n", auth_header);
    }
    json_decref(json_root);

    snprintf(graph_url, 512, "https://graph.microsoft.com/v1.0/groups?$filter=extj8xolrvw_linux/group%%20eq%%20%%27%s%%27&$select=id,extj8xolrvw_linux", name);

    char *groupresponse = nss_http_request(graph_url, auth_header);
    //printf("%s\n", groupresponse);

    json_root = json_loads(groupresponse, 0, &json_error);
    json_t *group_object = json_object_get(json_root, "value");
    if (!json_is_array(group_object)) return -1;
    if (json_array_size(group_object) < 1) return -1;
    for(int i = 0; i < json_array_size(group_object); i++)
    {
      json_t *entry_data = json_array_get(group_object, i);
      j_gr_id= json_object_get(entry_data, "id");
    }
    //printf("group id is %s", json_string_value(j_gr_id));

    if (json_is_string(j_gr_id)) {
      snprintf(members_url, 512, "%s%s%s", "https://graph.microsoft.com/v1.0/groups/", json_string_value(j_gr_id), "/members?$select=id,extj8xolrvw_linux");
    }
    json_decref(json_root);

    char *membersresponse = nss_http_request(members_url, auth_header);
    //printf("%s\n", membersresponse);


    if (!groupresponse) {
        *errnop = ENOENT;
        return NSS_STATUS_UNAVAIL;
    }
    if (!membersresponse) {
        *errnop = ENOENT;
        return NSS_STATUS_UNAVAIL;
    }

    group_root = json_loads(groupresponse, 0, &json_error);
    members_root = json_loads(membersresponse, 0, &json_error);

    if (!group_root) {
        *errnop = ENOENT;
        return NSS_STATUS_UNAVAIL;
    }
    if (!members_root) {
        *errnop = ENOENT;
        return NSS_STATUS_UNAVAIL;
    }

    int pack_result = pack_group_struct(group_root, members_root, result, buffer, buflen);

    if (pack_result == -1) {
        json_decref(json_root);
        *errnop = ENOENT;
        return NSS_STATUS_UNAVAIL;
    }

    if (pack_result == -2) {
        json_decref(json_root);
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    json_decref(json_root);

    return NSS_STATUS_SUCCESS;
}


// Find a group by name
enum nss_status
_nss_aad_getgrnam_r(const char *name, struct group *result, char *buffer, size_t buflen, int *errnop)
{
    enum nss_status ret;
    NSS_HTTP_LOCK();
    ret = _nss_aad_getgrnam_r_locked(name, result, buffer, buflen, errnop);
    NSS_HTTP_UNLOCK();
    return ret;
}

