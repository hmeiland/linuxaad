#include "nss_aad.h"
#include <aad_attribute.h>

static pthread_mutex_t NSS_HTTP_MUTEX = PTHREAD_MUTEX_INITIALIZER;
#define NSS_HTTP_LOCK()    do { pthread_mutex_lock(&NSS_HTTP_MUTEX); } while (0)
#define NSS_HTTP_UNLOCK()  do { pthread_mutex_unlock(&NSS_HTTP_MUTEX); } while (0)

static json_t *ent_json_root = NULL;
static int ent_json_idx = 0;


// -1 Failed to parse
// -2 Buffer too small
static int
//pack_passwd_struct(json_t *root, struct passwd *result, char *buffer, size_t buflen)
pack_passwd_struct(json_t *entry_data, struct passwd *result, char *buffer, size_t buflen)
{
    char * next_buf = buffer;
    size_t bufleft = buflen;
    json_t *j_pw_name, *j_pw_passwd, *j_pw_uid, *j_pw_gid, *j_pw_gecos, *j_pw_dir, *j_pw_shell;

    if (!entry_data) return -1;
    //if (entry_data) printf("%s\n", json_dumps(entry_data, JSON_INDENT(2)));
    //printf("debug 1\n");
    //json_t *extension_object = json_object_get(entry_data, "extj8xolrvw_linux");
    //if (!json_is_null(extension_object)) return -1;
    //printf("%s\n", json_dumps(extension_object, JSON_INDENT(2)));

    //j_pw_name = json_object_get(extension_object, "user");
    j_pw_name = json_object_get(entry_data, AAD_UID);
    j_pw_passwd = NULL;
    //j_pw_passwd = json_object_get(extension_object, "passwd");
    //j_pw_uid = json_object_get(extension_object, "uid");
    j_pw_uid = json_object_get(entry_data, AAD_UIDNUMBER);
    //j_pw_gid = json_object_get(extension_object, "gidnumber");
    j_pw_gid = json_object_get(entry_data, AAD_GIDNUMBER);
    //j_pw_gecos = json_object_get(extension_object, "gecos");
    j_pw_gecos = json_object_get(entry_data, AAD_GECOS);
    //j_pw_dir = json_object_get(extension_object, "homedir");
    j_pw_dir = json_object_get(entry_data, AAD_UNIXHOMEDIRECTORY);
    //j_pw_shell = json_object_get(extension_object, "shell");
    j_pw_shell = json_object_get(entry_data, AAD_LOGINSHELL);

    if (!json_is_string(j_pw_name)) return -1;
    //if ((j_pw_passwd) && !json_is_string(j_pw_passwd) && !json_is_null(j_pw_passwd)) return -1;
    if (!json_is_integer(j_pw_uid)) return -1;
    if (!json_is_integer(j_pw_gid)) return -1;
    if ((j_pw_gecos) && !json_is_string(j_pw_gecos) && !json_is_null(j_pw_gecos)) return -1;
    if ((j_pw_dir) && !json_is_string(j_pw_dir)) return -1;
    if ((j_pw_shell) && !json_is_string(j_pw_shell)) return -1;

    memset(buffer, '\0', buflen);

    if (bufleft <= j_strlen(j_pw_name)) return -2;
    result->pw_name = strncpy(next_buf, json_string_value(j_pw_name), bufleft);
    next_buf += strlen(result->pw_name) + 1;
    bufleft  -= strlen(result->pw_name) + 1;

    if ((!j_pw_passwd) || json_is_null(j_pw_passwd))
    {
      if (bufleft <= 1) return -2;
      result->pw_passwd = strncpy(next_buf, "x", bufleft);
      next_buf += strlen("x") + 1;
      bufleft -= strlen("x") + 1;
    } else {
      if (bufleft <= j_strlen(j_pw_passwd)) return -2;
      result->pw_passwd = strncpy(next_buf, json_string_value(j_pw_passwd), bufleft);
      next_buf += strlen(result->pw_passwd) + 1;
      bufleft  -= strlen(result->pw_passwd) + 1;
    }
    // Yay, ints are so easy!
    result->pw_uid = json_integer_value(j_pw_uid);
    result->pw_gid = json_integer_value(j_pw_gid);

    if ((!j_pw_gecos) || json_is_null(j_pw_gecos))
    {
        if (bufleft <= 1) return -2;
        result->pw_gecos = strncpy(next_buf, "...", bufleft);
        next_buf += strlen("...") + 1;
        bufleft -= strlen("...") + 1;
    } else {
        if (bufleft <= j_strlen(j_pw_gecos)) return -2;
        result->pw_gecos = strncpy(next_buf, json_string_value(j_pw_gecos), bufleft);
        next_buf += strlen(result->pw_gecos) + 1;
        bufleft  -= strlen(result->pw_gecos) + 1;
    }

    if ((!j_pw_dir) || json_is_null(j_pw_dir))
    {
        if (bufleft <= 1) return -2;
        result->pw_dir = strncpy(next_buf, "unixhomedirectory_not_set_in_ad", bufleft);
        next_buf += strlen("unixhomedirectory_not_set_in_ad") + 1;
        bufleft -= strlen("unixhomedirectory_not_set_in_ad") + 1;
    } else {
        if (bufleft <= j_strlen(j_pw_dir)) return -2;
        result->pw_dir = strncpy(next_buf, json_string_value(j_pw_dir), bufleft);
        next_buf += strlen(result->pw_dir) + 1;
        bufleft  -= strlen(result->pw_dir) + 1;
    }

    if ((!j_pw_shell) || json_is_null(j_pw_shell))
    {
        if (bufleft <= 1) return -2;
        result->pw_shell = strncpy(next_buf, "loginshell_not_set_in_ad", bufleft);
        next_buf += strlen("loginshell_not_set_in_ad") + 1;
        bufleft -= strlen("loginshell_not_set_in_ad") + 1;
    } else {
        if (bufleft <= j_strlen(j_pw_shell)) return -2;
        result->pw_shell = strncpy(next_buf, json_string_value(j_pw_shell), bufleft);
        next_buf += strlen(result->pw_shell) + 1;
        bufleft  -= strlen(result->pw_shell) + 1;
    }

    return 0;
}


enum nss_status
_nss_aad_setpwent_locked(int stayopen)
{
    char graph_url[512], token_url[512], token_postfield[512], auth_header[2048];
    const char * access_token;
    json_t *json_root;
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
      snprintf(auth_header, 4096, "%s %s", "Authorization: Bearer", access_token);
    }
    json_decref(json_root);

    //snprintf(graph_url, 512, "https://graph.microsoft.com/v1.0/users?$filter=extj8xolrvw_linux/uid%%20ge%%20%%2725000%%27&$select=id,extj8xolrvw_linux,%s,%s,%s,%s,%s", AAD_UID, AAD_UIDNUMBER, AAD_GIDNUMBER, AAD_UNIXHOMEDIRECTORY, AAD_LOGINSHELL);
    snprintf(graph_url, 512, "https://graph.microsoft.com/v1.0/users?$filter=%s%%20ge%%20%%2725000%%27&$select=id,extj8xolrvw_linux,%s,%s,%s,%s,%s", AAD_UIDNUMBER,AAD_UID, AAD_UIDNUMBER, AAD_GIDNUMBER, AAD_UNIXHOMEDIRECTORY, AAD_LOGINSHELL);
    //printf("debug %s\n", graph_url);
    //printf("debug %s\n", auth_header);

    char *response = nss_http_request(graph_url, auth_header);

    if (!response) {
        return NSS_STATUS_UNAVAIL;
    }

    json_root = json_loads(response, 0, &json_error);
    //printf("%s\n", json_dumps(json_root, JSON_INDENT(2)));
    if (!json_is_array(json_object_get(json_root, "value"))) return -1;
    if (json_array_size(json_object_get(json_root, "value")) < 1) return -1;
    json_t *passwd_object = json_object_get(json_root, "value");
    //printf("%s\n", json_dumps(passwd_object, JSON_INDENT(2)));

    ent_json_root = passwd_object;
    ent_json_idx = 0;

    if (!json_root) {
        return NSS_STATUS_UNAVAIL;
    }

    return NSS_STATUS_SUCCESS;
}


// Called to open the passwd file
enum nss_status
_nss_aad_setpwent(int stayopen)
{
    enum nss_status ret;
    NSS_HTTP_LOCK();
    ret = _nss_aad_setpwent_locked(stayopen);
    NSS_HTTP_UNLOCK();
    return ret;
}


enum nss_status
_nss_aad_endpwent_locked(void)
{
    if (ent_json_root){
        while (ent_json_root->refcount > 0) json_decref(ent_json_root);
    }
    ent_json_root = NULL;
    ent_json_idx = 0;
    return NSS_STATUS_SUCCESS;
}


// Called to close the passwd file
enum nss_status
_nss_aad_endpwent(void)
{
    enum nss_status ret;
    NSS_HTTP_LOCK();
    ret = _nss_aad_endpwent_locked();
    NSS_HTTP_UNLOCK();
    return ret;
}


enum nss_status
_nss_aad_getpwent_r_locked(struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
    enum nss_status ret = NSS_STATUS_SUCCESS;
    //printf("debug 2\n");

    if (ent_json_root == NULL) {
        ret = _nss_aad_setpwent_locked(0);
    }

    if (ret != NSS_STATUS_SUCCESS) return ret;

    int pack_result = pack_passwd_struct(
        json_array_get(ent_json_root, ent_json_idx), result, buffer, buflen
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


// Called to look up next entry in passwd file
enum nss_status
_nss_aad_getpwent_r(struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
    enum nss_status ret;
    NSS_HTTP_LOCK();
    ret = _nss_aad_getpwent_r_locked(result, buffer, buflen, errnop);
    NSS_HTTP_UNLOCK();
    return ret;
}


// Find a passwd by uid
enum nss_status
_nss_aad_getpwuid_r_locked(uid_t uid, struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
    char graph_url[512], token_url[512], token_postfield[512], auth_header[2048];
    const char * access_token;
    json_t *json_root;
    json_error_t json_error;
    printf("debug 3\n");

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
    }
    json_decref(json_root);

    //snprintf(graph_url, 512, "https://graph.microsoft.com/v1.0/users?$filter=extj8xolrvw_linux/uid%%20eq%%20%%27%i%%27&$select=id,extj8xolrvw_linux,%s,%s,%s,%s,%s", uid, AAD_UID, AAD_UIDNUMBER, AAD_GIDNUMBER, AAD_UNIXHOMEDIRECTORY, AAD_LOGINSHELL);
    snprintf(graph_url, 512, "https://graph.microsoft.com/v1.0/users?$filter=%s%%20eq%%20%%27%i%%27&$select=id,extj8xolrvw_linux,%s,%s,%s,%s,%s", AAD_UIDNUMBER, uid, AAD_UID, AAD_UIDNUMBER, AAD_GIDNUMBER, AAD_UNIXHOMEDIRECTORY, AAD_LOGINSHELL);

    char *response = nss_http_request(graph_url, auth_header);

    if (!response) {
        *errnop = ENOENT;
        return NSS_STATUS_UNAVAIL;
    }

    json_root = json_loads(response, 0, &json_error);

    if (!json_root) {
        *errnop = ENOENT;
        return NSS_STATUS_UNAVAIL;
    }

    json_t *passwd_object = json_object_get(json_root, "value");
    if (!json_is_array(passwd_object)) return -1;
    if (json_array_size(passwd_object) < 1) return -1;

    json_t *entry_data = json_array_get(passwd_object, 0);

    int pack_result = pack_passwd_struct(entry_data, result, buffer, buflen);

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
_nss_aad_getpwuid_r(uid_t uid, struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
    enum nss_status ret;
    NSS_HTTP_LOCK();
    ret = _nss_aad_getpwuid_r_locked(uid, result, buffer, buflen, errnop);
    NSS_HTTP_UNLOCK();
    return ret;
}


enum nss_status
_nss_aad_getpwnam_r_locked(const char *name, struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
    char graph_url[512], token_url[512], token_postfield[512], auth_header[2048];
    const char * access_token;
    json_t *json_root;
    json_error_t json_error;
    printf("debug 4\n");
    
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
    }
    json_decref(json_root);

    //snprintf(graph_url, 512, "https://graph.microsoft.com/v1.0/users?$filter=extj8xolrvw_linux/user%%20eq%%20%%27%s%%27&$select=id,extj8xolrvw_linux,%s,%s,%s,%s,%s", name, AAD_UID, AAD_UIDNUMBER, AAD_GIDNUMBER, AAD_UNIXHOMEDIRECTORY, AAD_LOGINSHELL);
    snprintf(graph_url, 512, "https://graph.microsoft.com/v1.0/users?$filter=%s%%20eq%%20%%27%s%%27&$select=id,extj8xolrvw_linux,%s,%s,%s,%s,%s", AAD_UID, name, AAD_UID, AAD_UIDNUMBER, AAD_GIDNUMBER, AAD_UNIXHOMEDIRECTORY, AAD_LOGINSHELL);

    char *response = nss_http_request(graph_url, auth_header);

    if (!response) {
        *errnop = ENOENT;
        return NSS_STATUS_UNAVAIL;
    }

    json_root = json_loads(response, 0, &json_error);

    if (!json_root) {
        *errnop = ENOENT;
        return NSS_STATUS_UNAVAIL;
    }

    json_t *passwd_object = json_object_get(json_root, "value");
    if (!json_is_array(passwd_object)) return -1;
    if (json_array_size(passwd_object) < 1) return -1;
    printf("%s\n", json_dumps(passwd_object, JSON_INDENT(2)));

    json_t *entry_data = json_array_get(passwd_object, 0);

    int pack_result = pack_passwd_struct(entry_data, result, buffer, buflen);

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


// Find a passwd by name
enum nss_status
_nss_aad_getpwnam_r(const char *name, struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
    enum nss_status ret;
    NSS_HTTP_LOCK();
    ret = _nss_aad_getpwnam_r_locked(name, result, buffer, buflen, errnop);
    NSS_HTTP_UNLOCK();
    return ret;
}

