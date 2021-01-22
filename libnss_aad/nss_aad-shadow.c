#include "nss_aad.h"

static pthread_mutex_t NSS_HTTP_MUTEX = PTHREAD_MUTEX_INITIALIZER;
#define NSS_HTTP_LOCK()    do { pthread_mutex_lock(&NSS_HTTP_MUTEX); } while (0)
#define NSS_HTTP_UNLOCK()  do { pthread_mutex_unlock(&NSS_HTTP_MUTEX); } while (0)

static json_t *ent_json_root = NULL;
static int ent_json_idx = 0;


// -1 Failed to parse
// -2 Buffer too small
static int
//pack_shadow_struct(json_t *root, struct spwd *result, char *buffer, size_t buflen)
pack_shadow_struct(json_t *entry_data, struct spwd *result, char *buffer, size_t buflen)
{

    char *next_buf = buffer;
    size_t bufleft = buflen;

    //if (!json_is_object(root)) return -1;
    //    json_t *passwd_object = json_object_get(root, "value");
    //if (!json_is_array(passwd_object)) return -1;
    //if (json_array_size(passwd_object) < 1) return -1;
    //json_t *entry_data = json_array_get(passwd_object, 0);
    json_t *extension_object = json_object_get(entry_data, "extj8xolrvw_linux");

    json_t *j_sp_namp = json_object_get(extension_object, "user");
    //json_t *j_sp_pwdp = json_object_get(root, "sp_pwdp");
    //json_t *j_sp_lstchg = json_object_get(root, "sp_lstchg");
    //json_t *j_sp_min = json_object_get(root, "sp_min");
    //json_t *j_sp_max = json_object_get(root, "sp_max");
    //json_t *j_sp_warn = json_object_get(root, "sp_warn");
    //json_t *j_sp_inact = json_object_get(root, "sp_inact");
    //json_t *j_sp_expire = json_object_get(root, "sp_expire");
    //json_t *j_sp_flag = json_object_get(root, "sp_flag");

    if (!json_is_string(j_sp_namp)) return -1;
    //if (!json_is_string(j_sp_pwdp)) return -1;
    //if (!json_is_integer(j_sp_lstchg)) return -1;
    //if (!json_is_integer(j_sp_min)) return -1;
    //if (!json_is_integer(j_sp_max)) return -1;
    //if (!json_is_integer(j_sp_warn)) return -1;
    //if (!json_is_integer(j_sp_inact) && !json_is_null(j_sp_inact)) return -1;
    //if (!json_is_integer(j_sp_expire) && !json_is_null(j_sp_expire)) return -1;
    //if (!json_is_integer(j_sp_flag) && !json_is_null(j_sp_flag)) return -1;

    memset(buffer, '\0', buflen);

    if (bufleft <= j_strlen(j_sp_namp)) return -2;
    result->sp_namp = strncpy(next_buf, json_string_value(j_sp_namp), bufleft);
    next_buf += strlen(result->sp_namp) + 1;
    bufleft  -= strlen(result->sp_namp) + 1;

    if (bufleft <= strlen("*")) return -2;
    //result->sp_pwdp = strncpy(next_buf, json_string_value(j_sp_pwdp), bufleft);
    result->sp_pwdp = strncpy(next_buf, "*", bufleft);
    next_buf += strlen(result->sp_pwdp) + 1;
    bufleft  -= strlen(result->sp_pwdp) + 1;

    // Yay, ints are so easy!
    result->sp_lstchg = 18364; //json_integer_value(j_sp_lstchg);
    result->sp_min = 0; //json_integer_value(j_sp_min);
    result->sp_max = 99999; //json_integer_value(j_sp_max);
    result->sp_warn = 7; //json_integer_value(j_sp_warn);

    //if (!json_is_null(j_sp_inact)) result->sp_inact = json_integer_value(j_sp_inact);
    result->sp_inact = -1;

    //if (!json_is_null(j_sp_expire)) result->sp_expire = json_integer_value(j_sp_expire);
    result->sp_expire = -1;

    //if (!json_is_null(j_sp_flag)) result->sp_flag = json_integer_value(j_sp_flag);
    result->sp_flag = ~0ul;

    return 0;
}


enum nss_status
_nss_aad_setspent_locked(int stayopen)
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
      snprintf(auth_header, 2048, "%s %s\n", "Authorization: Bearer", access_token);
    }
    json_decref(json_root);

    snprintf(graph_url, 512, "https://graph.microsoft.com/v1.0/users?$filter=extj8xolrvw_linux/uid%%20ge%%20%%2725000%%27&$select=id,extj8xolrvw_linux");

    char *response = nss_http_request(graph_url, auth_header);
    
    if (!response) {
        return NSS_STATUS_UNAVAIL;
    }

    json_root = json_loads(response, 0, &json_error);
    if (!json_is_array(json_object_get(json_root, "value"))) return -1;
    if (json_array_size(json_object_get(json_root, "value")) < 1) return -1;
    json_t *shadow_object = json_object_get(json_root, "value");

    ent_json_root = shadow_object;
    ent_json_idx = 0;

    return NSS_STATUS_SUCCESS;
}


// Called to open the shadow file
enum nss_status
_nss_aad_setspent(int stayopen)
{
    enum nss_status ret;
    NSS_HTTP_LOCK();
    ret = _nss_aad_setspent_locked(stayopen);
    NSS_HTTP_UNLOCK();
    return ret;
}


enum nss_status
_nss_aad_endspent_locked(void)
{
    if (ent_json_root){
        while (ent_json_root->refcount > 0) json_decref(ent_json_root);
    }
    ent_json_root = NULL;
    ent_json_idx = 0;
    return NSS_STATUS_SUCCESS;
}


// Called to close the shadow file
enum nss_status
_nss_aad_endspent(void)
{
    enum nss_status ret;
    NSS_HTTP_LOCK();
    ret = _nss_aad_endspent_locked();
    NSS_HTTP_UNLOCK();
    return ret;
}


enum nss_status
_nss_aad_getspent_r_locked(struct spwd *result, char *buffer, size_t buflen, int *errnop)
{
    enum nss_status ret = NSS_STATUS_SUCCESS;

    if (ent_json_root == NULL) {
        ret = _nss_aad_setspent_locked(0);
    }

    if (ret != NSS_STATUS_SUCCESS) return ret;

    int pack_result = pack_shadow_struct(
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


// Called to look up next entry in shadow file
enum nss_status
_nss_aad_getspent_r(struct spwd *result, char *buffer, size_t buflen, int *errnop)
{
    enum nss_status ret;
    NSS_HTTP_LOCK();
    ret = _nss_aad_getspent_r_locked(result, buffer, buflen, errnop);
    NSS_HTTP_UNLOCK();
    return ret;
}


enum nss_status
_nss_aad_getspnam_r_locked(const char *name, struct spwd *result, char *buffer, size_t buflen, int *errnop)
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
      snprintf(auth_header, 2048, "%s %s\n", "Authorization: Bearer", access_token);
    }
    json_decref(json_root);

    snprintf(graph_url, 512, "https://graph.microsoft.com/v1.0/users?$filter=extj8xolrvw_linux/user%%20eq%%20%%27%s%%27&$select=id,extj8xolrvw_linux", name);
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
    if (!json_is_array(json_object_get(json_root, "value"))) return -1;
    if (json_array_size(json_object_get(json_root, "value")) < 1) return -1;
    json_t *shadow_object = json_object_get(json_root, "value");
    json_t *entry_data = json_array_get(shadow_object, 0);

    int pack_result = pack_shadow_struct(entry_data, result, buffer, buflen);

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


// Find a shadow by name
enum nss_status
_nss_aad_getspnam_r(const char *name, struct spwd *result, char *buffer, size_t buflen, int *errnop)
{
    enum nss_status ret;
    NSS_HTTP_LOCK();
    ret = _nss_aad_getspnam_r_locked(name, result, buffer, buflen, errnop);
    NSS_HTTP_UNLOCK();
    return ret;
}

