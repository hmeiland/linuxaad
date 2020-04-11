#include "nss_http.h"

struct response {
    char *data;
    size_t pos;
};


// Newer versions of Jansson have this but the version
// on Ubuntu 12.04 don't, so make a wrapper.
extern size_t
j_strlen(json_t *str)
{
    return strlen(json_string_value(str));
}


static size_t write_response(void *ptr, size_t size, size_t nmemb, void *stream)
{
    struct response *result = (struct response *)stream;
    size_t required_len = result->pos + size * nmemb;

    if(required_len >= NSS_HTTP_INITIAL_BUFFER_SIZE - 1)
    {
        if (required_len < NSS_HTTP_MAX_BUFFER_SIZE)
        {
            result->data = realloc(result->data, required_len);
            if (!result->data){
                // Failed to initialize a large enough buffer for the data.
                return 0;
            }
        } else {
            // Request data is too large.
            return 0;
        }
    }

    memcpy(result->data + result->pos, ptr, size * nmemb);
    result->pos += size * nmemb;

    return size * nmemb;
}


char *
nss_http_token_request(const char *token_url, const char *token_postfield)
{
    CURL *curl = NULL;
    CURLcode status;
    struct curl_slist *headers = NULL;
    char *data = NULL;
    long code;

    //printf("nss_http_token_request url %s\n", token_url);
    //printf("nss_http_token_request post %s\n", token_postfield);

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if(!curl) goto error;

    data = malloc(NSS_HTTP_INITIAL_BUFFER_SIZE);
    if(!data) goto error;

    struct response write_result = { .data = data, .pos = 0 };

    curl_easy_setopt(curl, CURLOPT_URL, token_url);

    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, token_postfield);
    //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &write_result);

    status = curl_easy_perform(curl);
    if(status != 0) goto error;

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    if(code != 200 && code != 400) goto error;

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    curl_global_cleanup();

    data[write_result.pos] = '\0';

    return data;

error:
    if(data)
        free(data);
    if(curl)
        curl_easy_cleanup(curl);
    if(headers)
        curl_slist_free_all(headers);
    curl_global_cleanup();

    return NULL;
}


char *
nss_http_request(const char *url, const char *auth_header)
{
    CURL *curl = NULL;
    CURLcode status;
    struct curl_slist *headers = NULL;
    char *data = NULL;
    long code;

    //printf("nss_http_request url %s\n", url);
    //printf("nss_http_request header %s\n", auth_header);

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if(!curl) goto error;

    data = malloc(NSS_HTTP_INITIAL_BUFFER_SIZE);
    if(!data) goto error;

    struct response write_result = { .data = data, .pos = 0 };

    curl_easy_setopt(curl, CURLOPT_URL, url);

    headers = curl_slist_append(headers, auth_header);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &write_result);

    status = curl_easy_perform(curl);
    if(status != 0) goto error;

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    if(code != 200) goto error;

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    curl_global_cleanup();

    data[write_result.pos] = '\0';

    return data;

error:
    if(data)
        free(data);
    if(curl)
        curl_easy_cleanup(curl);
    if(headers)
        curl_slist_free_all(headers);
    curl_global_cleanup();

    return NULL;
}

char *
nss_http_patch_request(const char *url, const char *auth_header, const char *patch_postfield)
{
    CURL *curl = NULL;
    CURLcode status;
    struct curl_slist *headers = NULL;
    char *data = NULL;
    long code;

    //printf("nss_http_request url %s\n", url);
    //printf("nss_http_request header %s\n", auth_header);
    //printf("nss_http_patch_request postfield %s\n", patch_postfield);

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if(!curl) goto error;

    data = malloc(NSS_HTTP_INITIAL_BUFFER_SIZE);
    if(!data) goto error;

    struct response write_result = { .data = data, .pos = 0 };

    curl_easy_setopt(curl, CURLOPT_URL, url);

    headers = curl_slist_append(headers, auth_header);
    headers = curl_slist_append(headers, "Content-type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, patch_postfield);
    //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &write_result);

    status = curl_easy_perform(curl);
    if(status != 0) goto error;

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    if(code != 200) goto error;

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    curl_global_cleanup();

    data[write_result.pos] = '\0';

    return data;

error:
    if(data)
        free(data);
    if(curl)
        curl_easy_cleanup(curl);
    if(headers)
        curl_slist_free_all(headers);
    curl_global_cleanup();

    return NULL;
}

char *
nss_read_config(const char *field)
{
    char *configdata = malloc(128);
    json_t *json_root;
    json_error_t error;

    char *file = NSS_CONFIG_FILE;
    json_root = json_load_file(file, 0, &error);

    json_t *data_object = json_object_get(json_root, field);
    if (json_is_string(data_object)) {
      strcpy(configdata, json_string_value(data_object));
    }
    json_decref(json_root);

    return configdata;
}
