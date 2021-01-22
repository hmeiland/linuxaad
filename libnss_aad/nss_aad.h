#ifndef NSS_HTTP_H
#define NSS_HTTP_H

#include <curl/curl.h>
#include <errno.h>
#include <grp.h>
#include <jansson.h>
#include <nss.h>
#include <pthread.h>
#include <pwd.h>
#include <shadow.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>

#define NSS_CONFIG_FILE "/etc/azuread/parameters.json"

#define NSS_HTTP_INITIAL_BUFFER_SIZE (256 * 1024)  /* 256 KB */
#define NSS_HTTP_MAX_BUFFER_SIZE (10 * 1024 * 1024)  /* 10 MB */

extern char *nss_http_request(const char *, const char *);
extern char *nss_http_token_request(const char *, const char *);
extern char *nss_http_patch_request(const char *, const char *, const char *);
extern char *nss_read_config(const char *);
extern size_t j_strlen(json_t *);

#endif /* NSS_HTTP_H */
