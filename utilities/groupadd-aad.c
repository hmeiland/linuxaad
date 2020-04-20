
//Azure token request

#include <stdio.h>
#include <curl/curl.h>
#include <jansson.h>
#include <string.h>
#include <unistd.h>  
#include <getopt.h>  
#include <nss_http.h>

#define NSS_HTTP_INITIAL_BUFFER_SIZE (256 * 1024)  /* 256 KB */
#define NSS_HTTP_MAX_BUFFER_SIZE (10 * 1024 * 1024)  /* 10 MB */

void list_groups(char *format) 
{
    char graph_url[512], token_url[512], token_postfield[512], auth_header[2048];
    const char *access_token;
    json_t *json_root;
    json_error_t json_error;
    json_t *j_id, *j_displayname, *j_group, *j_gid;

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
      snprintf(auth_header, 2048, "%s %s", "Authorization: Bearer", access_token);
    }
    json_decref(json_root);

    snprintf(graph_url, 512, "https://graph.microsoft.com/v1.0/groups?$select=id,displayName,extj8xolrvw_linux");
    char *response = nss_http_request(graph_url, auth_header);
    
    if(!strcmp(format, "list")) printf("id\t\t\t\t\tdisplayName\t\tgroup\tgid\n");

    json_root = json_loads(response, 0, &json_error);
    json_t *passwd_object = json_object_get(json_root, "value");

    for(int i = 0; i < json_array_size(passwd_object); i++)
    {
      json_t *entry_data = json_array_get(passwd_object, i);
      j_id = json_object_get(entry_data, "id");
      j_displayname = json_object_get(entry_data, "displayName");

      json_t *extension_object = json_object_get(entry_data, "extj8xolrvw_linux");

      j_group = json_object_get(extension_object, "group");
      j_gid = json_object_get(extension_object, "gid");

      if (!strcmp(format, "list")) {
        printf("%s\t", json_string_value(j_id));
        if (!json_is_null(j_displayname)) {
          printf("%s\t", json_string_value(j_displayname));
          if (strlen(json_string_value(j_displayname)) < 25) printf("\t");
        }

        if (json_string_value(j_group)) { 
          printf("%s\t", json_string_value(j_group));
        } else { printf("not_set\t"); }

        if (json_integer_value(j_gid)) {
          printf("%lli\t", json_integer_value(j_gid));
        } else { printf("not_set\t"); }
        printf("\n");
      }
      //if (!strcmp(format, "group")) {
      //  printf("%s:x:%lli:%lli:,,,:%s:%s\n", json_string_value(j_user), json_integer_value(j_uid), json_integer_value(j_gidnumber), json_string_value(j_homedir), json_string_value(j_shell));
      //}
    }

exit(0);
}

void add_group(char *name, char *id) 
{
    char graph_url[512], token_url[512], token_postfield[512], auth_header[2048], patch[1024];
    const char * access_token;
    json_t *json_root;
    json_error_t json_error;
    json_t *j_id, *j_group, *j_displayname, *j_gid;

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
      snprintf(auth_header, 2048, "%s %s", "Authorization: Bearer", access_token);
    }
    json_decref(json_root);
    
    //search for max gid
    snprintf(graph_url, 512, "https://graph.microsoft.com/v1.0/groups?$select=id,displayName,extj8xolrvw_linux");

    char *search_max_uid = nss_http_request(graph_url, auth_header);

    json_root = json_loads(search_max_uid, 0, &json_error);
    json_t *group_object = json_object_get(json_root, "value");
    
    int max_gid = 25000;
    for(int i = 0; i < json_array_size(group_object); i++)
    {
      json_t *entry_data = json_array_get(group_object, i);
      j_id = json_object_get(entry_data, "id");
      j_displayname = json_object_get(entry_data, "displayName");

      json_t *extension_object = json_object_get(entry_data, "extj8xolrvw_linux");

      j_gid = json_object_get(extension_object, "gid");
      j_group = json_object_get(extension_object, "group");

      if (json_integer_value(j_gid)) {
        if (json_integer_value(j_gid) > max_gid) max_gid = json_integer_value(j_gid);
      }

      if (json_string_value(j_group)) {
        if(!strcmp(name, json_string_value(j_group))) {
          printf("groupname already exists: %s\n", json_string_value(j_group));
          exit(1);
        }
      } 
    }
    json_decref(json_root);
    max_gid++;

    // do add group
    snprintf(graph_url, 512, "https://graph.microsoft.com/v1.0/groups/%s", id);
    snprintf(patch, 1024, "{\"extj8xolrvw_linux\":{\"gid\":%i,\"group\":\"%s\"}}", max_gid, name);

    char *response = nss_http_patch_request(graph_url, auth_header, patch);
}


void update_user(char *name, char * id, int uid) 
{
    char graph_url[512], token_url[512], token_postfield[512], auth_header[2048], patch[1024];
    const char * access_token;
    json_t *json_root;
    json_error_t json_error;
    json_t *j_id, *j_mail, *j_principal, *j_user, *j_pw_passwd, *j_uid, *j_gidnumber, *j_pw_gecos, *j_homedir, *j_shell;

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
      snprintf(auth_header, 2048, "%s %s", "Authorization: Bearer", access_token);
    }
    json_decref(json_root);
    
    // do update user
    snprintf(graph_url, 512, "https://graph.microsoft.com/v1.0/users/%s", id);
    if (uid > -1)
    { 
      snprintf(patch, 1024, "{\"extj8xolrvw_linux\":{\"uid\":%i}}", uid);
      char *response = nss_http_patch_request(graph_url, auth_header, patch);
    }
    exit(0);
}

void print_usage() 
{
    printf("Usage: groupadd-aad [options] <group>\n");
    printf("  --list: 	list all AAD groups and their linux properties\n");
    printf("  --update <group>\n");
}

int main(int argc, char *argv[])
{
  int opt = 0, add = 0, list = 0, passwd = 0, update = 0;
  int uid = -1;
  char *id, *name, *homedir;

  static struct option long_options[] = {
    {"list",      no_argument,       0, 'l' },
    {"add",       no_argument,       0, 'a' },
    {"update",    no_argument,       0, 't' },
    {"passwd",    no_argument,       0, 'p' },
    {"id",        required_argument, 0, 'i' },
    {"uid",       required_argument, 0, 'u' },
    {"home-dir",  required_argument, 0, 'd' },
    {0,           0,                 0,  0  }
  };

  int long_index = 0;
  while ((opt = getopt_long(argc, argv,":l", 
          long_options, &long_index )) != -1) {
    switch (opt) {
      case 'a' : 
        add = 1;
        break;
      case 'p' : 
	passwd = 1;
        break;
      case 't' : 
	update = 1;
        break;
      case 'u' : 
	uid = atoi(optarg);
        break;
      case 'l' : 
        list = 1;
        break;
      case 'i' : 
        id = optarg;
        break;
      case 'd' : 
        homedir = optarg;
        break;
      default : printf("%s\n", optarg);
        //print_usage(); 
        exit(EXIT_FAILURE);
    }
  }

  if (list == 1) list_groups("list"); 
  if (passwd == 1) list_groups("passwd"); 

  if (!argv[optind]) {
    print_usage();
    exit(EXIT_FAILURE);
  } 
  name = argv[optind];

  if (add == 1 && name && id) add_group(name, id); 
  if (update == 1 && name && id && uid) update_user(name, id, uid); 

  return 0;
}
