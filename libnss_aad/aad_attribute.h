// lookup properties in AAD

#define SCHEMA_EXTENSION "extj8xolrvw_linux"
#define APP_ID "65ac6e754b3a4c39ad0c695cbe7ff29d"
#define EXTENSION "extension_" APP_ID

//#define AAD_UIDNUMBER "extension_65ac6e754b3a4c39ad0c695cbe7ff29d_uidNumber"
#define AAD_UIDNUMBER EXTENSION "_uidNumber"
//#define AAD_UID "extension_65ac6e754b3a4c39ad0c695cbe7ff29d_uid" //multi-value fields not supported in graph today
#define AAD_UID "extension_65ac6e754b3a4c39ad0c695cbe7ff29d_cn"
#define AAD_GID "extension_65ac6e754b3a4c39ad0c695cbe7ff29d_cn"
#define AAD_GIDNUMBER "extension_65ac6e754b3a4c39ad0c695cbe7ff29d_gidNumber"
#define AAD_UNIXHOMEDIRECTORY "extension_65ac6e754b3a4c39ad0c695cbe7ff29d_unixHomeDirectory"
#define AAD_LOGINSHELL "extension_65ac6e754b3a4c39ad0c695cbe7ff29d_loginShell"
#define AAD_GECOS "extension_65ac6e754b3a4c39ad0c695cbe7ff29d_gecos"


/* example users list query:
* https://graph.microsoft.com/v1.0/users?$select=userPrincipalName,extension_65ac6e754b3a4c39ad0c695cbe7ff29d_uid,extension_65ac6e754b3a4c39ad0c695cbe7ff29d_uidNumber,extension_65ac6e754b3a4c39ad0c695cbe7ff29d_gidNumber,extension_65ac6e754b3a4c39ad0c695cbe7ff29d_unixHomeDirectory,extension_65ac6e754b3a4c39ad0c695cbe7ff29d_loginShell,extension_65ac6e754b3a4c39ad0c695cbe7ff29d_gecos
* example groups list query
* https://graph.microsoft.com/v1.0/groups?$select=id,displayName,extj8xolrvw_linux,extension_65ac6e754b3a4c39ad0c695cbe7ff29d_gidNumber,extension_65ac6e754b3a4c39ad0c695cbe7ff29d_cn
*/
