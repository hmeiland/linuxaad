# linuxaad
Libs and utils for Azure Active Directory support for Linux.


# login example

![login with ssh and device code](screenshots/login.png)
![showing ls, id and getent](screenshots/ls-id-getent.png)

# Azure Active Directory

To host the linux properties in Azure Active Directory, the following schema extension is used:
https://developer.microsoft.com/en-us/graph/graph-explorer?request=schemaExtensions/extj8xolrvw_linux&method=GET&version=v1.0&GraphUrl=https://graph.microsoft.com

The nss_aad lib looks at the following properties:
  * passwd lookups: 
    * user (string, linux login name)
    * passwd (string, advised to keep empty)
    * uid (integer, linux uid, must be unique)
    * gidnumber (integer, primary group gid)
    * gecos (string, may be empty)
    * homedir (string, e.g. /home/<user>)
    * shell (string, e.g. /bin/bash)

  * shadow lookups:
    * user (string, linux login name)

  * group lookups:
    * group (string, linux group name)
    * gid (integer, group gid)

Group members are obtained from the actual members in the AAD group; the members field in the extension is not used.


## build on work from others
this code is based on a lot of the work of https://github.com/gmjosack/nss_http, which is originally licensed with MIT license.
