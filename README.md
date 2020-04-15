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
    * user (linux login name)
    * passwd (advised to keep empty)
    * uid (linux uid, must be unique)
    * gidnumber (primary group gid)
    * gecos (may be empty)
    * homedir (e.g. /home/<user>)
    * shell (e.g. /bin/bash)



## build on work from others
this code is based on a lot of the work of https://github.com/gmjosack/nss_http, which is originally licensed with MIT license.
