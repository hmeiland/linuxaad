# linuxaad
Libnss, pam and utils for Azure Active Directory support for Linux.


## login example

![login with ssh and device code](screenshots/login.png)
![showing ls, id and getent](screenshots/ls-id-getent.png)

## Azure Active Directory Schema Extension

To host the linux properties in Azure Active Directory (Microsoft Graph), the following schema extension is used:
https://developer.microsoft.com/en-us/graph/graph-explorer?request=schemaExtensions/extj8xolrvw_linux&method=GET&version=v1.0&GraphUrl=https://graph.microsoft.com.
This extension is now in status Available and thus usable in any Azure Active Directory Tenant.


The libnss_aad lib looks at the following properties:
  * passwd lookups: 
    * user (string, linux login name)
    * passwd (string, advised to keep empty)
    * uid (integer, linux uid, must be unique)
    * gidnumber (integer, primary group gid)
    * gecos (string, may be empty)
    * homedir (string, e.g. /home/\<user\>)
    * shell (string, e.g. /bin/bash)

  * shadow lookups:
    * user (string, linux login name)

  * group lookups:
    * group (string, linux group name)
    * gid (integer, group gid)

Group members are obtained from the actual members in the AAD group; the members field in the extension is not used.

## Utilities for modifying the schema

To enable and use the schema extension properties for users and groups, some utilities have been created. These utilities are described here: [Utilities](utilities.md)

## Azure AD Connect

As an alternative the aad_attribute branch now support the AD attributes from Azure AD Connect to store the posix values. This allows all posix attributes from the AD to be added to the AAD automaticly, withou needing a schema extension. Also the App registration is being done by Azure AD Connect. The only change is the UID attribute: in AD this is a multi-value attribute which is not supported properly in AAD at this time. As an alternative the CN attribute is being used here.
   
## App registration

To give the libnss_aad and pam_aad libraries access to the Azure Active Directory (Microsoft Graph), they should be registred as apps and given permission to read user properties. 
This can be done through the Azure Portal. The steps required are described here: [App Registration](app-registration.md)

![apps](screenshots/registered-apps.png)

## installing and enabling

Libnss_aad.so.2.0 must be placed in /usr/lib64 for CentOS or /usr/lib/x86_64-linux-gnu/ for Ubuntu and to ensure compatibility, softlinks to libnss_aad.so and libnss_aad.so.2 should be created.
In /etc/nsswitch.conf, 'aad' must be added to the passwd, shadow and group entries.

![nssswitch.conf](screenshots/nsswitch-conf.png)

Pam_aad.so must be placed in /usr/lib64/security. To use pam_aad with ssh, add the line "auth sufficient pam_aad.so" to the /etc/pam.d/sshd file. 
Also make sure to enable "PasswordAuthentication yes" in /etc/ssh/sshd_config.

![sshd](screenshots/pam-d-sshd.png)

To make it easy to deploy, an rpm has been created which basicly does all the above steps. See [linuxaad-0.1-2.x86_64.rpm](https://github.com/hmeiland/linuxaad/releases/download/v0.1/linuxaad-0.1-2.x86_64.rpm).

Both libraries use the /etc/azuread/parameters.json file to look up the tenant, the client-id. Libnss_aad also uses the client secret to get access to the user properties in Azure Active Directory.

    {
       "authority": "https://login.microsoftonline.com/<your AAD tenant name>",
       "client_id": "<your client id>",
       "scope": [ "https://graph.microsoft.com/.default" ],
       "secret": "<your client secret>",
       "endpoint": "https://graph.microsoft.com/v1.0/users"
    }


## build on work from others
This code is based on a lot of the work of https://github.com/gmjosack/nss_http, which is originally licensed with MIT license.
