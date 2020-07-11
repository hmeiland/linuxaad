
# Name Service Switch

Linux uses the Name Service Switch framework to allow applications to look up information for entities. These entities can be e.g. other hosts or protocols, but also users and groups. The NSS frameworks allows for several mechanisms to be used as fallbacks when the primary mechanism is not ble to provide an answer. For example, an ip-address lookup for a host will first try the local /etc/hosts file, and when the entry is not in there, it will try a dns request over the network. User information consist of:
 - username
 - password
 - user id
 - primary group id
 - gecos
 - home directory
 - shell  

For a more complete description of the passwd struct see https://man7.org/linux/man-pages/man5/passwd.5.html.

# Pluggable Authentication Mechanism

The Plugable Authentication Mechanism (PAM) is a framework where new sessions can verify authentication and authorization of users.

# Directory

To provide a consistent user and group information on different linux machines, a central directory is used. Several technologies have been created to provide directory information like YP, NIS, LDAP. Microsoft has implemented the LDAP protocol in its Active Directory product.
With the introduction of Azure Active Directory, an new protocol for directory information is being introduced: Microsoft Graph over HTTPS.

# NSS flow for user entries 
```
nsswitch.conf: 
passwd:     files

getent passwd user -> libnss_files -> 
  open /etc/passwd -> search line for user ->
  fill_passwd_struct -> user:x:1000:1000::/home/user:/bin/bash
```
```
nsswitch.conf:
passwd:     aad
getent passwd user -> libnss_aad ->
  open /etc/azuread/parameters.conf for app_id and secret ->
  get_bearer_token -> graph?filter='username=user' -> 
  fill_passwd_struct from json -> user:x:1000:1000::/home/user:/bin/bash 
```
```
nsswitch.conf:
passwd:     aad
getent passwd 1000 -> libnss_aad ->
  open /etc/azuread/parameters.conf for app_id and secret ->
  get_bearer_token -> graph.microsoft.com/v1.0/users?$filter=extj8xolrvw_linux/uid eq '1000'&$select=id,extj8xolrvw_linux
  fill_passwd_struct from json -> user:x:1000:1000::/home/user:/bin/bash 
```


# NSS flow for group entries
```
nsswitch.conf:
groups:     files

getent group mygroup -> libnss_files ->
  open /etc/groups -> search line for mygroup ->
  fill_group_struct -> mygroup:x:1000:user,otheruser
```
```
nsswitch.conf:
groups:     aad

getent group mygroup -> libnss_files ->
  open /etc/azuread/parameters.conf for app_id and secret ->
  get_bearer_token -> graph/groups/mygroup/members?$select=id,extj8xolrvw_linux -> 
  fill_group_struct from json -> mygroup:x:1000:user,otheruser 
```
```
nsswitch.conf:
groups:     aad

getent group 1000 -> libnss_files ->
  open /etc/azuread/parameters.conf for app_id and secret ->
  get_bearer_token -> graph.microsoft.com/v1.0/groups?$filter=extj8xolrvw_linux/gid eq '1000'&$select=id,extj8xolrvw_linux ->
  group = mygroup -> graph/groups/mygroup/members?$select=id,extj8xolrvw_linux -> 
  fill_group_struct from json -> mygroup:x:1000:user,otheruser 
```

