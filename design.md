
= Name Service Switch = 

Linux uses the Name Service Switch framework to allow applications to look up information for entities. These entities can be e.g. other hosts or protocols, but also users and groups. The NSS frameworks allows for several mechanisms to be used as fallbacks when the primary mechanism is not ble to provide an answer. For example, an ip-address lookup for a host will first try the local /etc/hosts file, and when the entry is not in there, it will try a dns request over the network. User information consist of:
 - username
 - uid
 - password
 - gecos
 - primary group
 - home directory
 - shell  

= Pluggable Authentication Mechanism =

The Plugable Authentication Mechanism (PAM) is a framework where new sessions can verify authentication and authorization of users.

= Directory = 

To provide a consistent user and group information on different linux machines, a central directory is used. Several technologies have been created to provide directory information like YP, NIS, LDAP. Microsoft has implemented the LDAP protocol in its Active Directory product.
With the introduction of Azure Active Directory, an new protocol for directory information is being introduced: Microsoft Graph over HTTPS.

