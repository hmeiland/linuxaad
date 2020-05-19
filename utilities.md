## useradd-aad

useradd-add is used to list and modify the linux properties of users in Azure Active Directory.

Listing users: `useradd-aad --list`

Listing users in passwd format: `useradd-aad --passwd`

```
$ useradd-aad --list
id                                      userPrincipalName               user    uid     gidnumber       homedir         shell
c7be0dfc-7905-41cc-a557-f7846e4583c9    testuser@microsoft.com          not_set not_set not_set         not_set         not_set
$ useradd-aad --add --id c7be0dfc-7905-41cc-a557-f7846e4583c9 testuser
$ useradd-aad --list
id                                      userPrincipalName               user    uid     gidnumber       homedir         shell
c7be0dfc-7905-41cc-a557-f7846e4583c9    testuser@microsoft.com          testuser 25001   25000          /home/testuser  /bin/bash
```

## groupadd-aad

groupadd-add is used to list and modify the linux properties of groups in Azure Active Directory.

Listing groups: `groupadd-aad --list`
