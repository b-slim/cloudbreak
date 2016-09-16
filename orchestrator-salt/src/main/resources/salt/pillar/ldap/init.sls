ldap:
  name: "my-ldap"
  description: "my ldap"
  serverHost: "10.0.3.138"
  serverPort: 389
  serverSSL: false
  bindDn: "CN=Administrator,CN=Users,DC=ad,DC=apache,DC=org"
  bindPassword: "Password!"
  userSearchBase: "CN=Users,DC=ad,DC=apache,DC=org"
  userSearchFilter: "&amp;(objectclass=person)(sAMAccountName={2}))"
  groupSearchBase: "DC=hadoop,DC=apache,DC=org"
  groupSearchFilter: "string"
  principalRegex: "string"
  id: -1
  public: false
  userClass: person
  userAttribute: uid
  groupClass: group
  groupAttribute: cn
  memberAttribute: member
  distinguishName: distinguishName
  baseDistinguishName: "DC=ad,dc=apache,dc=org"