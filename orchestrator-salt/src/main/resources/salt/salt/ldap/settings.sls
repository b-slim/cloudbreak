{% set name = salt['pillar.get']('ldap:name') %}
{% set description = salt['pillar.get']('ldap:description') %}
{% set serverHost = salt['pillar.get']('ldap:serverHost') %}
{% set serverPort = salt['pillar.get']('ldap:serverPort') %}
{% set serverSSL = salt['pillar.get']('ldap:serverSSL') %}
{% set bindDn = salt['pillar.get']('ldap:bindDn') %}
{% set bindPassword = salt['pillar.get']('ldap:bindPassword') %}
{% set userSearchBase = salt['pillar.get']('ldap:userSearchBase') %}
{% set userSearchFilter = salt['pillar.get']('ldap:userSearchFilter') %}
{% set groupSearchBase = salt['pillar.get']('ldap:groupSearchBase') %}
{% set groupSearchFilter = salt['pillar.get']('ldap:groupSearchFilter') %}
{% set principalRegex = salt['pillar.get']('ldap:principalRegex') %}
{% set userClass = salt['pillar.get']('ldap:userClass') %}
{% set userAttribute = salt['pillar.get']('ldap:userAttribute') %}
{% set groupClass = salt['pillar.get']('ldap:groupClass') %}
{% set groupAttribute = salt['pillar.get']('ldap:groupAttribute') %}
{% set memberAttribute = salt['pillar.get']('ldap:memberAttribute') %}
{% set distinguishName = salt['pillar.get']('ldap:distinguishName') %}
{% set baseDistinguishName = salt['pillar.get']('ldap:baseDistinguishName') %}

{% set ldap = {} %}
{% do ldap.update({
    'name': name,
    'description': description,
    'serverHost': serverHost,
    'serverPort': serverPort,
    'serverSSL': serverSSL,
    'bindDn': bindDn,
    'bindPassword': bindPassword,
    'userSearchBase': userSearchBase,
    'userSearchFilter': userSearchFilter,
    'groupSearchBase': groupSearchBase,
    'groupSearchFilter': groupSearchFilter,
    'principalRegex': principalRegex,
    'userClass': userClass,
    'userAttribute': userAttribute,
    'groupClass': groupClass,
    'groupAttribute': groupAttribute,
    'memberAttribute': memberAttribute,
    'distinguishName': distinguishName,
    'baseDistinguishName': baseDistinguishName
}) %}