# sssd-operator

[![CharmHub Badge](https://charmhub.io/sssd/badge.svg)](https://charmhub.io/sssd)

Charmhub package name: sssd-operator
More information: https://charmhub.io/sssd-operator

SSSD OPERATOR.

This operator provides a connection to SSSD.

Utilizes a requires integration to connect to the server.

## Usage

You can deploy the operator as such:

```shell
# Deploy the charm
$ juju deploy sssd --channel edge
```

Since the sssd-operator is a subordinate it cannot be deployed alone and can be integrated with any charm with the juju-info integration as such:

```shell
juju integrate sssd:juju-info ubuntu:juju-info
```

## Integrations

The sssd-operator can integrate with the glauth-operator over the ldap-client integration. If glauth is deployed properly, then the principal charm sssd is integrated with will be provided ldap services by glauth.

```shell
juju integrate glauth:ldap-client sssd:ldap-client
```
