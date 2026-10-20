# SSSD operator

[![sssd charm tests](https://github.com/canonical/sssd-operator/actions/workflows/ci.yaml/badge.svg)](https://github.com/canonical/sssd-operator/actions/workflows/ci.yaml)
[![Release to `latest/edge` channel on Charmhub](https://github.com/canonical/sssd-operator/actions/workflows/release.yaml/badge.svg)](https://github.com/canonical/sssd-operator/actions/workflows/release.yaml)
![GitHub License](https://img.shields.io/github/license/canonical/sssd-operator)
[![Matrix](https://img.shields.io/matrix/ubuntu-hpc%3Amatrix.org?logo=matrix&label=ubuntu-hpc)](https://matrix.to/#/#hpc:ubuntu.com)

A [Juju](https://canonical.com/juju) charm for automating the full lifecycle operations of
[SSSD](https://sssd.io) (System Security Services Daemon), a system service to access
remote directories and authentication mechanisms such as LDAP, Kerberos, or FreeIPA.

## ✨ Getting Started

To deploy the SSSD operator, you'll need to integrate it with a principal charm:

```shell
juju deploy ubuntu --base ubuntu@26.04
juju deploy sssd --channel latest/edge
juju integrate sssd ubuntu
```

The SSSD operator is the client side of the identity provider component for a [Charmed HPC](https://ubuntu.com/hpc/docs)
cluster. Integrated with a principal charm, it enrolls that machine with a remote 
LDAP directory so that your cluster's users can log into the machine with their LDAP credentials.
The operator supports the following integrations:

- `ldap`: receive LDAP configuration data from an identity provider. The recommended
  identity provider for Charmed HPC clusters is
  [Authentik](https://github.com/canonical/authentik-ldap-outpost-operator), whose
  LDAP outpost serves the LDAP directory that SSSD enrolls your machines with.
- `receive-ca-cert`: receive the CA certificate that signs the identity provider's
  TLS certificate. This integration is needed with Charmed Authentik because it serves
  LDAPS (TLS-encrypted LDAP) by default.
- `ssh-config`: provide SSH daemon configuration to charmed operators such as
  [OpenSSH](https://charmhub.io/openssh) to enable SSH key-based authentication for
  your cluster's users.

Deploying a working Authentik deployment is more involved than deploying a single
charm, so refer to the
[Deploy an identity provider](https://ubuntu.com/hpc/docs/latest/howto/deploy/deploy-identity-provider/)
how-to in the Charmed HPC documentation for complete instructions on deploying
Authentik, integrating it with SSSD, and enabling SSH key-based authentication. Once
deployed, refer to the
[Manage users and groups](https://ubuntu.com/hpc/docs/latest/howto/manage/manage-users-and-groups/)
how-to for instructions on managing your cluster's users and groups with the Authentik
Terraform provider, including setting users' default login shells and public SSH keys.

## 🤔 What's next?

If you want to learn more about all the things you can do with the SSSD operator,
or have any further questions on what you can do with the operator, here are some
further resources for you to explore:

* [Charmed HPC documentation](https://ubuntu.com/hpc/docs/latest)
* [Open an issue](https://github.com/canonical/sssd-operator/issues/new?title=ISSUE+TITLE&body=*Please+describe+your+issue*)
* [Ask a question](https://discourse.ubuntu.com/c/project/hpc/151)

## 🛠️ Development

This project uses [uv](https://docs.astral.sh/uv/) and [just](https://just.systems) for development. You can install them with:

```shell
sudo snap install astral-uv --classic
sudo snap install just --classic
```

The project provides several useful commands that will help you while hacking on the SSSD operator:

```shell
just fmt           # Apply formatting standards to code.
just lint          # Check code against coding style standards.
just typecheck     # Run static type checks.
just unit          # Run unit tests.
```

To run the SSSD operator integration tests, you'll need to have both
[Juju](https://juju.is) and [LXD](https://ubuntu.com/lxd) installed
on your machine:

```shell
just integration   # Run integration tests.
```

If you're interested in contributing, take a look at our [contributing guidelines](./CONTRIBUTING.md).

## 🤝 Project and community

The SSSD operator is a project of the [Ubuntu High-Performance Computing community](https://ubuntu.com/community/governance/teams/hpc).
Interested in contributing bug fixes, patches, documentation, or feedback? Want to join the
Ubuntu HPC community? You've come to the right place 🤩

Here's some links to help you get started with joining the community:

* [Ubuntu Code of Conduct](https://ubuntu.com/community/ethos/code-of-conduct)
* [Contributing guidelines](./CONTRIBUTING.md)
* [Join the conversation on Matrix](https://matrix.to/#/#hpc:ubuntu.com)
* [Get the latest news or ask and answer questions on the Ubuntu Discourse](https://discourse.ubuntu.com/c/project/hpc/151)

## 📋 License

The SSSD operator is free software, distributed under the Apache Software License, version 2.0.
See the [Apache-2.0 LICENSE](./LICENSE) file for further details.

SSSD is licensed under the GNU General Public License, version 3.0.
See the upstream SSSD [COPYING](https://github.com/SSSD/sssd/blob/master/COPYING) file
for further licensing information about SSSD.
