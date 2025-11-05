# SSSD operator

[![sssd charm tests](https://github.com/canonical/sssd-operator/actions/workflows/ci.yaml/badge.svg)](https://github.com/canonical/sssd-operator/actions/workflows/ci.yaml)
[![Release to `latest/edge` channel on Charmhub](https://github.com/canonical/sssd-operator/actions/workflows/release.yaml/badge.svg)](https://github.com/canonical/sssd-operator/actions/workflows/release.yaml)
![GitHub License](https://img.shields.io/github/license/canonical/sssd-operator)
[![Matrix](https://img.shields.io/matrix/ubuntu-hpc%3Amatrix.org?logo=matrix&label=ubuntu-hpc)](https://matrix.to/#/#hpc:ubuntu.com)

A [Juju](https://juju.is) charm for automating the full lifecycle operations of 
[SSSD](https://sssd.io) (System Security Services Daemon), a system service to access 
remote directories and authentication mechanisms such as LDAP, Kerberos, or FreeIPA.

## ✨ Getting Started

To deploy the SSSD operator, you'll need to integrate it with a principal charm:

```shell
juju deploy ubuntu --base ubuntu@24.04
juju deploy sssd --channel edge
juju integrate sssd ubuntu
```

The sssd-operator can integrate with the [glauth-k8s-operator](https://github.com/canonical/glauth-k8s-operator) over the ldap integration. If glauth-k8s is deployed properly, then the principal charm sssd is integrated with will be provided ldap services by glauth-k8s:

```shell
juju integrate glauth-k8s:ldap sssd:ldap
```

## 🤔 What's next?

If you want to learn more about all the things you can do with the SSSD operator,
or have any further questions on what you can do with the operator, here are some
further resources for you to explore:

* [Charmed HPC documentation](https://documentation.ubuntu.com/charmed-hpc)
* [Open an issue](https://github.com/canonical/sssd-operator/issues/new?title=ISSUE+TITLE&body=*Please+describe+your+issue*)
* [Ask a question on GitHub](https://github.com/orgs/charmed-hpc/discussions/categories/q-a)

## 🛠️ Development

This project uses [tox](https://tox.wiki) for development. You can install it with:

```shell
pip install tox
```

The project provides several useful commands that will help you while hacking on the SSSD operator:

```shell
tox -e fmt           # Apply formatting standards to code.
tox -e lint          # Check code against coding style standards.
tox -e typecheck     # Run static type checks.
tox -e unit          # Run unit tests.
```

To run the SSSD operator integration tests, you'll need to have both
[Juju](https://juju.is) and [LXD](https://ubuntu.com/lxd) installed
on your machine:

```shell
tox -e integration   # Run integration tests.
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
* [Get the latest news on Discourse](https://discourse.ubuntu.com/c/hpc/151)
* [Ask and answer questions on GitHub](https://github.com/orgs/charmed-hpc/discussions/categories/q-a)

## 📋 License

The SSSD operator is free software, distributed under the Apache Software License, version 2.0.
See the [Apache-2.0 LICENSE](./LICENSE) file for further details.

SSSD is licensed under the GNU General Public License, version 3.0. 
See the upstream SSSD [COPYING](https://github.com/SSSD/sssd/blob/master/COPYING) file
for further licensing information about SSSD.