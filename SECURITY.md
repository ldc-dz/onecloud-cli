# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Report it privately through GitHub: on this repository, open the
**Security** tab, then **Report a vulnerability**
(<https://github.com/ldc-dz/onecloud-cli/security/advisories/new>).

Include what you can of:

- the affected `ocd` version (`ocd version`) and platform;
- the steps to reproduce, or a proof of concept;
- the impact you expect (what an attacker gains).

We acknowledge reports within 5 working days and keep you informed until a
fix is released. Please give us a reasonable delay to ship the fix before any
public disclosure.

## Supported versions

Only the latest stable release receives security fixes. Upgrade by running
the installer again (see the README).

## Scope

In scope: the `ocd` CLI, its installers (`install.sh`, `install.ps1`) and the
release artifacts published on this repository.

Out of scope: the OneCloud platform services themselves (portal, identity
provider, access gateway). Report those through your OneCloud support
contact.
