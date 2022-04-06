<!--
SPDX-FileCopyrightText: 2022 Paul Schaub <info@pgpainless.org>

SPDX-License-Identifier: Apache-2.0
-->

# Ecosystem

PGPainless consists of an ecosystem of different libraries and projects.

## [PGPainless](https://github.com/pgpainless/pgpainless)

The main repository contains the following components:

* `pgpainless-core` - core implementation - powerful, yet easy to use OpenPGP API
* `pgpainless-sop` - super simple OpenPGP implementation. Drop-in for `sop-java`
* `pgpainless-cli` - SOP CLI implementation using PGPainless

## [SOP-Java](https://github.com/pgpainless/sop-java)

An API definition and CLI implementation of the [Stateless OpenPGP Protocol](https://www.ietf.org/archive/id/draft-dkg-openpgp-stateless-cli-03.html).

* `sop-java` - generic OpenPGP API definition
* `sop-java-picocli` - Abstract CLI implementation for `sop-java`

## [WKD-Java](https://github.com/pgpainless/wkd-java)

Implementation of the [Web Key Directory](https://www.ietf.org/archive/id/draft-koch-openpgp-webkey-service-13.html).

* `wkd-java` - abstract WKD discovery implementation
* `wkd-java-cli` - CLI application implementing WKD discovery using PGPainless
* `wkd-test-suite` - Generator for test vectors for testing WKD implementations

## [VKS-Java](https://github.com/pgpainless/vks-java)

Client-side API for communicating with Verifying Key Servers, such as https://keys.openpgp.org/.

* `vks-java` - VKS client implementation

## [Cert-D-Java](https://github.com/pgpainless/cert-d-java)

Implementations of the [Shared OpenPGP Certificate Directory specification](https://sequoia-pgp.gitlab.io/pgp-cert-d/).

* `pgp-certificate-store` - abstract definitions of OpenPGP certificate stores
* `pgp-cert-d-java` - implementation of `pgp-certificate-store` following the PGP-CERT-D spec.
* `pgp-cert-d-java-jdbc-sqlite-lookup` - subkey lookup using sqlite database

## [Cert-D-PGPainless](https://github.com/pgpainless/cert-d-pgpainless)

Implementation of the [Shared OpenPGP Certificate Directory specification](https://sequoia-pgp.gitlab.io/pgp-cert-d/) using PGPainless.

* `pgpainless-cert-d` - PGPainless-based implementation of `pgp-cert-d-java`.
* `pgpainless-cert-d-cli` - CLI frontend for `pgpainless-cert-d`.