<!--
SPDX-FileCopyrightText: 2022 Paul Schaub <info@pgpainless.org>

SPDX-License-Identifier: Apache-2.0
-->

# Shared PGP Certificate Directory for Java

Backend-agnostic implementation of the [Shared PGP Certificate Directory Specification](https://sequoia-pgp.gitlab.io/pgp-cert-d/).
This module implements the non-OpenPGP parts of the spec, e.g. locating the directory, resolving certificate file paths,
locking the directory for writes etc.

To get a useful implementation, a backend implementation such as `pgpainless-cert-d` is required, which needs to provide
support for reading and merging certificates.

`pgp-cert-d-java` can be used as an implementation of `pgp-certificate-store`.