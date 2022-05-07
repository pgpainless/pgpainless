<!--
SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>

SPDX-License-Identifier: Apache-2.0
-->

# PGPainless-CLI

[![javadoc](https://javadoc.io/badge2/org.pgpainless/pgpainless-cli/javadoc.svg)](https://javadoc.io/doc/org.pgpainless/pgpainless-cli)

PGPainless-CLI is an implementation of the [Stateless OpenPGP Command Line Interface](https://datatracker.ietf.org/doc/draft-dkg-openpgp-stateless-cli/) specification based on PGPainless.

It plugs `pgpainless-sop` into `sop-java-picocli`.

## Build
To build an executable, `gradle jar` should be sufficient. The resulting jar file can be found in `pgpainless-sop/build/libs/`.

## Execute

The jar file produced in the step above is executable as is.

```
java -jar pgpainless-cli-XXX.jar help
```

Alternatively you can use the provided `./pgpainless-cli` script to directly build and execute PGPainless' Stateless Command Line Interface from within Gradle.

To discover all available commands use

```
./pgpainless-cli help
```

Enjoy!
