<!--
SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>

SPDX-License-Identifier: Apache-2.0
-->

# SOP-Java

Stateless OpenPGP Protocol for Java.

This module contains interfaces that model the API described by the 
[Stateless OpenPGP Command Line Interface](https://datatracker.ietf.org/doc/draft-dkg-openpgp-stateless-cli/) specification.

This module is not a command line application! For that, see `sop-java-picocli`.

## Why should I use this?

If you need to use OpenPGP functionality like encrypting/decrypting messages, or creating/verifying
signatures inside your application, you probably don't want to start from scratch and instead reuse some library.

Instead of locking yourselves in by depending hard on that one library, you can simply depend on the interfaces from
`sop-java` and plug in a library (such as `pgpainless-sop`) that implements said interfaces.

That way you don't make yourself dependent from a single OpenPGP library and stay flexible.
Should another library emerge, that better suits your needs (and implements `sop-java`), you can easily switch
by swapping out the dependency with minimal changes to your code.

## Why should I *implement* this?

Did you create an [OpenPGP](https://datatracker.ietf.org/doc/html/rfc4880) implementation that can be used in the Java ecosystem?
By implementing the `sop-java` interface, you can turn your library into a command line interface (see `sop-java-picocli`).
This allows you to plug your library into the [OpenPGP interoperability test suite](https://tests.sequoia-pgp.org/)
of the [Sequoia-PGP](https://sequoia-pgp.org/) project.