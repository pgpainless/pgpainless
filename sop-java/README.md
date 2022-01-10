<!--
SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>

SPDX-License-Identifier: Apache-2.0
-->

# SOP-Java

[![Spec Revision: 3](https://img.shields.io/badge/Spec%20Revision-3-blue)](https://datatracker.ietf.org/doc/html/draft-dkg-openpgp-stateless-cli-03)
[![Maven Central](https://badgen.net/maven/v/maven-central/org.pgpainless/sop-java)](https://search.maven.org/artifact/org.pgpainless/sop-java)
[![JavaDoc](https://badgen.net/badge/javadoc/yes/green)](https://pgpainless.org/releases/latest/javadoc/sop/SOP.html)
[![REUSE status](https://api.reuse.software/badge/github.com/pgpainless/pgpainless)](https://api.reuse.software/info/github.com/pgpainless/pgpainless)

Stateless OpenPGP Protocol for Java.

This module contains interfaces that model the API described by the 
[Stateless OpenPGP Command Line Interface](https://datatracker.ietf.org/doc/html/draft-dkg-openpgp-stateless-cli-03) specification.

This module is not a command line application! For that, see `sop-java-picocli`.

## Usage Examples

The API defined by `sop-java` is super straight forward:
```java
SOP sop = ... // e.g. new org.pgpainless.sop.SOPImpl();
        
// Generate an OpenPGP key
byte[] key = sop.generateKey()
        .userId("Alice <alice@example.org>")
        .generate()
        .getBytes();

// Extract the certificate (public key)
byte[] cert = sop.extractCert()
        .key(key)
        .getBytes();

// Encrypt a message
byte[] message = ...
byte[] encrypted = sop.encrypt()
        .withCert(cert)
        .signWith(key)
        .plaintext(message)
        .getBytes();

// Decrypt a message
ByteArrayAndResult<DecryptionResult> messageAndVerifications = sop.decrypt()
        .verifyWith(cert)
        .withKey(key)
        .ciphertext(encrypted)
        .toByteArrayAndResult();
byte[] decrypted = messageAndVerifications.getBytes();
// Signature Verifications
DecryptionResult messageInfo = messageAndVerifications.getResult();
List<Verification> signatureVerifications = messageInfo.getVerifications();
```

Furthermore, the API is capable of signing messages and verifying unencrypted signed data, as well as adding and removing ASCII armor.

### Limitations
As per the spec, sop-java does not (yet) deal with encrypted OpenPGP keys.

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
