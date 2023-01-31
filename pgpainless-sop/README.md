<!--
SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>

SPDX-License-Identifier: Apache-2.0
-->

# PGPainless-SOP

[![Spec Revision: 4](https://img.shields.io/badge/Spec%20Revision-4-blue)](https://datatracker.ietf.org/doc/draft-dkg-openpgp-stateless-cli/)
[![Maven Central](https://badgen.net/maven/v/maven-central/org.pgpainless/pgpainless-sop)](https://search.maven.org/artifact/org.pgpainless/pgpainless-sop)
[![javadoc](https://javadoc.io/badge2/org.pgpainless/pgpainless-sop/javadoc.svg)](https://javadoc.io/doc/org.pgpainless/pgpainless-sop)

Implementation of the Stateless OpenPGP Protocol using PGPainless.

This module implements `sop-java` using `pgpainless-core`.
If your code depends on `sop-java`, this module can be used as a realization of those interfaces.

## Get started

To start using pgpainless-sop in your code, include the following lines in your build script:
```
// If you use Gradle
...
dependencies {
    ...
    implementation "org.pgpainless:pgpainless-sop:1.4.3"
    ...
}

// If you use Maven
...
<dependencies>
    ...
    <dependency>
        <groupId>org.pgpainless</groupId>
        <artifactId>pgpainless-sop</artifactId>
        <version>1.4.3</version>
    </dependency>
    ...
</dependencies>
```

`pgpainless-sop` will transitively pull in its dependencies, such as `sop-java` and `pgpainless-core`.

## Usage Examples
```java
SOP sop = new SOPImpl();
        
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
