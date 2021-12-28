<!--
SPDX-FileCopyrightText: 2021 Paul Schaub <info@pgpainless.org>

SPDX-License-Identifier: Apache-2.0
-->

# PGPainless - Use OpenPGP Painlessly!

[![Travis (.com)](https://travis-ci.com/pgpainless/pgpainless.svg?branch=master)](https://travis-ci.com/pgpainless/pgpainless)
[![Maven Central](https://badgen.net/maven/v/maven-central/org.pgpainless/pgpainless-core)](https://search.maven.org/artifact/org.pgpainless/pgpainless-core)
[![Coverage Status](https://coveralls.io/repos/github/pgpainless/pgpainless/badge.svg?branch=master)](https://coveralls.io/github/pgpainless/pgpainless?branch=master)
[![JavaDoc](https://badgen.net/badge/javadoc/yes/green)](https://pgpainless.org/releases/latest/javadoc/)
[![Interoperability Test-Suite](https://badgen.net/badge/Sequoia%20Test%20Suite/%232/green)](https://tests.sequoia-pgp.org/)
[![PGP](https://img.shields.io/badge/pgp-A027%20DB2F%203E1E%20118A-blue)](https://keyoxide.org/7F9116FEA90A5983936C7CFAA027DB2F3E1E118A)
[![REUSE status](https://api.reuse.software/badge/github.com/pgpainless/pgpainless)](https://api.reuse.software/info/github.com/pgpainless/pgpainless)
## About

PGPainless aims to make using OpenPGP in Java projects as simple as possible.
It does so by introducing an intuitive Builder structure, which allows easy 
setup of encryption/decryption operations, as well as straight forward key generation.

PGPainless is based around the Bouncycastle java library and can be used on Android down to API level 10.
It can be configured to either use the Java Cryptographic Engine (JCE), or Bouncycastles lightweight reimplementation.

While signature verification in Bouncycastle is limited to signature correctness, PGPainless goes much further.
It also checks if signing subkeys are properly bound to their primary key, if keys are expired or revoked, as well as
if keys are allowed to create signatures in the first place.

These rigorous checks make PGPainless stand out from other Java-based OpenPGP libraries and are the reason why
PGPainless currently [*scores second place* on Sequoia-PGPs Interoperability Test-Suite](https://tests.sequoia-pgp.org).

> At FlowCrypt we are using PGPainless in our Kotlin code bases on Android and on server side.
> The ergonomics of legacy PGP tooling on Java is not very good, and PGPainless improves it greatly.
> We were so happy with our initial tests and with Paul - the maintainer, that we decided to sponsor further development of this library.
>
> -Tom @ FlowCrypt.com

> Finally, testing irrefutably confirmed that the library removes many associated difficulties with PGP use in its provision of an approachable and uncomplicated API.
> In this regard, Paul Schaub deserves the utmost praise.
>
> -Mario @ Cure53.de

## Features

Most of PGPainless' features can be accessed directly from the `PGPainless` class.
If you want to get started, this class is your friend :)

For further details you should check out the [javadoc](https://pgpainless.org/releases/latest/javadoc/)!

### Handle Keys
Reading keys from ASCII armored strings or from binary files is easy:

```java
        String key = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"...
        PGPSecretKeyRing secretKey = PGPainless.readKeyRing()
                .secretKeyRing(key);
```

Similarly, keys can quickly be exported::

```java
        PGPSecretKeyRing secretKey = ...;
        String armored = PGPainless.asciiArmor(secretKey);
        ByteArrayOutputStream binary = new ByteArrayOutputStream();
        secretKey.encode(binary);
```

Extract a public key certificate from a secret key:

```java
        PGPSecretKeyRing secretKey = ...;
        PGPPublicKeyRing certificate = PGPainless.extractCertificate(secretKey);
```

### Easily Generate Keys
PGPainless comes with a simple to use `KeyRingBuilder` class that helps you to quickly generate modern OpenPGP keys.
There are some predefined key archetypes, but it is possible to fully customize key generation to your needs.

```java
        // RSA key without additional subkeys
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .simpleRsaKeyRing("Juliet <juliet@montague.lit>", RsaLength._4096);
                
        // EdDSA primary key with EdDSA signing- and XDH encryption subkeys
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("Romeo <romeo@montague.lit>", "I defy you, stars!");

        // Customized key
        PGPSecretKeyRing keyRing = PGPainless.buildKeyRing()
                .setPrimaryKey(KeySpec.getBuilder(
                        RSA.withLength(RsaLength._8192),
                        KeyFlag.SIGN_DATA, KeyFlag.CERTIFY_OTHER))
                .addSubkey(
                        KeySpec.getBuilder(ECDSA.fromCurve(EllipticCurve._P256), KeyFlag.SIGN_DATA)
                                .overrideCompressionAlgorithms(CompressionAlgorithm.ZLIB)
                ).addSubkey(
                        KeySpec.getBuilder(
                                        ECDH.fromCurve(EllipticCurve._P256),
                                        KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE)
                ).addUserId("Juliet <juliet@montague.lit>")
                .addUserId("xmpp:juliet@capulet.lit")
                .setPassphrase("romeo_oh_Romeo<3")
                .build();
```

### Encrypt and Sign Data
PGPainless makes it easy and painless to encrypt and/or sign data.
Passed in keys are automatically evaluated, so that you don't accidentally encrypt to revoked or expired keys.
PGPainless will furthermore detect which algorithms are supported by recipient keys and will negotiate
algorithms accordingly.
Still it allows you to manually specify which algorithms to use of course.

```java
        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                .onOutputStream(outputStream)
                .withOptions(
                        ProducerOptions.signAndEncrypt(
                                new EncryptionOptions()
                                        .addRecipient(aliceKey)
                                        .addRecipient(bobsKey)
                                        // optionally encrypt to a passphrase
                                        .addPassphrase(Passphrase.fromPassword("password123"))
                                        // optionally override symmetric encryption algorithm
                                        .overrideEncryptionAlgorithm(SymmetricKeyAlgorithm.AES_192),
                                new SigningOptions()
                                        // Sign in-line (using one-pass-signature packet)
                                        .addInlineSignature(secretKeyDecryptor, aliceSecKey, signatureType)
                                        // Sign using a detached signature
                                        .addDetachedSignature(secretKeyDecryptor, aliceSecKey, signatureType)
                                        // optionally override hash algorithm
                                        .overrideHashAlgorithm(HashAlgorithm.SHA256)
                        ).setAsciiArmor(true) // Ascii armor or not
                );

        Streams.pipeAll(plaintextInputStream, encryptionStream);
        encryptionStream.close();

        // Information about the encryption (algorithms, detached signatures etc.)
        EncryptionResult result = encryptionStream.getResult();
```

### Decrypt and Verify Signatures

Decrypting data and verifying signatures is being done similarly.
PGPainless will not only verify *correctness* of signatures, but also if the signing key was allowed to create the signature.
A key might not be allowed to create signatures if, for example, it expired or was revoked, or was not properly bound to the key ring.
Furthermore, PGPainless will reject signatures made using weak algorithms like SHA-1. 
This behaviour can be modified though using the `Policy` class.

```java
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(encryptedInputStream)
                .withOptions(new ConsumerOptions()
                        .addDecryptionKey(bobSecKeys, secretKeyProtector)
                        .addVerificationCert(alicePubKeys)
                );

        Streams.pipeAll(decryptionStream, outputStream);
        decryptionStream.close();

        // Result contains information like signature status etc.
        OpenPgpMetadata metadata = decryptionStream.getResult();
```

*After* the `DecryptionStream` was closed, you can get metadata about the processed data by retrieving the `OpenPgpMetadata`.
Again, this object will contain information about how the message was encrypted, who signed it and so on.

#### Many more examples can be found in the [examples package](pgpainless-core/src/test/java/org/pgpainless/example)!!!

## Include PGPainless in your Project

PGPainless is available on maven central. In order to include it in your project, just add the 
maven central repository and add PGPainless as a dependency.

```gradle
repositories {
	mavenCentral()
}

dependencies {
	implementation 'org.pgpainless:pgpainless-core:1.0.0'
}
```

## About
PGPainless is a by-product of my [Summer of Code 2018 project](https://blog.jabberhead.tk/summer-of-code-2018/)
implementing OpenPGP support for the XMPP client library [Smack](https://github.com/igniterealtime/Smack).
For that project I was in need of a simple-to-use OpenPGP library.

Originally I was going to use [Bouncy-GPG](https://github.com/neuhalje/bouncy-gpg) for my project,
but ultimately I decided to create my own OpenPGP library which better fits my needs.

However, PGPainless was heavily influenced by Bouncy-GPG.

To reach out to the development team, feel free to send a mail: info@pgpainless.org

## Development
PGPainless is developed in - and accepts contributions from - the following places:

* [Github](https://github.com/pgpainless/pgpainless)
* [Codeberg](https://codeberg.org/PGPainless/pgpainless)

Please follow the [code of conduct](CODE_OF_CONDUCT.md) if you want to be part of the project.

## Acknowledgements
Development on PGPainless is generously sponsored by [FlowCrypt.com](https://flowcrypt.com). Thank you very very very much!

Continuous Integration is kindly provided by [Travis-CI.com](https://travis-ci.com/).
