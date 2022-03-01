<!--
SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>

SPDX-License-Identifier: Apache-2.0
-->

# PGPainless-Core

[![javadoc](https://javadoc.io/badge2/org.pgpainless/pgpainless-core/javadoc.svg)](https://javadoc.io/doc/org.pgpainless/pgpainless-core)
[![Maven Central](https://badgen.net/maven/v/maven-central/org.pgpainless/pgpainless-core)](https://search.maven.org/artifact/org.pgpainless/pgpainless-core)

Wrapper around Bouncy Castle's OpenPGP implementation.

## Protection Against Attacks

PGPainless aims to fulfill the primary goals of cryptography:
* Confidentiality through message encryption
* Authenticity through signatures
* Integrity through the use of Modification Detection Code and again signatures

In short: Communication protected using PGPainless is intended to be private,
users can verify that messages they receive were really send by their communication peer
and users can verify that messages have not been tampered with.

This is being achieved by preventing a number of typical attacks on the user's communication,
like the attacker introducing an evil subkey to the victims public key, or the attacker creating
counterfeit signatures to fool the victim.

Due to its nature as a library however, it does not make sense to set up defences against all possible
attack types (see below).
So here is a threat model that best applies to PGPainless.

### Threat Model
A threat model that makes the most sense for PGPainless would be an evil attacker using PGPainless
through a benign client application (like an email app) on a trustworthy device.

The attacker can try to feed the application malicious input (like manipulated public key updates,
specially crafted PGP message objects etc.) but they cannot access the victims decrypted secret key material as
it is protected by the device (e.g. stored in a secure key store).

### What doesn't PGPainless Protect Against?

#### Brute Force Attacks
It was decided that protection against brute force attacks on passwords used in symmetric encryption
(password encrypted messages/keys) are out of scope for PGPainless.
PGPainless cannot limit access to the ciphertext that is being brute forced, as that is provided by
the application that uses PGPainless.
Therefore, protection against brute force attacks must be employed by the application itself.

#### (Public) Key Modification Attacks
As a library, PGPainless cannot protect against swapped out public keys.
It is therefore responsibility of the consumer to ensure that an attacker on the same system cannot tamper with stored keys.
It is highly advised to store both secret and public keys in a secure key storage which protects against modifications.

Furthermore, PGPainless cannot verify key authenticity, so it is up to the application that uses PGPainless to check,
if a key really belongs to a certain user.
