# Proposal

## Application Name
OpenPGP Smart Card Support for Bouncy Castle and PGPainless

## Short Description
This project aims to extend Bouncy Castles OpenPGP implementation to enable managing and using secret key material
stored on external devices, such as OpenPGP Smart Cards and to reintegrate this support into PGPainless.

## Detailed Description

### Introduction to Concerned Software Components

[Bouncy Castle](https://www.bouncycastle.org/about/) by KeyFactor is a Java library implementing a multitude of
cryptographic algorithms and protocols.
It provides APIs for the OpenPGP protocol both in a high-level and a low-level manner.
It is licensed under the MIT license.

[PGPainless](https://pgpainless.org/) is an OpenPGP library written in Kotlin and based on Bouncy Castle.
It aims to make using OpenPGP in the Java/Kotlin ecosystem as easy as possible by providing a high-level API with sane
defaults.
it is licensed under the Apache-2.0 license.

[YubiKit](https://developers.yubico.com/yubikit-android/) by Yubico is a Kotlin library by Yubico, intended to
communicate with Yubikey hardware tokens.
It is licensed under the Apache-2.0 license.

### Evaluation of the Current Situation
Bouncy Castle's OpenPGP API currently relies solely upon "software-keys", that is Transferable Secret Key
([TSK](https://www.rfc-editor.org/rfc/rfc9580.html#name-transferable-secret-keys)) objects where the private key
material is stored either encrypted or in plaintext as part of the TSK object itself.
Hardware-keys on the other hand are TSK objects that do not contain the private key material, neither in plaintext nor
encrypted form, and instead have the private key material moved to some external device, such as an OpenPGP Smart Card.
Compared to software keys, hardware keys can prevent the extraction of the private key material, be it by an attacker,
or by [accident](https://www.golem.de/news/verschluesselung-bsi-verschickt-privaten-pgp-schluessel-2111-161073.html).

Unfortunately, the way for implementations to signal, that a private key is stored on a hardware device is not really
standardized. 
GnuPG defines its own proprietary way through an
[extension of the S2K mechanism](https://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob;f=doc/DETAILS;hb=5d855f76c8af280f0a2b01d64283a9efa0f5d795#l1560).
There are efforts to create a similar, well standardized and documented
[mechanism](https://www.ietf.org/archive/id/draft-dkg-openpgp-external-secrets-02.html) through the IETF
standardization process.
Bouncy Castle already supports the GNU method, but throughout this project, it shall be extended to support the latter
mechanism as well.

Bouncy Castle in its current form cannot be used with hardware keys, as most of its APIs for generating keys,
creating bindings or certifications, signing and decrypting messages do expect a private software key
([PGPPrivateKey](https://github.com/bcgit/bc-java/blob/main/pg/src/main/java/org/bouncycastle/openpgp/PGPPrivateKey.java)).
In order to allow for hardware keys to be used, said APIs need to be extended to allow passing in public keys instead,
such that backend implementations that can handle hardware keys can delegate cryptographic operations to hardware
devices instead.

The [Functional Specification of the OpenPGP application on ISO Smart Card Operating Systems](https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf)
defines, how applications communicate with Smart Cards.
It is neither in-scope, nor desirable for this project to create its own implementation of a library to communicate
with hardware devices. Instead, this project shall leverage an existing library such as
[Yubico's YubiKit](https://github.com/Yubico/yubikit-android/) for hardware communication.
To achieve maximum flexibility though, Bouncy Castle's API shall not contain references to - nor be limited by - a
specific Smart Card library.
The goal is to design Bouncy Castle's APIs in a way that makes it easy to adapt arbitrary OpenPGP Smart Card libraries.

Bouncy Castle's modular architecture already leverages the factory pattern to allow the injection of different
cryptographic OpenPGP backend implementations, such as BCs own lightweight API or the JCE/JCA backend for operations
such as creating signatures or decrypting messages.
In a similar fashion, once required modifications are made it would be possible to inject a backend that is conscious
of hardware tokens. That way, upon encountering a hardware-backed TSK object, the backend could delegate cryptographic
operations to the respective hardware token.

## Project Dependencies
PGPainless fundamentally depends on Bouncy Castle. It itself merely presents an easy-to-use API around BC.
Tests in PGPainless are based on JUnit and serve to not only test PGPainless, but Bouncy Castle as well.
PGPainless' command line interface is built using `sop-java-picocli`, which depends on `picocli`.

Bouncy Castle has no notable external dependencies that are of concern for this project.

In order to complete this project as currently outlined, the planned module `bcpg-yubikit` will depend on the `yubikit`
library.

## Dependent Projects
Bouncy Castles OpenPGP API is used by many projects that offer OpenPGP support. From User-facing applications like
OpenKeychain, K-9 Mail/Thunderbird for Android or the Android Password Store project, OpenPGP libraries like PGPainless
or Bouncy-GPG, to build systems like Maven or Gradle, and software packagers like Apache packager, many projects
depend on OpenPGP support in Bouncy Castle.

PGPainless is still quite a young project (inception year is 2018), yet already a number of projects rely on it to add
OpenPGP support to their applications. Among them are the email clients FlowCrypt and ltt.rs, as well as the XMPP
client library Smack and the Android Password Store password manager.

## Target Groups
Adding support for OpenPGP Smart Cards will increase Bouncy Castle's value for security critical applications and
areas of deployment.
Notable areas of deployment are signing of software distributions on build servers (see for example
[FDroid](https://f-droid.org/en/docs/Signing_Process/), which uses hardware security modules for signing) or the
exchange of encrypted and/or signed messages, e.g. in the financial technology sector.

## Example Scenario
Hardware-backed OpenPGP keys can be used to sign software packages without exposing the private key material to the
machine itself.
That way, an attacker gaining access to a build server cannot extract the private key material, as they would be able
to if the build server used a software key.
Conceivable target projects would be signing plugins of various build systems, e.g. `maven-signing`.

Another scenario is an email client that leverages OpenPGP for message encryption and authentication.
Being able to use a hardware token drastically reduces the risks of private key extraction, be it by an attacker or
by accident.

## Historic Sources of Funding
In the past, my work on PGPainless was financed by a sponsorship from [FlowCrypt.com](https://flowcrypt.com).

Parts of PGPainless were [funded by NGI Assure through NLnet](https://nlnet.nl/project/PGPainless/).

Most recently, OpenPGP support for PGPainless and Bouncy Castle was funded through a successful
[Sovereign Tech Fund project](https://warmwasserwerfer.de/2025/08/28/towards-openpgp-v6-in-pgpainless/).

PGPainless was also part of the [GitHub Secure Open Source Fund](https://github.blog/open-source/maintainers/securing-the-supply-chain-at-scale-starting-with-71-important-open-source-projects/).

## Challenges in Maintenance
PGPainless is still a one-man project and there isn't really a community around it.
I am a freelance software developer and PGPainless is my primary project.
At the moment I depend on external funding through programs like the STF to fund my work.
Users of PGPainless often remain anonymous, which makes it hard to probe, which features would be useful to them.

I'm an external contributor to Bouncy Castle, so I depend on them to merge my changes.
I especially depend on them if there are shortcomings of BC, which hinder implementing features in PGPainless.
However, my past contributions are being maintained by myself and members of the Bouncy Castle team.

For the long run, I'm trying to implement as many features inside Bouncy Castle directly instead of PGPainless.
The reason for this is that I hope to expose my changes to a broader audience in oder to benefit from Bouncy Castle's
community and vice versa.

## Alternatives
There are a bunch of OpenPGP libraries that serve as alternatives to PGPainless / Bouncy Castle.

Most notably, [GnuPG](https://gnupg.org/) pioneered the use of Smart Cards for OpenPGP.
Unfortunately, it is not easy to use as a library from within an external application, although currently many
signing applications written in Java do delegate signing to the GnuPG binary.
It is worthy to note, that GnuPG exposes OpenPGP Smart Cards to other applications via the
[gpg-agent](https://www.gnupg.org/documentation/manuals/gnupg/Invoking-GPG_002dAGENT.html) service, which presents
a potential future backend implementation for Bouncy Castle.

[PC/SC and pcsc-lite](https://github.com/OpenSC/OpenSC/wiki/PCSC-and-pcsc-lite) provide cross-platform APIs to
communicate with Smart Card readers.
These libraries are not tailored towards the OpenPGP use-case and are comparably low-level.
pcsc-lite is licensed under a BSD-like license.

[Sequoia-PGP](https://sequoia-pgp.org/) is an OpenPGP library written in Rust.
It provides [Smart Card support](https://book.sequoia-pgp.org/hardware_keys.html) by leveraging `gpg-agent`.

[openpgp-card](https://crates.io/crates/openpgp-card) is an OpenPGP implementation agnostic client library written in
Rust.
As [openpgp-card-rpgp](https://crates.io/crates/openpgp-card-rpgp) it provides OpenPGP card support for rPGP.

An alternative to `yubikit` would be _Confidential Technologies_' [hwsecurity](https://github.com/hwsecurity-sdk/hwsecurity),
though it is licensed  under the GPLv3 and/or a commercial license and is therefore not compatible with Bouncy Castle.

## The Plan - Identified Project Objectives
* **BC: Add low-level support for the "OpenPGP External Secret Keys" protocol extension**  
  _1W_  
  This allows BC to "understand" when a key is stored on a Smart Card.  
  * Create tests
  * Modify `OpenPGPCertificate` / `OpenPGPKey` classes to expose properties / methods
  * `PGPSecretKey`: Add method to mark key as external
* **Create software-based simulation for hardware-tokens**  
  _3W_  
  During testing, we might not always have hardware-tokens available. Also, hardware tokens provide some overhead
  compared to software-keys. By simulating hardware keys using software keys, we can simplify development.
* **Modify BCs low-level API to allow for message decryption using external keys**  
  _1W_  
  This is a hard requirement, as the current API does not allow for decryption without access to the private key.
  * Create tests using simulated hardware keys
* **Modify BCs low-level API to allow for signature generation using external keys**  
  _4W_  
  This is another hard requirement, as the current API does not allow for signature generation without access to
  the private key.
  * Create tests using simulated hardware keys
* **BC: Create implementation-agnostic hardware-backend interface definitions**  
  _5W_  
  As we don't want to add any dependencies to BC directly, we need to define an abstract interface for Smart Cards to
  be used by Bouncy Castle. This interface should be as simple as possible to implement using any concrete OpenPGP
  Smart Card library.
  * Check hardware-token state
  * Inspect hardware-tokens for existing fingerprints etc.
  * Reset hardware-tokens
  * Change PINs
  * Create implementation-agnostic test suite using high-level OpenPGP API and simulated hardware keys
  * Create documentation for future implementers
* **Create module (working title `bcpg-yubikit`) implementing hardware-backend interface using the `yubikit` library**  
  _6W_  
  YubiKit offers a suitable OpenPGP Smart Card implementation to be adapted to Bouncy Castle. We will choose it for a
  concrete implementation of the above-mentioned abstract hardware-backend interface definition.
  This module will not live inside the Bouncy Castle repository, but will be a separate library.
  * For now, focus on desktop applications, but perhaps allow android later on
  * Adapt implementation-agnostic test suite to the module
* **Modify `OpenPGPKeyEditor` to allow for hardware-related operations**  
  _3W_  
  Bouncy Castle's high-level `OpenPGPKeyEditor` offers an API to modify existing OpenPGP keys.
  By extending it to support hardware-backed keys, users are able to modify their OpenPGP hardware keys.
  * API for signaling external secret keys
  * For now: Allow generating hardware-backed subkeys for existing software keys
  * For now: Allow moving existing software-based subkeys to hardware tokens
  * Later on: Hardware-backed primary keys: Allow binding components (user-ids, subkeys...)
* **Modify `OpenPGPKeyGenerator` to allow for hardware-backed key generation**  
  _3W_  
  The `ÒpenPGPKeyGenerator` can be used to generate OpenPGP (software-) keys. We will extend it to support hardware
  keys as well.
  * For now: Generate mixed keys with software-backed primary key and hardware-backed subkeys
  * Later on: Generate hardware-only keys
* **PGPainless: Reintegrate Smart Card Support from BC**  
  _4W_  
  PGPainless internally depends on Bouncy Castle. We will adopt its API to leverage BCs new Smart Card capabilities.

## Estimated Work-Hours
600h

## Estimated Cost in EUR
100€/h * 600h = 60.000€

## Estimated Months to Complete
600h / 5h/d = 120d
120d / 4d/w = 30w
+4w absence = 34w
~= 8M

## Developers
Paul Schaub

## Your Name
Paul Schaub (@vanitasvitae)

## Profile Link
https://github.com/vanitasvitae