<!--
SPDX-FileCopyrightText: 2021 Paul Schaub <info@pgpainless.org>
SPDX-License-Identifier: CC0-1.0
-->

# PGPainless Changelog

## 0.2.18
- Fix compatibility with PGPainless < 0.2.10
- Fix interoperability with Kleopatra
  - Decryption: Do not skip over first PKESKs when we have a matching decryption key
  - MessageInspector: Break from object factory loop after encountering encrypted data (we cannot go deeper)
- Move hash algorithm negotiation to own class
- Change return value of `EncryptionOptions.overrideEncryptionAlgorithm()`

## 0.2.17
- Fix prematurely throwing `MissingPassphraseException` when decrypting message with multiple possible keys and passphrases

## 0.2.16
- Fix handling of subkey revocation signatures
- SOP: improve API use with byte arrays
- Fix `AssertionError` when determining encryption subkeys from set containing unbound key
- Add `ConsumerOptions.setMissingKeyPassphraseStrategy(strategy)` to modify behavior when missing key passphrases are encountered during decryption

## 0.2.15
- Add `ConsumerOptions.setIgnoreMDCErrors()` which can be used to consume broken messages. Not recommended!
- Add `MessageInspector.isSignedOnly()` which can be used to identify messages created via `gpg --sign --armor`
- Workaround for BCs `PGPUtil.getDecoderStream` mistaking plaintext for base64 encoded data
- Cleanup of unused internal methods
- SOP: Fix `ArmorImpl` writing data to provided output stream instead of `System.out`
- Fix hen and egg problem with streams in signature detaching implementation of SOP
- Make code [REUSE](https://reuse.software) compliant

## 0.2.14
- Export dependency on Bouncycastle's `bcprov-jdk15on`
- Rework Key Generation API
  - Replace builder-chain structure with single `KeyRingBuilder` class
- Change return value of `CleartextSignatureProcessor.process()` to `DecryptionStream`
- Rename `CleartextSignatureProcessor.process()` to `CleartextSignatureProcessor.getVerificationStream()`
- Add support for creating cleartext signed messages by calling `ProducerOptions.setCleartextSigned()`
- Add examples for signing messages in the `examples` package.

## 0.2.13
- Add `MessageInspector` class to determine IDs of recipient keys.
- PGPainless now tries decryption using keys with available passphrases first and only then request key passphrases using callbacks.

## 0.2.12
- Fix: Add workaround for BC defaulting to S2K `USAGE_CHECKSUM` by changing S2K usage to `USAGE_SHA1`
- Repair keys with `USAGE_CHECKSUM` when changing passphrase

## 0.2.11
- Fix: When changing expiration date of keys, also consider generic and casual certifications

## 0.2.10
- Cleartext Signature Framework 
  - Reuse `ConsumerOptions` class for verification
  - Return `OpenPgpMetadata` object as result of verification
- Change default compression algorithm from `UNCOMPRESSED` to `ZIP`
- Cleanup: Move Signature Verification code to dedicated internal stream

## 0.2.9
- Allow customization of ASCII armor comment and version headers
- Small bug fixes of SOP implementation
- Readability fixes
- Switch from JUL to [slf4j](http://www.slf4j.org/) for logging
- SOP: Native support for verify-not-before and verify-not-after
- SOP: Adopt changes for SOP spec version 2
  - Add `detach-inband-signatures-and-message` subcommand
  - Add support for environment variables
  - Remove `-allow-nested`
- Cleartext Signature Framework: Fix handling of trailing newlines

## 0.2.8
- Encrypt to all capable subkeys by default
- Ignore missing CRC checksums in ASCII Armor

## 0.2.7
- Fix writing data to standard out in the `java-sop-picocli` module
- Improve handling of signatures with missing issuer-key-id packets
- Properly ignore marker packets
- Add issuer-fingerprint packets to message signatures by default
- Fix ordering (bracketing) and nested-ness of one-pass-signatures
- Fix interoperability issue with Thunderbird  
  - Some keys caused wrong partial-length encodings for integrity protected session packets

## 0.2.6
- Actually properly detect CRC checksum errors in ASCII armor

## 0.2.5
- Explicitly reject non-self-signatures when picking user-id self-signatures
- pgpainless-cli: Set executable name in help text
- Properly detect CRC checksum errors in ASCII armor

## 0.2.4
- Java based Stateless OpenPGP Protocol
  - Introduce `sop-java` module  
  Contains Java interfaces modelling the Stateless OpenPGP Protocol
  - Introduce `sop-java-picocli`  
  Command Line Interface frontend for `sop-java` based OpenPGP implementations
  - `pgpainless-sop` now contains an implementation of `sop-java` using `pgpainless-core`
  - `pgpainless-cli` now contains a ready to use OpenPGP command line application  
  It simply plugs `pgpainless-sop` into `sop-java-picocli`.
- Remove deprecated encryption API
- Remove deprecated decryption API
- Add `PGPainless.extractCertificate()` and `PGPainless.asciiArmor()` methods
- `OpenPgpMetadata`: `getDecryptionKey()` and `getVerifiedSignatures()` now return `SubkeyIdentifier` objects
- `KeyRingReader` now properly ignores marker packets
- Encryption: File-related metadata (e.g. file name) moved to `ProducerOptions`
- `pgpainless-cli/pgpainless-cli` executable script: Fix piping and parameter passing
- `sop-java-picocli`: Add `help` command
- When changing passphrases: Subkeys with `GNU_DUMMY_S2K` will now be ignored

## 0.2.3
- Introduce new simplified decryption API  
  The new API (`withOptions(ConsumerOptions)`) resembles the encryption API and is more friendly to dynamic
  construction of decryption properties  
  The old API has been deprecated and will be removed in a future release
- Add `example` package in the JUnit tests  
  This package contains always-up-to-date usage examples for the PGPainless' API and various use cases
- Add `KeyRingInfo.getVersion`
- Add `CachingSecretKeyRingProtector.addPassphrase(OpenPgpV4Fingerprint, Passphrase)`
- Make builds of all jars reproducible
- Fix `NullPointerException` in `KeyRingInfo.getExpirationDateForUse()`

## 0.2.2
- Fix bug where adding a subkey would ignore the user-requested key flags  
  This would cause subkeys to erroneously carry the certify-others key flag

## 0.2.1
- Bump Bouncycastle dependency to `1.69`  
  This fixes a number of issues ([#70](https://github.com/pgpainless/pgpainless/issues/70),
  [#72](https://github.com/pgpainless/pgpainless/issues/72), [#84](https://github.com/pgpainless/pgpainless/issues/84)).
  As a result the test suite should now run more smoothly \o/
- Remove Android SDK build dependency  
  We can now build PGPainless without the need to have the Android SDK installed
- `SignatureUtils`: Add `getSignatureDigestPrefix()` method
- Add `KeyIdUtil` which allows converting 16 digit hex fingerprints to key-ids
- `SignatureSubpacketsUtil`: Add methods to get notations by name
- Add public key algorithm policy to reject signatures made by weak signing keys
