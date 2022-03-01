<!--
SPDX-FileCopyrightText: 2021 Paul Schaub <info@pgpainless.org>
SPDX-License-Identifier: CC0-1.0
-->

# PGPainless Changelog

## 1.1.2-SNAPSHOT
- Fix `keyRingInfo.getEmailAddresses()` incorrectly matching some mail addresses (thanks @bratkartoffel for reporting and initial patch proposal)

## 1.1.1
- Add `producerOptions.setComment(string)` to allow adding ASCII armor comments when creating OpenPGP messages (thanks @ferenc-hechler)
- Simplify consumption of cleartext-signed data
- Change default criticality of signature subpackets
  - Issuer Fingerprint: critical -> non-critical
  - Revocable: non-critical -> critical
  - Issuer KeyID: critical -> non-critical
  - Preferred Algorithms: critical -> non-critical
  - Revocation Reason: critical -> non-critical

## 1.1.0
- `pgpainless-sop`: Update `sop-java` to version 1.2.0
    - Treat passwords and session keys as indirect parameters
      This means they are no longer treated as string input, but pointers to files or env variables

## 1.0.4
- Yet another patch for faulty ASCII armor detection 😒

## 1.0.3
- Fix detection of unarmored data in signature verification

## 1.0.2
- Update SOP implementation to specification revision 03
- Move `sop-java` and `sop-java-picocli` modules to [its own repository](https://github.com/pgpainless/sop-java)
- `OpenPGPV4Fingerprint`: Hex decode bytes in constructor
- Add `ArmorUtils.toAsciiArmoredString()` for single key
- Fix `ClassCastException` when retrieving `RevocationKey` subpackets from signatures
- Fix `pgpainless-sop` gradle script
  - it now automatically pulls in transitive dependencies

## 1.0.1
- Fix sourcing of preferred algorithms by primary user-id when key is located via key-id

## 1.0.0
- Introduce `DateUtil.toSecondsPrecision()`
- Clean JUnit tests, fix code style issues and fix typos in documentation

## 1.0.0-rc9
- When key has both direct-key sig + primary user-id sig: resolve expiration date to the earliest expiration
- Add `SecretKeyRingEditor.removeUserId()` convenience methods that do soft-revoke the user-id.
- Add `SelectUserId.byEmail()` which also matches the plain email address

## 1.0.0-rc8
- `KeyRingInfo.getPrimaryUserId()`: return first user-id when no primary user-id is found
- Rename method `getBoundButPossiblyExpiredUserIds` to `getValidAndExpiredUserIds()`
- Remove audit resource material

## 1.0.0-rc7
- Make `Passphrase` comparison constant time
- Bump Bouncycastle to 1.70
  - Use new `PGPCanonicalizedDataGenerator` where applicable
  - Implement decryption with user-provided session key
  - Remove workaround for invalid signature processing
- Remove Blowfish from default symmetric decryption/encryption policy
- When adding/generating keys: Check compliance to `PublicKeyAlgorithmPolicy`
- Fix `BaseSecretKeyRingProtector` misinterpreting empty passphrases
- SOP: Fix NPE when attempting to sign with key with missing signing subkey
- Describe Threat Model in [pgpainless-core/README.md]
- Fix NPE when attempting to decrypt GNU_DUMMY_S2K key
- Validate public key parameters when unlocking secret keys
- Introduce iteration limits to prevent resource exhaustion when
  - reading signatures
  - reading keys
- `CachingSecretKeyRingProtector`: Prevent accidental passphrase overriding via `addPassphrase()`
- `EncryptionOptions`: replace method argument type `PGPPublicKeyRingCollection` with `Iterable<PGPPublicKeyRing>` to allow for `Collection<PGPPublicKeyRing>` as argument
- `SigningOptions`: replace method argument type `PGPSecretKeyRingCollection` with `Iterable<PGPSecretKeyRing>` to allow for `Collection<PGPSecretKeyRing>` as argument
- Prevent message decryption with non-encryption subkey
- Rework key modification API to fix inconsistency problems with expiration and primary user-ids.
  - Remove methods to change expiration dates of subkeys and specific user-ids
  - Rework primary user-id marking logic to unmark non-primary ids
- Added [Cure53 Security Audit Report](https://gh.pgpainless.org/assets/Audit-PGPainless.pdf) to the website
- Reworked tests for cryptographic backend to use custom `InvocationContextProvider` implementation
- Source `PGPObjectFactory` objects from `ImplementationProvider`
- Fix typo `getCommendHeader() -> getCommentHeader()`

## 1.0.0-rc6
- Restructure method arguments in `SecretKeyRingEditor`
- Add explanations of revocation reasons to `RevocationAttributes`
- Rename `CertificationSignatureBuilder` to `ThirdPartyCertificationSignatureBuilder`
- `KeyAccessor.ViaKeyId`: Differentiate between primary key (rely on direct-key sig) and subkey (subkey binding sig)
- Expose `SignatureSubpacketsUtil.getKeyLifetimeInSeconds`
- Various cleanup steps and new tests

## 1.0.0-rc5
- Fix invalid cursor mark in `BufferedInputStream` when processing large cleartext signed messages
- Add `SecretKeyRingEditor.revokeUserIds(SelectUserId, SecretKeyRingProtector, RevocationSignatureSubpackets.Callback)`

## 1.0.0-rc4
- Fix bug where `KeyRingBuilder` would mark additional user-ids as primary

## 1.0.0-rc3
- New Signature builder API for more fine-grained control over key-signatures:
  - Introduce `CertificationSignatureSubpackets` builder class to wrap `PGPSignatureSubpacketGenerator` for
    certification style signatures.
  - Introduce `SelfSignatureSubpackets` builder class for self-signatures.
  - Introduce `RevocationSignatureSubpackets` builder class for revocation signatures.
  - Introduce `CertificationSignatureSubpackets.Callback`, `SelfSignatureSubpackets.Callback` and
    `RevocationSignatureSubpackets.Callback` to allow modification of signature subpackets by the user.
  - Incorporate `*SignatureSubpackets.Callback` classes as arguments in `SecretKeyRingEditor` and `KeyRingBuilder` methods.
- Start working on `ProofUtil` to create KeyOxide style identity proofs (WIP)
- Move Signature verification related code to `org.pgpainless.signature.consumer` package
- Ensure keyflags and other common subpackets are set in new signatures when adding user-ids
- Ensure subkey can carry keyflag when adding it to a key
- Refactor `SecretKeyRingProtector` methods and code

## 1.0.0-rc2
- `SecretKeyRingEditor`: Remove support for user-id- and subkey *deletion* in favor of *revocation*
  - Deletion causes all sorts of problems. Most notably, receiving implementations will not honor deletion of user-ids/subkeys.
    If you really need to delete user-ids there now is `KeyRingUtils.deleteUserId(keys, userid)`,
    but its use is highly discouraged and should only (if ever) be used for local manipulations of keys.
- `pgpainless-core` & `pgpainless-sop`: Fix accidental compile scope dependency on `logback-classic`
- `KeyRingInfo`: Sensible arguments for methods to get preferred algorithms

## 1.0.0-rc1
- First release candidate for a 1.0.0 release! \o/
- Rename `EncryptionPurpose.STORAGE_AND_COMMUNICATIONS` to `EncryptionPurpose.ANY`
- Hide `PGPainless.verifyCleartextSignedMessage()` behind `PGPainless.decryptAndVerify()`.
  - the latter now checks whether the message is cleartext-signed or not and automatically calls the proper API
  - `MultiPassStrategy` objects are now set through `ConsumerOptions.setMultiPassStrategy()`.
- Separate key ring generation through templates from custom key ring builder
  - `PGPainless.generateKeyRing()` now offers to generate keys from templates
  - `PGPainless.buildKeyRing()` offers a detailed API to build custom keys
- Fix detection of non-armored data

## 0.2.19
- Some preparations for OpenPGP V5 keys: `OpenPgpV4Fingerprint` is now an implementation of `OpenPgpFingerprint`
- `SignatureVerification` and `Failure` now have `toString()` implementations
- Logging: `logback-classic` is now an optional runtime dependency

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
- SOP: improve API usage with byte arrays
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
