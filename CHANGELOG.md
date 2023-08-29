<!--
SPDX-FileCopyrightText: 2021 Paul Schaub <info@pgpainless.org>
SPDX-License-Identifier: CC0-1.0
-->

# PGPainless Changelog

# 1.6.2-SNAPSHOT
- Switch `bcpg` and `bcprov` artifacts from `-jdk15to18`variant to `-jdk18on`
- Bump `bcpg-jdk8on` to `1.76`
- Bump `bcprov-jdk18on` to `1.76`
- Add `EncryptionOptions.setAllowEncryptionWithMissingKeyFlags()` to properly allow
    encrypting to legacy keys which do not carry any key flags.
- Allow overriding of reference time in `EncryptionOptions` and `SigningOptions`.

# 1.6.1
- `KeyRingBuilder`: Require UTF8 when adding user-ID via `addUserId(byte[])`
- `pgpainless-sop`: Remove dependency on jetbrains annotations
- Add `CertificateAuthority` interface to allow integration with [`pgpainless-wot`](https://github.com/pgpainless/pgpainless-wot)
  - Add `EncryptionOptions.addAuthenticatableRecipients()` method
  - Add `MessageMetadata.isAuthenticatablySignedBy()` method

## 1.6.0
- Bump `sop-java` to `7.0.0`, implementing [SOP Spec Revision 07](https://www.ietf.org/archive/id/draft-dkg-openpgp-stateless-cli-07.html)
  - Implement `revoke-key` subcommand and API
  - Implement `change-key-password` subcommand and API
  - `generate-key`: Add support for new `--signing-only` option
- Move some methods related to password changing from `SecretKeyRingEditor` to `KeyRingUtils`

## 1.5.6
- Bump `jacoco` to `0.8.8` (thanks @hkos)
- Ignore malformed, non-UTF8 user-IDs on certificates
- `KeyRingReader.readPublicKeyRingCollection()`: Extract and return public keys from encountered secret keys
- Add some utility methods to `KeyRingInfo`:
  - `getValidSubkeys()` only returns validly bound sub-keys
- Add some utility methods to `SignatureUtils`:
  - `getDelegations()` returns all third-party signatures made over the primary key
  - `get3rdPartyCertificationsFor(userId)` returns all third-party certification signatures made over the given user-id
- Add some utility methods to `SignatureSubpacketsUtil`:
  - `isExportable()` will return true if the signature is *not* marked as non-exportable
  - `getTrustDepthOr()` returns the signatures trust-depth, or a default value if there is no trust-signature subpacket
  - `getTrustAmountOr()` returns the signatures trust-amount, or a default value if there is no trust-signature subpacket

## 1.5.5
- Bump `bcpg-jdk15to18` to `1.75`
- Bump `bcprov-jdk15to18` to `1.75`
- Bump `checkstyle` to `10.12.1` to fix build dependency on [vulnerable guava](https://github.com/pgpainless/pgpainless/security/dependabot/6).
- `SecretKeyRingEditor`:
  - Rename `createRevocationCertificate()` to `createRevocation()`
  - Add `createMinimalRevocationCertificate()` method to generate OpenPGP v6-style self-certifying revocation certificates

## 1.5.4
- Bump `bcpg-jdk15to18` to `1.74`
- Bump `bcprov-jdk15to18` to `1.74`
- Remove unused methods from `SignatureUtils`
- Encryption: Allow anonymous recipients using wildcard key-IDs
- Add `SignatureSubpacketsUtil.getRegularExpressions()`
- Tests, tests, tests

## 1.5.3
- Fix minimal bit-strength check for signing-subkeys accidentally comparing the bit-strength of the primary key
- `SigningOptions`: Add new methods to add signatures using a single, chosen signing subkey

## 1.5.2
- Bugfix: Create proper direct-key signatures
- `KeyRingTemplates`:
  - Add `rsaKeyRing()` for generating RSA keys with primary key and dedicated signing, encryption subkeys
  - Reduce number of template methods by replacing `UserId`, `String` arguments with `CharSequence`
- Add `MessageMetadata.getRecipientKeyIds()`
- Work towards more null-safe API by annotating methods in `EncryptionOptions`, `SigningOptions`, `KeyRingInfo`, `PGPainless` with `@Nonnull`, `@Nullable`
- `KeyRingUtils`: Removed `removeSecretKey()` in favour of `stripSecretKey()`
- General code cleanup
- SOP: generating keys with `rfc4880` profile now generates key with primary key and subkeys
- Deprecate ElGamal key type
- Key generation: Set expiration period of 5 years by default
- Set AES-128 as default fallback symmetric algorithm
- `ProducerOptions`: Allow setting custom version header when encrypting/signing message

## 1.5.2-rc1
- Bump `sop-java` to `6.1.0`
- Normalize `OpenPgpMessageInputStream.read()` behaviour when reading past the stream
  - Instead of throwing a `MalformedOpenPgpMessageException` which could throw off unsuspecting parsers,
    we now simply return `-1` like every other `InputStream`.

## 1.5.1
- SOP: Emit signature `mode:{binary|text}` in `Verification` results
- core: Relax constraints on decryption subkeys to improve interoperability with broken clients
    - Allow decryption with revoked keys
    - Allow decryption with expired keys
    - Allow decryption with erroneously addressed keys without encryption key flags

## 1.5.0
- Bump `bcpg-jdk15to18` to `1.73`
- Bump `bcprov-jdk15to18` to `1.73`
- Introduce `OpenPgpv6Fingerprint` class
- Bump `sop-java` to `5.0.0`, implementing [SOP Spec Revision 05](https://www.ietf.org/archive/id/draft-dkg-openpgp-stateless-cli-05.html)
  - Add support for `list-profiles` subcommand (`generate-key` only for now)
  - `generate-key`: Add support for `--profile=` option
    - Add profile `draft-koch-eddsa-for-openpgp-00` which represents status quo.
    - Add profile `rfc4880` which generates keys based on 4096-bit RSA.
- Bump `sop-java` to `6.0.0`, implementing [SOP Spec Revision 06](https://www.ietf.org/archive/id/draft-dkg-openpgp-stateless-cli-06.html)
  - `encrypt`: Add support for `--profile=` option
    - Add profile `rfc4880` to reflect status quo
  - `version`: Add support for `--sop-spec` option

## 1.4.5
- Bugfix: Direct-Key signatures are calculated over the signee key only, not the signer key + signee key
- Security: Fix faulty bit-strength policy check for signing subkeys

## 1.4.4
- Fix expectations on subpackets of v3 signatures (thanks @bjansen)
  - Properly verify v3 signatures, which do not yet have signature subpackets, yet we required them to have  
    a hashed creation date subpacket.

## 1.4.3
- Bump `sop-java` to `4.1.1`
- Reuse shared test suite of `sop-java`
- Add `EncryptionOptions.hasEncryptionMethod()`
- SOP `encrypt`: Throw `MissingArg` exception if no encryption method was provided
- Fix redundant dot in exception message (thanks @DenBond7)

## 1.4.2
- Properly decrypt messages without MDC packets when `ConsumerOptions.setIgnoreMDCErrors(true)` is set
- Fix crash in `sop generate-key --with-key-password` when more than one user-id is given
- Revert integration with `pgp-certificate-store`
- Bump `sop-java` to `4.1.0`

## 1.4.1
- Add `UserId.parse()` method to parse user-ids into their components

## 1.4.0
- `sop generate-key`: Add support for keys without user-ids
- `sop inline-sign --as=clearsigned`: Make signature in TEXT mode
- Make countermeasures against [KOpenPGP](https://kopenpgp.com/) attacks configurable
  - Countermeasures are now disabled by default since they are costly and have a specific threat model
  - Can be enabled by calling `Policy.setEnableKeyParameterValidation(true)`

## 1.4.0-rc2
- Bump `bcpg-jdk15to18` to `1.72.3`
- Use BCs `PGPEncryptedDataList.extractSessionKeyEncryptedData()` method
  to do decryption using session keys. This enables decryption of messages
  without encrypted session key packets.
- Use BCs `PGPEncryptedDataList.isIntegrityProtected()` to check for integrity protection
- Depend on `pgp-certificate-store`
- Add `ConsumerOptions.addVerificationCerts(PGPCertificateStore)` to allow sourcing certificates from
  e.g. a [certificate store implementation](https://github.com/pgpainless/cert-d-java).
- Make `DecryptionStream.getMetadata()` first class
  - Deprecate `DecryptionStream.getResult()`

## 1.4.0-rc1
- Reimplement message consumption via new `OpenPgpMessageInputStream`
    - Fix validation of prepended signatures (#314)
    - Fix validation of nested signatures (#319)
    - Reject malformed messages (#237)
        - Utilize new `PDA` syntax verifier class
        - Allow for custom message syntax via `Syntax` class
    - Gracefully handle `UnsupportedPacketVersionException` for signatures
    - Allow plugin decryption code (e.g. to add support for hardware-backed keys (see #318))
        - Add `HardwareSecurity` utility class
        - Add `GnuPGDummyKeyUtil` which can be used to mimic GnuPGs proprietary S2K extensions
          for keys which were placed on hardware tokens
    - Add `OpenPgpPacket` enum class to enumerate available packet tags
    - Remove old decryption classes in favor of new implementation
        - Removed `DecryptionStream` class and replaced with new abstract class
        - Removed `DecryptionStreamFactory`
        - Removed `FinalIOException`
        - Removed `MissingLiteralDataException` (replaced by `MalformedOpenPgpMessageException`)
    - Introduce `MessageMetadata` class as potential future replacement for `OpenPgpMetadata`.
        - can be obtained via `((OpenPgpMessageInputStream) decryptionStream).getMetadata();`
- Add `CachingBcPublicKeyDataDecryptorFactory` which can be extended to prevent costly decryption
  of session keys
- Fix: Only verify message integrity once
- Remove unnecessary `@throws` declarations on `KeyRingReader` methods
- Remove unnecessary `@throws` declarations on `KeyRingUtils` methods
- Add `KeyIdUtil.formatKeyId(long id)` to format hexadecimal key-ids.
- Add `KeyRingUtils.publicKeys(PGPKeyRing keys)`
- Remove `BCUtil` class

## 1.3.17
- Bugfix: Direct-Key signatures are calculated over the signee key only, not the signer key + signee key
- Security: Fix faulty bit-strength policy check for signing subkeys

## 1.3.16
- Bump `sop-java` to `4.1.0`
- Bump `gradlew` to `7.5`

## 1.3.15
- Fix crash in `sop generate-key --with-key-password` when more than one user-id is given
- `sop generate-key`: Allow key generation without user-ids
- `sop inline-sign --as=clearsigned`: Make signatures of type 'text' instead of 'binary'

## 1.3.14
- Bump `bcpg` to `1.72.3`
- Fix DSA key parameter check
- Use proper method to unlock private signing keys when creating detached signatures

## 1.3.13
- Bump `sop-java` to `4.0.7`

## 1.3.12
- Bump `sop-java` to `4.0.5`
- Fix: `sop inline-sign`: Adopt `--as=clearsigned` instead of `--as=cleartextsigned`
- SOP: Hide `Version: PGPainless` armor header in all armored outputs
- Fix: `sop armor`: Do not re-armor already armored data

## 1.3.11
- Fix: When verifying subkey binding signatures with embedded recycled primary
  key binding signatures, do not reject signature if primary key binding
  predates subkey binding
- SOP `verify`: Forcefully expect `data()` to be non-OpenPGP data
- SOP `sign`: Fix matching of keys and passphrases
- CLI: Added tons of tests \o/

## 1.3.10
- Bump `sop-java` to `4.0.3`
- Fix: Fix NPE when verifying signature made by key without key flags on direct-key signature

## 1.3.9
- Bump `sop-java` to `4.0.2`
- SOP: Improve exception handling

## 1.3.8
- Bump `bcprov` to `1.72`
- Bump `bcpg` to `1.72.1`
- Add `ProducerOptions.setHideArmorHeaders(boolean)` to hide automatically added armor headers
    in encrypted messages

## 1.3.7
- Bugfix: Fix signature verification when `DecryptionStream` is drained byte-by-byte using `read()` call
- Add `KeyRingUtils.injectCertification(keys, certification)`
- Add `PGPainless.asciiArmor(key, outputStream)`
- Add `PGPainless.asciiArmor(signature)`

## 1.3.6
- Remove deprecated methods
  - `ArmorUtils.createArmoredOutputStreamFor()` -> use `ArmorUtils.toAsciiArmoredStream()` instead
  - `EncryptionResult.getSymmetricKeyAlgorithm()` -> use `EncryptionResult.getEncryptionAlgorithm()` instead
- Add `KeyRingInfo.getRevocationState()`
  - Better way to determine whether a key is revoked
- Add `SigningOptions.addDetachedSignature(protector, key)` shortcut method
- Add `EncryptionOptions.get()`, `ConsumerOptions.get()` factory methods
- Add support for generating keys without user-id (only using `PGPainless.buildKeyRing()` for now)
- Switch to `SHA256` as default `S2K` hash algorithm for secret key protection
- Allow to set custom reference time when modifying secret keys
- Add diagnostic test to explore system PRNG performance

## 1.3.5
- Add `KeyRingInfo.isCapableOfSigning()`
- Add `KeyRingReader.readKeyRing(*)` methods that can take both secret- and public keys
- Add manpages
  - Add script to generate manpages from sop-java-picocli
- Build website from main branch

## 1.3.4
- Fix `KeyRingInfo.isUsableForEncryption()`, `KeyRingInfo.isUsableForSigning()` not detecting revoked primary keys
- Bump `sop-java` and `sop-java-picocli` to `4.0.1`
  - Fixes help text strings being resolved properly while allowing to override executable name

## 1.3.3
- Improve test compatibility against older JUnit versions
- Fix tests that read from jar-embedded resources (thanks @jcharaoui)
- `pgpainless-cli help`: Fix i18n strings

## 1.3.2
- Add `KeyRingInfo(Policy)` constructor
- Delete unused `KeyRingValidator` class
- Add `PGPainless.certify()` API
  - `certify().userIdOnCertificate()` can be used to certify other users User-IDs
  - `certify().certificate()` can be used to create direct-key signatures on other users keys
- We now have a [User Guide!](https://pgpainless.rtfd.io/)
- Fixed build script
  - `pgpainless-cli`s `gradle build` task no longer builds fat jar
  - Fat jars are now built by dedicated shadow plugin
- Fix third-party assigned user-ids on keys to accidentally get picked up as primary user-id
- Add `KeyRingUtils.publicKeyRingCollectionFrom(PGPSecretKeyRingCollection)`
- Add `SecretKeyRingEditor.replaceUserId(oldUid, newUid, protector)`
- Prevent adding `SymmetricKeyAlgorithm.NULL` (unencrypted) as encryption algo preference when generating keys

## 1.3.1
- Fix reproducibility of builds by setting fixed file permissions in archive task
- Improve encryption performance by buffering streams
- Fix `OpenPgpMetadata.isEncrypted()` to also return true for symmetrically encrypted messages
- SOP changes
  - decrypt: Do not throw `NoSignatures` if no signatures found
  - decrypt: Throw `BadData` when ciphertext is not encrypted

## 1.3.0
- Add `RevokedKeyException`
- `KeyRingUtils.stripSecretKey()`: Disallow stripping of primary secret key
- Remove support for reading compressed detached signatures
- Add `PGPainless.generateKeyRing().modernKeyRing(userId)` shortcut method without passphrase
- Add `CollectionUtils.addAll(Iterator, Collection)`
- Add `SignatureUtils.getSignaturesForUserIdBy(key, userId, keyId)`
- Add `OpenPgpFingerprint.parseFromBinary(bytes)`
- `SignatureUtils.wasIssuedBy()`: Add support for V5 fingerprints
- Prevent integer overflows when setting expiration dates
- SOP: Properly throw `KeyCannotDecrypt` exception
- Fix performance issues of encrypt and sign operations by using buffering
- Fix performance issues of armor and dearmor operations
- Bump dependency `sop-java` to `4.0.0`
- Add support for SOP specification version 04
  - Implement `inline-sign`
  - Implement `inline-verify`
  - Rename `DetachInbandSignatureAndMessageImpl` to `InlineDetachImpl`
  - Rename `SignImpl` to `DetachedSignImpl`
  - Rename `VerifyImpl` to `DetachedVerifyImpl`
  - Add support for `--with-key-password` option in `GenerateKeyImpl`, `DetachedSignImpl`, `DecryptImpl`, `EncryptImpl`.
  - `InlineDetachImpl` now supports 3 different message types:
    - Messages using Cleartext Signature Framework
    - OpenPGP messages using OnePassSignatures
    - OpenPGP messages without OnePassSignatures
- Introduce `OpenPgpMetadata.isCleartextSigned()`

## 1.2.2
- `EncryptionOptions.addRecipients(collection)`: Disallow empty collections to prevent misuse from resulting in unencrypted messages
- Deprecate default policy factory methods in favor of policy factory methods with expressive names
- Another fix for OpenPGP data detection
  - We now inspect the first packet of the data stream to figure out, whether it is plausible OpenPGP data, without exhausting the stream

## 1.2.1
- Bump `sop-java` dependency to `1.2.3`
- Bump `slf4j` dependency to `1.7.36`
- Bump `logback` dependency to `1.2.11`
- Add experimental support for creating signatures over pre-calculated `MessageDigest` objects.
  - `BcHashContextSigner.signHashContext()` can be used to create OpenPGP signatures over manually hashed data.  
    This allows applications to do the hashing themselves.
- Harden detection of binary/ascii armored/non-OpenPGP data
- Add `ConsumerOptions.forceNonOpenPgpData()` to force PGPainless to handle data as non-OpenPGP data
  - This is a workaround for when PGPainless accidentally mistakes non-OpenPGP data for binary OpenPGP data
- Implement "smart" hash algorithm policies, which take the 'usage-date' for algorithms into account
  - This allows for fine-grained signature hash algorithm policing with usage termination dates
- Switch to smart signature hash algorithm policies by default
  - PGPainless now accepts SHA-1 signatures if they were made before 2013-02-01
  - We also now accept RIPEMD160 signatures if they were made before 2013-02-01
  - We further accept MD5 signatures made prior to 1997-02-01
 

## 1.2.0
- Improve exception hierarchy for key-related exceptions
  - See [PR](https://github.com/pgpainless/pgpainless/pull/261) for more information on how to migrate.
- Bump Bouncy Castle to `1.71`
  - Switch from `bcpg-jdk15on:1.70` to `bcpg-jdk15to18:1.71`
  - Switch from `bcprov-jdk15on:1.70` to `bcprov-jdk15to18:1.71`
- Implement merging of certificate copies
  - can be used to implement updating certificates from key servers
- Fix `KeyRingUtils.keysPlusPublicKey()`
- Add support for adding `PolicyURI` and `RegularExpression` signature subpackets on signatures

## 1.1.5
- SOP encrypt: match signature type when using `encrypt --as=` option
- `ProducerOptions.setEncoding()`: The encoding is henceforth only considered metadata and will no longer trigger CRLF encoding.
  - This fixes broken signature generation for mismatching (`StreamEncoding`,`DocumentSignatureType`) tuples.
  - Applications that rely on CRLF-encoding can request PGPainless to apply this encoding by calling `ProducerOptions.applyCRLFEncoding(true)`.
- Rename `KeyRingUtils.removeSecretKey()` to `stripSecretKey()`.
- Add handy `SignatureOptions.addSignature()` method.
- Fix `ClassCastException` when evaluating a certificate with third party signatures. Thanks @p-barabas for the initial report and bug fix!

## 1.1.4
- Add utility method `KeyRingUtils.removeSecretKey()` to remove secret key part from key ring
  - This can come in handy when using primary keys stored offline
- Add `EncryptionResult.isEncryptedFor(certificate)`
- `ArmorUtils.toAsciiArmoredString()` methods now print out primary user-id and brief information about further user-ids (thanks @bratkartoffel for the patch)
- Methods of `KeyRingUtils` and `ArmorUtils` classes are now annotated with `@Nonnull/@Nullable`
- Enums `fromId(code)` methods are now annotated with `@Nullable` and there are now `requireFromId(code)` counterparts which are `@Nonnull`.
- `ProducerOptions.setForYourEyesOnly()` is now deprecated (reason is deprecation in the 
- [crypto-refresh-05](https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-05.html#name-special-filename-_console-d) document)
- Add `SessionKey.toString()`
- Partially fix generation of malformed signature packets when using different combinations of `StreamEncoding` and `DocumentSignatureType` values
  - Unfortunately PGPainless still produces broken signatures when using either `StreamEncoding.TEXT` or `StreamEncoding.UTF8` in combination with `DocumentSignatureType.BINARY_DOCUMENT`.
- Deprecate `ProducerOptions.setEncoding(StreamEncoding)`
  - Will be removed in a future release
- Remove `StreamEncoding.MIME` (was removed from the standard)

## 1.1.3
- Make `SigningOptions.getSigningMethods()` part of internal API
- Fix crash when trying to do verification of unmatched `SignersUserId` signature subpacket
  - For now, verification of `SignersUserId` is disabled but can be enabled via `Policy.setSignerUserIdValidationLevel()`
- Initial support for `OpenPgpV5Fingerprint`
- Add `OpenPgpFingerprint.parse(string)`
- Security: Fix `KeyRingInfo.getValidAndExpiredUserIds()` accidentally including unbound user-ids

## 1.0.5
- Security: Fix `KeyRingInfo.getValidAndExpiredUserIds()` accidentally including unbound user-ids

## 1.1.2
- Fix `keyRingInfo.getEmailAddresses()` incorrectly matching some mail addresses (thanks @bratkartoffel for reporting and initial patch proposal)
- Fix generic type of `CertificationSubpackets.Callback`
- Add `KeyRingInfo.isUsableForEncryption()`
- Add `PGPainless.inspectKeyRing(key, date)`
- Allow custom key creation dates during key generation
- Reject subkeys with bindings that predate key generation
- `EncryptionOptions.addRecipient()`: Transform `NoSuchElementException` into `IllegalArgumentException` with proper error message
- Fix `ClassCastException` by preventing accidental verification of 3rd-party-issued user-id revocation with primary key.
- Fix `NullPointerException` when trying to verify malformed signature

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
