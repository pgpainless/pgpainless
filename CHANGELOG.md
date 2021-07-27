# PGPainless Changelog

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
