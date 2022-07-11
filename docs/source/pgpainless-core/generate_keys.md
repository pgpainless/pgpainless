# PGPainless In-Depth: Generate Keys

There are two API endpoints for generating OpenPGP keys using `pgpainless-core`:

`PGPainless.generateKeyRing()` presents a selection of pre-configured OpenPGP key archetypes:

```java
// Modern, EC-based OpenPGP key with dedicated primary certification key
// This method is recommended by the authors
PGPSecretKeyRing secretKey = PGPainless.generateKeyRing()
        .modernKeyRing(
                "Alice <alice@pgpainless.org>",
                Passphrase.fromPassword("sw0rdf1sh"));

// Simple, EC-based OpenPGP key with combined certification and signing key
// plus encryption subkey
PGPSecretKeyRing secretKey = PGPainless.generateKeyRing()
        .simpleEcKeyRing(
                "Alice <alice@pgpainless.org>",
                Passphrase.fromPassword("0r4ng3"));

// Simple, RSA OpenPGP key made of a single RSA key used for all operations
PGPSecretKeyRing secretKey = PGPainless.generateKeyRing()
        .simpleRsaKeyRing(
                "Alice <alice@pgpainless.org>",
                RsaLength._4096, Passphrase.fromPassword("m0nk3y")):
```

If you have special requirements on algorithms you can use `PGPainless.buildKeyRing()` instead, which offers more
control over parameters:

```java
// Customized key

// Specification for primary key
KeySpecBuilder primaryKeySpec = KeySpec.getBuilder(
        KeyType.RSA(RsaLength._8192),                               // 8192 bits RSA key
        KeyFlag.CERTIFY_OTHER)                                      // used for certification
        // optionally override algorithm preferences
        .overridePreferredCompressionAlgorithms(CompressionAlgorithm.ZLIB)
        .overridePreferredHashAlgorithms(HashAlgorithm.SHA512, HashAlgorithm.SHA384)
        .overridePreferredSymmetricKeyAlgorithms(SymmetricKeyAlgorithm.AES256);

// Specification for a signing subkey
KeySpecBuilder signingSubKeySpec = KeySpec.getBuilder(
        KeyType.ECDSA(EllipticCurve._P256),                         // P-256 ECDSA key
        KeyFlag.SIGN_DATA);                                         // Used for signing

// Specification for an encryption subkey
KeySpecBuilder encryptionSubKeySpec = KeySpec.getBuilder(
        KeyType.ECDH(EllipticCurve._P256),
        KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE);

// Build the key itself
PGPSecretKeyRing secretKey = PGPainless.buildKeyRing()
        .setPrimaryKey(primaryKeySpec)
        .addSubkey(signingSubKeySpec)
        .addSubkey(encryptionSubKeySpec)
        .addUserId("Juliet <juliet@montague.lit>")                  // Primary User-ID
        .addUserId("xmpp:juliet@capulet.lit")                       // Additional User-ID
        .setPassphrase(Passphrase.fromPassword("romeo_oh_Romeo<3")) // passphrase protection
        .build();
```

To specify, which algorithm to use for a single (sub) key, `KeySpec.getBuilder(_)` can be used, passing a `KeyType`,
as well as some `KeyFlag`s as argument.

`KeyType` defines an algorithm and its parameters, e.g. RSA with a certain key size, or ECDH over a certain
elliptic curve.
Currently, PGPainless supports the following `KeyType`s:
* `KeyType.RSA(_)`: Signing, Certification, Encryption
* `KeyType.ECDH(_)`: Encryption
* `KeyType.ECDSA(_)`: Signing, Certification
* `KeyType.EDDSA(_)`: Signing, Certification
* `KeyType.XDH(_)`: Encryption

The `KeyFlag`s are used to specify, how the key will be used later on. A signing key can only be used for signing,
if it carries the `KeyFlag.SIGN_DATA`.
A key can carry multiple key flags.

It is possible to override the default algorithm preferences used by PGPainless with custom preferences.
An algorithm preference list contains algorithms from most to least preferred.

Every OpenPGP key MUST have a primary key. The primary key MUST be capable of certification, so you MUST use an
algorithm that can be used to generate signatures.
The primary key can be set by calling `setPrimaryKey(primaryKeySpec)`.

Furthermore, an OpenPGP key can contain zero or more subkeys.
Those can be set by repeatedly calling `addSubkey(subkeySpec)`.

OpenPGP keys are usually bound to User-IDs like names and/or email addresses.
There can be multiple user-ids bound to a key, in which case the very first User-ID will be marked as primary.
To add a User-ID to the key, call `addUserId(userId)`.

By default, keys do not have an expiration date. This can be changed by setting an expiration date using
`setExpirationDate(date)`.

To enable password protection for the OpenPGP key, you can call `setPassphrase(passphrase)`.
If this method is not called, or if the passed in `Passphrase` is empty, the key will be unprotected.

Finally, calling `build()` will generate a fresh OpenPGP key according to the specifications given.