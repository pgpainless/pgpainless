# Migration Guide PGPainless 2.0

PGPainless 2.0 makes use of Bouncy Castles new High Level API.
As a consequence, the use of certain "mid-level" classes, such as `PGPPublicKeyRing`, `PGPSecretKeyRing` is now
discouraged in favor of their high-level counterparts, e.g. `OpenPGPCertificate`, `OpenPGPKey`.

## Terminology Changes

Bouncy Castles high level API uses OpenPGP terminology as described in the book [OpenPGP for application developers](https://openpgp.dev/book/).
Therefore, some terms used in the mid-level API are no longer used.

| Old Term        | New Term                   | Description                                          |
|-----------------|----------------------------|------------------------------------------------------|
| key ring        | OpenPGP certificate or key |                                                      |
| public key ring | certificate                |                                                      |
| secret key ring | key                        |                                                      |
| subkey          | component key              | A component key is either a primary key, or a subkey |


## Key Material

The use of `PGPPublicKeyRing` objects is now discouraged in favor of `OpenPGPCertificate`.
Appropriately, `OpenPGPKey` replaces `PGPSecretKeyRing`. `OpenPGPKey` extends the `OpenPGPCertificate` class, but also
contains secret key material.

An `OpenPGPCertificate` consists of `OpenPGPComponentSignature`s and `OpenPGPCertificateComponent`s,
such as `OpenPGPComponentKey`s and `OpenPGPIdentityComponent`s.
`OpenPGPIdentityComponent`s are either `OpenPGPUserId`s or `OpenPGPUserAttribute`s.
Components of an OpenPGP certificate, which contain key material (public keys, secret keys, subkeys...) are represented
by the `OpenPGPComponentKey` class, from which `OpenPGPPrimaryKey`, `OpenPGPSubkey` and `OpenPGPSecretKey` inherit.

`OpenPGPCertificateComponent`s are bound to the certificate by `OpenPGPSignature`s, which Bouncy Castle organizes into
`OpenPGPSignatureChains` internally.

## `KeyIdentifier`
OpenPGP has evolved over time and with it the way to identify individual keys.
Old protocol versions rely on 64-bit key-ids, which are nowadays deprecated, as 64-bits are not exactly collision-resistant.
For some time already, the use of fingerprints is therefore encouraged as a replacement.
However, key-ids were not everywhere at once in the protocol, so many artifacts still contain elements with key-ids in them.
An example for this are public-key encrypted session-key packets, which in version 1 still only contain the recipients
key-id.
In signatures, both key-ids and fingerprints are present.

To solve this inconsistency, Bouncy Castle introduced the `KeyIdentifier` type as an abstraction of both key-ids and fingerprints.
Now most methods that take some sort of identifier, be it fingerprint or key-id, now also accept a `KeyIdentifier` object.

Consequently, `KeyIdentifier` is now also the preferred way to reference keys in PGPainless and many places where previously
a key-id or fingerprint was exepcted, now also accept `KeyIdentifier` objects.

## Differences between BCs high level API and PGPainless

With Bouncy Castle now introducing its own high-level API, you might ask, what differences there are between
high-level PGPainless classes and their new Bouncy Castle counterparts.

### `KeyRingInfo` vs. `OpenPGPCertificate`/`OpenPGPKey`

PGPainless' `KeyRingInfo` class fulfils a similar task as the new `OpenPGPCertificate`/`OpenPGPKey` classes,
namely evaluating OpenPGP key material, checking self signatures, exposing certain properties like
subkeys, algorithm preferences etc. in a way accessible for the user, all with respect to a given reference time.

However, `KeyRingInfo` historically gets instantiated *per reference time*, while`OpenPGPCertificate`/`OpenPGPKey`
is instantiated only *once* and expects you to pass in the reference time each time you are using a
property getter, lazily evaluating applicable signatures as needed.
Under the hood, the Bouncy Castle classes now cache expensive signature verification results for later use.
Consequently, `KeyRingInfo` now wraps `OpenPGPCertificate`/`OpenPGPKey`, forwarding method calls while passing along
the chosen reference time and mapping basic data types to PGPainless' high level types / enums.

## Replacements

| Old                          | New                   | Comment                                                             |
|------------------------------|-----------------------|---------------------------------------------------------------------|
| `PGPPublicKeyRing`           | `OpenPGPCertificate`  | Self-Signatures are automagically evaluated                         |
| `PGPSecretKeyRing`           | `OpenPGPKey`          | Same as `OpenPGPCertificate`, but also contains secret key material |
| `PGPPublicKey` (primary key) | `OpenPGPPrimaryKey`   | -                                                                   |
| `PGPPublicKey` (subkey)      | `OpenPGPComponentKey` | -                                                                   |
| `PGPSecretKey` (primary key) | `OpenPGPSecretKey`    | -                                                                   |
| `PGPSecretKey` (subkey)      | `OpenPGPSecretKey`    | -                                                                   |
| `PGPPrivateKey`              | `OpenPGPPrivateKey`   | -                                                                   |
| `Long` (Key-ID)              | `KeyIdentifier`       | -                                                                   |
| `byte[]` (Key Fingerprint)   | `KeyIdentifier`       | -                                                                   |