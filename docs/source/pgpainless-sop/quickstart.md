## SOP API with pgpainless-sop

The Stateless OpenPGP Protocol (SOP) defines a simplistic interface for the most important OpenPGP operations.
It allows you to encrypt, decrypt, sign and verify messages, generate keys and add/remove ASCII armor from data.
However, it does not yet provide tools for key management.
Furthermore, the implementation is deciding for you, which (secure) algorithms to use, and it doesn't let you
change those.

If you want to read more about the background of the SOP protocol, there is a [whole chapter](../sop) dedicated to it.

### Setup

PGPainless' releases are published to and can be fetched from Maven Central.
To get started, you first need to include `pgpainless-sop` in your projects build script.
```
// If you use Gradle
...
dependencies {
    ...
    implementation "org.pgpainless:pgpainless-sop:XYZ"
    ...
}

// If you use Maven
...
<dependencies>
    ...
    <dependency>
        <groupId>org.pgpainless</groupId>
        <artifactId>pgpainless-sop</artifactId>
        <version>XYZ</version>
    </dependency>
    ...
</dependencies>
```

:::{important}
Replace `XYZ` with the current version, in this case {{ env.config.version }}!
:::

The entry point to the API is the `SOP` interface, for which `pgpainless-sop` provides a concrete implementation
`SOPImpl`.

```java
// Instantiate the API
SOP sop = new SOPImpl();
```

Now you are ready to go!

### Generate a Key

To generate a new OpenPGP key, the method `SOP.generateKey()` is your friend:

```java
// generate key
byte[] keyBytes = sop.generateKey()
        .userId("John Doe <john.doe@pgpainless.org>")
        .withKeyPassword("f00b4r")
        .generate()
        .getBytes();
```

The call `userId(String userId)` can be called multiple times to add multiple user-ids to the key, but it MUST
be called at least once.
The argument given in the first invocation will become the keys primary user-id.

Optionally, the key can be protected with a password by calling `withKeyPassword(String password)`.
If this method is not called, the key will be unprotected.

The `generate()` method call generates the key and returns a `Ready` object.
This in turn can be used to write the result to a stream via `writeTo(OutputStream out)`, or to get the result
as bytes via `getBytes()`.
In both cases, the resulting output will be the UTF8 encoded, ASCII armored OpenPGP secret key.

To disable ASCII armoring, call `noArmor()` before calling `generate()`.

Revision `05` of the Stateless OpenPGP Protocol specification introduced the concept of profiles for
certain operations.
The key generation feature is the first operation to make use of profiles to specify different key algorithms.
To set a profile, simply call `profile(String profileName)` and pass in one of the available profile identifiers.

To explore, which profiles are available, refer to the dedicated [section](#explore-profiles).

The default profile used by `pgpainless-sop` is called `draft-koch-eddsa-for-openpgp-00`.
If this profile is used, the resulting OpenPGP secret key will consist of a certification-capable 256-bits
ed25519 EdDSA primary key, a 256-bits ed25519 EdDSA subkey used for signing, as well as a 256-bits X25519
ECDH subkey for encryption.

Another profile defined by `pgpainless-sop` is `rfc4880`, which changes the key generation behaviour such that
the resulting key is a single 4096-bit RSA key capable of certifying, signing and encrypting.

The whole key does not have an expiration date set.

### Extract a Certificate

Now that you generated your secret key, you probably want to share the public key with your contacts.
To extract the OpenPGP public key (which we will call *certificate* from now on) from the secret key,
use the `SOP.extractCert()` method call:

```java
// extract certificate
byte[] certificateBytes = sop.extractCert()
        .key(keyBytes)
        .getBytes();
```

The `key(_)` method either takes a byte array (like in the example), or an `InputStream`.
In both cases it returns another `Ready` object from which the certificate can be accessed, either via
`writeTo(OutputStream out)` or `getBytes()`.

By default, the resulting certificate will be ASCII armored, regardless of whether the input key was armored or not.
To disable ASCII armoring, call `noArmor()` before calling `key(_)`.

In our example, `certificateBytes` can now safely be shared with anyone.

### Change Key Password

OpenPGP keys can (but don't need to) be password protected.
The `changeKeyPassword()` API can be used to add, change or remove password protection from OpenPGP keys.
While the input to this operation can be keys with different per-subkey passwords, the output will use at most one password.

Via `oldKeyPassphrase()`, multiple decryption passphrase candidates can be provided.
These are tried one after another to unlock protected subkeys.

In order to successfully change the passphrase of an OpenPGP key, all of its subkeys needs to be successfully decrypted.
If one or more subkeys cannot be decrypted, the operation fails with a `KeyIsProtected` exception.
The result is either fully encrypted for a single passphrase (passed via `newKeyPassphrase()`),
or unprotected if the new key passphrase is omitted.


```java
byte[] keyBefore = ...
byte[] keyAfter = sop.changeKeyPassword()
        // Provide old passphrases - all subkeys need to be decryptable,
        //  otherwise KeyIsProtected exception will be thrown
        .oldKeyPassphrase("4d4m5m1th")
        .oldKeyPassphrase("d4v1dR1c4rd0")
        // Provide the new passphrase - if omitted, key will be unprotected
        .newKeyPassphrase("fr1edr1ch3n93l5")
        .keys(keyBefore)
        .getBytes();
```

### Generate Revocation Certificates

You might want to generate a revocation certificate for your OpenPGP key.
This certificate can be published to a key server to let your contacts known that your key is no longer
trustworthy.
The `revokeKey()` API can be used to generate a "hard-revocation", which retroactively invalidates all
signatures previously issued by the key.

If the input secret key is an OpenPGP v6 key, the result will be a minimal revocation certificate,
consisting of only the bare primary public key and a revocation signature. For v4 keys, the result
will consist of the whole public certificate plus a revocation signature.

```java
byte[] keys = ...
byte[] revoked = sop.revokeKey()
        // primary key password(s) if the key(s) are protected
        .withKeyPassword("5w0rdf1sh")
        // one or more secret keys
        .keys(keys)
        .getBytes();
```

### Apply / Remove ASCII Armor

Perhaps you want to print your secret key onto a piece of paper for backup purposes,
but you accidentally called `noArmor()` when generating the key.

To add ASCII armor to some binary OpenPGP data, the `armor()` API can be used:

```java
// wrap data in ASCII armor
byte[] armoredData = sop.armor()
        .data(binaryData)
        .getBytes();
```

The `data(_)` method can either be called by providing a byte array, or an `InputStream`.

To remove ASCII armor from armored data, simply use the `dearmor()` API:

```java
// remove ASCII armor
byte[] binaryData = sop.unarmor()
        .data(armoredData)
        .getBytes();
```

Once again, the `data(_)` method can be called either with a byte array or an `InputStream` as argument.

If the input data is not validly armored OpenPGP data, the `data(_)` method call will throw a `BadData` exception.

### Encrypt a Message

Now lets get to the juicy part and finally encrypt a message!
In this example, we will assume that Alice is the sender that wants to send a message to Bob.
Beforehand, Alice acquired Bobs certificate, e.g. by fetching it from a key server.

To encrypt a message, you can make use of the `encrypt()` API:

```java
// encrypt and sign a message
byte[] aliceKey = ...;  // Alice' secret key
byte[] aliceCert = ...; // Alice' certificate (e.g. via extractCert())
byte[] bobCert = ...;   // Bobs certificate

byte[] plaintext = "Hello, World!\n".getBytes(); // plaintext

byte[] ciphertext = sop.encrypt()
        // encrypt for each recipient
        .withCert(bobCert)
        .withCert(aliceCert)
        // Optionally: Sign the message
        .signWith(aliceKey)
        .withKeyPassword("sw0rdf1sh") // if signing key is protected
        // provide the plaintext
        .plaintext(plaintext)
        .getBytes();
```

Here you encrypt the message for each recipient (Alice probably wants to be able to decrypt the message too!)
by calling `withCert(_)` with the recipients certificate as argument. It does not matter, if the certificate
is ASCII armored or not, and the method can either be called with a byte array or an `InputStream` as argument.

The API not only supports asymmetric encryption via OpenPGP certificates, but it can also encrypt messages
symmetrically using one or more passwords. Both mechanisms can even be used together in the same message!
To (additionally or exclusively) encrypt the message for a password, simply call `withPassword(String password)`
before the `plaintext(_)` method call.

It is recommended (but not required) to sign encrypted messages.
In order to sign the message before encryption is applied, call `signWith(_)` with the signing key as argument.
This method call can be repeated multiple times to sign the message with multiple signing keys.

If any keys used for signing are password protected, you need to provide the signing key password via
`withKeyPassword(_)`.
It does not matter in which order signing keys and key passwords are provided, the implementation will figure out
matches on its own. If different key passwords are used, the `withKeyPassword(_)` method can be called multiple times.

You can modify the behaviour of the encrypt operation by switching between different profiles via the
`profile(String profileName)` method.
At the time of writing, the only available profile for this operation is `rfc4880` which applies encryption
as defined in [rfc4880](https://datatracker.ietf.org/doc/html/rfc4880).

To explore, which profiles are available, refer to the dedicated [section](#explore-profiles).

By default, the encrypted message will be ASCII armored. To disable ASCII armor, call `noArmor()` before the
`plaintext(_)` method call.

Lastly, you need to provide the plaintext by calling `plaintext(_)` with either a byte array or an `InputStream`
as argument.
The ciphertext can then be accessed from the resulting `Ready` object as usual.

### Decrypt a Message

Now let's switch perspective and help Bob decrypt the message from Alice.

Decrypting encrypted messages is done in a similar fashion using the `decrypt()` API:

```java
// decrypt a message and verify its signature(s)
byte[] aliceCert = ...; // Alice' certificate
byte[] bobKey = ...;    // Bobs secret key 
byte[] bobCert = ...;   // Bobs certificate

byte[] ciphertext = ...; // the encrypted message

ReadyWithResult<DecryptionResult> readyWithResult = sop.decrypt()
        .withKey(bobKey)
        .verifyWithCert(aliceCert)
        .withKeyPassword("password123") // if decryption key is protected
        .ciphertext(ciphertext);
```

The `ReadyWithResult<DecryptionResult>` can now be processed in two different ways, depending on whether you want the
plaintext as bytes or simply write it out to an `OutputStream`.

To get the plaintext bytes directly, you shall proceed as follows:

```java
ByteArrayAndResult<DecryptionResult> bytesAndResult = readyWithResult.toByteArrayAndResult();
DecryptionResult result = bytesAndResult.getResult();
byte[] plaintext = bytesAndResult.getBytes();
```

If you instead want to write the plaintext out to an `OutputStream`, the following code can be used:

```java
OutputStream out = ...;
DecryptionResult result = readyWithResult.writeTo(out);
```

Note, that in both cases you acquire a `DecryptionResult` object. This contains information about the message,
such as which signatures could successfully be verified.

If you provided the senders certificate for the purpose of signature verification via `verifyWith(_)`, you now
probably want to check, if the message was actually signed by the sender by checking `result.getVerifications()`.

:::{note}
Signature verification will be discussed in more detail in section "Verifications".
:::

If the message was encrypted symmetrically using a password, you can also decrypt is symmetrically by calling
`withPassword(String password)` before the `ciphertext(_)` method call. This method call can be repeated multiple
times. The implementation will try different passwords until it finds a matching one.

### Sign a Message

There are three different main ways of signing a message:
* Inline Signatures
* Cleartext Signatures
* Detached Signatures

An inline-signature will be part of the message itself (e.g. like with messages that are encrypted *and* signed).
Inline-signed messages are not human-readable without prior processing.

A cleartext signature makes use of the [cleartext signature framework](https://datatracker.ietf.org/doc/html/rfc4880#section-7).
Messages signed in this way do have an ASCII armor header and footer, yet the content of the message is still
human-readable without special software.

Lastly, a detached signature can be distributed as an extra file alongside the message without altering it.
This is useful if the plaintext itself cannot be modified (e.g. if a binary file is signed).

The SOP API can generate all of those signature types.

#### Inline-Signatures

Let's start with an inline signature:

```java
byte[] signingKey = ...;
byte[] message = ...;

byte[] inlineSignedMessage = sop.inlineSign()
        .mode(InlineSignAs.Text) // or 'Binary'
        .key(signingKey)
        .withKeyPassword("fnord")
        .data(message)
        .getBytes();
```

You can choose between two different signature formats which can be set using `mode(InlineSignAs mode)`.
The default value is `Binary`. You can also set it to `Text` which signals to the receiver that the data is
UTF8 text.

:::{note}
For inline signatures, do NOT set the `mode()` to `CleartextSigned`, as that will create message which uses the
cleartext signature framework (see further below).
:::

You must provide at least one signing key using `key(_)` in order to be able to sign the message.

If any key is password protected, you need to provide its password using `withKeyPassword(_)` which
can be called multiple times to provide multiple passwords.

Once you provide the plaintext using `data(_)` with either a byte array or an `InputStream` as argument,
you will get a `Ready` object back, from which the signed message can be retrieved as usual.

By default, the signed message will be ASCII armored. This can be disabled by calling `noArmor()`
before the `data(_)` method call.

#### Cleartext Signatures

A cleartext-signed message can be generated in a similar way to an inline-signed message, however,
there are is one subtle difference:

```java
byte[] signingKey = ...;
byte[] message = ...;

byte[] cleartextSignedMessage = sop.inlineSign()
        .mode(InlineSignAs.CleartextSigned) // This MUST be set
        .key(signingKey)
        .withKeyPassword("fnord")
        .data(message)
        .getBytes();
```

:::{important}
In order to produce a cleartext-signed message, the signature mode MUST be set to `CleartextSigned`
by calling `mode(InlineSignAs.CleartextSigned)`.
:::

:::{note}
Calling `noArmor()` will have no effect for cleartext-signed messages, so such method call will be ignored.
:::

#### Detached Signatures

As the name suggests, detached signatures are detached from the message itself and can be distributed separately.

To produce a detached signature, the `detachedSign()` API is used:

```java
byte[] signingKey = ...;
byte[] message = ...;

ReadyWithResult<SigningResult> readyWithResult = sop.detachedSign()
        .key(signingKey)
        .withKeyPassword("fnord")
        .data(message);
```

Here you have the choice, how you want to write out the signature.
If you want to write the signature to an `OutputStream`, you can do the following:

```java
OutputStream out = ...;
SigningResult result = readyWithResult.writeTo(out);
```

If instead you want to get the signature as a byte array, do this instead:

```java
ByteArrayAndResult<SigningResult> bytesAndResult = readyWithResult.toByteArrayAndResult();
SigningResult result = bytesAndResult.getResult();
byte[] detachedSignature = bytesAndResult.getBytes();
```

In any case, the detached signature can now be distributed alongside the original message.

By default, the resulting detached signature will be ASCII armored. This can be disabled by calling `noArmor()`
prior to calling `data(_)`.

The `SigningResult` object you got back in both cases contains information about the signature.

### Verify a Signature

In order to verify signed messages, there are two API endpoints available.

#### Inline and Cleartext Signatures

To verify inline-signed messages, or messages that make use of the cleartext signature framework,
use the `inlineVerify()` API:

```java
byte[] signingCert = ...;
byte[] signedMessage = ...;

ReadyWithResult<List<Verification>> readyWithResult = sop.inlineVerify()
        .cert(signingCert)
        .data(signedMessage);
```

The `cert(_)` method MUST be called at least once. It takes either a byte array or an `InputStream` containing
an OpenPGP certificate.
If you are not sure, which certificate was used to sign the message, you can provide multiple certificates.

It is also possible to reject signatures that were not made within a certain time window by calling
`notBefore(Date timestamp)` and/or `notAfter(Date timestamp)`.
Signatures made before the `notBefore(_)` or after the `notAfter(_)` constraints will be rejected.

You can now either write out the plaintext message to an `OutputStream`...

```java
OutputStream out = ...;
List<Verifications> verifications = readyWithResult.writeTo(out);
```

... or you can acquire the plaintext message as a byte array directly:

```java
ByteArrayAndResult<List<Verifications>> bytesAndResult = readyWithResult.toByteArrayAndResult();
byte[] plaintextMessage = bytesAndResult.getBytes();
List<Verifications> verifications = bytesAndResult.getResult();
```

In both cases, the plaintext message will have the signatures stripped.

#### Detached Signatures

To verify detached signatures (signatures that come separate from the message itself), you can use the
`detachedVerify()` API:

```java
byte[] signingCert = ...;
byte[] message = ...;
byte[] detachedSignature = ...;

List<Verification> verifications = sop.detachedVerify()
        .cert(signingCert)
        .signatures(detachedSignature)
        .data(signedMessage);
```

You can provide one or more OpenPGP certificates using `cert(_)`, providing either a byte array or an `InputStream`.

The detached signatures need to be provided separately using the `signatures(_)` method call.
You can provide as many detached signatures as you like, and those can be binary or ASCII armored.

Like with Inline Signatures, you can constrain the time window for signature validity using
`notAfter(_)` and `notBefore(_)`.

#### Verifications

In all above cases, the `verifications` list will contain `Verification` objects for each verifiable, valid signature.
Those objects contain information about the signatures:
`verification.getSigningCertFingerprint()` will return the fingerprint of the certificate that created the signature.
`verification.getSigningKeyFingerprint()` will return the fingerprint of the used signing subkey within that certificate.

### Detach Signatures from Messages

It is also possible, to detach inline or cleartext signatures from signed messages to transform them into
detached signatures.
The same way you can turn inline or cleartext signed messages into plaintext messages.

To detach signatures from messages, use the `inlineDetach()` API:

```java
byte[] signedMessage = ...;

ReadyWithResult<Signatures> readyWithResult = sop.inlineDetach()
        .message(signedMessage);
ByteArrayAndResult<Signatures> bytesAndResult = readyWithResult.toByteArrayAndResult();

byte[] plaintext = bytesAndResult.getBytes();
Signatures signatures = bytesAndResult.getResult();
byte[] encodedSignatures = signatures.getBytes();
```

By default, the signatures output will be ASCII armored. This can be disabled by calling `noArmor()`
prior to `message(_)`.

The detached signatures can now be verified like in the section above.

### Explore Profiles

Certain operations allow modification of their behaviour by selecting between different profiles.
An example for this is the `generateKey()` operation, where different profiles result in different algorithms used
during key generation.

To explore, which profiles are supported by a certain operation, you can use the `listProfiles()` operation.
For example, this is how you can get a list of profiles supported by the `generateKey()` operation:

```java
List<Profile> profiles = sop.listProfiles().subcommand("generate-key");
```

:::{note}
As you can see, the argument passed into the `subcommand()` method must match the operation name as defined in the
[Stateless OpenPGP Protocol specification](https://datatracker.ietf.org/doc/draft-dkg-openpgp-stateless-cli/).
:::

At the time of writing (the latest revision of the SOP spec is 06), only `generate-key` and `encrypt` accept profiles.