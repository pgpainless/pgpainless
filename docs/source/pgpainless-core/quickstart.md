## PGPainless API with pgpainless-core

The `pgpainless-core` module contains the bulk of the actual OpenPGP implementation.

This is a quickstart guide. For more in-depth exploration of the API, checkout [](indepth.md).

:::{note}
This chapter is work in progress.
:::

### Setup

PGPainless' releases are published to and can be fetched from Maven Central.
To get started, you first need to include `pgpainless-core` in your projects build script:

```
// If you use Gradle
...
dependencies {
    ...
    implementation "org.pgpainless:pgpainless-core:XYZ"
    ...
}

// If you use Maven
...
<dependencies>
    ...
    <dependency>
        <groupId>org.pgpainless</groupId>
        <artifactId>pgpainless-core</artifactId>
        <version>XYZ</version>
    </dependency>
    ...
</dependencies>
```

This will automatically pull in PGPainless' dependencies, such as Bouncy Castle.

:::{important}
Replace `XYZ` with the current version, in this case {{ env.config.version }}!
:::

The entry point to the API is the `PGPainless` class.
For many common use-cases, examples can be found in the
{{ '[examples package](https://{}/main/pgpainless-core/src/test/java/org/pgpainless/example)'.format(repo_pgpainless_src) }}.
There is a very good chance that you can find code examples there that fit your needs.

### Read and Write Keys
Reading keys from ASCII armored strings or from binary files is easy:

```java
String key = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"...;
PGPSecretKeyRing secretKey = PGPainless.readKeyRing()
        .secretKeyRing(key);
```

Similarly, keys or certificates can quickly be exported:

```java
// ASCII armored key
PGPSecretKeyRing secretKey = ...;
String armored = PGPainless.asciiArmor(secretKey);
        
// binary (unarmored) key
byte[] binary = secretKey.getEncoded();
```

### Generate a Key
PGPainless comes with a method to quickly generate modern OpenPGP keys.
There are some predefined key archetypes, but it is possible to fully customize the key generation to fit your needs.

```java
// EdDSA primary key with EdDSA signing- and XDH encryption subkeys
PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
        .modernKeyRing("Romeo <romeo@montague.lit>", "thisIsAPassword");

// RSA key without additional subkeys
PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
        .simpleRsaKeyRing("Juliet <juliet@montague.lit>", RsaLength._4096);
```

As you can see, it is possible to generate all kinds of different keys.

### Extract a Certificate
If you have a secret key, you might want to extract a public key certificate from it:

```java
PGPSecretKeyRing secretKey = ...;
PGPPublicKeyRing certificate = PGPainless.extractCertificate(secretKey);
```

### Apply / Remove ASCII Armor
ASCII armor is a layer of radix64 encoding that can be used to wrap binary OpenPGP data in order to make it save to
transport via text-based channels (e.g. email bodies).

The way in which ASCII armor can be applied depends on the type of data that you want to protect.
The easies way to ASCII armor an OpenPGP key or certificate is by using PGPainless' `asciiArmor()` method:

```java
PGPPublicKey certificate = ...;
String asciiArmored = PGPainless.asciiArmor(certificate);
```

If you want to ASCII armor ciphertext, you can enable ASCII armoring during encrypting/signing by requesting
PGPainless to armor the result:

```java
ProducerOptions producerOptions = ...; // prepare as usual (see next section)

producerOptions.setAsciiArmor(true); // enable armoring

EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
        .onOutputStream(out)
        .withOptions(producerOptions);

...
```

If you have an already encrypted / signed binary message and want to add ASCII armoring retrospectively, you need
to make use of BouncyCastle's `ArmoredOutputStream` as follows:

```java
InputStream binaryOpenPgpIn = ...; // e.g. new ByteArrayInputStream(binaryMessage);

OutputStream output = ...; // e.g. new ByteArrayOutputStream();
ArmoredOutputStream armorOut = ArmoredOutputStreamFactory.get(output);

Streams.pipeAll(binaryOpenPgpIn, armorOut);
armorOut.close(); // important!
```

The output stream will now contain the ASCII armored representation of the binary data.

If the data you want to wrap in ASCII armor is non-OpenPGP data (e.g. the String "Hello World!"),
you need to use the following code:

```java
InputStream inputStream = ...;
OutputStream output = ...;

EncryptionStream armorStream = PGPainless.encryptAndOrSign()
        .onOutputStream(output)
        .withOptions(ProducerOptions.noEncryptionNoSigning()
                .setAsciiArmor(true));

Streams.pipeAll(inputStream, armorStream);
armorStream.close();
```

To remove ASCII armor, you can make use of BouncyCastle's `ArmoredInputStream` as follows:

```java
InputStream input = ...; // e.g. new ByteArrayInputStream(armoredString.getBytes(StandardCharsets.UTF8));
OutputStream output = ...;

ArmoredInputStream armorIn = new ArmoredInputStream(input);
Streams.pipeAll(armorIn, output);
armorIn.close();
```

The output stream will now contain the binary OpenPGP data.

### Encrypt and/or Sign a Message
Encrypting and signing messages is done using the same API in PGPainless.
The type of action depends on the configuration of the `ProducerOptions` class, which in term accepts
`SigningOptions` and `EncryptionOptions` objects:

```java
// Encrypt only
ProducerOptions options = ProducerOptions.encrypt(encryptionOptions);

// Sign only
ProducerOptions options = ProducerOptions.sign(signingOptions);

// Sign and encrypt
ProducerOptions options = ProducerOptions.signAndEncrypt(signingOptions, encryptionOptions);
```

The `ProducerOptions` object can then be passed into the `encryptAndOrSign()` API:

```java
InputStream plaintext = ...; // The data that shall be encrypted and/or signed
OutputStream ciphertext = ...; // Destination for the ciphertext

EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
        .onOutputStream(ciphertext)
        .withOptions(options); // pass in the options object

Streams.pipeAll(plaintext, encryptionStream); // pipe the data through
encryptionStream.close(); // important! Close the stream to finish encryption/signing

EncryptionResult result = encryptionStream.getResult(); // metadata
```

The `ciphertext` output stream now contains the encrypted and/or signed data.

Now lets take a look at the configuration of the `SigningOptions` object and how to instruct PGPainless to add a simple
signature to the message:

```java
PGPSecretKeyRing signingKey = ...; // Key used for signing
SecretKeyRingProtector protector = ...; // Protector to unlock the signing key

SigningOptions signOptions = SigningOptions.get()
        .addSignature(protector, signingKey);
```
This will add an inline signature to the message.

It is possible to add multiple signatures from different keys by repeating the `addSignature()` method call.

If instead of an inline signature, you want to create a detached signature instead (e.g. because you do not want
to alter the data you are signing), you can add the signature as follows:

```java
signOptions.addDetachedSignature(protector, signingKey);
```

Passing in the `SigningOptions` object like this will result in the signature not being added to the message itself.
Instead, the signature can later be acquired from the `EncryptionResult` object via `EncryptionResult.getDetachedSignatures()`.
That way, it can be distributed independent of the message.

The `EncryptionOptions` object can be configured in a similar way:

```java
PGPPublicKey certificate = ...;

EncryptionOptions encOptions = EncryptionOptions.get()
        .addRecipient(certificate);
```

Once again, it is possible to add multiple recipients by repeating the `addRecipient()` method call.

You can also encrypt a message to a password like this:
```java
encOptions.addPassphrase(Passphrase.fromPassword("sw0rdf1sh"));
```

Both methods can be used in combination to create a message which can be decrypted with either a recipients secret key
or the passphrase.

### Decrypt and/or Verify a Message
Decryption and verification of a message is both done using the same API.
Whether a message was actually signed / encrypted can be determined after the message has been processed by checking
the `MessageMetadata` object which can be obtained from the `DecryptionStream`.

To configure the decryption / verification process, the `ConsumerOptions` object is used:

```java
PGPPublicKeyRing verificationCert = ...; // optional, signers certificate for signature verification
PGPSecretKeyRing decryptionKey = ...; // optional, decryption key

ConsumerOptions options = ConsumerOptions.get()
        .addVerificationCert(verificationCert) // add a verification cert for signature verification
        .addDecryptionKey(decryptionKey); // add a secret key for message decryption
```

Both verification certificates and decryption keys are optional.
If you know the message is signed, but not encrypted you can omit providing a decryption key.
Same goes for if you know that the message is encrypted, but not signed.
In this case you can omit the verification certificate.

On the other hand, providing these parameters does not hurt.
PGPainless will ignore unused keys / certificates, so if you provide a decryption key and the message is not encrypted,
nothing bad will happen.

It is possible to provide multiple verification certs and decryption keys. PGPainless will pick suitable ones on the fly.
If the message is signed with key `0xAAAA` and you provide certificates `0xAAAA` and `0xBBBB`, it will verify
with cert `0xAAAA` and ignore `0xBBBB`.

To do the actual decryption / verification of the message, do the following:

```java
InputStream ciphertext = ...; // encrypted and/or signed message
OutputStream plaintext = ...; // destination for the plaintext

ConsumerOptions options = ...; // see above
DecryptionStream consumerStream = PGPainless.decryptAndOrVerify()
        .onInputStream(ciphertext)
        .withOptions(options);

Streams.pipeAll(consumerStream, plaintext);
consumerStream.close(); // important!

// The result will contain metadata of the message
MessageMetadata result = consumerStream.getMetadata();
```

After the message has been processed, you can consult the `MessageMetadata` object to determine the nature of the message:

```java
boolean wasEncrypted = result.isEncrypted();
SubkeyIdentifier decryptionKey = result.getDecryptionKey();
List<SignatureVerification> validSignatures = result.getVerifiedSignatures();
boolean wasSignedByCert = result.isVerifiedSignedBy(certificate);

// For files:
String fileName = result.getFileName();
Date modificationData = result.getModificationDate();
```

### Verify a Signature
In some cases, detached signatures are distributed alongside the message.
This is the case for example with Debians `Release` and `Release.gpg` files.
Here, `Release` is the plaintext message, which is unaltered by the signing process while `Release.gpg` contains
the detached OpenPGP signature.

To verify a detached signature, you need to call the PGPainless API like this:

```java
InputStream plaintext = ...; // e.g. new FileInputStream(releaseFile);
InputStream detachedSignature = ...; // e.g. new FileInputStream(releaseGpgFile);
PGPPublicKeyRing certificate = ...; // e.g. debians public signing key

ConsumerOptions options = ConsumerOptions.get()
        .addVerificationCert(certificate) // provide certificate for verification
        .addVerificationOfDetachedSignatures(detachedSignature) // provide detached signature

DecryptionStream verificationStream = PGPainless.decryptAndOrVerify()
        .onInputStream(plaintext)
        .withOptions(options);

Streams.drain(verificationStream); // push all the data through the stream
verificationStream.close(); // finish verification

MessageMetadata result = verificationStream.getMetadata(); // get metadata of signed message
assertTrue(result.isVerifiedSignedBy(certificate)); // check if message was in fact signed
```