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
// Secret Keys
String key = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"...;
PGPSecretKeyRing secretKey = PGPainless.readKeyRing()
        .secretKeyRing(key);

// Certificates (Public Keys)
String cert = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...";
PGPPublicKeyRing certificate = PGPainless.readKeyRing()
        .publicKeyRing(cert);
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

In order to prevent metadata leaks, you might want to add recipients anonymously.
Anonymous recipients have their key-id hidden by replacing it with a wildcard.
That way, it is not easily possible for an attacker to deduce the recipients of a message without further
analysis of additional metadata.
Anonymous recipients can be added like follows:
```java
encOptions.addHiddenRecipient(certificate);
```

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

### Legacy Compatibility
Out of the box, PGPainless is configured to use secure defaults and perform checks for recommended
security features. This means that for example messages generated using older OpenPGP
implementations which do not follow those best practices might fail to decrypt/verify.

It is however possible to circumvent certain security checks to allow processing of such messages.

:::{note}
It is not recommended to disable security checks, as that might enable certain attacks on the OpenPGP protocol.
:::

#### Missing / broken MDC (modification detection code)
RFC4880 has two different types of encrypted data packets. The *Symmetrically Encrypted Data* packet (SED) and the *Symmetrically Encrypted Integrity-Protected Data* packet.
The latter has an added MDC packet which prevents modifications to the ciphertext.

While implementations are highly encouraged to only use the latter package type, some older implementations still generate
encrypted data packets which are not integrity protected.

To allow PGPainless to decrypt such messages, you need to set a flag in the `ConsumerOptions` object:
```java
ConsumerOptions options = ConsumerOptions.get()
        .setIgnoreMDCErrors(true) // <-
        .setDecryptionKey(secretKey)
        ...

DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
        .onInputStream(ciphertextIn)
        .withOptions(options);
...
```

:::{note}
It is highly advised to only set this flag if you know what you are doing.
It might also be a good idea to try decrypting a message without the flag set first and only re-try
decryption with the flag set in case of a `MessageNotIntegrityProtectedException` (don't forget to rewind the ciphertextInputStream).
:::

#### Weak keys and broken algorithms
Some users might cling on to older keys using weak algorithms / small key sizes.
PGPainless refuses to encrypt to weak certificates and sign with weak keys.
By default, PGPainless follows the recommendations for acceptable key sizes of [the German BSI in 2021](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf).
It can however be configured to accept older key material / algorithms too.

Minimal key lengths can be configured by changing PGPainless' policy:
```java
Map<PublicKeyAlgorithm, Integer> algorithms = new HashMap<>();
// put all acceptable algorithms and their minimal key length
algorithms.put(PublicKeyAlgorithm.RSA_GENERAL, 1024);
algorithms.put(PublicKeyAlgorithm.ECDSA, 100);
...
Policy.PublicKeyAlgorithmPolicy pkPolicy = 
        new Policy.PublicKeyAlgorithmPolicy(algorithms);
// set the custom algorithm policy
PGPainless.getPolicy().setPublicKeyAlgorithmPolicy();
```

Since OpenPGP uses a hybrid encryption scheme of asymmetric and symmetric encryption algorithms,
it also comes with a policy for symmetric encryption algorithms.
This list can be modified to allow for weaker algorithms like follows:
```java
// default fallback algorithm for message encryption
SymmetricKeyAlgorithm fallbackAlgorithm = SymmetricKeyAlgorithm.AES_256;
// acceptable algorithms
List<SymmetricKeyAlgorithm> algorithms = new ArrayList<>();
algorithms.add(SymmetricKeyAlgorithm.AES_256);
algorithms.add(SymmetricKeyAlgorithm.AES_192);
algorithms.add(SymmetricKeyAlgorithm.AES_128);
algorithms.add(SymmetricKeyAlgorithm.TWOFISH);
algorithms.add(SymmetricKeyAlgorithm.BLOWFISH);
...
Policy.SymmetricKeyAlgorithmPolicy skPolicy = 
        new SymmtricKeyAlgorithmPolicy(fallbackAlgorithm, algorithms);
// set the custom algorithm policy
// algorithm policy applicable when decrypting messages created by legacy senders:
PGPainless.getPolicy()
        .setSymmetricKeyDecryptionAlgorithmPolicy(skPolicy);
// algorithm policy applicable when generating messages for legacy recipients:
PGPainless.getPolicy()
        .setSymmetricKeyEncryptionAlgorithmPolicy(skPolicy);
```

Hash algorithms are used in OpenPGP to create signatures.
Since signature verification is an integral part of the OpenPGP protocol, PGPainless comes
with multiple policies for acceptable hash algorithms, depending on the use-case.
Revocation signatures are critical, so you might want to handle revocation signatures differently from normal signatures.

By default, PGPainless uses a smart hash algorithm policy for both use-cases, which takes into consideration
not only the hash algorithm itself, but also the creation date of the signature.
That way, signatures using SHA-1 are acceptable if they were created before February 2013, but are rejected if their
creation date is after that point in time.

A custom hash algorithm policy can be set like this:
```java
HashAlgorithm fallbackAlgorithm = HashAlgorithm.SHA512;
Map<HashAlgorithm, Date> algorithms = new HashMap<>();
// Accept MD5 on signatures made before 1997-02-01
algorithms.put(HashAlgorithm.MD5,
        DateUtil.parseUTCDate("1997-02-01 00:00:00 UTC"));
// Accept SHA-1, regardless of signature creation time
algorithms.put(HashAlgorithm.SHA1, null);
...
Policy.HashAlgorithmPolicy hPolicy =
        new Policy.HashAlgorithmPolicy(fallbackAlgorithm, algorithms);
// set policy for revocation signatures
PGPainless.getPolicy()
        .setRevocationSignatureHashAlgorithmPolicy(hPolicy);
// set policy for normal signatures (certifications and document signatures)
PGPainless.getPolicy()
        .setSignatureHashAlgorithmPolicy(hPolicy);
```

Lastly, PGPainless comes with a policy on acceptable compression algorithms, which currently accepts any
compression algorithm.
A custom compression algorithm policy can be set in a similar way:
```java
CompressionAlgorithm fallback = CompressionAlgorithm.ZIP;
List<CompressionAlgorithm> algorithms = new ArrayList<>();
algorithms.add(CompressionAlgorith.ZIP);
algorithms.add(CompressionAlgorithm.BZIP2);
...
Policy.CompressionAlgorithmPolicy cPolicy =
        new Policy.CompressionAlgorithmPolicy(fallback, algorithms);
PGPainless.getPolicy()
        .setCompressionAlgorithmPolicy(cPolicy);
```

To prevent a class of attacks described in the [paper](https://www.kopenpgp.com/#paper)
"Victory by KO: Attacking OpenPGP Using Key Overwriting",
PGPainless offers the option to validate private key material each time before using it,
to make sure that an attacker didn't tamper with the corresponding public key parameters.

These checks are disabled by default, but they can be enabled as follows:
```java
PGPainless.getPolicy()
        .setEnableKeyParameterValidation(true);
```

:::{note}
Validation checks against KOpenPGP attacks are disabled by default, since they are very costly
and only make sense in certain scenarios.
Please read and understand the paper to decide, if enabling the checks makes sense for your use-case.
:::


### Known Notations
In OpenPGP, signatures can contain [notation subpackets](https://www.rfc-editor.org/rfc/rfc4880#section-5.2.3.16).
A notation can give meaning to a signature, or add additional contextual information.
Signature subpackets can be marked as critical, meaning an implementation that does not know about
a certain subpacket MUST reject the signature.
The same is true for critical notations.

For that reason, PGPainless comes with a `NotationRegistry` class which can be used to register known notations,
such that a signature containing a critical notation of a certain value is not rejected.
To register a known notation, you can do the following:

```java
NotationRegistry registry = PGPainless.getPolicy()
        .getNotationRegistry();

registry.addKnownNotation("sample@example.com");
```