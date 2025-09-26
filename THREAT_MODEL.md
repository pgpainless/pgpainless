# Threat Model

The OpenPGP message protocol can be used to enforce the triad of *Confidentiality*, *Integrity* and *Authenticity* of
messages.

## Threats vs. Vulnerabilities vs. Risks
* Threats: the potential actor or method that could exploit a weakness
* Vulnerabilities: a weakness that can be exploited
* Risks: the potential of a successful exploitation

PGPainless being an OpenPGP library has a rather simple threat model, as it works on only a very limited set of input
data types and operations.
As the user, you typically supply it with some input data (keys, certificates, messages) and expect some result types
(again, keys, certificates, messages or metadata).
You have some expectations about the result though, e.g. if you encrypt a message, you expect only the intended set of
recipients to be able to access the message contents.
Of if you verify a signed message, you expect PGPainless to report back only the proper signature issuer,
if and only if the message has not been tampered with on the way.

Let's take a look at the Simplified STRIDE Framework to analyze PGPainless' threat model:

## Simplified STRIDE Framework
* Spoofing: Someone pretending to be someone they're not
* Tampering: Unauthorized changes to your code and data
* Repudiation: Denying having performed an action
* Information disclosure: Exposing sensitive data
* Denial of Service: Making your project unavailable
* Elevation of Privilege: Gaining more access than intended

We can see that not all of those classes of attacks do apply to PGPainless.
PGPainless does not require or manage special privileged contexts, so for example the viability of a privilege
escalation attack very specifically depends on the host application that integrates with PGPainless.
Similarly, PGPainless does not directly manage (i.e. store) user data, which an attacker might try to tamper with.
PGPainless can be used to make changes to keys and certificates, but the host application is responsible for storing
these artifacts safely.

When it comes to identity spoofing, PGPainless can only work on the limited view of the world you provide it with.
It does not know, which certificates and keys belong to which users, although it provides some tooling to make educated
guesses (i.e. the web-of-trust).

Let's dissect the attack classes with more scrutiny, assuming that you're playing the role of Alice who wants to
communicate securely and privately with Bob and Charlie, while Mallory is playing the role of an attacker:

### Spoofing
*Someone pretending to be someone they're not*

An attacker might try to spoof their identity in different places, but since PGPainless only operates on OpenPGP
artifacts, all conceivable attacks require the attacker to trick your application into feeding PGPainless some modified
OpenPGP artifacts (e.g. modified keys, certificates or messages).

If Mallory controls a source for OpenPGP certificates, e.g. gains access to a key server, they can provide your
application with tampered certificates or fake updates to existing certificates.


In a similar way, Mallory could try to spoof signatures on messages, claiming they signed a particular message,
or claiming that a trusted entity (e.g. Bob, Charlie) signed a message they did in fact not intend to sign.

### Tampering
*Unauthorized changes to your code and data*

It is expected from PGPainless to reject tampered messages. Message integrity is one of OpenPGPs core security goals.
An attacker without access to a keys secret key material might try to inject information into OpenPGP artifacts, e.g.
faked user-ids using spoofed signatures.
PGPainless MUST detect such fake user-ids and signatures and MUST NOT present those to the user as valid under any
circumstances.


### Repudiation
*Denying having performed an action*

Repudiation is not an attack class that applies to PGPainless' threat model.

### Information disclosure
*Exposing sensitive data*

The contents of messages encrypted using PGPainless are expected to be only accessible by entities that have access
to the recipient secret key material or passphrases.

There are certain advanced attacks, like [KOpenPGP](https://kopenpgp.com), which rely on tampering with public key parameters
in a way that results in partial or complete disclosure of secret key parameters when used to create an encrypted 
and/or signed message.
While such an attack requires a very special scenario (public key parameters are stored accessible to an attacker),
it is expected from PGPainless to provide users with means to defend against such attacks.

### Denial of Service
*Making your project unavailable*

Your application is the service and PGPainless is a building brick that makes up this service.
Stability of your service depends on the way you use PGPainless, i.e. the way you handle exceptions thrown by PGPainless.
An attacker might provide you with malformed OpenPGP artifacts that produce errors during processing.
It is PGPainless' responsibility to clearly define, what types of exceptions can occur during operations, but since
it is a good pattern to fail early and to hand exceptions up to the downstream application, ultimately it is your
responsibility to ensure that exceptions from PGPainless do not crash your service.

Apart from exceptions, there are other ways an attacker could try to impact the operation of your app, for example
resource exhaustion. The attacker could provide you with artifacts that consist of many layers of nested packets.
It is PGPainless' responsibility to detect such attacks and to reject processing before exhausting resources.

Another example of resource exhaustion is memory-hard hash functions used in S2K-specifiers (e.g. when encrypting
messages or secret key material). An attacker might create an OpenPGP artifact that uses excessive Argon2 parameters,
requiring massive amounts of RAM to decrypt. PGPainless should reject such artifacts before attempting decryption.

It is noteworthy to declare that denial of message processing by tampering with OpenPGP artifacts is NOT scope of
the threat model, as failing to decrypt/process tampered messages is actually expected from an OpenPGP implementation.

### Elevation of Privilege
*Gaining more access than intended*

PGPainless does not require elevated privileges by itself and it is required not to run it with any more privileges
than necessary.
