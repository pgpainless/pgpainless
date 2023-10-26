<!--
SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>

SPDX-License-Identifier: Apache-2.0
-->

# Signature Verification and Validation

This package can be a bit overwhelming, hence this README file.

Signature verification and validation in OpenPGP is a complex topic (see a 
[related blog post of mine](https://blog.jabberhead.tk/2021/04/03/why-signature-verification-in-openpgp-is-hard/)), 
therefore let me quickly outline some of its challenges for you:

A signature is either valid or it is not.
However, signature validity goes beyond merely checking the cryptographic correctness like BouncyCastle does.
A signature that is correct can still be invalid, e.g. if it is past its expiry date
or the key that issued the signature got revoked or is simply not a signing key in the first place.

All the little criteria like "is not expired", "has a hashed signature creation time subpacket",
"does not contain critical unknown notations/subpackets" and so forth
are implemented in the SignatureValidator class. This class defines an abstract "verify()" method
which is overwritten in a collection of anonymous subclasses which check for one or more such criteria.

Whether a signature is cryptographically correct is checked in the SignatureVerifier class.
This class draws on the SignatureValidator class to compose the subclass building blocks depending on
the signature type to check if the signature fulfills formal criteria and further checks for
cryptographic correctness.

Lastly the CertificateValidator class not only verifies single signatures, but also verifies that
the corresponding certificate (public key ring) is still valid.
It checks if the signing subkey is properly bound to its primary key, that no key in the chain is
revoked or expired and that the signing key is capable of signing in the first place.

I hope this little guide helps you to get access to the package more quickly.
Happy Hacking!