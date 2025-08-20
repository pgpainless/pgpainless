// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.exception

import java.util.*
import javax.annotation.Nonnull
import org.bouncycastle.bcpg.KeyIdentifier
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.bouncycastle.openpgp.api.OpenPGPCertificate.OpenPGPComponentKey
import org.pgpainless.algorithm.PublicKeyAlgorithm
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.key.OpenPgpFingerprint.Companion.of
import org.pgpainless.util.DateUtil.Companion.formatUTCDate

abstract class KeyException : RuntimeException {

    val fingerprint: OpenPgpFingerprint

    protected constructor(message: String, fingerprint: OpenPgpFingerprint) : super(message) {
        this.fingerprint = fingerprint
    }

    protected constructor(
        message: String,
        fingerprint: OpenPgpFingerprint,
        underlying: Throwable
    ) : super(message, underlying) {
        this.fingerprint = fingerprint
    }

    class ExpiredKeyException(fingerprint: OpenPgpFingerprint, expirationDate: Date) :
        KeyException(
            "Key $fingerprint is expired. Expiration date: ${formatUTCDate(expirationDate)}",
            fingerprint,
        ) {

        constructor(cert: OpenPGPCertificate, expirationDate: Date) : this(of(cert), expirationDate)

        constructor(
            componentKey: OpenPGPComponentKey,
            expirationDate: Date
        ) : this(of(componentKey), expirationDate)
    }

    class RevokedKeyException : KeyException {
        constructor(
            fingerprint: OpenPgpFingerprint
        ) : super(
            "Key $fingerprint appears to be revoked.",
            fingerprint,
        )

        constructor(
            componentKey: OpenPGPComponentKey
        ) : super(
            "Subkey ${componentKey.keyIdentifier} appears to be revoked.",
            of(componentKey),
        )

        constructor(
            cert: OpenPGPCertificate
        ) : super(
            "Key or certificate ${cert.keyIdentifier} appears to be revoked.",
            of(cert),
        )
    }

    class UnacceptableEncryptionKeyException : KeyException {
        constructor(cert: OpenPGPCertificate) : this(of(cert))

        constructor(
            subkey: OpenPGPComponentKey
        ) : super(
            "Subkey ${subkey.keyIdentifier} is not an acceptable encryption key.",
            of(subkey),
        )

        constructor(
            fingerprint: OpenPgpFingerprint
        ) : super("Key $fingerprint has no acceptable encryption key.", fingerprint)

        constructor(
            reason: PublicKeyAlgorithmPolicyException
        ) : super(
            "Key ${reason.fingerprint} has no acceptable encryption key.",
            reason.fingerprint,
            reason)
    }

    class UnacceptableSigningKeyException : KeyException {
        constructor(cert: OpenPGPCertificate) : this(of(cert))

        constructor(subkey: OpenPGPComponentKey) : this(of(subkey))

        constructor(
            fingerprint: OpenPgpFingerprint
        ) : super("Key $fingerprint has no acceptable signing key.", fingerprint)

        constructor(
            reason: KeyException.PublicKeyAlgorithmPolicyException
        ) : super(
            "Key ${reason.fingerprint} has no acceptable signing key.", reason.fingerprint, reason)
    }

    class UnacceptableThirdPartyCertificationKeyException(fingerprint: OpenPgpFingerprint) :
        KeyException("Key $fingerprint has no acceptable certification key.", fingerprint) {}

    class UnacceptableSelfSignatureException : KeyException {
        constructor(cert: OpenPGPCertificate) : this(of(cert))

        constructor(
            fingerprint: OpenPgpFingerprint
        ) : super(
            "Key $fingerprint does not have a valid/acceptable signature to derive an expiration date from.",
            fingerprint,
        )
    }

    class MissingSecretKeyException : KeyException {
        val missingSecretKeyIdentifier: KeyIdentifier

        constructor(
            publicKey: OpenPGPComponentKey
        ) : this(
            of(publicKey.certificate),
            publicKey.keyIdentifier,
        )

        constructor(
            fingerprint: OpenPgpFingerprint,
            keyIdentifier: KeyIdentifier
        ) : super(
            "Key $fingerprint does not contain a secret key for public key $keyIdentifier",
            fingerprint,
        ) {
            missingSecretKeyIdentifier = keyIdentifier
        }

        @Deprecated("Pass in a KeyIdentifier instead.")
        constructor(
            fingerprint: OpenPgpFingerprint,
            keyId: Long
        ) : this(fingerprint, KeyIdentifier(keyId))
    }

    class PublicKeyAlgorithmPolicyException : KeyException {
        val violatingSubkeyId: KeyIdentifier

        constructor(
            subkey: OpenPGPComponentKey,
            algorithm: PublicKeyAlgorithm,
            bitSize: Int
        ) : super(
            """Subkey ${subkey.keyIdentifier} of key ${subkey.certificate.keyIdentifier} is violating the Public Key Algorithm Policy:
$algorithm of size $bitSize is not acceptable.""",
            of(subkey),
        ) {
            this.violatingSubkeyId = subkey.keyIdentifier
        }

        constructor(
            fingerprint: OpenPgpFingerprint,
            keyId: Long,
            algorithm: PublicKeyAlgorithm,
            bitSize: Int
        ) : super(
            """Subkey ${java.lang.Long.toHexString(keyId)} of key $fingerprint is violating the Public Key Algorithm Policy:
$algorithm of size $bitSize is not acceptable.""",
            fingerprint,
        ) {
            this.violatingSubkeyId = KeyIdentifier(keyId)
        }
    }

    class UnboundUserIdException(
        fingerprint: OpenPgpFingerprint,
        userId: String,
        userIdSignature: PGPSignature?,
        userIdRevocation: PGPSignature?
    ) :
        KeyException(
            errorMessage(
                fingerprint,
                userId,
                userIdSignature,
                userIdRevocation,
            ),
            fingerprint,
        ) {

        companion object {
            private fun errorMessage(
                @Nonnull fingerprint: OpenPgpFingerprint,
                @Nonnull userId: String,
                userIdSignature: PGPSignature?,
                userIdRevocation: PGPSignature?
            ): String {
                val errorMessage = "UserID '$userId' is not valid for key $fingerprint: "
                if (userIdSignature == null) {
                    return errorMessage + "Missing binding signature."
                }
                if (userIdRevocation != null) {
                    return errorMessage + "UserID is revoked."
                }
                return errorMessage + "Unacceptable binding signature."
            }
        }
    }
}
