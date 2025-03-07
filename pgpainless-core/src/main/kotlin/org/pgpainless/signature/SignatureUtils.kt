// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature

import java.io.IOException
import java.io.InputStream
import java.util.*
import openpgp.plusSeconds
import org.bouncycastle.bcpg.sig.KeyExpirationTime
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.api.OpenPGPImplementation
import org.bouncycastle.util.encoders.Hex
import org.bouncycastle.util.io.Streams
import org.pgpainless.bouncycastle.extensions.*
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.key.util.RevocationAttributes.Reason
import org.pgpainless.util.ArmorUtils

const val MAX_ITERATIONS = 10000

class SignatureUtils {
    companion object {

        /**
         * Extract and return the key expiration date value from the given signature. If the
         * signature does not carry a [KeyExpirationTime] subpacket, return null.
         *
         * @param keyCreationDate creation date of the key
         * @param signature signature
         * @return key expiration date as given by the signature
         */
        @JvmStatic
        @Deprecated(
            "Deprecated in favor of PGPSignature extension method.",
            ReplaceWith(
                "signature.getKeyExpirationDate(keyCreationDate)",
                "org.bouncycastle.extensions.getKeyExpirationDate"))
        fun getKeyExpirationDate(keyCreationDate: Date, signature: PGPSignature): Date? {
            return signature.getKeyExpirationDate(keyCreationDate)
        }

        /**
         * Return the expiration date of the signature. If the signature has no expiration date,
         * this will return null.
         *
         * @param signature signature
         * @return expiration date of the signature, or null if it does not expire.
         */
        @JvmStatic
        @Deprecated(
            "Deprecated in favor of PGPSignature extension method.",
            ReplaceWith(
                "signature.signatureExpirationDate",
                "org.bouncycastle.extensions.signatureExpirationDate"))
        fun getSignatureExpirationDate(signature: PGPSignature): Date? =
            signature.signatureExpirationDate

        /**
         * Return a new date which represents the given date plus the given amount of seconds added.
         *
         * Since '0' is a special date value in the OpenPGP specification (e.g. '0' means no
         * expiration for expiration dates), this method will return 'null' if seconds is 0.
         *
         * @param date date
         * @param seconds number of seconds to be added
         * @return date plus seconds or null if seconds is '0'
         */
        @JvmStatic
        @Deprecated(
            "Deprecated in favor of Date extension method.",
            ReplaceWith("date.plusSeconds(seconds)", "openpgp.plusSeconds"))
        fun datePlusSeconds(date: Date, seconds: Long): Date? {
            return date.plusSeconds(seconds)
        }

        /**
         * Return true, if the expiration date of the [PGPSignature] lays in the past. If no
         * expiration date is present in the signature, it is considered non-expired.
         *
         * @param signature signature
         * @return true if expired, false otherwise
         */
        @JvmStatic
        @Deprecated(
            "Deprecated in favor of PGPSignature extension method.",
            ReplaceWith("signature.isExpired()", "org.bouncycastle.extensions.isExpired"))
        fun isSignatureExpired(signature: PGPSignature): Boolean {
            return signature.isExpired()
        }

        /**
         * Return true, if the expiration date of the given [PGPSignature] is past the given
         * comparison [Date]. If no expiration date is present in the signature, it is considered
         * non-expiring.
         *
         * @param signature signature
         * @param referenceTime reference date
         * @return true if sig is expired at reference date, false otherwise
         */
        @JvmStatic
        @Deprecated(
            "Deprecated in favor of PGPSignature extension method.",
            ReplaceWith(
                "signature.isExpired(referenceTime)", "org.bouncycastle.extensions.isExpired"))
        fun isSignatureExpired(signature: PGPSignature, referenceTime: Date): Boolean {
            return signature.isExpired(referenceTime)
        }

        /**
         * Return true if the provided signature is a hard revocation. Hard revocations are
         * revocation signatures which either carry a revocation reason of [Reason.KEY_COMPROMISED]
         * or [Reason.NO_REASON], or no reason at all.
         *
         * @param signature signature
         * @return true if signature is a hard revocation
         */
        @JvmStatic
        @Deprecated(
            "Deprecated in favor of PGPSignature extension function.",
            ReplaceWith(
                "signature.isHardRevocation", "org.bouncycastle.extensions.isHardRevocation"))
        fun isHardRevocation(signature: PGPSignature): Boolean {
            return signature.isHardRevocation
        }

        @JvmStatic
        fun readSignatures(encodedSignatures: String): List<PGPSignature> {
            return readSignatures(encodedSignatures.toByteArray())
        }

        @JvmStatic
        fun readSignatures(encodedSignatures: ByteArray): List<PGPSignature> {
            return readSignatures(encodedSignatures.inputStream())
        }

        @JvmStatic
        @Throws(IOException::class, PGPException::class)
        fun readSignatures(inputStream: InputStream): List<PGPSignature> {
            return readSignatures(inputStream, MAX_ITERATIONS)
        }

        /**
         * Read and return [PGPSignatures][PGPSignature]. This method can deal with signatures that
         * may be binary, armored and may contain marker packets.
         *
         * @param inputStream input stream
         * @param maxIterations number of loop iterations until reading is aborted
         * @return list of encountered signatures
         */
        @JvmStatic
        fun readSignatures(inputStream: InputStream, maxIterations: Int): List<PGPSignature> {
            val signatures = mutableListOf<PGPSignature>()
            val pgpIn = ArmorUtils.getDecoderStream(inputStream)
            val objectFactory = OpenPGPImplementation.getInstance().pgpObjectFactory(pgpIn)

            var i = 0
            var nextObject: Any? = null
            while (i++ < maxIterations &&
                objectFactory.nextObject().also { nextObject = it } != null) {
                // Since signatures are indistinguishable from randomness, there is no point in
                // having them compressed,
                //  except for an attacker who is trying to exploit flaws in the decompression
                // algorithm.
                //  Therefore, we ignore compressed data packets without attempting decompression.
                if (nextObject is PGPCompressedData) {
                    // getInputStream() does not do decompression, contrary to getDataStream().
                    Streams.drain(
                        (nextObject as PGPCompressedData)
                            .inputStream) // Skip packet without decompressing
                }

                if (nextObject is PGPSignatureList) {
                    signatures.addAll(nextObject as PGPSignatureList)
                }

                if (nextObject is PGPSignature) {
                    signatures.add(nextObject as PGPSignature)
                }
            }

            pgpIn.close()
            return signatures.toList()
        }

        /**
         * Determine the issuer key-id of a [PGPSignature]. This method first inspects the
         * [org.bouncycastle.bcpg.sig.IssuerKeyID] subpacket of the signature and returns the key-id
         * if present. If not, it inspects the [org.bouncycastle.bcpg.sig.IssuerFingerprint] packet
         * and retrieves the key-id from the fingerprint.
         *
         * Otherwise, it returns 0.
         *
         * @param signature signature
         * @return signatures issuing key id
         */
        @JvmStatic
        @Deprecated(
            "Deprecated in favor of PGPSignature extension method.",
            ReplaceWith("signature.issuerKeyId", "org.bouncycastle.extensions.issuerKeyId"))
        fun determineIssuerKeyId(signature: PGPSignature): Long {
            return signature.issuerKeyId
        }

        /**
         * Return the digest prefix of the signature as hex-encoded String.
         *
         * @param signature signature
         * @return digest prefix
         */
        @JvmStatic
        fun getSignatureDigestPrefix(signature: PGPSignature): String {
            return Hex.toHexString(signature.digestPrefix)
        }

        @JvmStatic
        @Deprecated(
            "Deprecated in favor of PGPSignature extension method",
            ReplaceWith(
                "signature.wasIssuedBy(fingerprint)", "org.bouncycastle.extensions.wasIssuedBy"))
        fun wasIssuedBy(fingerprint: ByteArray, signature: PGPSignature): Boolean {
            return signature.wasIssuedBy(fingerprint)
        }

        @JvmStatic
        @Deprecated(
            "Deprecated in favor of PGPSignature extension method",
            ReplaceWith(
                "signature.wasIssuedBy(fingerprint)", "org.bouncycastle.extensions.wasIssuedBy"))
        fun wasIssuedBy(fingerprint: OpenPgpFingerprint, signature: PGPSignature): Boolean {
            return signature.wasIssuedBy(fingerprint)
        }

        /**
         * Extract all signatures from the given <pre>key</pre> which were issued by
         * <pre>issuerKeyId</pre> over <pre>userId</pre>.
         *
         * @param key public key
         * @param userId user-id
         * @param issuer issuer key-id
         * @return (potentially empty) list of signatures
         */
        @JvmStatic
        fun getSignaturesOverUserIdBy(
            key: PGPPublicKey,
            userId: String,
            issuer: Long
        ): List<PGPSignature> {
            val signatures = key.getSignaturesForID(userId) ?: return listOf()
            return signatures.asSequence().filter { it.keyID == issuer }.toList()
        }

        @JvmStatic
        fun getDelegations(key: PGPPublicKeyRing): List<PGPSignature> {
            return key.publicKey.keySignatures
                .asSequence()
                .filter { key.getPublicKey(it.keyID) == null } // Filter out back-sigs from subkeys
                .toList()
        }

        @JvmStatic
        fun get3rdPartyCertificationsFor(
            key: PGPPublicKeyRing,
            userId: String
        ): List<PGPSignature> {
            return key.publicKey
                .getSignaturesForID(userId)
                .asSequence()
                .filter { it.keyID != key.publicKey.keyID } // Filter out self-sigs
                .toList()
        }
    }
}
