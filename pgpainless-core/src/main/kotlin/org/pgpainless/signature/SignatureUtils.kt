// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature

import org.bouncycastle.bcpg.sig.KeyExpirationTime
import org.bouncycastle.openpgp.*
import org.bouncycastle.util.encoders.Hex
import org.bouncycastle.util.io.Streams
import org.pgpainless.algorithm.SignatureType
import org.pgpainless.implementation.ImplementationFactory
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.key.util.RevocationAttributes.Reason
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil
import org.pgpainless.util.ArmorUtils
import java.io.IOException
import java.io.InputStream
import java.util.*

const val MAX_ITERATIONS = 10000

class SignatureUtils {
    companion object {

        /**
         * Extract and return the key expiration date value from the given signature.
         * If the signature does not carry a [KeyExpirationTime] subpacket, return null.
         *
         * @param keyCreationDate creation date of the key
         * @param signature signature
         * @return key expiration date as given by the signature
         */
        @JvmStatic
        fun getKeyExpirationDate(keyCreationDate: Date, signature: PGPSignature): Date? {
            val expirationPacket: KeyExpirationTime = SignatureSubpacketsUtil.getKeyExpirationTime(signature) ?: return null
            val expiresInSeconds = expirationPacket.time
            return datePlusSeconds(keyCreationDate, expiresInSeconds)
        }

        /**
         * Return the expiration date of the signature.
         * If the signature has no expiration date, [datePlusSeconds] will return null.
         *
         * @param signature signature
         * @return expiration date of the signature, or null if it does not expire.
         */
        @JvmStatic
        fun  getSignatureExpirationDate(signature: PGPSignature): Date? {
            val expirationTime = SignatureSubpacketsUtil.getSignatureExpirationTime(signature) ?: return null

            val expiresInSeconds = expirationTime.time
            return datePlusSeconds(signature.creationTime, expiresInSeconds)
        }

        /**
         * Return a new date which represents the given date plus the given amount of seconds added.
         *
         * Since '0' is a special date value in the OpenPGP specification
         * (e.g. '0' means no expiration for expiration dates), this method will return 'null' if seconds is 0.
         *
         * @param date date
         * @param seconds number of seconds to be added
         * @return date plus seconds or null if seconds is '0'
         */
        @JvmStatic
        fun datePlusSeconds(date: Date, seconds: Long): Date? {
            if (seconds == 0L) {
                return null
            }
            return Date(date.time + 1000 * seconds)
        }

        /**
         * Return true, if the expiration date of the [PGPSignature] lays in the past.
         * If no expiration date is present in the signature, it is considered non-expired.
         *
         * @param signature signature
         * @return true if expired, false otherwise
         */
        @JvmStatic
        fun isSignatureExpired(signature: PGPSignature): Boolean {
            return isSignatureExpired(signature, Date())
        }

        /**
         * Return true, if the expiration date of the given [PGPSignature] is past the given comparison [Date].
         * If no expiration date is present in the signature, it is considered non-expiring.
         *
         * @param signature signature
         * @param referenceTime reference date
         * @return true if sig is expired at reference date, false otherwise
         */
        @JvmStatic
        fun isSignatureExpired(signature: PGPSignature, referenceTime: Date): Boolean {
            val expirationDate = getSignatureExpirationDate(signature) ?: return false
            return referenceTime >= expirationDate
        }

        /**
         * Return true if the provided signature is a hard revocation.
         * Hard revocations are revocation signatures which either carry a revocation reason of
         * [Reason.KEY_COMPROMISED] or [Reason.NO_REASON], or no reason at all.
         *
         * @param signature signature
         * @return true if signature is a hard revocation
         */
        @JvmStatic
        fun isHardRevocation(signature: PGPSignature): Boolean {
            val type = SignatureType.requireFromCode(signature.signatureType)
            if (type != SignatureType.KEY_REVOCATION && type != SignatureType.SUBKEY_REVOCATION && type != SignatureType.CERTIFICATION_REVOCATION) {
                // Not a revocation
                return false
            }

            val reason = SignatureSubpacketsUtil.getRevocationReason(signature) ?: return true // no reason -> hard revocation
            return Reason.isHardRevocation(reason.revocationReason)
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
         * Read and return [PGPSignatures][PGPSignature].
         * This method can deal with signatures that may be binary, armored and may contain marker packets.
         *
         * @param inputStream input stream
         * @param maxIterations number of loop iterations until reading is aborted
         * @return list of encountered signatures
         */
        @JvmStatic
        fun readSignatures(inputStream: InputStream, maxIterations: Int): List<PGPSignature> {
            val signatures = mutableListOf<PGPSignature>()
            val pgpIn = ArmorUtils.getDecoderStream(inputStream)
            val objectFactory = ImplementationFactory.getInstance().getPGPObjectFactory(pgpIn)

            var i = 0
            var nextObject: Any? = null
            while (i++ < maxIterations && objectFactory.nextObject().also { nextObject = it } != null) {
                // Since signatures are indistinguishable from randomness, there is no point in having them compressed,
                //  except for an attacker who is trying to exploit flaws in the decompression algorithm.
                //  Therefore, we ignore compressed data packets without attempting decompression.
                if (nextObject is PGPCompressedData) {
                    // getInputStream() does not do decompression, contrary to getDataStream().
                    Streams.drain((nextObject as PGPCompressedData).inputStream) // Skip packet without decompressing
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
         * Determine the issuer key-id of a [PGPSignature].
         * This method first inspects the [org.bouncycastle.bcpg.sig.IssuerKeyID] subpacket of the signature and returns the key-id if present.
         * If not, it inspects the [org.bouncycastle.bcpg.sig.IssuerFingerprint] packet and retrieves the key-id from the fingerprint.
         *
         * Otherwise, it returns 0.
         * @param signature signature
         * @return signatures issuing key id
         */
        @JvmStatic
        fun determineIssuerKeyId(signature: PGPSignature): Long {
            if (signature.version == 3) {
                // V3 sigs do not contain subpackets
                return signature.keyID
            }

            val issuerKeyId = SignatureSubpacketsUtil.getIssuerKeyId(signature)
            val issuerFingerprint = SignatureSubpacketsUtil.getIssuerFingerprintAsOpenPgpFingerprint(signature)

            if (issuerKeyId != null && issuerKeyId.keyID != 0L) {
                return issuerKeyId.keyID
            }
            if (issuerKeyId == null && issuerFingerprint != null) {
                return issuerFingerprint.keyId
            }
            return 0
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
        fun wasIssuedBy(fingerprint: ByteArray, signature: PGPSignature): Boolean {
            return try {
                val pgpFingerprint = OpenPgpFingerprint.parseFromBinary(fingerprint)
                wasIssuedBy(pgpFingerprint, signature)
            } catch (e : IllegalArgumentException) {
                // Unknown fingerprint length
                false
            }
        }

        @JvmStatic
        fun wasIssuedBy(fingerprint: OpenPgpFingerprint, signature: PGPSignature): Boolean {
            val issuerFp = SignatureSubpacketsUtil.getIssuerFingerprintAsOpenPgpFingerprint(signature)
                    ?: return fingerprint.keyId == signature.keyID
            return fingerprint == issuerFp
        }

        /**
         * Extract all signatures from the given <pre>key</pre> which were issued by <pre>issuerKeyId</pre>
         * over <pre>userId</pre>.
         *
         * @param key public key
         * @param userId user-id
         * @param issuer issuer key-id
         * @return (potentially empty) list of signatures
         */
        @JvmStatic
        fun getSignaturesOverUserIdBy(key: PGPPublicKey, userId: String, issuer: Long): List<PGPSignature> {
            val signatures = key.getSignaturesForID(userId) ?: return listOf()
            return signatures
                    .asSequence()
                    .filter { it.keyID == issuer }
                    .toList()
        }

        @JvmStatic
        fun getDelegations(key: PGPPublicKeyRing): List<PGPSignature> {
            return key.publicKey.keySignatures
                    .asSequence()
                    .filter { key.getPublicKey(it.keyID) == null } // Filter out back-sigs from subkeys
                    .toList()
        }

        @JvmStatic
        fun get3rdPartyCertificationsFor(key: PGPPublicKeyRing, userId: String): List<PGPSignature> {
            return key.publicKey.getSignaturesForID(userId)
                    .asSequence()
                    .filter { it.keyID != key.publicKey.keyID } // Filter out self-sigs
                    .toList()
        }
    }
}