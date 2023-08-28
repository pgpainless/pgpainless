// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.subpackets

import org.bouncycastle.bcpg.sig.*
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector
import org.pgpainless.algorithm.*
import org.pgpainless.algorithm.KeyFlag.Companion.hasKeyFlag
import org.pgpainless.algorithm.KeyFlag.Companion.toBitmask
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.key.OpenPgpV4Fingerprint
import org.pgpainless.key.OpenPgpV5Fingerprint
import org.pgpainless.key.OpenPgpV6Fingerprint
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.key.util.KeyIdUtil
import org.pgpainless.signature.SignatureUtils
import java.util.*

class SignatureSubpacketsUtil {
    companion object {

        /**
         * Return the issuer-fingerprint subpacket of the signature.
         * Since this packet is self-authenticating, we expect it to be in the unhashed area,
         * however as it cannot hurt we search for it in the hashed area first.
         *
         * @param signature signature
         * @return issuer fingerprint or null
         */
        @JvmStatic
        fun getIssuerFingerprint(signature: PGPSignature): IssuerFingerprint? =
                hashedOrUnhashed(signature, SignatureSubpacket.issuerFingerprint)

        /**
         * Return the [IssuerFingerprint] subpacket of the signature into a [org.pgpainless.key.OpenPgpFingerprint].
         * If no v4, v5 or v6 issuer fingerprint is present in the signature, return null.
         *
         * @param signature signature
         * @return fingerprint of the issuer, or null
         */
        @JvmStatic
        fun getIssuerFingerprintAsOpenPgpFingerprint(signature: PGPSignature): OpenPgpFingerprint? {
            val subpacket = getIssuerFingerprint(signature) ?: return null
            return when(subpacket.keyVersion) {
                4 -> OpenPgpV4Fingerprint(subpacket.fingerprint)
                5 -> OpenPgpV5Fingerprint(subpacket.fingerprint)
                6 -> OpenPgpV6Fingerprint(subpacket.fingerprint)
                else -> null
            }
        }

        @JvmStatic
        fun getIssuerKeyId(signature: PGPSignature): IssuerKeyID? =
                hashedOrUnhashed(signature, SignatureSubpacket.issuerKeyId)

        /**
         * Inspect the given signature's [IssuerKeyID] packet to determine the issuer key-id.
         * If no such packet is present, return null.
         *
         * @param signature signature
         * @return issuer key-id as {@link Long}
         */
        @JvmStatic
        fun getIssuerKeyIdAsLong(signature: PGPSignature): Long? =
                getIssuerKeyId(signature)?.keyID

        /**
         * Return the revocation reason subpacket of the signature.
         * Since this packet is rather important for revocations, we only search for it in the
         * hashed area of the signature.
         *
         * @param signature signature
         * @return revocation reason
         */
        @JvmStatic
        fun getRevocationReason(signature: PGPSignature): RevocationReason? =
                hashed(signature, SignatureSubpacket.revocationReason)

        /**
         * Return the signature creation time subpacket.
         * Since this packet is rather important, we only search for it in the hashed area
         * of the signature.
         *
         * @param signature signature
         * @return signature creation time subpacket
         */
        @JvmStatic
        fun getSignatureCreationTime(signature: PGPSignature): SignatureCreationTime? =
                if (signature.version == 3) SignatureCreationTime(false, signature.creationTime)
                else hashed(signature, SignatureSubpacket.signatureCreationTime)

        /**
         * Return the signature expiration time subpacket of the signature.
         * Since this packet is rather important, we only search for it in the hashed area of the signature.
         *
         * @param signature signature
         * @return signature expiration time
         */
        @JvmStatic
        fun getSignatureExpirationTime(signature: PGPSignature): SignatureExpirationTime? =
                hashed(signature, SignatureSubpacket.signatureExpirationTime)

        /**
         * Return the signatures' expiration time as a date.
         * The expiration date is computed by adding the expiration time to the signature creation date.
         * If the signature has no expiration time subpacket, or the expiration time is set to '0', this message returns null.
         *
         * @param signature signature
         * @return expiration time as date
         */
        @JvmStatic
        fun getSignatureExpirationTimeAsDate(signature: PGPSignature): Date? =
                getSignatureExpirationTime(signature)?.let {
                    SignatureUtils.datePlusSeconds(signature.creationTime, it.time)
                }

        /**
         * Return the key expiration time subpacket of this signature.
         * We only look for it in the hashed area of the signature.
         *
         * @param signature signature
         * @return key expiration time
         */
        @JvmStatic
        fun getKeyExpirationTime(signature: PGPSignature): KeyExpirationTime? =
                hashed(signature, SignatureSubpacket.keyExpirationTime)

        /**
         * Return the signatures key-expiration time as a date.
         * The expiration date is computed by adding the signatures' key-expiration time to the signing keys
         * creation date.
         * If the signature does not have a key-expiration time subpacket, or its value is '0', this method returns null.
         *
         * @param signature self-signature carrying the key-expiration time subpacket
         * @param signingKey signature creation key
         * @return key expiration time as date
         */
        @JvmStatic
        fun getKeyExpirationTimeAsDate(signature: PGPSignature, signingKey: PGPPublicKey): Date? =
                require(signature.keyID == signingKey.keyID) {
                    "Provided key (${KeyIdUtil.formatKeyId(signingKey.keyID)}) did not create the signature (${KeyIdUtil.formatKeyId(signature.keyID)})"
                }.run {
                    getKeyExpirationTime(signature)?.let {
                        SignatureUtils.datePlusSeconds(signingKey.creationTime, it.time)
                    }
                }

        /**
         * Calculate the duration in seconds until the key expires after creation.
         *
         * @param expirationTime new expiration date
         * @param creationTime key creation time
         * @return lifetime of the key in seconds
         */
        @JvmStatic
        fun getKeyLifetimeInSeconds(creationTime: Date, expirationTime: Date?): Long =
                expirationTime?.let {
                    require(creationTime <= it) {
                        "Key MUST NOT expire before being created.\n" +
                                "(creation: $creationTime, expiration: $it)"
                    }.run {
                        (it.time - creationTime.time) / 1000
                    }
                } ?: 0 // 0 means "no expiration"

        /**
         * Return the revocable subpacket of this signature.
         * We only look for it in the hashed area of the signature.
         *
         * @param signature signature
         * @return revocable subpacket
         */
        @JvmStatic
        fun getRevocable(signature: PGPSignature): Revocable? =
                hashed(signature, SignatureSubpacket.revocable)

        /**
         * Return the symmetric algorithm preferences from the signatures hashed area.
         *
         * @param signature signature
         * @return symm. algo. prefs
         */
        @JvmStatic
        fun getPreferredSymmetricAlgorithms(signature: PGPSignature): PreferredAlgorithms? =
                hashed(signature, SignatureSubpacket.preferredSymmetricAlgorithms)

        /**
         * Return the preferred [SymmetricKeyAlgorithms][SymmetricKeyAlgorithm] as present in the signature.
         * If no preference is given with regard to symmetric encryption algorithms, return an empty set.
         *
         * In any case, the resulting set is ordered by occurrence.
         * @param signature signature
         * @return ordered set of symmetric key algorithm preferences
         */
        @JvmStatic
        fun parsePreferredSymmetricKeyAlgorithms(signature: PGPSignature): Set<SymmetricKeyAlgorithm> =
                getPreferredSymmetricAlgorithms(signature)
                        ?.preferences
                        ?.map { SymmetricKeyAlgorithm.fromId(it) }
                        ?.filterNotNull()
                        ?.toSet() ?: setOf()

        /**
         * Return the hash algorithm preferences from the signatures hashed area.
         *
         * @param signature signature
         * @return hash algo prefs
         */
        @JvmStatic
        fun getPreferredHashAlgorithms(signature: PGPSignature): PreferredAlgorithms? =
                hashed(signature, SignatureSubpacket.preferredHashAlgorithms)

        /**
         * Return the preferred [HashAlgorithms][HashAlgorithm] as present in the signature.
         * If no preference is given with regard to hash algorithms, return an empty set.
         *
         * In any case, the resulting set is ordered by occurrence.
         * @param signature signature
         * @return ordered set of hash algorithm preferences
         */
        @JvmStatic
        fun parsePreferredHashAlgorithms(signature: PGPSignature): Set<HashAlgorithm> =
                getPreferredHashAlgorithms(signature)
                        ?.preferences
                        ?.map { HashAlgorithm.fromId(it) }
                        ?.filterNotNull()
                        ?.toSet() ?: setOf()

        /**
         * Return the compression algorithm preferences from the signatures hashed area.
         *
         * @param signature signature
         * @return compression algo prefs
         */
        @JvmStatic
        fun getPreferredCompressionAlgorithms(signature: PGPSignature): PreferredAlgorithms? =
                hashed(signature, SignatureSubpacket.preferredCompressionAlgorithms)

        /**
         * Return the preferred [CompressionAlgorithms][CompressionAlgorithm] as present in the signature.
         * If no preference is given with regard to compression algorithms, return an empty set.
         *
         * In any case, the resulting set is ordered by occurrence.
         * @param signature signature
         * @return ordered set of compression algorithm preferences
         */
        @JvmStatic
        fun parsePreferredCompressionAlgorithms(signature: PGPSignature): Set<CompressionAlgorithm> =
                getPreferredCompressionAlgorithms(signature)
                        ?.preferences
                        ?.map { CompressionAlgorithm.fromId(it) }
                        ?.filterNotNull()
                        ?.toSet() ?: setOf()

        @JvmStatic
        fun getPreferredAeadAlgorithms(signature: PGPSignature): PreferredAEADCiphersuites? =
                hashed(signature, SignatureSubpacket.preferredAEADAlgorithms)

        /**
         * Return the primary user-id subpacket from the signatures hashed area.
         *
         * @param signature signature
         * @return primary user id
         */
        @JvmStatic
        fun getPrimaryUserId(signature: PGPSignature): PrimaryUserID? =
                hashed(signature, SignatureSubpacket.primaryUserId)

        /**
         * Return the key flags subpacket from the signatures hashed area.
         *
         * @param signature signature
         * @return key flags
         */
        @JvmStatic
        fun getKeyFlags(signature: PGPSignature): KeyFlags? =
                hashed(signature, SignatureSubpacket.keyFlags)

        /**
         * Return a list of key flags carried by the signature.
         * If the signature is null, or has no [KeyFlags] subpacket, return null.
         *
         * @param signature signature
         * @return list of key flags
         */
        @JvmStatic
        fun parseKeyFlags(signature: PGPSignature?): List<KeyFlag>? =
                signature?.let { sig ->
                    getKeyFlags(sig)?.let {
                        KeyFlag.fromBitmask(it.flags)
                    }
                }

        /**
         * Return the features subpacket from the signatures hashed area.
         *
         * @param signature signature
         * @return features subpacket
         */
        @JvmStatic
        fun getFeatures(signature: PGPSignature): Features? =
                hashed(signature, SignatureSubpacket.features)

        /**
         * Parse out the features subpacket of a signature.
         * If the signature has no features subpacket, return null.
         * Otherwise, return the features as a feature set.
         *
         * @param signature signature
         * @return features as set
         */
        @JvmStatic
        fun parseFeatures(signature: PGPSignature): Set<Feature>? =
                getFeatures(signature)?.let {
                    Feature.fromBitmask(it.features.toInt()).toSet()
                }

        /**
         * Return the signature target subpacket from the signature.
         * We search for this subpacket in the hashed and unhashed area (in this order).
         *
         * @param signature signature
         * @return signature target
         */
        @JvmStatic
        fun getSignatureTarget(signature: PGPSignature): SignatureTarget? =
                hashedOrUnhashed(signature, SignatureSubpacket.signatureTarget)

        /**
         * Return the notation data subpackets from the signatures hashed area.
         *
         * @param signature signature
         * @return hashed notations
         */
        @JvmStatic
        fun getHashedNotationData(signature: PGPSignature): List<NotationData> =
                signature.hashedSubPackets.notationDataOccurrences.toList()

        /**
         * Return a list of all [NotationData] objects from the hashed area of the signature that have a
         * notation name equal to the given notationName argument.
         *
         * @param signature signature
         * @param notationName notation name
         * @return list of matching notation data objects
         */
        @JvmStatic
        fun getHashedNotationData(signature: PGPSignature, notationName: String): List<NotationData> =
                getHashedNotationData(signature)
                        .filter { it.notationName == notationName }

        /**
         * Return the notation data subpackets from the signatures unhashed area.
         *
         * @param signature signature
         * @return unhashed notations
         */
        @JvmStatic
        fun getUnhashedNotationData(signature: PGPSignature): List<NotationData> =
                signature.unhashedSubPackets.notationDataOccurrences.toList()

        /**
         * Return a list of all [NotationData] objects from the unhashed area of the signature that have a
         * notation name equal to the given notationName argument.
         *
         * @param signature signature
         * @param notationName notation name
         * @return list of matching notation data objects
         */
        @JvmStatic
        fun getUnhashedNotationData(signature: PGPSignature, notationName: String) =
                getUnhashedNotationData(signature)
                        .filter { it.notationName == notationName }

        /**
         * Return the revocation key subpacket from the signatures hashed area.
         *
         * @param signature signature
         * @return revocation key
         */
        @JvmStatic
        fun getRevocationKey(signature: PGPSignature): RevocationKey? =
                hashed(signature, SignatureSubpacket.revocationKey)

        /**
         * Return the signers user-id from the hashed area of the signature.
         * TODO: Can this subpacket also be found in the unhashed area?
         *
         * @param signature signature
         * @return signers user-id
         */
        @JvmStatic
        fun getSignerUserID(signature: PGPSignature): SignerUserID? =
                hashed(signature, SignatureSubpacket.signerUserId)

        /**
         * Return the intended recipients fingerprint subpackets from the hashed area of this signature.
         *
         * @param signature signature
         * @return intended recipient fingerprint subpackets
         */
        @JvmStatic
        fun getIntendedRecipientFingerprints(signature: PGPSignature): List<IntendedRecipientFingerprint> =
                signature.hashedSubPackets.intendedRecipientFingerprints.toList()

        /**
         * Return the embedded signature subpacket from the signatures hashed area or unhashed area.
         *
         * @param signature signature
         * @return embedded signature
         */
        @JvmStatic
        fun getEmbeddedSignature(signature: PGPSignature): PGPSignatureList =
                signature.hashedSubPackets.embeddedSignatures.let {
                    if (it.isEmpty) signature.unhashedSubPackets.embeddedSignatures
                    else it
                }

        /**
         * Return the signatures exportable certification subpacket from the hashed area.
         *
         * @param signature signature
         * @return exportable certification subpacket
         */
        @JvmStatic
        fun getExportableCertification(signature: PGPSignature): Exportable? =
                hashed(signature, SignatureSubpacket.exportableCertification)

        /**
         * Return true, if the signature is not explicitly marked as non-exportable.
         */
        @JvmStatic
        fun isExportable(signature: PGPSignature): Boolean =
                getExportableCertification(signature)?.isExportable ?: true

        /**
         * Return the trust signature packet from the signatures hashed area.
         *
         * @param signature signature
         * @return trust signature subpacket
         */
        @JvmStatic
        fun getTrustSignature(signature: PGPSignature): TrustSignature? =
                hashed(signature, SignatureSubpacket.trustSignature)

        /**
         * Return the trust depth set in the signatures [TrustSignature] packet, or [defaultDepth] if no such packet
         * is found.
         *
         * @param signature signature
         * @param defaultDepth default value that is returned if no trust signature packet is found
         * @return depth or default depth
         */
        @JvmStatic
        fun getTrustDepthOr(signature: PGPSignature, defaultDepth: Int): Int =
                getTrustSignature(signature)?.depth ?: defaultDepth

        /**
         * Return the trust amount set in the signatures [TrustSignature] packet, or [defaultAmount] if no such packet
         * is found.
         *
         * @param signature signature
         * @param defaultAmount default value that is returned if no trust signature packet is found
         * @return amount or default amount
         */
        @JvmStatic
        fun getTrustAmountOr(signature: PGPSignature, defaultAmount: Int): Int =
                getTrustSignature(signature)?.trustAmount ?: defaultAmount

        /**
         * Return all regular expression subpackets from the hashed area of the given signature.
         *
         * @param signature signature
         * @return list of regular expressions
         */
        @JvmStatic
        fun getRegularExpressions(signature: PGPSignature): List<RegularExpression> =
                signature.hashedSubPackets.regularExpressions.toList()

        /**
         * Select a list of all signature subpackets of the given type, which are present in either the hashed
         * or the unhashed area of the given signature.
         *
         * @param signature signature
         * @param type subpacket type
         * @param <P> generic subpacket type
         * @return list of subpackets from the hashed/unhashed area
         */
        @JvmStatic
        fun <P : org.bouncycastle.bcpg.SignatureSubpacket> hashedOrUnhashed(signature: PGPSignature, type: SignatureSubpacket): P? {
            return hashed(signature, type) ?: unhashed(signature, type)
        }

        /**
         * Select a list of all signature subpackets of the given type, which are present in the hashed area of
         * the given signature.
         *
         * @param signature signature
         * @param type subpacket type
         * @param <P> generic subpacket type
         * @return list of subpackets from the hashed area
         */
        @JvmStatic
        fun <P : org.bouncycastle.bcpg.SignatureSubpacket> hashed(signature: PGPSignature, type: SignatureSubpacket): P? {
            return getSignatureSubpacket(signature.hashedSubPackets, type)
        }

        /**
         * Select a list of all signature subpackets of the given type, which are present in the unhashed area of
         * the given signature.
         *
         * @param signature signature
         * @param type subpacket type
         * @param <P> generic subpacket type
         * @return list of subpackets from the unhashed area
         */
        @JvmStatic
        fun <P : org.bouncycastle.bcpg.SignatureSubpacket> unhashed(signature: PGPSignature, type: SignatureSubpacket): P? {
            return getSignatureSubpacket(signature.unhashedSubPackets, type)
        }

        /**
         * Return the last occurrence of a subpacket type in the given signature subpacket vector.
         *
         * @param vector subpacket vector (hashed/unhashed)
         * @param type subpacket type
         * @param <P> generic return type of the subpacket
         * @return last occurrence of the subpacket in the vector
         */
        @JvmStatic
        fun <P : org.bouncycastle.bcpg.SignatureSubpacket> getSignatureSubpacket(vector: PGPSignatureSubpacketVector?, type: SignatureSubpacket): P? {
            val allPackets = vector?.getSubpackets(type.code) ?: return null
            return if (allPackets.isEmpty())
                null
            else
                @Suppress("UNCHECKED_CAST")
                allPackets.last() as P
        }

        @JvmStatic
        fun assureKeyCanCarryFlags(type: KeyType, vararg flags: KeyFlag) {
            assureKeyCanCarryFlags(type.algorithm, *flags)
        }

        @JvmStatic
        fun assureKeyCanCarryFlags(algorithm: PublicKeyAlgorithm, vararg flags: KeyFlag) {
            val mask = toBitmask(*flags)

            if (!algorithm.isSigningCapable() && hasKeyFlag(mask, KeyFlag.CERTIFY_OTHER)) {
                throw IllegalArgumentException("Algorithm $algorithm cannot be used with key flag CERTIFY_OTHER.")
            }

            if (!algorithm.isSigningCapable() && hasKeyFlag(mask, KeyFlag.SIGN_DATA)) {
                throw IllegalArgumentException("Algorithm $algorithm cannot be used with key flag SIGN_DATA.")
            }

            if (!algorithm.isEncryptionCapable() && hasKeyFlag(mask, KeyFlag.ENCRYPT_COMMS)) {
                throw IllegalArgumentException("Algorithm $algorithm cannot be used with key flag ENCRYPT_COMMS.")
            }

            if (!algorithm.isEncryptionCapable() && hasKeyFlag(mask, KeyFlag.ENCRYPT_STORAGE)) {
                throw IllegalArgumentException("Algorithm $algorithm cannot be used with key flag ENCRYPT_STORAGE.")
            }

            if (!algorithm.isSigningCapable() && hasKeyFlag(mask, KeyFlag.AUTHENTICATION)) {
                throw IllegalArgumentException("Algorithm $algorithm cannot be used with key flag AUTHENTICATION.")
            }
        }
    }
}