// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.util

import openpgp.openPgpKeyId
import org.bouncycastle.bcpg.S2K
import org.bouncycastle.bcpg.SecretKeyPacket
import org.bouncycastle.extensions.certificate
import org.bouncycastle.openpgp.*
import org.bouncycastle.util.Strings
import org.pgpainless.exception.MissingPassphraseException
import org.pgpainless.implementation.ImplementationFactory
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.key.protection.fixes.S2KUsageFix
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.io.ByteArrayOutputStream
import kotlin.jvm.Throws

class KeyRingUtils {

    companion object {

        @JvmStatic
        private val LOGGER: Logger = LoggerFactory.getLogger(KeyRingUtils::class.java)

        /**
         * Return the primary {@link PGPSecretKey} from the provided {@link PGPSecretKeyRing}.
         * If it has no primary secret key, throw a {@link NoSuchElementException}.
         *
         * @param secretKeys secret keys
         * @return primary secret key
         */
        @JvmStatic
        fun requirePrimarySecretKeyFrom(secretKeys: PGPSecretKeyRing): PGPSecretKey {
            return getPrimarySecretKeyFrom(secretKeys)
                    ?: throw NoSuchElementException("Provided PGPSecretKeyRing has no primary secret key.")
        }

        /**
         * Return the primary secret key from the given secret key ring.
         * If the key ring only contains subkeys (e.g. if the primary secret key is stripped),
         * this method may return null.
         *
         * @param secretKeys secret key ring
         * @return primary secret key
         */
        @JvmStatic
        fun getPrimarySecretKeyFrom(secretKeys: PGPSecretKeyRing): PGPSecretKey? {
            return secretKeys.secretKey.let {
                if (it.isMasterKey) {
                    it
                } else {
                    null
                }
            }
        }

        /**
         * Return the primary {@link PGPPublicKey} from the provided key ring.
         * Throws a {@link NoSuchElementException} if the key ring has no primary public key.
         *
         * @param keyRing key ring
         * @return primary public key
         */
        @JvmStatic
        fun requirePrimaryPublicKeyFrom(keyRing: PGPKeyRing): PGPPublicKey {
            return getPrimaryPublicKey(keyRing)
                    ?: throw NoSuchElementException("Provided PGPKeyRing has no primary public key.")
        }

        /**
         * Return the primary {@link PGPPublicKey} from the provided key ring or null if it has none.
         *
         * @param keyRing key ring
         * @return primary public key
         */
        @JvmStatic
        fun getPrimaryPublicKey(keyRing: PGPKeyRing): PGPPublicKey? {
            return keyRing.publicKey.let {
                if (it.isMasterKey) {
                    it
                } else {
                    null
                }
            }
        }

        /**
         * Require the public key with the given subKeyId from the keyRing.
         * If no such subkey exists, throw an {@link NoSuchElementException}.
         *
         * @param keyRing key ring
         * @param subKeyId subkey id
         * @return subkey
         */
        @JvmStatic
        fun requirePublicKeyFrom(keyRing: PGPKeyRing, subKeyId: Long): PGPPublicKey {
            return keyRing.getPublicKey(subKeyId)
                    ?: throw NoSuchElementException("KeyRing does not contain public key with keyId ${subKeyId.openPgpKeyId()}.")
        }

        /**
         * Require the secret key with the given secret subKeyId from the secret keyRing.
         * If no such subkey exists, throw an {@link NoSuchElementException}.
         *
         * @param keyRing secret key ring
         * @param subKeyId subkey id
         * @return secret subkey
         */
        @JvmStatic
        fun requireSecretKeyFrom(keyRing: PGPSecretKeyRing, subKeyId: Long): PGPSecretKey {
            return keyRing.getSecretKey(subKeyId)
                    ?: throw NoSuchElementException("KeyRing does not contain secret key with keyID ${subKeyId.openPgpKeyId()}.")
        }

        @JvmStatic
        fun publicKeys(keys: PGPKeyRing): PGPPublicKeyRing {
            return when (keys) {
                is PGPPublicKeyRing -> keys
                is PGPSecretKeyRing -> keys.certificate
                else -> throw IllegalArgumentException("Unknown keys class: ${keys.javaClass.name}")
            }
        }

        /**
         * Extract a {@link PGPPublicKeyRing} containing all public keys from the provided {@link PGPSecretKeyRing}.
         *
         * @param secretKeys secret key ring
         * @return public key ring
         */
        @JvmStatic
        @Deprecated("Deprecated in favor of PGPSecretKeyRing extension method.",
                ReplaceWith("secretKeys.certificate", "org.bouncycastle.extensions.certificate"))
        fun publicKeyRingFrom(secretKeys: PGPSecretKeyRing): PGPPublicKeyRing {
            return secretKeys.certificate
        }

        /**
         * Extract {@link PGPPublicKeyRing PGPPublicKeyRings} from all {@link PGPSecretKeyRing PGPSecretKeyRings} in
         * the given {@link PGPSecretKeyRingCollection} and return them as a {@link PGPPublicKeyRingCollection}.
         *
         * @param secretKeyRings secret key ring collection
         * @return public key ring collection
         */
        @JvmStatic
        fun publicKeyRingCollectionFrom(secretKeyRings: PGPSecretKeyRingCollection): PGPPublicKeyRingCollection {
            return PGPPublicKeyRingCollection(
                    secretKeyRings.keyRings.asSequence()
                            .map { it.certificate }
                            .toList())
        }

        /**
         * Create a new {@link PGPPublicKeyRingCollection} from an array of {@link PGPPublicKeyRing PGPPublicKeyRings}.
         *
         * @param certificates array of public key rings
         * @return key ring collection
         */
        @JvmStatic
        fun keyRingsToKeyRingCollection(vararg certificates: PGPPublicKeyRing): PGPPublicKeyRingCollection {
            return PGPPublicKeyRingCollection(certificates.toList())
        }

        /**
         * Create a new {@link PGPSecretKeyRingCollection} from an array of {@link PGPSecretKeyRing PGPSecretKeyRings}.
         *
         * @param secretKeys array of secret key rings
         * @return secret key ring collection
         */
        @JvmStatic
        fun keyRingsToKeyRingCollection(vararg secretKeys: PGPSecretKeyRing): PGPSecretKeyRingCollection {
            return PGPSecretKeyRingCollection(secretKeys.toList())
        }

        /**
         * Return true, if the given {@link PGPPublicKeyRing} contains a {@link PGPPublicKey} for the given key id.
         *
         * @param certificate public key ring
         * @param keyId id of the key in question
         * @return true if ring contains said key, false otherwise
         */
        @JvmStatic
        fun keyRingContainsKeyWithId(certificate: PGPPublicKeyRing, keyId: Long): Boolean {
            return certificate.getPublicKey(keyId) != null
        }

        /**
         * Inject a key certification for the primary key into the given key ring.
         *
         * @param keyRing key ring
         * @param certification key signature
         * @return key ring with injected signature
         * @param <T> either {@link PGPPublicKeyRing} or {@link PGPSecretKeyRing}
         */
        @JvmStatic
        fun <T : PGPKeyRing> injectCertification(keyRing: T, certification: PGPSignature): T {
            return injectCertification(keyRing, keyRing.publicKey, certification)
        }

        /**
         * Inject a key certification for the given key into the given key ring.
         *
         * @param keyRing key ring
         * @param certifiedKey signed public key
         * @param certification key signature
         * @param <T> either {@link PGPPublicKeyRing} or {@link PGPSecretKeyRing}
         * @return key ring with injected signature
         *
         * @throws NoSuchElementException in case that the signed key is not part of the key ring
         */
        @JvmStatic
        fun <T : PGPKeyRing> injectCertification(keyRing: T, certifiedKey: PGPPublicKey, certification: PGPSignature): T {
            val secretAndPublicKeys = secretAndPublicKeys(keyRing)
            val secretKeys: PGPSecretKeyRing? = secretAndPublicKeys.first
            var certificate: PGPPublicKeyRing = secretAndPublicKeys.second

            if (!keyRingContainsKeyWithId(certificate, certifiedKey.keyID)) {
                throw NoSuchElementException("Cannot find public key with id ${certifiedKey.keyID.openPgpKeyId()} in the provided key ring.")
            }

            certificate = PGPPublicKeyRing(
                    certificate.publicKeys.asSequence().map {
                        if (it.keyID == certifiedKey.keyID) {
                            PGPPublicKey.addCertification(it, certification)
                        } else {
                            it
                        }
                    }.toList())
            return if (secretKeys == null) {
                certificate as T
            } else {
                PGPSecretKeyRing.replacePublicKeys(secretKeys, certificate) as T
            }
        }

        /**
         * Inject a user-id certification into the given key ring.
         *
         * @param keyRing key ring
         * @param userId signed user-id
         * @param certification signature
         * @param <T> either {@link PGPPublicKeyRing} or {@link PGPSecretKeyRing}
         * @return key ring with injected certification
         */
        @JvmStatic
        fun <T : PGPKeyRing> injectCertification(keyRing: T, userId: CharSequence, certification: PGPSignature): T {
            val secretAndPublicKeys = secretAndPublicKeys(keyRing)
            val secretKeys: PGPSecretKeyRing? = secretAndPublicKeys.first
            var certificate: PGPPublicKeyRing = secretAndPublicKeys.second

            certificate = PGPPublicKeyRing(
                    listOf<PGPPublicKey>(
                            PGPPublicKey.addCertification(requirePrimaryPublicKeyFrom(certificate),
                                    userId.toString(), certification)
                    ).plus(certificate.publicKeys.asSequence().drop(1)))

            return if (secretKeys == null) {
                certificate as T
            } else {
                PGPSecretKeyRing.replacePublicKeys(secretKeys, certificate) as T
            }
        }

        /**
         * Inject a user-attribute vector certification into the given key ring.
         *
         * @param keyRing key ring
         * @param userAttributes certified user attributes
         * @param certification certification signature
         * @param <T> either {@link PGPPublicKeyRing} or {@link PGPSecretKeyRing}
         * @return key ring with injected user-attribute certification
         */
        @JvmStatic
        fun <T : PGPKeyRing> injectCertification(keyRing: T, userAttributes: PGPUserAttributeSubpacketVector, certification: PGPSignature): T {
            val secretAndPublicKeys = secretAndPublicKeys(keyRing)
            val secretKeys: PGPSecretKeyRing? = secretAndPublicKeys.first
            var certificate: PGPPublicKeyRing = secretAndPublicKeys.second

            certificate = PGPPublicKeyRing(
                    listOf<PGPPublicKey>(
                            PGPPublicKey.addCertification(requirePrimaryPublicKeyFrom(certificate),
                                    userAttributes, certification)
                    ).plus(certificate.publicKeys.asSequence().drop(1)))

            return if (secretKeys == null) {
                certificate as T
            } else {
                PGPSecretKeyRing.replacePublicKeys(secretKeys, certificate) as T
            }
        }

        /**
         * Inject a {@link PGPPublicKey} into the given key ring.
         *
         * @param keyRing key ring
         * @param publicKey public key
         * @param <T> either {@link PGPPublicKeyRing} or {@link PGPSecretKeyRing}
         * @return key ring with injected public key
         */
        @JvmStatic
        fun <T : PGPKeyRing> keysPlusPublicKey(keyRing: T, publicKey: PGPPublicKey): T {
            val secretAndPublicKeys = secretAndPublicKeys(keyRing)
            val secretKeys: PGPSecretKeyRing? = secretAndPublicKeys.first
            var certificate: PGPPublicKeyRing = secretAndPublicKeys.second

            return if (secretKeys == null) {
                PGPPublicKeyRing.insertPublicKey(certificate, publicKey) as T
            } else {
                PGPSecretKeyRing.insertOrReplacePublicKey(secretKeys, publicKey) as T
            }
        }

        @JvmStatic
        private fun secretAndPublicKeys(keyRing: PGPKeyRing): Pair<PGPSecretKeyRing?, PGPPublicKeyRing> {
            var secretKeys: PGPSecretKeyRing? = null
            val certificate: PGPPublicKeyRing
            when (keyRing) {
                is PGPSecretKeyRing -> {
                    secretKeys = keyRing
                    certificate = secretKeys.certificate
                }
                is PGPPublicKeyRing -> {
                    certificate = keyRing
                }
                else -> throw IllegalArgumentException("keyRing is an unknown PGPKeyRing subclass: ${keyRing.javaClass.name}")
            }
            return secretKeys to certificate
        }

        /**
         * Inject a {@link PGPSecretKey} into a {@link PGPSecretKeyRing}.
         *
         * @param secretKeys secret key ring
         * @param secretKey secret key
         * @return secret key ring with injected secret key
         */
        @JvmStatic
        fun keysPlusSecretKey(secretKeys: PGPSecretKeyRing, secretKey: PGPSecretKey): PGPSecretKeyRing {
            return PGPSecretKeyRing.insertSecretKey(secretKeys, secretKey)
        }

        /**
         * Inject the given signature into the public part of the given secret key.
         * @param secretKey secret key
         * @param signature signature
         * @return secret key with the signature injected in its public key
         */
        @JvmStatic
        fun secretKeyPlusSignature(secretKey: PGPSecretKey, signature: PGPSignature): PGPSecretKey {
            PGPPublicKey.addCertification(secretKey.publicKey, signature).let {
                return PGPSecretKey.replacePublicKey(secretKey, it)
            }
        }

        /**
         * Remove the secret key of the subkey identified by the given secret key id from the key ring.
         * The public part stays attached to the key ring, so that it can still be used for encryption / verification of signatures.
         *
         * This method is intended to be used to remove secret primary keys from live keys when those are kept in offline storage.
         *
         * @param secretKeys secret key ring
         * @param keyId id of the secret key to remove
         * @return secret key ring with removed secret key
         *
         * @throws IOException in case of an error during serialization / deserialization of the key
         * @throws PGPException in case of a broken key
         */
        @JvmStatic
        fun stripSecretKey(secretKeys: PGPSecretKeyRing, keyId: Long): PGPSecretKeyRing {
            require(keyId != secretKeys.publicKey.keyID) {
                "Bouncy Castle currently cannot deal with stripped primary secret keys."
            }
            if (secretKeys.getSecretKey(keyId) == null) {
                throw NoSuchElementException("PGPSecretKeyRing does not contain secret key ${keyId.openPgpKeyId()}.")
            }

            val out = ByteArrayOutputStream()
            secretKeys.forEach {
                if (it.keyID == keyId) {
                    // only encode the public key
                    it.publicKey.encode(out)
                } else {
                    // else encode the whole secret + public key
                    it.encode(out)
                }
            }
            secretKeys.extraPublicKeys.forEach {
                it.encode(out)
            }
            return PGPSecretKeyRing(out.toByteArray(), ImplementationFactory.getInstance().keyFingerprintCalculator)
        }

        /**
         * Strip all user-ids, user-attributes and signatures from the given public key.
         *
         * @param bloatedKey public key
         * @return stripped public key
         * @throws PGPException if the packet is faulty or the required calculations fail
         */
        @JvmStatic
        fun getStrippedDownPublicKey(bloatedKey: PGPPublicKey): PGPPublicKey {
            return PGPPublicKey(bloatedKey.publicKeyPacket, ImplementationFactory.getInstance().keyFingerprintCalculator)
        }

        @JvmStatic
        fun getUserIdsIgnoringInvalidUTF8(key: PGPPublicKey): List<String> {
            return buildList {
                key.rawUserIDs.forEach {
                    try {
                        add(Strings.fromUTF8ByteArray(it))
                    } catch (e : IllegalArgumentException) {
                        LOGGER.warn("Invalid UTF-8 user-ID encountered: ${String(it)}")
                    }
                }
            }
        }

        @JvmStatic
        @Throws(MissingPassphraseException::class, PGPException::class)
        fun changePassphrase(keyId: Long?,
                             secretKeys: PGPSecretKeyRing,
                             oldProtector: SecretKeyRingProtector,
                             newProtector: SecretKeyRingProtector): PGPSecretKeyRing {
            return if (keyId == null) {
                PGPSecretKeyRing(
                        secretKeys.secretKeys.asSequence().map {
                            reencryptPrivateKey(it, oldProtector, newProtector)
                        }.toList()
                )
            } else {
                PGPSecretKeyRing(
                        secretKeys.secretKeys.asSequence().map {
                            if (it.keyID == keyId) {
                                reencryptPrivateKey(it, oldProtector, newProtector)
                            } else {
                                it
                            }
                        }.toList()
                )
            }.let { s2kUsageFixIfNecessary(it, newProtector) }
        }

        @JvmStatic
        fun reencryptPrivateKey(secretKey: PGPSecretKey,
                                oldProtector: SecretKeyRingProtector,
                                newProtector: SecretKeyRingProtector): PGPSecretKey {
            if (secretKey.s2K != null && secretKey.s2K.type == S2K.GNU_DUMMY_S2K) {
                // If the key uses GNU_DUMMY_S2K we leave it as is
                return secretKey
            }

            return PGPSecretKey.copyWithNewPassword(secretKey,
                    oldProtector.getDecryptor(secretKey.keyID),
                    newProtector.getEncryptor(secretKey.keyID))
        }

        @JvmStatic
        fun s2kUsageFixIfNecessary(secretKeys: PGPSecretKeyRing, protector: SecretKeyRingProtector): PGPSecretKeyRing {
            if (secretKeys.secretKeys.asSequence().any { it.s2KUsage == SecretKeyPacket.USAGE_CHECKSUM }) {
                return S2KUsageFix.replaceUsageChecksumWithUsageSha1(secretKeys, protector, true)
            }
            return secretKeys
        }

    }
}