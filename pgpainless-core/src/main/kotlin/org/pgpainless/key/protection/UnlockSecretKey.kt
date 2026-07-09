// Copyright 2023 Paul Schaub.
// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.protection

import kotlin.jvm.Throws
import openpgp.openPgpKeyId
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.api.OpenPGPKey.OpenPGPPrivateKey
import org.bouncycastle.openpgp.api.OpenPGPKey.OpenPGPSecretKey
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor
import org.pgpainless.PGPainless
import org.pgpainless.bouncycastle.extensions.isEncrypted
import org.pgpainless.exception.KeyIntegrityException
import org.pgpainless.exception.WrongPassphraseException
import org.pgpainless.key.util.PublicKeyParameterValidationUtil
import org.pgpainless.policy.Policy
import org.pgpainless.util.Passphrase

/**
 * Methods for unlocking OpenPGP secret keys. Depending on the [Policy] configuration, these helper
 * functions will check the unlocked OpenPGP key for tampering.
 *
 * @see [KOpenPGP attack](https://kopenpgp.com)
 */
class UnlockSecretKey {

    companion object {

        /**
         * Unlock the given [PGPSecretKey] with the given [SecretKeyRingProtector].
         *
         * Note: This method sources its [Policy] instance from the default singleton instance of
         * [PGPainless], so in multi-instance setups, this might not be the expected policy.
         * Therefore, this method is deprecated in favor of a method taking in an additional
         * [Policy] instance.
         *
         * @param secretKey secret key
         * @param protector protector to unlock the secret key with
         * @return unlocked private key
         */
        // TODO: Remove in 2.2
        @JvmStatic
        @Throws(PGPException::class, KeyIntegrityException::class)
        @Deprecated("Deprecated in favor of method taking policy instance.")
        fun unlockSecretKey(
            secretKey: PGPSecretKey,
            protector: SecretKeyRingProtector
        ): PGPPrivateKey {
            return unlockSecretKey(secretKey, protector, PGPainless.getInstance().algorithmPolicy)
        }

        /**
         * Unlock the given [PGPSecretKey] with the given [SecretKeyRingProtector].
         *
         * @param secretKey secret key
         * @param protector protector to unlock the secret key with
         * @return unlocked private key
         */
        @JvmStatic
        @Throws(PGPException::class, KeyIntegrityException::class)
        fun unlockSecretKey(
            secretKey: PGPSecretKey,
            protector: SecretKeyRingProtector,
            policy: Policy
        ): PGPPrivateKey {
            return if (secretKey.isEncrypted()) {
                unlockSecretKey(secretKey, protector.getDecryptor(secretKey.keyIdentifier), policy)
            } else {
                unlockSecretKey(secretKey, null as PBESecretKeyDecryptor?, policy)
            }
        }

        /**
         * Unlock the given [OpenPGPSecretKey] with the given [SecretKeyRingProtector].
         *
         * Note: This method sources its [Policy] instance from the default singleton instance of
         * [PGPainless], so in multi-instance setups, this might not be the expected policy.
         * Therefore, this method is deprecated in favor of a method taking in an additional
         * [Policy] instance.
         *
         * @param secretKey secret key
         * @param protector protector to unlock the secret key with
         * @return unlocked private key
         */
        // TODO: Remove in 2.2
        @JvmStatic
        @Throws(PGPException::class, KeyIntegrityException::class)
        @Deprecated("Deprecated in favor of method taking policy instance.")
        fun unlockSecretKey(
            secretKey: OpenPGPSecretKey,
            protector: SecretKeyRingProtector
        ): OpenPGPPrivateKey {
            return unlockSecretKey(secretKey, protector, PGPainless.getInstance().algorithmPolicy)
        }

        /**
         * Unlock the given [OpenPGPSecretKey] with the given [SecretKeyRingProtector].
         *
         * @param secretKey secret key
         * @param protector protector to unlock the secret key with
         * @return unlocked private key
         */
        @JvmStatic
        @Throws(PGPException::class, KeyIntegrityException::class)
        fun unlockSecretKey(
            secretKey: OpenPGPSecretKey,
            protector: SecretKeyRingProtector,
            policy: Policy
        ): OpenPGPPrivateKey {
            val privateKey =
                try {
                    secretKey.unlock(protector)
                } catch (e: PGPException) {
                    throw WrongPassphraseException(secretKey.keyIdentifier, e)
                }

            if (privateKey == null) {
                if (secretKey.pgpSecretKey.s2K.type in 100..110) {
                    throw PGPException(
                        "Cannot decrypt secret key ${secretKey.keyIdentifier}: \n" +
                            "Unsupported private S2K type ${secretKey.pgpSecretKey.s2K.type}")
                }
                throw PGPException("Cannot decrypt secret key.")
            }

            if (policy.isEnableKeyParameterValidation()) {
                PublicKeyParameterValidationUtil.verifyPublicKeyParameterIntegrity(
                    privateKey.keyPair.privateKey, privateKey.keyPair.publicKey)
            }

            return privateKey
        }

        /**
         * Unlock the given [PGPSecretKey] with the given [PBESecretKeyDecryptor].
         *
         * Note: This method sources its [Policy] instance from the default singleton instance of
         * [PGPainless], so in multi-instance setups, this might not be the expected policy.
         * Therefore, this method is deprecated in favor of a method taking in an additional
         * [Policy] instance.
         *
         * @param secretKey secret key
         * @param decryptor decryptor to unlock the secret key with
         * @return unlocked private key
         */
        // TODO: Remove in 2.2
        @JvmStatic
        @Throws(PGPException::class, KeyIntegrityException::class)
        @Deprecated("Deprecated in favor of method taking policy instance.")
        fun unlockSecretKey(
            secretKey: PGPSecretKey,
            decryptor: PBESecretKeyDecryptor?
        ): PGPPrivateKey {
            return unlockSecretKey(secretKey, decryptor, PGPainless.getInstance().algorithmPolicy)
        }

        /**
         * Unlock the given [PGPSecretKey] with the given [PBESecretKeyDecryptor].
         *
         * @param secretKey secret key
         * @param decryptor decryptor to unlock the secret key with
         * @return unlocked private key
         */
        @JvmStatic
        @Throws(PGPException::class, KeyIntegrityException::class)
        fun unlockSecretKey(
            secretKey: PGPSecretKey,
            decryptor: PBESecretKeyDecryptor?,
            policy: Policy
        ): PGPPrivateKey {
            val privateKey =
                try {
                    secretKey.extractPrivateKey(decryptor)
                } catch (e: PGPException) {
                    throw WrongPassphraseException(secretKey.keyIdentifier, e)
                }

            if (privateKey == null) {
                if (secretKey.s2K.type in 100..110) {
                    throw PGPException(
                        "Cannot decrypt secret key ${secretKey.keyID.openPgpKeyId()}: \n" +
                            "Unsupported private S2K type ${secretKey.s2K.type}")
                }
                throw PGPException("Cannot decrypt secret key.")
            }

            if (policy.isEnableKeyParameterValidation()) {
                PublicKeyParameterValidationUtil.verifyPublicKeyParameterIntegrity(
                    privateKey, secretKey.publicKey)
            }

            return privateKey
        }

        /**
         * Unlock the given [PGPSecretKey] with the given [Passphrase].
         *
         * Note: This method sources its [Policy] instance from the default singleton instance of
         * [PGPainless], so in multi-instance setups, this might not be the expected policy.
         * Therefore, this method is deprecated in favor of a method taking in an additional
         * [Policy] instance.
         *
         * @param secretKey secret key
         * @param passphrase passphrase to unlock the secret key with
         * @return unlocked private key
         */
        // TODO: Remove in 2.2
        @JvmStatic
        @Throws(PGPException::class, KeyIntegrityException::class)
        @Deprecated("Deprecated in favor of method taking policy.")
        fun unlockSecretKey(secretKey: PGPSecretKey, passphrase: Passphrase?): PGPPrivateKey {
            return unlockSecretKey(secretKey, passphrase, PGPainless.getInstance().algorithmPolicy)
        }

        /**
         * Unlock the given [PGPSecretKey] with the given [Passphrase].
         *
         * @param secretKey secret key
         * @param passphrase passphrase to unlock the secret key with
         * @return unlocked private key
         */
        @JvmStatic
        @Throws(PGPException::class, KeyIntegrityException::class)
        fun unlockSecretKey(
            secretKey: PGPSecretKey,
            passphrase: Passphrase?,
            policy: Policy
        ): PGPPrivateKey {
            return if (passphrase == null) {
                unlockSecretKey(secretKey, SecretKeyRingProtector.unprotectedKeys(), policy)
            } else {
                unlockSecretKey(
                    secretKey,
                    SecretKeyRingProtector.unlockSingleKeyWith(passphrase, secretKey),
                    policy)
            }
        }

        /**
         * Unlock the given [OpenPGPSecretKey] with the given [Passphrase].
         *
         * Note: This method sources its [Policy] instance from the default singleton instance of
         * [PGPainless], so in multi-instance setups, this might not be the expected policy.
         * Therefore, this method is deprecated in favor of a method taking in an additional
         * [Policy] instance.
         *
         * @param secretKey secret key
         * @param passphrase passphrase to unlock the secret key with
         * @return unlocked private key
         */
        // TODO: Remove in 2.2
        @JvmStatic
        @Throws(PGPException::class, KeyIntegrityException::class)
        @Deprecated("Deprecated in favor of method taking policy.")
        fun unlockSecretKey(
            secretKey: OpenPGPSecretKey,
            passphrase: Passphrase
        ): OpenPGPPrivateKey {
            return unlockSecretKey(secretKey, passphrase, PGPainless.getInstance().algorithmPolicy)
        }

        /**
         * Unlock the given [OpenPGPSecretKey] with the given [Passphrase].
         *
         * @param secretKey secret key
         * @param passphrase passphrase to unlock the secret key with
         * @return unlocked private key
         */
        @JvmStatic
        @Throws(PGPException::class, KeyIntegrityException::class)
        fun unlockSecretKey(
            secretKey: OpenPGPSecretKey,
            passphrase: Passphrase,
            policy: Policy
        ): OpenPGPPrivateKey =
            unlockSecretKey(secretKey, SecretKeyRingProtector.unlockAnyKeyWith(passphrase), policy)
    }
}
