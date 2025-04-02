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

class UnlockSecretKey {

    companion object {

        @JvmStatic
        @Throws(PGPException::class, KeyIntegrityException::class)
        fun unlockSecretKey(
            secretKey: PGPSecretKey,
            protector: SecretKeyRingProtector
        ): PGPPrivateKey {
            return if (secretKey.isEncrypted()) {
                unlockSecretKey(secretKey, protector.getDecryptor(secretKey.keyIdentifier))
            } else {
                unlockSecretKey(secretKey, null as PBESecretKeyDecryptor?)
            }
        }

        @JvmStatic
        @JvmOverloads
        @Throws(PGPException::class)
        fun unlockSecretKey(
            secretKey: OpenPGPSecretKey,
            protector: SecretKeyRingProtector,
            policy: Policy = PGPainless.getInstance().algorithmPolicy
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

        @JvmStatic
        @JvmOverloads
        @Throws(PGPException::class)
        fun unlockSecretKey(
            secretKey: PGPSecretKey,
            decryptor: PBESecretKeyDecryptor?,
            policy: Policy = PGPainless.getInstance().algorithmPolicy
        ): PGPPrivateKey {
            val privateKey =
                try {
                    secretKey.extractPrivateKey(decryptor)
                } catch (e: PGPException) {
                    throw WrongPassphraseException(secretKey.keyID, e)
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

        @JvmStatic
        fun unlockSecretKey(secretKey: PGPSecretKey, passphrase: Passphrase?): PGPPrivateKey {
            return if (passphrase == null) {
                unlockSecretKey(secretKey, SecretKeyRingProtector.unprotectedKeys())
            } else {
                unlockSecretKey(
                    secretKey, SecretKeyRingProtector.unlockSingleKeyWith(passphrase, secretKey))
            }
        }

        @JvmStatic
        fun unlockSecretKey(secretKey: OpenPGPSecretKey, passphrase: Passphrase): OpenPGPPrivateKey =
            unlockSecretKey(secretKey, SecretKeyRingProtector.unlockAnyKeyWith(passphrase))
    }
}
