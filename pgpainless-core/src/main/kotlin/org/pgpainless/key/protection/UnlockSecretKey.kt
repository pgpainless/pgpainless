// Copyright 2023 Paul Schaub.
// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.protection

import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor
import org.pgpainless.PGPainless
import org.pgpainless.exception.KeyIntegrityException
import org.pgpainless.exception.WrongPassphraseException
import org.pgpainless.key.info.KeyInfo
import org.pgpainless.key.util.KeyIdUtil
import org.pgpainless.key.util.PublicKeyParameterValidationUtil
import org.pgpainless.util.Passphrase
import kotlin.jvm.Throws

class UnlockSecretKey {

    companion object {

        @JvmStatic
        @Throws(PGPException::class, KeyIntegrityException::class)
        fun unlockSecretKey(secretKey: PGPSecretKey, protector: SecretKeyRingProtector): PGPPrivateKey {
            return if (KeyInfo.isEncrypted(secretKey)) {
                unlockSecretKey(secretKey, protector.getDecryptor(secretKey.keyID))
            } else {
                unlockSecretKey(secretKey, null as PBESecretKeyDecryptor?)
            }
        }

        @JvmStatic
        @Throws(PGPException::class)
        fun unlockSecretKey(secretKey: PGPSecretKey, decryptor: PBESecretKeyDecryptor?): PGPPrivateKey {
            val privateKey = try {
                secretKey.extractPrivateKey(decryptor)
            } catch (e : PGPException) {
                throw WrongPassphraseException(secretKey.keyID, e)
            }

            if (privateKey == null) {
                if (secretKey.s2K.type in 100..110) {
                    throw PGPException("Cannot decrypt secret key ${KeyIdUtil.formatKeyId(secretKey.keyID)}: \n" +
                            "Unsupported private S2K type ${secretKey.s2K.type}")
                }
                throw PGPException("Cannot decrypt secret key.")
            }

            if (PGPainless.getPolicy().isEnableKeyParameterValidation()) {
                PublicKeyParameterValidationUtil.verifyPublicKeyParameterIntegrity(privateKey, secretKey.publicKey)
            }

            return privateKey
        }

        @JvmStatic
        fun unlockSecretKey(secretKey: PGPSecretKey, passphrase: Passphrase?): PGPPrivateKey {
            return if (passphrase == null) {
                unlockSecretKey(secretKey, SecretKeyRingProtector.unprotectedKeys())
            } else {
                unlockSecretKey(secretKey, SecretKeyRingProtector.unlockSingleKeyWith(passphrase, secretKey))
            }
        }
    }
}