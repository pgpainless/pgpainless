// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing

import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.bouncycastle.openpgp.api.OpenPGPSignature.OpenPGPDocumentSignature
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.SignatureType
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.key.protection.UnlockSecretKey
import java.security.MessageDigest

class BcHashContextSigner {

    companion object {
        @JvmStatic
        fun signHashContext(
            hashContext: MessageDigest,
            signatureType: SignatureType,
            secretKey: OpenPGPKey,
            protector: SecretKeyRingProtector
        ): OpenPGPDocumentSignature {
            val info = PGPainless.getInstance().inspect(secretKey)
            return info.signingSubkeys
                .mapNotNull { info.getSecretKey(it.keyIdentifier) }
                .firstOrNull()
                ?.let {
                    signHashContext(hashContext, signatureType, UnlockSecretKey.unlockSecretKey(it, protector))
                }
                ?: throw PGPException("Key does not contain suitable signing subkey.")
        }

        /**
         * Create an OpenPGP Signature over the given [MessageDigest] hash context.
         *
         * @param hashContext hash context
         * @param privateKey signing-capable key
         * @return signature
         * @throws PGPException in case of an OpenPGP error
         */
        @JvmStatic
        internal fun signHashContext(
            hashContext: MessageDigest,
            signatureType: SignatureType,
            privateKey: OpenPGPKey.OpenPGPPrivateKey
        ): OpenPGPDocumentSignature {
            return PGPSignatureGenerator(
                BcPGPHashContextContentSignerBuilder(hashContext),
                privateKey.keyPair.publicKey)
                .apply { init(signatureType.code, privateKey.keyPair.privateKey) }
                .generate()
                .let { OpenPGPDocumentSignature(it, privateKey.publicKey) }
        }
    }
}
