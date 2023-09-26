// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing

import org.bouncycastle.extensions.unlock
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.SignatureType
import org.pgpainless.key.protection.SecretKeyRingProtector
import java.security.MessageDigest

class BcHashContextSigner {

    companion object {
        @JvmStatic
        fun signHashContext(hashContext: MessageDigest,
                            signatureType: SignatureType,
                            secretKey: PGPSecretKeyRing,
                            protector: SecretKeyRingProtector): PGPSignature {
            val info = PGPainless.inspectKeyRing(secretKey)
            return info.signingSubkeys.mapNotNull { info.getSecretKey(it.keyID) }.firstOrNull()
                    ?.let { signHashContext(hashContext, signatureType, it.unlock(protector)) }
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
        internal fun signHashContext(hashContext: MessageDigest,
                                     signatureType: SignatureType,
                                     privateKey: PGPPrivateKey): PGPSignature {
            return PGPSignatureGenerator(BcPGPHashContextContentSignerBuilder(hashContext))
                    .apply { init(signatureType.code, privateKey) }
                    .generate()
        }
    }
}