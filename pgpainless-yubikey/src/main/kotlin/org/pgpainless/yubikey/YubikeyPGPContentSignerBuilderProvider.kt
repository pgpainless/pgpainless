// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.yubikey

import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.openpgp.OpenPgpSession
import java.io.OutputStream
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.api.OpenPGPImplementation
import org.bouncycastle.openpgp.operator.PGPContentSigner
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilderProvider
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.key.protection.passphrase_provider.SecretKeyPassphraseProvider

/**
 * [PGPContentSignerBuilderProvider] that can be used with software- and hardware-based OpenPGP
 * keys.
 */
class YubikeyPGPContentSignerBuilderProvider(
    val hashAlgorithm: HashAlgorithm,
    private val smartcardConnection: SmartCardConnection,
    private val userPinCallback: SecretKeyPassphraseProvider,
    private val implementation: OpenPGPImplementation = OpenPGPImplementation.getInstance()
) : PGPContentSignerBuilderProvider(hashAlgorithm.algorithmId) {

    private val softwareSignerBuilderProvider =
        implementation.pgpContentSignerBuilderProvider(hashAlgorithm.algorithmId)

    override fun get(publicSigningKey: PGPPublicKey): PGPContentSignerBuilder {
        return object : PGPContentSignerBuilder {

            override fun build(signatureType: Int, privateKey: PGPPrivateKey?): PGPContentSigner {
                // Delegate software-based signing keys to the implementations default
                //  content signer builder provider
                return softwareSignerBuilderProvider
                    .get(publicSigningKey)
                    .build(signatureType, privateKey)
            }

            override fun build(signatureType: Int): PGPContentSigner {
                val digestCalculator =
                    implementation.pgpDigestCalculatorProvider().get(hashAlgorithmId)
                val openPgpSession = OpenPgpSession(smartcardConnection)

                val userPin = userPinCallback.getPassphraseFor(publicSigningKey.keyIdentifier)
                userPin?.getChars()?.let { openPgpSession.verifyUserPin(it, false) }

                // Return custom PGPContentSigner utilizing Yubikit for signing operations
                return object : PGPContentSigner {

                    override fun getOutputStream(): OutputStream {
                        return digestCalculator.outputStream
                    }

                    override fun getSignature(): ByteArray {
                        return openPgpSession.sign(digest)
                    }

                    override fun getDigest(): ByteArray {
                        return digestCalculator.digest
                    }

                    override fun getType(): Int {
                        return signatureType
                    }

                    override fun getHashAlgorithm(): Int {
                        return hashAlgorithmId
                    }

                    override fun getKeyAlgorithm(): Int {
                        return publicSigningKey.algorithm
                    }

                    override fun getKeyID(): Long {
                        return publicSigningKey.keyID
                    }
                }
            }
        }
    }
}
