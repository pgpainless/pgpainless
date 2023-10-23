// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing

import java.io.OutputStream
import java.security.MessageDigest
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.crypto.CipherParameters
import org.bouncycastle.crypto.CryptoException
import org.bouncycastle.crypto.Digest
import org.bouncycastle.crypto.Signer
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.DSADigestSigner
import org.bouncycastle.crypto.signers.DSASigner
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.signers.Ed448Signer
import org.bouncycastle.crypto.signers.RSADigestSigner
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.operator.PGPContentSigner
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyConverter
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.PublicKeyAlgorithm

/**
 * Implementation of [PGPContentSignerBuilder] using the BC API, which can be used to sign hash
 * contexts. This can come in handy to sign data, which was already processed to calculate the hash
 * context, without the need to process it again to calculate the OpenPGP signature.
 */
class BcPGPHashContextContentSignerBuilder(private val messageDigest: MessageDigest) :
    PGPHashContextContentSignerBuilder() {

    private val keyConverter = BcPGPKeyConverter()
    private val _hashAlgorithm: HashAlgorithm

    init {
        _hashAlgorithm = requireFromName(messageDigest.algorithm)
    }

    override fun build(signatureType: Int, privateKey: PGPPrivateKey): PGPContentSigner {
        val keyAlgorithm = PublicKeyAlgorithm.requireFromId(privateKey.publicKeyPacket.algorithm)
        val privKeyParam = keyConverter.getPrivateKey(privateKey)
        val signer = createSigner(keyAlgorithm, messageDigest, privKeyParam)
        signer.init(true, privKeyParam)

        return object : PGPContentSigner {
            override fun getOutputStream(): OutputStream = SignerOutputStream(signer)

            override fun getSignature(): ByteArray =
                try {
                    signer.generateSignature()
                } catch (e: CryptoException) {
                    throw IllegalStateException("unable to create signature.", e)
                }

            override fun getDigest(): ByteArray = messageDigest.digest()

            override fun getType(): Int = signatureType

            override fun getHashAlgorithm(): Int = _hashAlgorithm.algorithmId

            override fun getKeyAlgorithm(): Int = keyAlgorithm.algorithmId

            override fun getKeyID(): Long = privateKey.keyID
        }
    }

    companion object {
        @JvmStatic
        private fun requireFromName(digestName: String): HashAlgorithm {
            val algorithm = HashAlgorithm.fromName(digestName)
            require(algorithm != null) { "Cannot recognize OpenPGP Hash Algorithm: $digestName" }
            return algorithm
        }

        @JvmStatic
        private fun createSigner(
            keyAlgorithm: PublicKeyAlgorithm,
            messageDigest: MessageDigest,
            keyParam: CipherParameters
        ): Signer {
            val staticDigest = ExistingMessageDigest(messageDigest)
            return when (keyAlgorithm.algorithmId) {
                PublicKeyAlgorithmTags.RSA_GENERAL,
                PublicKeyAlgorithmTags.RSA_SIGN -> RSADigestSigner(staticDigest)
                PublicKeyAlgorithmTags.DSA -> DSADigestSigner(DSASigner(), staticDigest)
                PublicKeyAlgorithmTags.ECDSA -> DSADigestSigner(ECDSASigner(), staticDigest)
                PublicKeyAlgorithmTags.EDDSA_LEGACY -> {
                    if (keyParam is Ed25519PrivateKeyParameters ||
                        keyParam is Ed25519PublicKeyParameters)
                        EdDsaSigner(Ed25519Signer(), staticDigest)
                    else EdDsaSigner(Ed448Signer(byteArrayOf()), staticDigest)
                }
                else -> throw PGPException("cannot recognize keyAlgorithm: $keyAlgorithm")
            }
        }
    }

    // Copied from BCs BcImplProvider - required since BCs class is package visible only :/
    internal class EdDsaSigner(private val signer: Signer, private val digest: Digest) : Signer {
        private val digBuf: ByteArray = ByteArray(digest.digestSize)

        override fun init(forSigning: Boolean, param: CipherParameters) {
            signer.init(forSigning, param)
            digest.reset()
        }

        override fun update(b: Byte) {
            digest.update(b)
        }

        override fun update(b: ByteArray, off: Int, len: Int) {
            digest.update(b, off, len)
        }

        override fun generateSignature(): ByteArray {
            digest.doFinal(digBuf, 0)
            signer.update(digBuf, 0, digBuf.size)
            return signer.generateSignature()
        }

        override fun verifySignature(signature: ByteArray): Boolean {
            digest.doFinal(digBuf, 0)
            signer.update(digBuf, 0, digBuf.size)
            return signer.verifySignature(signature)
        }

        override fun reset() {
            digBuf.fill(0)
            signer.reset()
            digest.reset()
        }
    }
}
