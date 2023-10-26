// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.util

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.math.BigInteger
import java.security.SecureRandom
import org.bouncycastle.bcpg.*
import org.bouncycastle.extensions.publicKeyAlgorithm
import org.bouncycastle.openpgp.*
import org.bouncycastle.util.Arrays
import org.bouncycastle.util.io.Streams
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.PublicKeyAlgorithm.Companion.requireFromId
import org.pgpainless.algorithm.SignatureType
import org.pgpainless.algorithm.SymmetricKeyAlgorithm
import org.pgpainless.exception.KeyIntegrityException
import org.pgpainless.implementation.ImplementationFactory.Companion.getInstance

/**
 * Utility class to verify keys against Key Overwriting (KO) attacks. This class of attacks is only
 * possible if the attacker has access to the (encrypted) secret key material. To execute the
 * attack, they would modify the unauthenticated parameters of the users public key. Using the
 * modified public key in combination with the unmodified secret key material can then lead to the
 * extraction of secret key parameters via weakly crafted messages.
 *
 * @see <a href="https://www.kopenpgp.com/">Key Overwriting (KO) Attacks against OpenPGP</a>
 */
class PublicKeyParameterValidationUtil {

    companion object {
        @JvmStatic
        @Throws(KeyIntegrityException::class)
        fun verifyPublicKeyParameterIntegrity(privateKey: PGPPrivateKey, publicKey: PGPPublicKey) {
            val algorithm = publicKey.publicKeyAlgorithm
            var valid = true

            val key = privateKey.privateKeyDataPacket
            when (privateKey.privateKeyDataPacket) {
                is RSASecretBCPGKey ->
                    valid =
                        verifyRSAKeyIntegrity(
                            key as RSASecretBCPGKey,
                            publicKey.publicKeyPacket.key as RSAPublicBCPGKey)
                is EdSecretBCPGKey ->
                    valid =
                        verifyEdDsaKeyIntegrity(
                            key as EdSecretBCPGKey,
                            publicKey.publicKeyPacket.key as EdDSAPublicBCPGKey)
                is DSASecretBCPGKey ->
                    valid =
                        verifyDsaKeyIntegrity(
                            key as DSASecretBCPGKey,
                            publicKey.publicKeyPacket.key as DSAPublicBCPGKey)
                is ElGamalSecretBCPGKey ->
                    valid =
                        verifyElGamalKeyIntegrity(
                            key as ElGamalSecretBCPGKey,
                            publicKey.publicKeyPacket.key as ElGamalPublicBCPGKey)
            }

            if (!valid) throw KeyIntegrityException()

            // Additional to the algorithm-specific tests further above, we also perform
            // generic functionality tests with the key, such as whether it is able to decrypt
            // encrypted data
            // or verify signatures.
            // These tests should be more or less constant time.
            if (algorithm.isSigningCapable()) {
                valid = verifyCanSign(privateKey, publicKey)
            }
            if (algorithm.isEncryptionCapable()) {
                valid = valid and verifyCanDecrypt(privateKey, publicKey)
            }

            if (!valid) throw KeyIntegrityException()
        }

        @JvmStatic
        @Throws(KeyIntegrityException::class)
        private fun verifyRSAKeyIntegrity(
            secretKey: RSASecretBCPGKey,
            publicKey: RSAPublicBCPGKey
        ): Boolean {
            // Verify that the public keys N is equal to private keys p*q
            return publicKey.modulus.equals(secretKey.primeP.multiply(secretKey.primeQ))
        }

        @JvmStatic
        @Throws(KeyIntegrityException::class)
        private fun verifyEdDsaKeyIntegrity(
            secretKey: EdSecretBCPGKey,
            publicKey: EdDSAPublicBCPGKey
        ): Boolean {
            // TODO: Implement
            return true
        }

        @JvmStatic
        @Throws(KeyIntegrityException::class)
        private fun verifyDsaKeyIntegrity(
            privateKey: DSASecretBCPGKey,
            publicKey: DSAPublicBCPGKey
        ): Boolean {
            // Not sure what value to put here in order to have a "robust" primality check
            // I went with 40, since that's what SO recommends:
            // https://stackoverflow.com/a/6330138
            val certainty = 40
            val pG = publicKey.g
            val pP = publicKey.p
            val pQ = publicKey.q
            val pY = publicKey.y
            val sX = privateKey.x

            val pPrime = pP.isProbablePrime(certainty)
            if (!pPrime) {
                return false
            }

            val qPrime = pQ.isProbablePrime(certainty)
            if (!qPrime) {
                return false
            }

            // q > 160 bits
            val qLarge = pQ.bitLength() > 160
            if (!qLarge) {
                return false
            }

            // q divides p - 1
            val qDividesPminus1 = pP.subtract(BigInteger.ONE).mod(pQ) == BigInteger.ZERO
            if (!qDividesPminus1) {
                return false
            }

            // 1 < g < p
            val gInBounds = BigInteger.ONE.max(pG) == pG && pG.max(pP) == pP
            if (!gInBounds) {
                return false
            }

            // g^q = 1 mod p
            val gPowXModPEquals1 = pG.modPow(pQ, pP) == BigInteger.ONE
            if (!gPowXModPEquals1) {
                return false
            }

            // y = g^x mod p
            return pY == pG.modPow(sX, pP)
        }

        /**
         * Validate ElGamal public key parameters.
         *
         * Original implementation by the openpgpjs authors: <a
         * href="https://github.com/openpgpjs/openpgpjs/blob/main/src/crypto/public_key/elgamal.js#L76-L143>OpenPGP.js
         * source</a>
         *
         * @param secretKey secret key
         * @param publicKey public key
         * @return true if supposedly valid, false if invalid
         */
        @JvmStatic
        @Throws(KeyIntegrityException::class)
        private fun verifyElGamalKeyIntegrity(
            secretKey: ElGamalSecretBCPGKey,
            publicKey: ElGamalPublicBCPGKey
        ): Boolean {
            val p = publicKey.p
            val g = publicKey.g
            val y = publicKey.y
            val one = BigInteger.ONE

            // 1 < g < p
            if (g.min(one) == g || g.max(p) == g) {
                return false
            }

            // p-1 is large
            if (p.bitLength() < 1023) {
                return false
            }

            // g^(p-1) mod p = 1
            if (g.modPow(p.subtract(one), p) != one) {
                return false
            }

            // check g^i mod p != 1 for i < threshold
            var res = g
            // 262144
            val threshold = 2 shl 17
            var i = 1
            while (i < threshold) {
                res = res.multiply(g).mod(p)
                if (res == one) {
                    return false
                }
                i++
            }

            // blinded exponentiation to check y = g^(r*(p-1)+x) mod p
            val random = SecureRandom()
            val x = secretKey.x
            val r = BigInteger(p.bitLength(), random)
            val rqx = p.subtract(one).multiply(r).add(x)
            return y == g.modPow(rqx, p)
        }

        /**
         * Verify that the public key can be used to successfully verify a signature made by the
         * private key.
         *
         * @param privateKey private key
         * @param publicKey public key
         * @return false if signature verification fails
         */
        @JvmStatic
        private fun verifyCanSign(privateKey: PGPPrivateKey, publicKey: PGPPublicKey): Boolean {
            val data = ByteArray(512).also { SecureRandom().nextBytes(it) }
            val signatureGenerator =
                PGPSignatureGenerator(
                    getInstance()
                        .getPGPContentSignerBuilder(
                            requireFromId(publicKey.algorithm), HashAlgorithm.SHA256))
            return try {
                signatureGenerator
                    .apply {
                        init(SignatureType.TIMESTAMP.code, privateKey)
                        update(data)
                    }
                    .generate()
                    .apply {
                        init(getInstance().pgpContentVerifierBuilderProvider, publicKey)
                        update(data)
                    }
                    .verify()
            } catch (e: PGPException) {
                false
            }
        }

        /**
         * Verify that the public key can be used to encrypt a message which can successfully be
         * decrypted using the private key.
         *
         * @param privateKey private key
         * @param publicKey public key
         * @return false if decryption of a message encrypted with the public key fails
         */
        @JvmStatic
        private fun verifyCanDecrypt(privateKey: PGPPrivateKey, publicKey: PGPPublicKey): Boolean {
            val data = ByteArray(1024).also { SecureRandom().nextBytes(it) }
            val encryptedDataGenerator =
                PGPEncryptedDataGenerator(
                        getInstance().getPGPDataEncryptorBuilder(SymmetricKeyAlgorithm.AES_256))
                    .apply {
                        addMethod(getInstance().getPublicKeyKeyEncryptionMethodGenerator(publicKey))
                    }

            var out = ByteArrayOutputStream()
            try {
                val outputStream = encryptedDataGenerator.open(out, ByteArray(1024))
                outputStream.write(data)
                encryptedDataGenerator.close()
                val encryptedDataList = PGPEncryptedDataList(out.toByteArray())
                val decryptorFactory = getInstance().getPublicKeyDataDecryptorFactory(privateKey)
                val encryptedData =
                    encryptedDataList.encryptedDataObjects.next() as PGPPublicKeyEncryptedData
                val decrypted = encryptedData.getDataStream(decryptorFactory)
                out = ByteArrayOutputStream()
                Streams.pipeAll(decrypted, out)
                decrypted.close()
            } catch (e: IOException) {
                return false
            } catch (e: PGPException) {
                return false
            }
            return Arrays.constantTimeAreEqual(data, out.toByteArray())
        }
    }
}
