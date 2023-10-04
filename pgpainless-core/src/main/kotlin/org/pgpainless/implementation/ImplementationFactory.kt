// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.implementation

import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.operator.*
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.PublicKeyAlgorithm
import org.pgpainless.algorithm.SymmetricKeyAlgorithm
import org.pgpainless.util.Passphrase
import org.pgpainless.util.SessionKey
import java.io.InputStream
import java.security.KeyPair
import java.util.*

abstract class ImplementationFactory {

    companion object {
        @JvmStatic
        private var instance: ImplementationFactory = BcImplementationFactory()

        @JvmStatic
        fun getInstance() = instance

        @JvmStatic
        fun setFactoryImplementation(implementation: ImplementationFactory) = apply {
            instance = implementation
        }
    }

    abstract val pgpDigestCalculatorProvider: PGPDigestCalculatorProvider
    abstract val pgpContentVerifierBuilderProvider: PGPContentVerifierBuilderProvider
    abstract val keyFingerprintCalculator: KeyFingerPrintCalculator

    val v4FingerprintCalculator: PGPDigestCalculator
        get() = getPGPDigestCalculator(HashAlgorithm.SHA1)

    @Throws(PGPException::class)
    abstract fun getPBESecretKeyEncryptor(symmetricKeyAlgorithm: SymmetricKeyAlgorithm,
                                          digestCalculator: PGPDigestCalculator,
                                          passphrase: Passphrase): PBESecretKeyEncryptor

    @Throws(PGPException::class)
    abstract fun getPBESecretKeyDecryptor(passphrase: Passphrase): PBESecretKeyDecryptor

    @Throws(PGPException::class)
    abstract fun getPBESecretKeyEncryptor(encryptionAlgorithm: SymmetricKeyAlgorithm, hashAlgorithm: HashAlgorithm,
                                          s2kCount: Int, passphrase: Passphrase): PBESecretKeyEncryptor

    fun getPGPDigestCalculator(hashAlgorithm: HashAlgorithm): PGPDigestCalculator =
            getPGPDigestCalculator(hashAlgorithm.algorithmId)

    fun getPGPDigestCalculator(hashAlgorithm: Int): PGPDigestCalculator =
            pgpDigestCalculatorProvider.get(hashAlgorithm)

    fun getPGPContentSignerBuilder(keyAlgorithm: PublicKeyAlgorithm, hashAlgorithm: HashAlgorithm): PGPContentSignerBuilder =
            getPGPContentSignerBuilder(keyAlgorithm.algorithmId, hashAlgorithm.algorithmId)

    abstract fun getPGPContentSignerBuilder(keyAlgorithm: Int, hashAlgorithm: Int): PGPContentSignerBuilder

    @Throws(PGPException::class)
    abstract fun getPBEDataDecryptorFactory(passphrase: Passphrase): PBEDataDecryptorFactory

    abstract fun getPublicKeyDataDecryptorFactory(privateKey: PGPPrivateKey): PublicKeyDataDecryptorFactory

    fun getSessionKeyDataDecryptorFactory(sessionKey: SessionKey): SessionKeyDataDecryptorFactory =
            getSessionKeyDataDecryptorFactory(PGPSessionKey(sessionKey.algorithm.algorithmId, sessionKey.key))

    abstract fun getSessionKeyDataDecryptorFactory(sessionKey: PGPSessionKey): SessionKeyDataDecryptorFactory

    abstract fun getPublicKeyKeyEncryptionMethodGenerator(key: PGPPublicKey): PublicKeyKeyEncryptionMethodGenerator

    abstract fun getPBEKeyEncryptionMethodGenerator(passphrase: Passphrase): PBEKeyEncryptionMethodGenerator

    fun getPGPDataEncryptorBuilder(symmetricKeyAlgorithm: SymmetricKeyAlgorithm): PGPDataEncryptorBuilder =
            getPGPDataEncryptorBuilder(symmetricKeyAlgorithm.algorithmId)

    abstract fun getPGPDataEncryptorBuilder(symmetricKeyAlgorithm: Int): PGPDataEncryptorBuilder

    @Throws(PGPException::class)
    abstract fun getPGPKeyPair(publicKeyAlgorithm: PublicKeyAlgorithm, keyPair: KeyPair, creationDate: Date): PGPKeyPair

    fun getPGPObjectFactory(bytes: ByteArray): PGPObjectFactory =
            getPGPObjectFactory(bytes.inputStream())

    abstract fun getPGPObjectFactory(inputStream: InputStream): PGPObjectFactory

    override fun toString(): String {
        return javaClass.simpleName
    }
}