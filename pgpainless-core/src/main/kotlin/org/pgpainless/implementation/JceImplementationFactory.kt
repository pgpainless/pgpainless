// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.implementation

import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.operator.*
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair
import org.bouncycastle.openpgp.operator.jcajce.JcePBEDataDecryptorFactoryBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcePBEKeyEncryptionMethodGenerator
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator
import org.bouncycastle.openpgp.operator.jcajce.JceSessionKeyDataDecryptorFactoryBuilder
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.PublicKeyAlgorithm
import org.pgpainless.algorithm.SymmetricKeyAlgorithm
import org.pgpainless.provider.ProviderFactory
import org.pgpainless.util.Passphrase
import java.io.InputStream
import java.security.KeyPair
import java.util.*

class JceImplementationFactory : ImplementationFactory() {
    override val pgpDigestCalculatorProvider: PGPDigestCalculatorProvider =
            JcaPGPDigestCalculatorProviderBuilder()
                    .setProvider(ProviderFactory.provider)
                    .build()
    override val pgpContentVerifierBuilderProvider: PGPContentVerifierBuilderProvider =
            JcaPGPContentVerifierBuilderProvider()
                    .setProvider(ProviderFactory.provider)
    override val keyFingerprintCalculator: KeyFingerPrintCalculator =
            JcaKeyFingerprintCalculator()
                    .setProvider(ProviderFactory.provider)

    override fun getPBESecretKeyEncryptor(symmetricKeyAlgorithm: SymmetricKeyAlgorithm,
                                          digestCalculator: PGPDigestCalculator,
                                          passphrase: Passphrase): PBESecretKeyEncryptor =
            JcePBESecretKeyEncryptorBuilder(symmetricKeyAlgorithm.algorithmId, digestCalculator)
                    .setProvider(ProviderFactory.provider)
                    .build(passphrase.getChars())

    override fun getPBESecretKeyEncryptor(encryptionAlgorithm: SymmetricKeyAlgorithm,
                                          hashAlgorithm: HashAlgorithm,
                                          s2kCount: Int,
                                          passphrase: Passphrase): PBESecretKeyEncryptor =
            JcePBESecretKeyEncryptorBuilder(
                    encryptionAlgorithm.algorithmId,
                    getPGPDigestCalculator(hashAlgorithm),
                    s2kCount)
                    .setProvider(ProviderFactory.provider)
                    .build(passphrase.getChars())

    override fun getPBESecretKeyDecryptor(passphrase: Passphrase): PBESecretKeyDecryptor =
            JcePBESecretKeyDecryptorBuilder(pgpDigestCalculatorProvider)
                    .setProvider(ProviderFactory.provider)
                    .build(passphrase.getChars())

    override fun getPGPContentSignerBuilder(keyAlgorithm: Int, hashAlgorithm: Int): PGPContentSignerBuilder =
            JcaPGPContentSignerBuilder(keyAlgorithm, hashAlgorithm)
                    .setProvider(ProviderFactory.provider)

    override fun getPBEDataDecryptorFactory(passphrase: Passphrase): PBEDataDecryptorFactory =
            JcePBEDataDecryptorFactoryBuilder(pgpDigestCalculatorProvider)
                    .setProvider(ProviderFactory.provider)
                    .build(passphrase.getChars())

    override fun getPublicKeyDataDecryptorFactory(privateKey: PGPPrivateKey): PublicKeyDataDecryptorFactory =
            JcePublicKeyDataDecryptorFactoryBuilder()
                    .setProvider(ProviderFactory.provider)
                    .build(privateKey)

    override fun getSessionKeyDataDecryptorFactory(sessionKey: PGPSessionKey): SessionKeyDataDecryptorFactory =
            JceSessionKeyDataDecryptorFactoryBuilder()
                    .setProvider(ProviderFactory.provider)
                    .build(sessionKey)

    override fun getPublicKeyKeyEncryptionMethodGenerator(key: PGPPublicKey): PublicKeyKeyEncryptionMethodGenerator =
            JcePublicKeyKeyEncryptionMethodGenerator(key)
                    .setProvider(ProviderFactory.provider)

    override fun getPBEKeyEncryptionMethodGenerator(passphrase: Passphrase): PBEKeyEncryptionMethodGenerator =
            JcePBEKeyEncryptionMethodGenerator(passphrase.getChars())
                    .setProvider(ProviderFactory.provider)

    override fun getPGPDataEncryptorBuilder(symmetricKeyAlgorithm: Int): PGPDataEncryptorBuilder =
            JcePGPDataEncryptorBuilder(symmetricKeyAlgorithm)
                    .setProvider(ProviderFactory.provider)

    override fun getPGPKeyPair(publicKeyAlgorithm: PublicKeyAlgorithm, keyPair: KeyPair, creationDate: Date): PGPKeyPair =
            JcaPGPKeyPair(publicKeyAlgorithm.algorithmId, keyPair, creationDate)

    override fun getPGPObjectFactory(inputStream: InputStream): PGPObjectFactory =
            PGPObjectFactory(inputStream, keyFingerprintCalculator)
}