// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.implementation

import java.io.InputStream
import java.security.KeyPair
import java.util.*
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory
import org.bouncycastle.openpgp.operator.*
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPBEDataDecryptorFactory
import org.bouncycastle.openpgp.operator.bc.BcPBEKeyEncryptionMethodGenerator
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyConverter
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator
import org.bouncycastle.openpgp.operator.bc.BcSessionKeyDataDecryptorFactory
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.PublicKeyAlgorithm
import org.pgpainless.algorithm.SymmetricKeyAlgorithm
import org.pgpainless.util.Passphrase

class BcImplementationFactory : ImplementationFactory() {
    override val pgpDigestCalculatorProvider: BcPGPDigestCalculatorProvider =
        BcPGPDigestCalculatorProvider()
    override val pgpContentVerifierBuilderProvider: BcPGPContentVerifierBuilderProvider =
        BcPGPContentVerifierBuilderProvider()
    override val keyFingerprintCalculator: BcKeyFingerprintCalculator = BcKeyFingerprintCalculator()

    override fun getPBESecretKeyEncryptor(
        symmetricKeyAlgorithm: SymmetricKeyAlgorithm,
        digestCalculator: PGPDigestCalculator,
        passphrase: Passphrase
    ): PBESecretKeyEncryptor =
        BcPBESecretKeyEncryptorBuilder(symmetricKeyAlgorithm.algorithmId, digestCalculator)
            .build(passphrase.getChars())

    override fun getPBESecretKeyEncryptor(
        encryptionAlgorithm: SymmetricKeyAlgorithm,
        hashAlgorithm: HashAlgorithm,
        s2kCount: Int,
        passphrase: Passphrase
    ): PBESecretKeyEncryptor =
        BcPBESecretKeyEncryptorBuilder(
                encryptionAlgorithm.algorithmId, getPGPDigestCalculator(hashAlgorithm), s2kCount)
            .build(passphrase.getChars())

    override fun getPBESecretKeyDecryptor(passphrase: Passphrase): PBESecretKeyDecryptor =
        BcPBESecretKeyDecryptorBuilder(pgpDigestCalculatorProvider).build(passphrase.getChars())

    override fun getPGPContentSignerBuilder(
        keyAlgorithm: Int,
        hashAlgorithm: Int
    ): PGPContentSignerBuilder = BcPGPContentSignerBuilder(keyAlgorithm, hashAlgorithm)

    override fun getPBEDataDecryptorFactory(passphrase: Passphrase): PBEDataDecryptorFactory =
        BcPBEDataDecryptorFactory(passphrase.getChars(), pgpDigestCalculatorProvider)

    override fun getPublicKeyDataDecryptorFactory(
        privateKey: PGPPrivateKey
    ): PublicKeyDataDecryptorFactory = BcPublicKeyDataDecryptorFactory(privateKey)

    override fun getSessionKeyDataDecryptorFactory(
        sessionKey: PGPSessionKey
    ): SessionKeyDataDecryptorFactory = BcSessionKeyDataDecryptorFactory(sessionKey)

    override fun getPublicKeyKeyEncryptionMethodGenerator(
        key: PGPPublicKey
    ): PublicKeyKeyEncryptionMethodGenerator = BcPublicKeyKeyEncryptionMethodGenerator(key)

    override fun getPBEKeyEncryptionMethodGenerator(
        passphrase: Passphrase
    ): PBEKeyEncryptionMethodGenerator = BcPBEKeyEncryptionMethodGenerator(passphrase.getChars())

    override fun getPGPDataEncryptorBuilder(symmetricKeyAlgorithm: Int): PGPDataEncryptorBuilder =
        BcPGPDataEncryptorBuilder(symmetricKeyAlgorithm)

    override fun getPGPKeyPair(
        publicKeyAlgorithm: PublicKeyAlgorithm,
        keyPair: KeyPair,
        creationDate: Date
    ): PGPKeyPair =
        BcPGPKeyPair(
            publicKeyAlgorithm.algorithmId,
            jceToBcKeyPair(publicKeyAlgorithm, keyPair, creationDate),
            creationDate)

    override fun getPGPObjectFactory(inputStream: InputStream): PGPObjectFactory =
        BcPGPObjectFactory(inputStream)

    private fun jceToBcKeyPair(
        publicKeyAlgorithm: PublicKeyAlgorithm,
        keyPair: KeyPair,
        creationDate: Date
    ): AsymmetricCipherKeyPair =
        BcPGPKeyConverter().let { converter ->
            JcaPGPKeyPair(publicKeyAlgorithm.algorithmId, keyPair, creationDate).let { pair ->
                AsymmetricCipherKeyPair(
                    converter.getPublicKey(pair.publicKey),
                    converter.getPrivateKey(pair.privateKey))
            }
        }
}
