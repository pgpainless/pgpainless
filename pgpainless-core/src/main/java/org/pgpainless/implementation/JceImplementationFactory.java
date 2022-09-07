// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.implementation;

import java.io.InputStream;
import java.security.KeyPair;
import java.util.Date;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.SessionKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JceSessionKeyDataDecryptorFactoryBuilder;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.provider.ProviderFactory;
import org.pgpainless.s2k.Passphrase;

public class JceImplementationFactory extends ImplementationFactory {

    public PBESecretKeyEncryptor getPBESecretKeyEncryptor(PGPSecretKey secretKey, Passphrase passphrase) {
        return new JcePBESecretKeyEncryptorBuilder(secretKey.getKeyEncryptionAlgorithm())
                .setProvider(ProviderFactory.getProvider())
                .build(passphrase.getChars());
    }

    public PBESecretKeyEncryptor getPBESecretKeyEncryptor(SymmetricKeyAlgorithm symmetricKeyAlgorithm, PGPDigestCalculator digestCalculator, Passphrase passphrase) {
        return new JcePBESecretKeyEncryptorBuilder(symmetricKeyAlgorithm.getAlgorithmId(), digestCalculator)
                .setProvider(ProviderFactory.getProvider())
                .build(passphrase.getChars());
    }

    public PBESecretKeyDecryptor getPBESecretKeyDecryptor(Passphrase passphrase) throws PGPException {
        return new JcePBESecretKeyDecryptorBuilder(getPGPDigestCalculatorProvider())
                .setProvider(ProviderFactory.getProvider())
                .build(passphrase.getChars());
    }

    public PGPDigestCalculatorProvider getPGPDigestCalculatorProvider()
            throws PGPException {
        return new JcaPGPDigestCalculatorProviderBuilder()
                .setProvider(ProviderFactory.getProvider())
                .build();
    }

    public PGPContentVerifierBuilderProvider getPGPContentVerifierBuilderProvider() {
        return new JcaPGPContentVerifierBuilderProvider()
                .setProvider(ProviderFactory.getProvider());
    }

    public PGPContentSignerBuilder getPGPContentSignerBuilder(int keyAlgorithm, int hashAlgorithm) {
        return new JcaPGPContentSignerBuilder(keyAlgorithm, hashAlgorithm)
                .setProvider(ProviderFactory.getProvider());
    }

    public KeyFingerPrintCalculator getKeyFingerprintCalculator() {
        return new JcaKeyFingerprintCalculator()
                .setProvider(ProviderFactory.getProvider());
    }

    public PBEDataDecryptorFactory getPBEDataDecryptorFactory(Passphrase passphrase)
            throws PGPException {
        return new JcePBEDataDecryptorFactoryBuilder(getPGPDigestCalculatorProvider())
                .setProvider(ProviderFactory.getProvider())
                .build(passphrase.getChars());
    }

    public PublicKeyDataDecryptorFactory getPublicKeyDataDecryptorFactory(PGPPrivateKey privateKey) {
        return new JcePublicKeyDataDecryptorFactoryBuilder()
                .setProvider(ProviderFactory.getProvider())
                .build(privateKey);
    }

    public PublicKeyKeyEncryptionMethodGenerator getPublicKeyKeyEncryptionMethodGenerator(PGPPublicKey key) {
        return new JcePublicKeyKeyEncryptionMethodGenerator(key)
                .setProvider(ProviderFactory.getProvider());
    }

    public PBEKeyEncryptionMethodGenerator getPBEKeyEncryptionMethodGenerator(Passphrase passphrase) {
        return new JcePBEKeyEncryptionMethodGenerator(passphrase.getChars())
                .setProvider(ProviderFactory.getProvider());
    }

    public PGPDataEncryptorBuilder getPGPDataEncryptorBuilder(int symmetricKeyAlgorithm) {
        return new JcePGPDataEncryptorBuilder(symmetricKeyAlgorithm)
                .setProvider(ProviderFactory.getProvider());
    }

    public PGPKeyPair getPGPKeyPair(PublicKeyAlgorithm algorithm, KeyPair keyPair, Date creationDate) throws PGPException {
        return new JcaPGPKeyPair(algorithm.getAlgorithmId(), keyPair, creationDate);
    }

    public PBESecretKeyEncryptor getPBESecretKeyEncryptor(SymmetricKeyAlgorithm encryptionAlgorithm, HashAlgorithm hashAlgorithm, int s2kCount, Passphrase passphrase) throws PGPException {
        return new JcePBESecretKeyEncryptorBuilder(
                encryptionAlgorithm.getAlgorithmId(),
                getPGPDigestCalculator(hashAlgorithm),
                s2kCount)
                .setProvider(ProviderFactory.getProvider())
                .build(passphrase.getChars());
    }

    @Override
    public SessionKeyDataDecryptorFactory provideSessionKeyDataDecryptorFactory(PGPSessionKey sessionKey) {
        return new JceSessionKeyDataDecryptorFactoryBuilder().build(sessionKey);
    }

    @Override
    public PGPObjectFactory getPGPObjectFactory(InputStream inputStream) {
        return new JcaPGPObjectFactory(inputStream);
    }

    @Override
    public PGPObjectFactory getPGPObjectFactory(byte[] bytes) {
        return new JcaPGPObjectFactory(bytes);
    }
}
