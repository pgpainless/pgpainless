package org.pgpainless.implementation;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
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
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.provider.ProviderFactory;
import org.pgpainless.util.Passphrase;

public class JceCryptoEngineImplementation implements CryptoEngineImplementation {

    @Override
    public PBESecretKeyEncryptor getPBESecretKeyEncryptor(PGPSecretKey secretKey, Passphrase passphrase)
            throws PGPException {
        return new JcePBESecretKeyEncryptorBuilder(secretKey.getKeyEncryptionAlgorithm())
                .setProvider(ProviderFactory.getProvider())
                .build(passphrase.getChars());
    }

    @Override
    public PBESecretKeyEncryptor getPBESecretKeyEncryptor(SymmetricKeyAlgorithm symmetricKeyAlgorithm, PGPDigestCalculator digestCalculator, Passphrase passphrase) {
        return new JcePBESecretKeyEncryptorBuilder(symmetricKeyAlgorithm.getAlgorithmId(), digestCalculator)
                .setProvider(ProviderFactory.getProvider())
                .build(passphrase.getChars());
    }

    @Override
    public PBESecretKeyDecryptor getPBESecretKeyDecryptor(Passphrase passphrase) throws PGPException {
        return new JcePBESecretKeyDecryptorBuilder(getPGPDigestCalculatorProvider())
                .setProvider(ProviderFactory.getProvider())
                .build(passphrase.getChars());
    }

    @Override
    public PGPDigestCalculatorProvider getPGPDigestCalculatorProvider()
            throws PGPException {
        return new JcaPGPDigestCalculatorProviderBuilder()
                .setProvider(ProviderFactory.getProvider())
                .build();
    }

    @Override
    public PGPContentVerifierBuilderProvider getPGPContentVerifierBuilderProvider() {
        return new JcaPGPContentVerifierBuilderProvider()
                .setProvider(ProviderFactory.getProvider());
    }

    @Override
    public PGPContentSignerBuilder getPGPContentSignerBuilder(int keyAlgorithm, int hashAlgorithm) {
        return new JcaPGPContentSignerBuilder(keyAlgorithm, hashAlgorithm)
                .setProvider(ProviderFactory.getProvider());
    }

    @Override
    public KeyFingerPrintCalculator getKeyFingerprintCalculator() {
        return new JcaKeyFingerprintCalculator()
                .setProvider(ProviderFactory.getProvider());
    }

    @Override
    public PBEDataDecryptorFactory getPBEDataDecryptorFactory(Passphrase passphrase)
            throws PGPException {
        return new JcePBEDataDecryptorFactoryBuilder(getPGPDigestCalculatorProvider())
                .setProvider(ProviderFactory.getProvider())
                .build(passphrase.getChars());
    }

    @Override
    public PublicKeyDataDecryptorFactory getPublicKeyDataDecryptorFactory(PGPPrivateKey privateKey) {
        return new JcePublicKeyDataDecryptorFactoryBuilder()
                .setProvider(ProviderFactory.getProvider())
                .build(privateKey);
    }

    @Override
    public PublicKeyKeyEncryptionMethodGenerator getPublicKeyKeyEncryptionMethodGenerator(PGPPublicKey key) {
        return new JcePublicKeyKeyEncryptionMethodGenerator(key)
                .setProvider(ProviderFactory.getProvider());
    }

    @Override
    public PBEKeyEncryptionMethodGenerator getPBEKeyEncryptionMethodGenerator(Passphrase passphrase) {
        return new JcePBEKeyEncryptionMethodGenerator(passphrase.getChars())
                .setProvider(ProviderFactory.getProvider());
    }

    @Override
    public PGPDataEncryptorBuilder getPGPDataEncryptorBuilder(int symmetricKeyAlgorithm) {
        return new JcePGPDataEncryptorBuilder(symmetricKeyAlgorithm)
                .setProvider(ProviderFactory.getProvider());
    }

    @Override
    public PGPKeyPair getPGPKeyPair(PublicKeyAlgorithm algorithm, KeyPair keyPair, Date creationDate) throws PGPException {
        return new JcaPGPKeyPair(algorithm.getAlgorithmId(), keyPair, creationDate);
    }

    @Override
    public PGPKeyPair getPGPKeyPair(PublicKeyAlgorithm algorithm, AsymmetricCipherKeyPair keyPair, Date creationDate) throws PGPException, NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        return new JcaPGPKeyPair(algorithm.getAlgorithmId(), bcToJceKeyPair(keyPair), creationDate);
    }

    @Override
    public PBESecretKeyEncryptor getPBESecretKeyEncryptor(SymmetricKeyAlgorithm encryptionAlgorithm, HashAlgorithm hashAlgorithm, int s2kCount, Passphrase passphrase) throws PGPException {
        return new JcePBESecretKeyEncryptorBuilder(
                encryptionAlgorithm.getAlgorithmId(),
                getPGPDigestCalculator(hashAlgorithm),
                s2kCount)
                .setProvider(ProviderFactory.getProvider())
                .build(passphrase.getChars());
    }

    private KeyPair bcToJceKeyPair(AsymmetricCipherKeyPair keyPair)
            throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        byte[] pkcs8Encoded = PrivateKeyInfoFactory.createPrivateKeyInfo(keyPair.getPrivate()).getEncoded();
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(pkcs8Encoded);
        byte[] spkiEncoded = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(keyPair.getPublic()).getEncoded();
        X509EncodedKeySpec spkiKeySpec = new X509EncodedKeySpec(spkiEncoded);
        KeyFactory keyFac = KeyFactory.getInstance("RSA");
        return new KeyPair(keyFac.generatePublic(spkiKeySpec), keyFac.generatePrivate(pkcs8KeySpec));
    }
}
