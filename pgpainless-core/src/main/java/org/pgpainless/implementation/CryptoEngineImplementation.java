package org.pgpainless.implementation;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
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
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.util.Passphrase;

public interface CryptoEngineImplementation {

    PBESecretKeyEncryptor getPBESecretKeyEncryptor(PGPSecretKey secretKey, Passphrase passphrase) throws PGPException;

    default PBESecretKeyEncryptor getPBESecretKeyEncryptor(SymmetricKeyAlgorithm symmetricKeyAlgorithm,
                                                           Passphrase passphrase)
            throws PGPException {
        return getPBESecretKeyEncryptor(symmetricKeyAlgorithm,
                getPGPDigestCalculator(HashAlgorithm.SHA1), passphrase);
    }

    PBESecretKeyEncryptor getPBESecretKeyEncryptor(SymmetricKeyAlgorithm symmetricKeyAlgorithm,
                                                   PGPDigestCalculator digestCalculator,
                                                   Passphrase passphrase);

    PBESecretKeyDecryptor getPBESecretKeyDecryptor(Passphrase passphrase) throws PGPException;

    PGPDigestCalculatorProvider getPGPDigestCalculatorProvider() throws PGPException;

    default PGPDigestCalculator getPGPDigestCalculator(HashAlgorithm algorithm) throws PGPException {
        return getPGPDigestCalculator(algorithm.getAlgorithmId());
    }

    default PGPDigestCalculator getPGPDigestCalculator(int algorithm) throws PGPException {
        return getPGPDigestCalculatorProvider().get(algorithm);
    }

    PGPContentVerifierBuilderProvider getPGPContentVerifierBuilderProvider();

    default PGPContentSignerBuilder getPGPContentSignerBuilder(PublicKeyAlgorithm keyAlgorithm, HashAlgorithm hashAlgorithm) {
        return getPGPContentSignerBuilder(keyAlgorithm.getAlgorithmId(), hashAlgorithm.getAlgorithmId());
    }

    PGPContentSignerBuilder getPGPContentSignerBuilder(int keyAlgorithm, int hashAlgorithm);

    KeyFingerPrintCalculator getKeyFingerprintCalculator();

    PBEDataDecryptorFactory getPBEDataDecryptorFactory(Passphrase passphrase) throws PGPException;

    PublicKeyDataDecryptorFactory getPublicKeyDataDecryptorFactory(PGPPrivateKey privateKey);

    PublicKeyKeyEncryptionMethodGenerator getPublicKeyKeyEncryptionMethodGenerator(PGPPublicKey key);

    PBEKeyEncryptionMethodGenerator getPBEKeyEncryptionMethodGenerator(Passphrase passphrase);

    default PGPDataEncryptorBuilder getPGPDataEncryptorBuilder(SymmetricKeyAlgorithm symmetricKeyAlgorithm) {
        return getPGPDataEncryptorBuilder(symmetricKeyAlgorithm.getAlgorithmId());
    }

    PGPDataEncryptorBuilder getPGPDataEncryptorBuilder(int symmetricKeyAlgorithm);

    PGPKeyPair getPGPKeyPair(PublicKeyAlgorithm algorithm, KeyPair keyPair, Date creationDate) throws PGPException;

    PGPKeyPair getPGPKeyPair(PublicKeyAlgorithm algorithm, AsymmetricCipherKeyPair keyPair, Date creationDate) throws PGPException, NoSuchAlgorithmException, IOException, InvalidKeySpecException;

    PBESecretKeyEncryptor getPBESecretKeyEncryptor(SymmetricKeyAlgorithm encryptionAlgorithm,
                                                   HashAlgorithm hashAlgorithm,
                                                   int s2kCount,
                                                   Passphrase passphrase) throws PGPException;
}
