// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.implementation;

import java.security.KeyPair;
import java.util.Date;

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

public abstract class ImplementationFactory {

    private static ImplementationFactory FACTORY_IMPLEMENTATION;

    public static void setFactoryImplementation(ImplementationFactory implementation) {
        FACTORY_IMPLEMENTATION = implementation;
    }

    public static ImplementationFactory getInstance() {
        if (FACTORY_IMPLEMENTATION == null) {
            FACTORY_IMPLEMENTATION = new BcImplementationFactory();
        }
        return FACTORY_IMPLEMENTATION;
    }

    public PBESecretKeyEncryptor getPBESecretKeyEncryptor(SymmetricKeyAlgorithm symmetricKeyAlgorithm,
                                                   Passphrase passphrase)
            throws PGPException {
        return getPBESecretKeyEncryptor(symmetricKeyAlgorithm,
                getPGPDigestCalculator(HashAlgorithm.SHA1), passphrase);
    }

    public abstract PBESecretKeyEncryptor getPBESecretKeyEncryptor(PGPSecretKey secretKey, Passphrase passphrase) throws PGPException;

    public abstract PBESecretKeyEncryptor getPBESecretKeyEncryptor(SymmetricKeyAlgorithm symmetricKeyAlgorithm,
                                                          PGPDigestCalculator digestCalculator,
                                                          Passphrase passphrase);

    public abstract PBESecretKeyDecryptor getPBESecretKeyDecryptor(Passphrase passphrase) throws PGPException;

    public PGPDigestCalculator getPGPDigestCalculator(HashAlgorithm algorithm) throws PGPException {
        return getPGPDigestCalculator(algorithm.getAlgorithmId());
    }

    public PGPDigestCalculator getPGPDigestCalculator(int algorithm) throws PGPException {
        return getPGPDigestCalculatorProvider().get(algorithm);
    }

    public abstract PGPDigestCalculatorProvider getPGPDigestCalculatorProvider() throws PGPException;

    public abstract PGPContentVerifierBuilderProvider getPGPContentVerifierBuilderProvider();

    public PGPContentSignerBuilder getPGPContentSignerBuilder(PublicKeyAlgorithm keyAlgorithm, HashAlgorithm hashAlgorithm) {
        return getPGPContentSignerBuilder(keyAlgorithm.getAlgorithmId(), hashAlgorithm.getAlgorithmId());
    }

    public abstract PGPContentSignerBuilder getPGPContentSignerBuilder(int keyAlgorithm, int hashAlgorithm);

    public abstract KeyFingerPrintCalculator getKeyFingerprintCalculator();

    public abstract PBEDataDecryptorFactory getPBEDataDecryptorFactory(Passphrase passphrase) throws PGPException;

    public abstract PublicKeyDataDecryptorFactory getPublicKeyDataDecryptorFactory(PGPPrivateKey privateKey);

    public abstract PublicKeyKeyEncryptionMethodGenerator getPublicKeyKeyEncryptionMethodGenerator(PGPPublicKey key);

    public abstract PBEKeyEncryptionMethodGenerator getPBEKeyEncryptionMethodGenerator(Passphrase passphrase);

    public PGPDataEncryptorBuilder getPGPDataEncryptorBuilder(SymmetricKeyAlgorithm symmetricKeyAlgorithm) {
        return getPGPDataEncryptorBuilder(symmetricKeyAlgorithm.getAlgorithmId());
    }

    public abstract PGPDataEncryptorBuilder getPGPDataEncryptorBuilder(int symmetricKeyAlgorithm);

    public abstract PGPKeyPair getPGPKeyPair(PublicKeyAlgorithm algorithm, KeyPair keyPair, Date creationDate) throws PGPException;

    public abstract PBESecretKeyEncryptor getPBESecretKeyEncryptor(SymmetricKeyAlgorithm encryptionAlgorithm,
                                                                   HashAlgorithm hashAlgorithm, int s2kCount,
                                                                   Passphrase passphrase) throws PGPException;

    @Override
    public String toString() {
        return getClass().getSimpleName();
    }
}
