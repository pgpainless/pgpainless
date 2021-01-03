/*
 * Copyright 2020 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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

public abstract class ImplementationFactory {

    private static ImplementationFactory FACTORY_IMPLEMENTATION = new BcImplementationFactory();

    public static void setFactoryImplementation(ImplementationFactory implementation) {
        FACTORY_IMPLEMENTATION = implementation;
    }

    public static ImplementationFactory getInstance() {
        return FACTORY_IMPLEMENTATION;
    }

    public PBESecretKeyEncryptor getPBESecretKeyEncryptor(SymmetricKeyAlgorithm symmetricKeyAlgorithm,
                                                   Passphrase passphrase)
            throws PGPException {
        return getPBESecretKeyEncryptor(symmetricKeyAlgorithm,
                getPGPDigestCalculator(HashAlgorithm.SHA1), passphrase);
    }

    public PBESecretKeyEncryptor getPBESecretKeyEncryptor(PGPSecretKey secretKey, Passphrase passphrase) throws PGPException {
        return FACTORY_IMPLEMENTATION.getPBESecretKeyEncryptor(secretKey, passphrase);
    }

    public PBESecretKeyEncryptor getPBESecretKeyEncryptor(SymmetricKeyAlgorithm symmetricKeyAlgorithm, PGPDigestCalculator digestCalculator, Passphrase passphrase) {
        return FACTORY_IMPLEMENTATION.getPBESecretKeyEncryptor(symmetricKeyAlgorithm, digestCalculator, passphrase);
    }

    public PBESecretKeyDecryptor getPBESecretKeyDecryptor(Passphrase passphrase) throws PGPException {
        return FACTORY_IMPLEMENTATION.getPBESecretKeyDecryptor(passphrase);
    }

    public PGPDigestCalculator getPGPDigestCalculator(HashAlgorithm algorithm) throws PGPException {
        return getPGPDigestCalculator(algorithm.getAlgorithmId());
    }

    public PGPDigestCalculator getPGPDigestCalculator(int algorithm) throws PGPException {
        return getPGPDigestCalculatorProvider().get(algorithm);
    }

    public PGPDigestCalculatorProvider getPGPDigestCalculatorProvider() throws PGPException {
        return FACTORY_IMPLEMENTATION.getPGPDigestCalculatorProvider();
    }

    public PGPContentVerifierBuilderProvider getPGPContentVerifierBuilderProvider() {
        return FACTORY_IMPLEMENTATION.getPGPContentVerifierBuilderProvider();
    }

    public PGPContentSignerBuilder getPGPContentSignerBuilder(PublicKeyAlgorithm keyAlgorithm, HashAlgorithm hashAlgorithm) {
        return getPGPContentSignerBuilder(keyAlgorithm.getAlgorithmId(), hashAlgorithm.getAlgorithmId());
    }

    public PGPContentSignerBuilder getPGPContentSignerBuilder(int keyAlgorithm, int hashAlgorithm) {
        return FACTORY_IMPLEMENTATION.getPGPContentSignerBuilder(keyAlgorithm, hashAlgorithm);
    }

    public KeyFingerPrintCalculator getKeyFingerprintCalculator() {
        return FACTORY_IMPLEMENTATION.getKeyFingerprintCalculator();
    }

    public PBEDataDecryptorFactory getPBEDataDecryptorFactory(Passphrase passphrase) throws PGPException {
        return FACTORY_IMPLEMENTATION.getPBEDataDecryptorFactory(passphrase);
    }

    public PublicKeyDataDecryptorFactory getPublicKeyDataDecryptorFactory(PGPPrivateKey privateKey) {
        return FACTORY_IMPLEMENTATION.getPublicKeyDataDecryptorFactory(privateKey);
    }

    public PublicKeyKeyEncryptionMethodGenerator getPublicKeyKeyEncryptionMethodGenerator(PGPPublicKey key) {
        return FACTORY_IMPLEMENTATION.getPublicKeyKeyEncryptionMethodGenerator(key);
    }

    public PBEKeyEncryptionMethodGenerator getPBEKeyEncryptionMethodGenerator(Passphrase passphrase) {
        return FACTORY_IMPLEMENTATION.getPBEKeyEncryptionMethodGenerator(passphrase);
    }

    public PGPDataEncryptorBuilder getPGPDataEncryptorBuilder(SymmetricKeyAlgorithm symmetricKeyAlgorithm) {
        return getPGPDataEncryptorBuilder(symmetricKeyAlgorithm.getAlgorithmId());
    }

    public PGPDataEncryptorBuilder getPGPDataEncryptorBuilder(int symmetricKeyAlgorithm) {
        return FACTORY_IMPLEMENTATION.getPGPDataEncryptorBuilder(symmetricKeyAlgorithm);
    }

    public PGPKeyPair getPGPKeyPair(PublicKeyAlgorithm algorithm, KeyPair keyPair, Date creationDate) throws PGPException {
        return FACTORY_IMPLEMENTATION.getPGPKeyPair(algorithm, keyPair, creationDate);
    }

    public PGPKeyPair getPGPKeyPair(PublicKeyAlgorithm algorithm, AsymmetricCipherKeyPair keyPair, Date creationDate) throws PGPException, NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        return FACTORY_IMPLEMENTATION.getPGPKeyPair(algorithm, keyPair, creationDate);
    }

    public PBESecretKeyEncryptor getPBESecretKeyEncryptor(SymmetricKeyAlgorithm encryptionAlgorithm, HashAlgorithm hashAlgorithm, int s2kCount, Passphrase passphrase) throws PGPException {
        return FACTORY_IMPLEMENTATION.getPBESecretKeyEncryptor(encryptionAlgorithm, hashAlgorithm, s2kCount, passphrase);
    }
}
