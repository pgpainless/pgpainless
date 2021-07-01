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

import java.security.KeyPair;
import java.util.Date;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
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
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyConverter;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.util.Passphrase;

public class BcImplementationFactory extends ImplementationFactory {

    @Override
    public PBESecretKeyEncryptor getPBESecretKeyEncryptor(PGPSecretKey secretKey, Passphrase passphrase)
            throws PGPException {
        int keyEncryptionAlgorithm = secretKey.getKeyEncryptionAlgorithm();

        if (secretKey.getS2K() == null) {
            return getPBESecretKeyEncryptor(SymmetricKeyAlgorithm.fromId(keyEncryptionAlgorithm), passphrase);
        }

        int hashAlgorithm = secretKey.getS2K().getHashAlgorithm();
        PGPDigestCalculator digestCalculator = getPGPDigestCalculator(hashAlgorithm);
        long iterationCount = secretKey.getS2K().getIterationCount();

        return new BcPBESecretKeyEncryptorBuilder(keyEncryptionAlgorithm, digestCalculator, (int) iterationCount)
                .build(passphrase.getChars());
    }

    @Override
    public PBESecretKeyEncryptor getPBESecretKeyEncryptor(SymmetricKeyAlgorithm symmetricKeyAlgorithm,
                                                          PGPDigestCalculator digestCalculator,
                                                          Passphrase passphrase) {
        return new BcPBESecretKeyEncryptorBuilder(symmetricKeyAlgorithm.getAlgorithmId(), digestCalculator)
                .build(passphrase.getChars());
    }

    @Override
    public PBESecretKeyDecryptor getPBESecretKeyDecryptor(Passphrase passphrase) {
        return new BcPBESecretKeyDecryptorBuilder(getPGPDigestCalculatorProvider())
                .build(passphrase.getChars());
    }

    @Override
    public BcPGPDigestCalculatorProvider getPGPDigestCalculatorProvider() {
        return new BcPGPDigestCalculatorProvider();
    }

    @Override
    public PGPContentVerifierBuilderProvider getPGPContentVerifierBuilderProvider() {
        return new BcPGPContentVerifierBuilderProvider();
    }

    @Override
    public PGPContentSignerBuilder getPGPContentSignerBuilder(int keyAlgorithm, int hashAlgorithm) {
        return new BcPGPContentSignerBuilder(keyAlgorithm, hashAlgorithm);
    }

    @Override
    public KeyFingerPrintCalculator getKeyFingerprintCalculator() {
        return new BcKeyFingerprintCalculator();
    }

    @Override
    public PBEDataDecryptorFactory getPBEDataDecryptorFactory(Passphrase passphrase) {
        return new BcPBEDataDecryptorFactory(passphrase.getChars(), getPGPDigestCalculatorProvider());
    }

    @Override
    public PublicKeyDataDecryptorFactory getPublicKeyDataDecryptorFactory(PGPPrivateKey privateKey) {
        return new BcPublicKeyDataDecryptorFactory(privateKey);
    }

    @Override
    public PublicKeyKeyEncryptionMethodGenerator getPublicKeyKeyEncryptionMethodGenerator(PGPPublicKey key) {
        return new BcPublicKeyKeyEncryptionMethodGenerator(key);
    }

    @Override
    public PBEKeyEncryptionMethodGenerator getPBEKeyEncryptionMethodGenerator(Passphrase passphrase) {
        return new BcPBEKeyEncryptionMethodGenerator(passphrase.getChars());
    }

    @Override
    public PGPDataEncryptorBuilder getPGPDataEncryptorBuilder(int symmetricKeyAlgorithm) {
        return new BcPGPDataEncryptorBuilder(symmetricKeyAlgorithm);
    }

    @Override
    public PGPKeyPair getPGPKeyPair(PublicKeyAlgorithm algorithm, KeyPair keyPair, Date creationDate)
            throws PGPException {
        return new BcPGPKeyPair(algorithm.getAlgorithmId(), jceToBcKeyPair(algorithm, keyPair, creationDate), creationDate);
    }

    @Override
    public PBESecretKeyEncryptor getPBESecretKeyEncryptor(SymmetricKeyAlgorithm encryptionAlgorithm, HashAlgorithm hashAlgorithm, int s2kCount, Passphrase passphrase) throws PGPException {
        return new BcPBESecretKeyEncryptorBuilder(
                encryptionAlgorithm.getAlgorithmId(),
                getPGPDigestCalculator(hashAlgorithm),
                s2kCount)
                .build(passphrase.getChars());
    }

    private AsymmetricCipherKeyPair jceToBcKeyPair(PublicKeyAlgorithm algorithm,
                                                   KeyPair keyPair,
                                                   Date creationDate) throws PGPException {
        BcPGPKeyConverter converter = new BcPGPKeyConverter();

        PGPKeyPair pair = new JcaPGPKeyPair(algorithm.getAlgorithmId(), keyPair, creationDate);
        AsymmetricKeyParameter publicKey = converter.getPublicKey(pair.getPublicKey());
        AsymmetricKeyParameter privateKey = converter.getPrivateKey(pair.getPrivateKey());

        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }
}
