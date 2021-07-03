/*
 * Copyright 2018 Paul Schaub.
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
package org.pgpainless.key;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.provider.ProviderFactory;

public class BouncycastleExportSubkeys {

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestImplementationFactoryProvider#provideImplementationFactories")
    public void testExportImport(ImplementationFactory implementationFactory) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, PGPException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);
        KeyPairGenerator generator;
        KeyPair pair;

        // Generate master key

        generator = KeyPairGenerator.getInstance("ECDSA", ProviderFactory.getProvider());
        generator.initialize(new ECNamedCurveGenParameterSpec("P-256"));

        pair = generator.generateKeyPair();
        PGPKeyPair pgpMasterKey = new JcaPGPKeyPair(PublicKeyAlgorithmTags.ECDSA, pair, new Date());

        PGPSignatureSubpacketGenerator subPackets = new PGPSignatureSubpacketGenerator();
        subPackets.setKeyFlags(false, KeyFlags.AUTHENTICATION & KeyFlags.CERTIFY_OTHER & KeyFlags.SIGN_DATA);
        subPackets.setPreferredCompressionAlgorithms(false, new int[] {
                SymmetricKeyAlgorithmTags.AES_256,
                SymmetricKeyAlgorithmTags.AES_128,
                SymmetricKeyAlgorithmTags.AES_128});
        subPackets.setPreferredHashAlgorithms(false, new int[] {
                HashAlgorithmTags.SHA512,
                HashAlgorithmTags.SHA384,
                HashAlgorithmTags.SHA256,
                HashAlgorithmTags.SHA224});
        subPackets.setPreferredCompressionAlgorithms(false, new int[] {
                CompressionAlgorithmTags.ZLIB,
                CompressionAlgorithmTags.BZIP2,
                CompressionAlgorithmTags.ZIP,
                CompressionAlgorithmTags.UNCOMPRESSED});
        subPackets.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);

        // Generate sub key

        generator = KeyPairGenerator.getInstance("ECDH", ProviderFactory.getProvider());
        generator.initialize(new ECNamedCurveGenParameterSpec("P-256"));

        pair = generator.generateKeyPair();
        PGPKeyPair pgpSubKey = new JcaPGPKeyPair(PublicKeyAlgorithmTags.ECDH, pair, new Date());

        // Assemble key

        PGPDigestCalculator calculator = new JcaPGPDigestCalculatorProviderBuilder()
                .setProvider(ProviderFactory.getProvider())
                .build()
                .get(HashAlgorithmTags.SHA1);

        PGPContentSignerBuilder signerBuilder = new JcaPGPContentSignerBuilder(
                pgpMasterKey.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA512)
                .setProvider(ProviderFactory.getProvider());

        PGPKeyRingGenerator pgpGenerator = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION,
                pgpMasterKey, "alice@wonderland.lit", calculator, subPackets.generate(), null,
                signerBuilder, null);

        // Add sub key

        subPackets.setKeyFlags(false, KeyFlags.ENCRYPT_STORAGE & KeyFlags.ENCRYPT_COMMS);

        pgpGenerator.addSubKey(pgpSubKey, subPackets.generate(), null);

        // Generate SecretKeyRing

        PGPSecretKeyRing secretKeys = pgpGenerator.generateSecretKeyRing();
        PGPPublicKeyRing publicKeys = pgpGenerator.generatePublicKeyRing();

        // Test

        /*
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream(2048);
        outputStream.write(secretKeys.getEncoded());

        PGPPublicKeyRing publicKeys = new PGPPublicKeyRing(outputStream.toByteArray(), new BcKeyFingerprintCalculator());

        Iterator<PGPPublicKey> iterator = secretKeys.getPublicKeys();
        while (iterator.hasNext()) {
            assertNotNull(publicKeys.getPublicKey(iterator.next().getKeyID()));
        }
        */
    }
}
