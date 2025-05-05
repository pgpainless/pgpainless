// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.MessageEncryptionMechanism;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.AEADAlgorithm;
import org.pgpainless.algorithm.AEADCipherMode;
import org.pgpainless.algorithm.AlgorithmSuite;
import org.pgpainless.algorithm.Feature;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.OpenPGPKeyVersion;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.MessageMetadata;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa_legacy.EdDSALegacyCurve;
import org.pgpainless.key.generation.type.xdh_legacy.XDHLegacySpec;
import org.pgpainless.util.TestAllImplementations;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class MechanismNegotiationTest {

    private static final String testMessage =
            "Ah, Juliet, if the measure of thy joy\n" +
                    "Be heaped like mine, and that thy skill be more\n" +
                    "To blazon it, then sweeten with thy breath\n" +
                    "This neighbor air, and let rich music’s tongue\n" +
                    "Unfold the imagined happiness that both\n" +
                    "Receive in either by this dear encounter.";

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testEncryptToOnlyV4CertWithOnlySEIPD1Feature() throws PGPException, IOException {
        testEncryptDecryptAndCheckExpectations(
                MessageEncryptionMechanism.integrityProtected(SymmetricKeyAlgorithm.AES_192.getAlgorithmId()),
                new KeySpecification(OpenPGPKeyVersion.v4, AlgorithmSuite.emptyBuilder()
                        .overrideSymmetricKeyAlgorithms(SymmetricKeyAlgorithm.AES_192)
                        .overrideFeatures(Feature.MODIFICATION_DETECTION)
                        .build()));
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testEncryptToOnlyV4CertWithOnlySEIPD2Feature() throws PGPException, IOException {
        testEncryptDecryptAndCheckExpectations(
                MessageEncryptionMechanism.aead(SymmetricKeyAlgorithm.AES_256.getAlgorithmId(), AEADAlgorithm.OCB.getAlgorithmId()),
                new KeySpecification(OpenPGPKeyVersion.v4, AlgorithmSuite.emptyBuilder()
                        .overrideAeadAlgorithms(new AEADCipherMode(AEADAlgorithm.OCB, SymmetricKeyAlgorithm.AES_256))
                        .overrideFeatures(Feature.MODIFICATION_DETECTION_2)
                        .build()));
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testEncryptToOnlyV6CertWithOnlySEIPD2Features() throws IOException, PGPException {
        testEncryptDecryptAndCheckExpectations(
                MessageEncryptionMechanism.aead(SymmetricKeyAlgorithm.AES_256.getAlgorithmId(), AEADAlgorithm.OCB.getAlgorithmId()),
                new KeySpecification(OpenPGPKeyVersion.v6, AlgorithmSuite.emptyBuilder()
                        .overrideAeadAlgorithms(new AEADCipherMode(AEADAlgorithm.OCB, SymmetricKeyAlgorithm.AES_256))
                        .overrideFeatures(Feature.MODIFICATION_DETECTION_2)
                        .build()));
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testEncryptToV6SEIPD1CertAndV6SEIPD2Cert() throws IOException, PGPException {
        testEncryptDecryptAndCheckExpectations(
                MessageEncryptionMechanism.integrityProtected(SymmetricKeyAlgorithm.AES_192.getAlgorithmId()),

                new KeySpecification(OpenPGPKeyVersion.v6, AlgorithmSuite.emptyBuilder()
                        .overrideAeadAlgorithms(new AEADCipherMode(AEADAlgorithm.OCB, SymmetricKeyAlgorithm.AES_256))
                        .overrideFeatures(Feature.MODIFICATION_DETECTION_2)
                        .build()),
                new KeySpecification(OpenPGPKeyVersion.v6, AlgorithmSuite.emptyBuilder()
                        .overrideSymmetricKeyAlgorithms(SymmetricKeyAlgorithm.AES_192)
                        .overrideFeatures(Feature.MODIFICATION_DETECTION)
                        .build()));
    }


    private void testEncryptDecryptAndCheckExpectations(MessageEncryptionMechanism expectation, KeySpecification... keys)
            throws PGPException, IOException {
        PGPainless api = PGPainless.getInstance();
        List<OpenPGPKey> keyList = new ArrayList<>();
        for (KeySpecification spec : keys) {
            if (spec.version == OpenPGPKeyVersion.v4) {
                keyList.add(api.buildKey(spec.version)
                        .withPreferences(spec.preferences)
                        .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519), KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA))
                        .addSubkey(KeySpec.getBuilder(KeyType.XDH_LEGACY(XDHLegacySpec._X25519), KeyFlag.ENCRYPT_STORAGE, KeyFlag.ENCRYPT_COMMS))
                        .build());
            } else {
                keyList.add(api.buildKey(spec.version)
                        .withPreferences(spec.preferences)
                        .setPrimaryKey(KeySpec.getBuilder(KeyType.Ed25519(), KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA))
                        .addSubkey(KeySpec.getBuilder(KeyType.X25519(), KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE))
                        .build());
            }
        }

        EncryptionOptions encOpts = EncryptionOptions.encryptCommunications();
        for (OpenPGPKey k : keyList) {
            encOpts.addRecipient(k.toCertificate());
        }

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        EncryptionStream eOut = api.generateMessage().onOutputStream(bOut)
                .withOptions(ProducerOptions.encrypt(encOpts));
        eOut.write(testMessage.getBytes(StandardCharsets.UTF_8));
        eOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        DecryptionStream dIn = PGPainless.decryptAndOrVerify()
                .onInputStream(bIn)
                .withOptions(ConsumerOptions.get().addDecryptionKey(keyList.get(0)));

        bOut = new ByteArrayOutputStream();
        Streams.pipeAll(dIn, bOut);
        dIn.close();

        assertEquals(testMessage, bOut.toString());
        MessageMetadata metadata = dIn.getMetadata();
        MessageEncryptionMechanism encryptionMechanism = metadata.getEncryptionMechanism();
        assertEquals(expectation, encryptionMechanism);
    }

    private static class KeySpecification {
        private final OpenPGPKeyVersion version;
        private final AlgorithmSuite preferences;

        public KeySpecification(OpenPGPKeyVersion version,
                                AlgorithmSuite preferences) {
            this.version = version;
            this.preferences = preferences;
        }
    }

}
