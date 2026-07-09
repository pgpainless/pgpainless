// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.MessageEncryptionMechanism;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.AEADAlgorithm;
import org.pgpainless.algorithm.AEADCipherMode;
import org.pgpainless.algorithm.AlgorithmSuite;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.Feature;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.OpenPGPKeyVersion;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionResult;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.exception.UnacceptableAlgorithmException;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.ecc.EllipticCurve;
import org.pgpainless.key.generation.type.rsa.RsaLength;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.DateUtil;
import org.pgpainless.util.Passphrase;

public class PolicyTest {

    private static Policy policy;

    @BeforeAll
    public static void setup() {
        Map<HashAlgorithm, Date> sigHashAlgoMap = new HashMap<>();
        sigHashAlgoMap.put(HashAlgorithm.SHA512, null);
        sigHashAlgoMap.put(HashAlgorithm.SHA384, null);
        sigHashAlgoMap.put(HashAlgorithm.SHA256, null);
        sigHashAlgoMap.put(HashAlgorithm.SHA224, null);
        sigHashAlgoMap.put(HashAlgorithm.SHA1, DateUtil.parseUTCDate("2013-02-01 00:00:00 UTC"));

        Map<HashAlgorithm, Date> revHashAlgoMap = new HashMap<>();
        revHashAlgoMap.put(HashAlgorithm.SHA512, null);
        revHashAlgoMap.put(HashAlgorithm.SHA384, null);
        revHashAlgoMap.put(HashAlgorithm.SHA256, null);
        revHashAlgoMap.put(HashAlgorithm.SHA224, null);
        revHashAlgoMap.put(HashAlgorithm.SHA1, DateUtil.parseUTCDate("2013-02-01 00:00:00 UTC"));
        revHashAlgoMap.put(HashAlgorithm.RIPEMD160, DateUtil.parseUTCDate("2013-02-01 00:00:00 UTC"));

        policy = new Policy().copy()

                .withCompressionAlgorithmPolicy(new Policy.CompressionAlgorithmPolicy(CompressionAlgorithm.UNCOMPRESSED,
                        Arrays.asList(CompressionAlgorithm.ZIP, CompressionAlgorithm.ZLIB, CompressionAlgorithm.UNCOMPRESSED)))

                .withSymmetricKeyEncryptionAlgorithmPolicy(new Policy.SymmetricKeyAlgorithmPolicy(SymmetricKeyAlgorithm.AES_256,
                        Arrays.asList(SymmetricKeyAlgorithm.AES_256, SymmetricKeyAlgorithm.AES_192, SymmetricKeyAlgorithm.AES_128)))

                .withSymmetricKeyDecryptionAlgorithmPolicy(new Policy.SymmetricKeyAlgorithmPolicy(SymmetricKeyAlgorithm.AES_256,
                        Arrays.asList(SymmetricKeyAlgorithm.AES_256, SymmetricKeyAlgorithm.AES_192, SymmetricKeyAlgorithm.AES_128, SymmetricKeyAlgorithm.BLOWFISH)))

                .withCertificationSignatureHashAlgorithmPolicy(new Policy.HashAlgorithmPolicy(HashAlgorithm.SHA512, sigHashAlgoMap))

                .withRevocationSignatureHashAlgorithmPolicy(new Policy.HashAlgorithmPolicy(HashAlgorithm.SHA512,
                        revHashAlgoMap))

                .withPublicKeyAlgorithmPolicy(Policy.PublicKeyAlgorithmPolicy.bsi2021PublicKeyAlgorithmPolicy())

                .build();
    }

    @Test
    public void testAcceptableCompressionAlgorithm() {
        assertTrue(policy.getCompressionAlgorithmPolicy().isAcceptable(CompressionAlgorithm.ZIP));
        assertTrue(policy.getCompressionAlgorithmPolicy().isAcceptable(CompressionAlgorithm.ZIP.getAlgorithmId()));
    }

    @Test
    public void testUnacceptableCompressionAlgorithm() {
        assertFalse(policy.getCompressionAlgorithmPolicy().isAcceptable(CompressionAlgorithm.BZIP2));
        assertFalse(policy.getCompressionAlgorithmPolicy().isAcceptable(CompressionAlgorithm.BZIP2.getAlgorithmId()));
    }

    @Test
    public void testDefaultCompressionAlgorithm() {
        assertEquals(CompressionAlgorithm.UNCOMPRESSED, policy.getCompressionAlgorithmPolicy().defaultCompressionAlgorithm());
    }

    @Test
    public void testAcceptableSymmetricKeyEncryptionAlgorithm() {
        assertTrue(policy.getSymmetricKeyEncryptionAlgorithmPolicy().isAcceptable(SymmetricKeyAlgorithm.AES_256));
        assertTrue(policy.getSymmetricKeyEncryptionAlgorithmPolicy().isAcceptable(SymmetricKeyAlgorithm.AES_256.getAlgorithmId()));
    }

    @Test
    public void testUnAcceptableSymmetricKeyEncryptionAlgorithm() {
        assertFalse(policy.getSymmetricKeyEncryptionAlgorithmPolicy().isAcceptable(SymmetricKeyAlgorithm.BLOWFISH));
        assertFalse(policy.getSymmetricKeyEncryptionAlgorithmPolicy().isAcceptable(SymmetricKeyAlgorithm.BLOWFISH.getAlgorithmId()));
    }

    @Test
    public void testDefaultSymmetricKeyEncryptionAlgorithm() {
        assertEquals(SymmetricKeyAlgorithm.AES_256, policy.getSymmetricKeyEncryptionAlgorithmPolicy().getDefaultSymmetricKeyAlgorithm());
    }

    @Test
    public void testAcceptableSymmetricKeyDecryptionAlgorithm() {
        assertTrue(policy.getSymmetricKeyDecryptionAlgorithmPolicy().isAcceptable(SymmetricKeyAlgorithm.BLOWFISH));
        assertTrue(policy.getSymmetricKeyDecryptionAlgorithmPolicy().isAcceptable(SymmetricKeyAlgorithm.BLOWFISH.getAlgorithmId()));
    }

    @Test
    public void testUnAcceptableSymmetricKeyDecryptionAlgorithm() {
        assertFalse(policy.getSymmetricKeyDecryptionAlgorithmPolicy().isAcceptable(SymmetricKeyAlgorithm.CAMELLIA_128));
        assertFalse(policy.getSymmetricKeyDecryptionAlgorithmPolicy().isAcceptable(SymmetricKeyAlgorithm.CAMELLIA_128.getAlgorithmId()));
    }

    @Test
    public void testAcceptableSignatureHashAlgorithm() {
        assertTrue(policy.getCertificationSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.SHA512));
        assertTrue(policy.getCertificationSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.SHA512.getAlgorithmId()));
        // Usage date before termination date -> acceptable
        assertTrue(policy.getCertificationSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.SHA1, DateUtil.parseUTCDate("2000-01-01 00:00:00 UTC")));
        assertTrue(policy.getCertificationSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.SHA1.getAlgorithmId(), DateUtil.parseUTCDate("2000-01-01 00:00:00 UTC")));
    }

    @Test
    public void testUnacceptableSignatureHashAlgorithm() {
        assertFalse(policy.getCertificationSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.SHA1));
        assertFalse(policy.getCertificationSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.SHA1.getAlgorithmId()));
        assertFalse(policy.getCertificationSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.SHA1, DateUtil.parseUTCDate("2020-01-01 00:00:00 UTC")));
        assertFalse(policy.getCertificationSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.SHA1.getAlgorithmId(), DateUtil.parseUTCDate("2020-01-01 00:00:00 UTC")));
    }

    @Test
    public void testDefaultSignatureHashAlgorithm() {
        assertEquals(HashAlgorithm.SHA512, policy.getCertificationSignatureHashAlgorithmPolicy().defaultHashAlgorithm());
    }

    @Test
    public void testAcceptableRevocationSignatureHashAlgorithm() {
        assertTrue(policy.getRevocationSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.SHA384));
        assertTrue(policy.getRevocationSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.SHA384.getAlgorithmId()));
        assertTrue(policy.getCertificationSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.SHA1, DateUtil.parseUTCDate("2000-01-01 00:00:00 UTC")));
        assertTrue(policy.getCertificationSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.SHA1.getAlgorithmId(), DateUtil.parseUTCDate("2000-01-01 00:00:00 UTC")));
    }

    @Test
    public void testUnacceptableRevocationSignatureHashAlgorithm() {
        assertFalse(policy.getRevocationSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.RIPEMD160));
        assertFalse(policy.getRevocationSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.RIPEMD160.getAlgorithmId()));
        assertFalse(policy.getCertificationSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.SHA1, DateUtil.parseUTCDate("2020-01-01 00:00:00 UTC")));
        assertFalse(policy.getCertificationSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.SHA1.getAlgorithmId(), DateUtil.parseUTCDate("2020-01-01 00:00:00 UTC")));
    }

    @Test
    public void testDefaultRevocationSignatureHashAlgorithm() {
        assertEquals(HashAlgorithm.SHA512, policy.getRevocationSignatureHashAlgorithmPolicy().defaultHashAlgorithm());
    }

    @Test
    public void testAcceptablePublicKeyAlgorithm() {
        assertTrue(policy.getPublicKeyAlgorithmPolicy().isAcceptable(PublicKeyAlgorithm.ECDSA, 256));
        assertTrue(policy.getPublicKeyAlgorithmPolicy().isAcceptable(PublicKeyAlgorithm.ECDSA.getAlgorithmId(), 256));
        assertTrue(policy.getPublicKeyAlgorithmPolicy().isAcceptable(PublicKeyAlgorithm.RSA_GENERAL, 3072));
        assertTrue(policy.getPublicKeyAlgorithmPolicy().isAcceptable(PublicKeyAlgorithm.RSA_GENERAL.getAlgorithmId(), 3072));
    }

    @Test
    public void testUnacceptablePublicKeyAlgorithm() {
        assertFalse(policy.getPublicKeyAlgorithmPolicy().isAcceptable(PublicKeyAlgorithm.RSA_GENERAL, 1024));
        assertFalse(policy.getPublicKeyAlgorithmPolicy().isAcceptable(PublicKeyAlgorithm.RSA_GENERAL.getAlgorithmId(), 1024));
    }

    @Test
    public void testNotationRegistry() {
        assertFalse(policy.getNotationRegistry().isKnownNotation("notation@pgpainless.org"));
        policy.getNotationRegistry().addKnownNotation("notation@pgpainless.org");
        assertTrue(policy.getNotationRegistry().isKnownNotation("notation@pgpainless.org"));
    }

    @Test
    public void testUnknownSymmetricKeyEncryptionAlgorithmIsNotAcceptable() {
        assertFalse(policy.getSymmetricKeyEncryptionAlgorithmPolicy().isAcceptable(-1));
    }

    @Test
    public void testUnknownSymmetricKeyDecryptionAlgorithmIsNotAcceptable() {
        assertFalse(policy.getSymmetricKeyDecryptionAlgorithmPolicy().isAcceptable(-1));
    }

    @Test
    public void testUnknownSignatureHashAlgorithmIsNotAcceptable() {
        assertFalse(policy.getCertificationSignatureHashAlgorithmPolicy().isAcceptable(-1));
        assertFalse(policy.getCertificationSignatureHashAlgorithmPolicy().isAcceptable(-1, new Date()));
    }

    @Test
    public void testUnknownRevocationHashAlgorithmIsNotAcceptable() {
        assertFalse(policy.getRevocationSignatureHashAlgorithmPolicy().isAcceptable(-1));
        assertFalse(policy.getRevocationSignatureHashAlgorithmPolicy().isAcceptable(-1, new Date()));
    }

    @Test
    public void testUnknownCompressionAlgorithmIsNotAcceptable() {
        assertFalse(policy.getCompressionAlgorithmPolicy().isAcceptable(-1));
    }

    @Test
    public void testUnknownPublicKeyAlgorithmIsNotAcceptable() {
        assertFalse(policy.getPublicKeyAlgorithmPolicy().isAcceptable(-1, 4096));
    }

    @Test
    public void testRFC4880OnlyPolicyForcesAsymmetricFallbackForAEADOnlyKeys() throws IOException, PGPException {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey key = api.buildKey(OpenPGPKeyVersion.v4)
                .setPrimaryKey(KeySpec.getBuilder(
                        KeyType.RSA(RsaLength._3072),
                        KeyFlag.CERTIFY_OTHER,
                        KeyFlag.SIGN_DATA,
                        KeyFlag.ENCRYPT_COMMS,
                        KeyFlag.ENCRYPT_STORAGE))
                .withPreferences(AlgorithmSuite.emptyBuilder()
                        .overrideAeadAlgorithms(new AEADCipherMode(AEADAlgorithm.OCB, SymmetricKeyAlgorithm.AES_128))
                        .overrideFeatures(Feature.MODIFICATION_DETECTION_2)
                        .build())
                .build();

        Policy rfc4880Policy = api.getAlgorithmPolicy()
                .copy()
                .withMessageEncryptionAlgorithmPolicy(
                        Policy.MessageEncryptionMechanismPolicy.rfc4880(
                                Policy.SymmetricKeyAlgorithmPolicy.symmetricKeyEncryptionPolicy2022()
                        )).build();

        api = new PGPainless(rfc4880Policy);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream encOut = api.generateMessage()
                .onOutputStream(out)
                .withOptions(ProducerOptions.encrypt(
                        EncryptionOptions.encryptCommunications(api)
                                .addRecipient(key.toCertificate())
                ));
        encOut.write("Hello, World!\n".getBytes());
        encOut.close();

        EncryptionResult result = encOut.getResult();
        assertTrue(result.isEncryptedFor(key.toCertificate()));
        assertEquals(MessageEncryptionMechanism.integrityProtected(SymmetricKeyAlgorithm.AES_128.getAlgorithmId()),
                result.getEncryptionMechanism());
    }

    @Test
    public void testRFC4880OnlyPolicyRejectsConsumingSEIPDv2Messages()
            throws PGPException, IOException {
        PGPainless api = PGPainless.getInstance();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream eOut = api.generateMessage()
                .onOutputStream(out)
                .withOptions(ProducerOptions.encrypt(
                        EncryptionOptions.get(api)
                                .addMessagePassphrase(Passphrase.fromPassword("sw0rdf1sh"))
                                .overrideEncryptionMechanism(MessageEncryptionMechanism.aead(
                                        SymmetricKeyAlgorithm.AES_256.getAlgorithmId(),
                                        AEADAlgorithm.OCB.getAlgorithmId()
                                ))));

        eOut.write("Hello, World!\n".getBytes());
        eOut.close();

        PGPainless rfc4880Only = new PGPainless(api.getAlgorithmPolicy()
                .copy()
                .withMessageDecryptionAlgorithmPolicy(
                        Policy.MessageEncryptionMechanismPolicy.rfc4880(
                                Policy.SymmetricKeyAlgorithmPolicy.symmetricKeyDecryptionPolicy2022()))
                .build());

        assertThrows(UnacceptableAlgorithmException.class, () -> rfc4880Only.processMessage()
                .onInputStream(new ByteArrayInputStream(out.toByteArray()))
                .withOptions(ConsumerOptions.get(rfc4880Only)
                        .addMessagePassphrase(Passphrase.fromPassword("sw0rdf1sh"))));
    }

    @Test
    public void consumingMessagesRespectsCompressionAlgorithmPolicy() throws PGPException, IOException {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey key = api.generateKey()
                .modernKeyRing("Alice <alice@pgpainless.org>");
        OpenPGPCertificate cert = key.toCertificate();

        ByteArrayOutputStream mOut = new ByteArrayOutputStream();
        EncryptionStream eOut = api.generateMessage()
                .onOutputStream(mOut)
                .withOptions(ProducerOptions.signAndEncrypt(
                                EncryptionOptions.get(api)
                                        .addRecipient(cert),
                                SigningOptions.get(api)
                                        .addSignature(SecretKeyRingProtector.unprotectedKeys(), key))
                        .overrideCompressionAlgorithm(CompressionAlgorithm.ZIP));

        eOut.write("Hello, World!\n".getBytes());
        eOut.close();

        // Reject compression
        PGPainless rejectCompression = new PGPainless(api.getAlgorithmPolicy()
                .copy()
                .withCompressionAlgorithmPolicy(Policy.CompressionAlgorithmPolicy.rejectCompression())
                .build());

        ByteArrayInputStream bIn = new ByteArrayInputStream(mOut.toByteArray());
        assertThrows(UnacceptableAlgorithmException.class, () ->
                rejectCompression.processMessage()
                        .onInputStream(bIn)
                        .withOptions(ConsumerOptions.get(rejectCompression)
                                .addDecryptionKey(key)
                                .addVerificationCert(cert)));
    }

    @Test
    public void subkeyBindingSignaturesUseProperSignatureHashPolicy() throws IOException {
        Policy defPol = PGPainless.getInstance().getAlgorithmPolicy();
        Policy testPol = defPol.copy()
                .withDataSignatureHashAlgorithmPolicy(new Policy.HashAlgorithmPolicy(HashAlgorithm.SHA256, Collections.singletonList(HashAlgorithm.SHA256)))
                .withCertificationSignatureHashAlgorithmPolicy(new Policy.HashAlgorithmPolicy(HashAlgorithm.SHA384, Collections.singletonList(HashAlgorithm.SHA384)))
                .build();
        PGPainless api = new PGPainless(testPol);
        OpenPGPKey key = api.generateKey()
                .simpleEcKeyRing("Alice <alice@pgpainless.org>");

        key = api.modify(key)
                .addSubKey(KeySpec.getBuilder(
                        KeyType.ECDSA(EllipticCurve._BRAINPOOLP256R1), KeyFlag.SIGN_DATA).build(),
                        Passphrase.emptyPassphrase(),
                        SecretKeyRingProtector.unprotectedKeys())
                .done();
        assertEquals(HashAlgorithm.SHA384.getAlgorithmId(),
                key.getSigningKeys().get(1).getLatestSelfSignature().getSignature().getHashAlgorithm());
    }
}
