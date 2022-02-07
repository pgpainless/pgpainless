// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.cert_d;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.certificate_store.CertificateReader;
import org.pgpainless.key.OpenPgpFingerprint;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa.EdDSACurve;
import pgp.cert_d.CachingSharedPGPCertificateDirectoryWrapper;
import pgp.cert_d.FileLockingMechanism;
import pgp.cert_d.SharedPGPCertificateDirectory;
import pgp.cert_d.SharedPGPCertificateDirectoryImpl;
import pgp.cert_d.exception.BadDataException;
import pgp.cert_d.exception.BadNameException;
import pgp.cert_d.exception.NotAStoreException;
import pgp.certificate_store.Certificate;
import pgp.certificate_store.MergeCallback;

public class SharedPGPCertificateDirectoryTest {

    private static MergeCallback dummyMerge = new MergeCallback() {
        @Override
        public Certificate merge(Certificate data, Certificate existing) {
            return data;
        }
    };

    private static Stream<SharedPGPCertificateDirectory> provideTestSubjects() throws IOException, NotAStoreException {
        return Stream.of(
                new SharedPGPCertificateDirectoryImpl(tempDir(), new CertificateReader()),
                new CachingSharedPGPCertificateDirectoryWrapper(
                        new SharedPGPCertificateDirectoryImpl(tempDir(), new CertificateReader()))
        );
    }

    private static File tempDir() throws IOException {
        File tempDir = Files.createTempDirectory("pgp.cert.d-").toFile();
        tempDir.deleteOnExit();
        return tempDir;
    }

    @ParameterizedTest
    @MethodSource("provideTestSubjects")
    public void simpleInsertGet(SharedPGPCertificateDirectory directory)
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException,
            BadDataException, InterruptedException, BadNameException {
        PGPSecretKeyRing key = PGPainless.generateKeyRing().modernKeyRing("Alice", null);
        PGPPublicKeyRing cert = PGPainless.extractCertificate(key);
        OpenPgpFingerprint fingerprint = OpenPgpFingerprint.of(cert);
        ByteArrayInputStream certIn = new ByteArrayInputStream(cert.getEncoded());

        // standard case: get() is null
        assertNull(directory.getByFingerprint(fingerprint.toString().toLowerCase()));

        // insert and check returned certs fingerprint
        Certificate certificate = directory.insert(certIn, dummyMerge);
        assertEquals(fingerprint.toString().toLowerCase(), certificate.getFingerprint());

        // getIfChanged
        assertNull(directory.getByFingerprintIfChanged(certificate.getFingerprint(), certificate.getTag()));
        assertNotNull(directory.getByFingerprintIfChanged(certificate.getFingerprint(), "invalidTag"));

        // tryInsert
        certIn = new ByteArrayInputStream(cert.getEncoded());
        assertNotNull(directory.tryInsert(certIn, dummyMerge));
    }

    @ParameterizedTest
    @MethodSource("provideTestSubjects")
    public void simpleInsertGetBySpecialName(SharedPGPCertificateDirectory directory)
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException,
            BadDataException, InterruptedException, BadNameException {
        PGPSecretKeyRing key = PGPainless.buildKeyRing()
                .addUserId("trust-root")
                .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519), KeyFlag.CERTIFY_OTHER))
                .build();
        PGPPublicKeyRing trustRoot = PGPainless.extractCertificate(key);
        OpenPgpFingerprint fingerprint = OpenPgpFingerprint.of(trustRoot);
        ByteArrayInputStream certIn = new ByteArrayInputStream(trustRoot.getEncoded());

        // standard case: get() is null
        assertNull(directory.getBySpecialName("trust-root"));

        // insert and check returned certs fingerprint
        Certificate certificate = directory.insertWithSpecialName("trust-root", certIn, dummyMerge);
        assertEquals(fingerprint.toString().toLowerCase(), certificate.getFingerprint());

        // getIfChanged
        assertNull(directory.getBySpecialNameIfChanged("trust-root", certificate.getTag()));
        assertNotNull(directory.getBySpecialNameIfChanged("trust-root", "invalidTag"));

        // tryInsert
        certIn = new ByteArrayInputStream(trustRoot.getEncoded());
        assertNotNull(directory.tryInsertWithSpecialName("trust-root", certIn, dummyMerge));
    }

    @ParameterizedTest
    @MethodSource("provideTestSubjects")
    public void tryInsertFailsWithLockedStore(SharedPGPCertificateDirectory directory)
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException,
            BadDataException, InterruptedException {
        assumeTrue(directory.getLock() instanceof FileLockingMechanism);

        PGPSecretKeyRing key = PGPainless.generateKeyRing().modernKeyRing("Alice", null);
        PGPPublicKeyRing cert = PGPainless.extractCertificate(key);
        ByteArrayInputStream certIn = new ByteArrayInputStream(cert.getEncoded());

        directory.getLock().lockDirectory();
        assertNull(directory.tryInsert(certIn, dummyMerge));

        directory.getLock().releaseDirectory();
        assertNotNull(directory.tryInsert(certIn, dummyMerge));
    }

    @ParameterizedTest
    @MethodSource("provideTestSubjects")
    public void testGetItemsAndFingerprints(SharedPGPCertificateDirectory directory)
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException,
            BadDataException, InterruptedException, BadNameException {

        PGPSecretKeyRing trustRootKey = PGPainless.generateKeyRing().modernKeyRing("Alice", null);
        PGPPublicKeyRing trustRootCert = PGPainless.extractCertificate(trustRootKey);
        OpenPgpFingerprint trustRootFingerprint = OpenPgpFingerprint.of(trustRootCert);
        ByteArrayInputStream trustRootCertIn = new ByteArrayInputStream(trustRootCert.getEncoded());
        directory.insertWithSpecialName("trust-root", trustRootCertIn, dummyMerge);

        final int certificateCount = 3;
        Map<String, PGPPublicKeyRing> certificateMap = new HashMap<>();
        for (int i = 0; i < certificateCount; i++) {
            PGPSecretKeyRing key = PGPainless.generateKeyRing().modernKeyRing("Alice", null);
            PGPPublicKeyRing cert = PGPainless.extractCertificate(key);
            OpenPgpFingerprint fingerprint = OpenPgpFingerprint.of(cert);
            certificateMap.put(fingerprint.toString().toLowerCase(), cert);

            ByteArrayInputStream certIn = new ByteArrayInputStream(cert.getEncoded());
            directory.insert(certIn, dummyMerge);
        }

        Iterator<Certificate> certificates = directory.items();
        int count = 0;
        while (certificates.hasNext()) {
            count++;
            Certificate certificate = certificates.next();
            String fingerprint = certificate.getFingerprint();
            assertNotNull(certificateMap.get(fingerprint));
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            Streams.pipeAll(certificate.getInputStream(), out);
            assertArrayEquals(certificateMap.get(fingerprint).getEncoded(), out.toByteArray());
        }

        assertEquals(certificateCount, count);

        Iterator<String> fingerprints = directory.fingerprints();
        Set<String> fingerprintSet = new HashSet<>();
        while (fingerprints.hasNext()) {
            String fingerprint = fingerprints.next();
            fingerprintSet.add(fingerprint);
            assertNotNull(certificateMap.get(fingerprint));
        }

        assertEquals(certificateCount, fingerprintSet.size());
    }
}
