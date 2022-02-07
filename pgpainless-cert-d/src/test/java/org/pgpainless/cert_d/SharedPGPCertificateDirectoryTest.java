// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.cert_d;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.stream.Stream;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.pgpainless.PGPainless;
import org.pgpainless.certificate_store.CertificateReader;
import org.pgpainless.key.OpenPgpFingerprint;
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
}
