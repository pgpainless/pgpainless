// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.cert_d;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.platform.commons.logging.Logger;
import org.junit.platform.commons.logging.LoggerFactory;
import org.pgpainless.PGPainless;
import org.pgpainless.certificate_store.CertificateCertificateReader;
import org.pgpainless.key.OpenPgpFingerprint;
import pgp.cert_d.FileLockingMechanism;
import pgp.cert_d.LockingMechanism;
import pgp.cert_d.SharedPGPCertificateDirectory;
import pgp.cert_d.SharedPGPCertificateDirectoryImpl;
import pgp.cert_d.exception.BadDataException;
import pgp.cert_d.exception.BadNameException;
import pgp.cert_d.exception.NotAStoreException;
import pgp.certificate_store.Certificate;
import pgp.certificate_store.MergeCallback;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

public class SharedPGPCertificateDirectoryTest {

    Logger logger = LoggerFactory.getLogger(SharedPGPCertificateDirectoryTest.class);
    SharedPGPCertificateDirectory directory;

    private static MergeCallback dummyMerge = new MergeCallback() {
        @Override
        public Certificate merge(Certificate data, Certificate existing) {
            return data;
        }
    };

    @BeforeEach
    public void beforeEach() throws IOException, NotAStoreException {
        File tempDir = Files.createTempDirectory("pgp.cert.d-").toFile();
        tempDir.deleteOnExit();
        directory = new SharedPGPCertificateDirectoryImpl(tempDir, new CertificateCertificateReader());
    }

    @Test
    public void simpleInsertGet() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, BadDataException, InterruptedException, BadNameException {
        logger.info(() -> "simpleInsertGet: " + ((SharedPGPCertificateDirectoryImpl) directory).getBaseDirectory().getAbsolutePath());
        PGPSecretKeyRing key = PGPainless.generateKeyRing().modernKeyRing("Alice", null);
        PGPPublicKeyRing cert = PGPainless.extractCertificate(key);
        OpenPgpFingerprint fingerprint = OpenPgpFingerprint.of(cert);
        ByteArrayInputStream certIn = new ByteArrayInputStream(cert.getEncoded());

        // standard case: get() is null
        assertNull(directory.get(fingerprint.toString().toLowerCase()));

        // insert and check returned certs fingerprint
        Certificate certificate = directory.insert(certIn, dummyMerge);
        assertEquals(fingerprint.toString().toLowerCase(), certificate.getFingerprint());

        // getIfChanged
        assertNull(directory.getIfChanged(certificate.getFingerprint(), certificate.getTag()));
        assertNotNull(directory.getIfChanged(certificate.getFingerprint(), "invalidTag"));

        // tryInsert
        certIn = new ByteArrayInputStream(cert.getEncoded());
        assertNotNull(directory.tryInsert(certIn, dummyMerge));
    }

    @Test
    public void tryInsertFailsWithLockedStore() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, BadDataException, InterruptedException {
        SharedPGPCertificateDirectoryImpl fileDirectory = (SharedPGPCertificateDirectoryImpl) directory;
        logger.info(() -> "tryInsertFailsWithLockedStore: " + fileDirectory.getBaseDirectory().getAbsolutePath());
        PGPSecretKeyRing key = PGPainless.generateKeyRing().modernKeyRing("Alice", null);
        PGPPublicKeyRing cert = PGPainless.extractCertificate(key);
        ByteArrayInputStream certIn = new ByteArrayInputStream(cert.getEncoded());

        File lockFile = new File(fileDirectory.getBaseDirectory(), "writelock");
        LockingMechanism lock = new FileLockingMechanism(lockFile);
        lock.lockDirectory();

        assertNull(directory.tryInsert(certIn, dummyMerge));

        lock.releaseDirectory();

        assertNotNull(directory.tryInsert(certIn, dummyMerge));
    }
}
