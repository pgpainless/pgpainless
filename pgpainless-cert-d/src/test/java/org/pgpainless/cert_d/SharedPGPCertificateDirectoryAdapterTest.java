// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.cert_d;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pgpainless.certificate_store.CertificateReader;
import org.pgpainless.certificate_store.SharedPGPCertificateDirectoryAdapter;
import pgp.cert_d.SharedPGPCertificateDirectoryImpl;
import pgp.certificate_store.exception.BadDataException;
import pgp.certificate_store.exception.BadNameException;
import pgp.certificate_store.exception.NotAStoreException;
import pgp.certificate_store.Certificate;
import pgp.certificate_store.CertificateStore;

public class SharedPGPCertificateDirectoryAdapterTest {

    private static final String testCertificate = "98330462069cc616092b06010401da470f010107400db5906b09f701ab1f7f96087eedab6ba44c02fcbd2470137cfeacac5a2d032db405416c696365888f0413160a0041050262069cc609906f054e826378552516a104505b134a7e62f0f154ec3d036f054e8263785525029e01029b01059602030100048b09080705950a09080b0299010000a12600fd117925c0f2192ef5b2a44e3d3038e2a7ce5ba0343fc2dfb661a3a46d1276fb380100bf2872e7e36b63f61ae3556464c4a04344e7d36e0d7313e623effb0290ce0b0fb8380462069cc6120a2b06010401975501050101074034ffd523242385fe92034a5e326a82f4edff614516cc1028ca91fb653557f25b0301080788750418160a001d050262069cc6029e01029b0c059602030100048b09080705950a09080b000a09106f054e8263785525391400ff4eb85df8ddfc15e94c9cf28bc0aa9d0426b571ca64c5421be5889d5410d8632f00fd1ac5e9aed683e711282489d8980222d2ceff15c5ce0499fcb36716d850749406b8330462069cc616092b06010401da470f0101074058f296fb7ce456039856144db677f14018963a8bfd281c84aaeebe7e14df8f1c88d50418160a007d050262069cc6029e01029b02059602030100048b09080705950a09080b5f200419160a0006050262069cc6000a09108119c86e0a4c6dc73a7600ff5e25427da84d824cc3f8890bc6bd037f423f610006e1249b1aad3d7f70ac47a100fc08e67a6a945c1feec301df9dc27e7ea4e61d107d0720e814eea1dc4f1da20a08000a09106f054e8263785525359700ff4ce78cf267c261468322de906118d4f003ceefa72fa3b86119e26f99be3727fc00fe3895207c4aac814549f0189d2f494f5b1fcee7f6da344e63a0c32743b216b406";
    private static final String testCertFingerprint = "505b134a7e62f0f154ec3d036f054e8263785525";

    private SharedPGPCertificateDirectoryAdapter adapter;
    private CertificateStore store;

    @BeforeEach
    public void setupInstance() throws IOException, NotAStoreException {
        adapter = new SharedPGPCertificateDirectoryAdapter(
                new SharedPGPCertificateDirectoryImpl(tempDir(), new CertificateReader()));
        store = adapter;
    }

    private static File tempDir() throws IOException {
        File tempDir = Files.createTempDirectory("pgp.cert.d-").toFile();
        tempDir.deleteOnExit();
        return tempDir;
    }

    @Test
    public void getNonExistentCertIsNull() throws IOException, BadDataException, BadNameException {
        assertNull(store.getCertificate("eb85bb5fa33a75e15e944e63f231550c4f47e38e"));
    }

    @Test
    public void getInvalidIdentifierThrows() {
        assertThrows(BadNameException.class, () -> store.getCertificate("invalid"));
    }

    @Test
    public void insertAndGet() throws IOException, InterruptedException, BadDataException, BadNameException {
        byte[] bytes = Hex.decode(testCertificate);
        ByteArrayInputStream byteIn = new ByteArrayInputStream(bytes);
        String fingerprint = testCertFingerprint;

        Certificate certificate = store.insertCertificate(byteIn, (data, existing) -> data);

        assertEquals(fingerprint, certificate.getFingerprint());

        Certificate retrieved = store.getCertificate(fingerprint);
        assertNotNull(retrieved);
        ByteArrayOutputStream retrievedOut = new ByteArrayOutputStream();
        Streams.pipeAll(retrieved.getInputStream(), retrievedOut);

        assertArrayEquals(bytes, retrievedOut.toByteArray());
    }


    @Test
    public void tryInsertAndGet() throws IOException, BadDataException, BadNameException {
        byte[] bytes = Hex.decode(testCertificate);
        ByteArrayInputStream byteIn = new ByteArrayInputStream(bytes);
        String fingerprint = testCertFingerprint;

        Certificate certificate = store.tryInsertCertificate(byteIn, (data, existing) -> data);

        assertEquals(fingerprint, certificate.getFingerprint());

        Certificate retrieved = store.getCertificate(fingerprint);
        assertNotNull(retrieved);
        ByteArrayOutputStream retrievedOut = new ByteArrayOutputStream();
        Streams.pipeAll(retrieved.getInputStream(), retrievedOut);

        assertArrayEquals(bytes, retrievedOut.toByteArray());
    }


    @Test
    public void insertAndGetIfChanged() throws IOException, InterruptedException, BadDataException, BadNameException {
        byte[] bytes = Hex.decode(testCertificate);
        ByteArrayInputStream byteIn = new ByteArrayInputStream(bytes);
        String fingerprint = testCertFingerprint;

        Certificate certificate = store.insertCertificate(byteIn, (data, existing) -> data);
        String tag = certificate.getTag();

        assertNull(store.getCertificateIfChanged(fingerprint, tag));
        assertNotNull(store.getCertificateIfChanged(fingerprint, "invalid"));
    }

    @Test
    public void insertBySpecialNameAndGet() throws IOException, InterruptedException, BadDataException, BadNameException {
        byte[] bytes = Hex.decode(testCertificate);
        ByteArrayInputStream byteIn = new ByteArrayInputStream(bytes);
        String fingerprint = testCertFingerprint;
        String identifier = "trust-root";

        Certificate certificate = store.insertCertificateBySpecialName(identifier, byteIn, (data, existing) -> data);

        assertEquals(fingerprint, certificate.getFingerprint());

        Certificate retrieved = store.getCertificate(identifier);
        assertNotNull(retrieved);
        ByteArrayOutputStream retrievedOut = new ByteArrayOutputStream();
        Streams.pipeAll(retrieved.getInputStream(), retrievedOut);

        assertArrayEquals(bytes, retrievedOut.toByteArray());
    }

    @Test
    public void tryInsertBySpecialNameAndGet() throws IOException, BadDataException, BadNameException {
        byte[] bytes = Hex.decode(testCertificate);
        ByteArrayInputStream byteIn = new ByteArrayInputStream(bytes);
        String fingerprint = testCertFingerprint;
        String identifier = "trust-root";

        Certificate certificate = store.tryInsertCertificateBySpecialName(identifier, byteIn, (data, existing) -> data);

        assertEquals(fingerprint, certificate.getFingerprint());

        Certificate retrieved = store.getCertificate(identifier);
        assertNotNull(retrieved);
        ByteArrayOutputStream retrievedOut = new ByteArrayOutputStream();
        Streams.pipeAll(retrieved.getInputStream(), retrievedOut);

        assertArrayEquals(bytes, retrievedOut.toByteArray());
    }

    @Test
    public void insertBySpecialNameAndGetIfChanged() throws IOException, InterruptedException, BadDataException, BadNameException {
        byte[] bytes = Hex.decode(testCertificate);
        ByteArrayInputStream byteIn = new ByteArrayInputStream(bytes);
        String fingerprint = testCertFingerprint;
        String identifier = "trust-root";

        Certificate certificate = store.insertCertificateBySpecialName(identifier, byteIn, (data, existing) -> data);
        String tag = certificate.getTag();

        certificate = store.getCertificateIfChanged(identifier, tag);
        assertNull(certificate);
        certificate = store.getCertificateIfChanged(identifier, "invalid");
        assertNotNull(certificate);
        assertEquals(fingerprint, certificate.getFingerprint());
    }

    @Test
    public void getItemsAndFingerprints() throws IOException, InterruptedException, BadDataException, BadNameException {
        byte[] bytes1 = Hex.decode(testCertificate);
        ByteArrayInputStream byteIn1 = new ByteArrayInputStream(bytes1);
        Certificate firstCert = store.insertCertificate(byteIn1, (data, existing) -> data);

        byte[] bytes2 = Hex.decode("9833046206a37516092b06010401da470f010107409f55baab1599044096ba901d69854cf5307b84b0542871b15db3dd4c62664f37b403426f62888f0413160a004105026206a3750990ba01b5a9eea7e76716a104f1d47fb85ad74549a37974f3ba01b5a9eea7e767029e01029b01059602030100048b09080705950a09080b0299010000e6170100e08374a6fd32d0b4be2d3f7c75d3f6c13cb47b1b73589aa452a1b2a16b888b5000fe274e6565ab9faa34338cf4d805663f8775fdee4ec6a0fdf1ec2cf84b72907f05b838046206a375120a2b0601040197550105010107405641e74d2dda92003ce200422c3ab6f3562fc49a8ecc67ea02593988442b23780301080788750418160a001d05026206a375029e01029b0c059602030100048b09080705950a09080b000a0910ba01b5a9eea7e76732850100910a6049779773f455226cd91645884842b91017796287a634104ab5364a0c0d00fe20b5febb17de271394f31128f709c307c0bbca4f9502570744bd54e6dc9c2209b833046206a37516092b06010401da470f0101074059f008928cb69b48bed07a639f03f43a48808aade67109cd658f54bddefa5ec288d50418160a007d05026206a375029e01029b02059602030100048b09080705950a09080b5f200419160a000605026206a375000a0910dcdb34f4068368c0dffb010095fb1f6daac239bf3221d9d2ecc81b6cb258c2b058a300a7e103f7f36a58bf1900fe273a9eaaa03b613236df22bebcbbd69d7c02caf1b7af4fa29320c8d96d32310f000a0910ba01b5a9eea7e7671de20100a5044d24a9d860f9af7e8b9a095d4eac8820fad8b045e70be1ae5607fa4d6b4f010097b53d1527f3b3e3d3b78367c8269c999ee37575a51ffc582f73d2cba4df080f");
        ByteArrayInputStream byteIn2 = new ByteArrayInputStream(bytes2);
        Certificate secondCert = store.insertCertificate(byteIn2, ((data, existing) -> data));

        String trustRootHex = "9833046206a57e16092b06010401da470f010107401ad7351d9766843bf11a8414f68790df0649fad8b01c244323f47e4ebc87fc35b40a74727573742d726f6f74888f0413160a004105026206a57f09907c619691ddee5fc216a10489e1e05cb458758d0729eb0c7c619691ddee5fc2029e01029b01059602030100048b09080705950a09080b029901000080c100ff45d97dda133895e337416266f1ff2c38ff3947ecfbfe21328d51bc877ccba367010096698a5fbac9444b7b28b96389c66ca405821f04871f1bbbf5b5bf8b800f9104b838046206a57f120a2b06010401975501050101074074ff41705c50e8f27b18df40a53aded6cacd2ce4f88b471c7130036010ca60240301080788750418160a001d05026206a57f029e01029b0c059602030100048b09080705950a09080b000a09107c619691ddee5fc27b3c0100fba12230adf80a6a7a376b9568481ab4ae86628274db67412074cb4a846011a200ff437e4047bbafec42b41594b296f8be93fc03482b2d35ac92e87ce632b86bc900b833046206a57f16092b06010401da470f01010740ce99f97d1f0b5aa2f4e6f2a7a2aa231da8c2a2f489a593b747983a750f3928ae88d50418160a007d05026206a57f029e01029b02059602030100048b09080705950a09080b5f200419160a000605026206a57f000a0910b905cb706dec67e3f6050100a7ae51ea07f3d0d493fd1fdfbcbbe112c19de8dbbd29e03ba5e755345444402300fe2663252eeca21772012c5dc4eb9efa4e01566dffbb44e7d1536181eb3f8b420e000a09107c619691ddee5fc2a4190100fdbedf9defd5d30bad77937a5589441ef336028613a6fcfc4a959bee51de134e00fd128628567b66fa03ef099d6936324f7593e2060608b433828d336dda552e2c04";
        byte[] trustRootBytes = Hex.decode(trustRootHex);
        ByteArrayInputStream trustRootIn = new ByteArrayInputStream(trustRootBytes);
        Certificate trustRoot = store.insertCertificateBySpecialName("trust-root", trustRootIn, (data, existing) -> data);

        Set<String> expectedFingerprints = new HashSet<>();
        expectedFingerprints.add(firstCert.getFingerprint());
        expectedFingerprints.add(secondCert.getFingerprint());

        Iterator<Certificate> certificateIterator = store.getCertificates();
        Set<String> actualFingerprints = new HashSet<>();
        Certificate c = certificateIterator.next();
        actualFingerprints.add(c.getFingerprint());
        c = certificateIterator.next();
        actualFingerprints.add(c.getFingerprint());
        assertFalse(certificateIterator.hasNext());

        assertEquals(expectedFingerprints, actualFingerprints);
        assertFalse(actualFingerprints.contains(trustRoot.getFingerprint()));

        Iterator<String> fingerprintIterator = store.getFingerprints();
        actualFingerprints = new HashSet<>();
        actualFingerprints.add(fingerprintIterator.next());
        actualFingerprints.add(fingerprintIterator.next());
        assertFalse(fingerprintIterator.hasNext());

        assertEquals(expectedFingerprints, actualFingerprints);
        assertFalse(actualFingerprints.contains(trustRoot.getFingerprint()));
    }
}
