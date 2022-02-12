// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.cert_d;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.InputStream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.pgpainless.certificate_store.SharedPGPCertificateDirectoryAdapter;
import pgp.cert_d.SharedPGPCertificateDirectory;
import pgp.cert_d.exception.BadDataException;
import pgp.cert_d.exception.BadNameException;
import pgp.certificate_store.CertificateStore;
import pgp.certificate_store.MergeCallback;

public class SharedPGPCertificateDirectoryAdapterMockTest {

    private static final String invalidSpecialName = "trust-root";
    private static final String invalidFingerprint = "invalidFingerprint";
    private static final String badData = "badData";

    private static CertificateStore store;
    private static MergeCallback mergeCallback;
    private static InputStream inputStream;

    @BeforeAll
    public static void mockComponents() throws BadNameException, IOException, BadDataException, InterruptedException {
        mergeCallback = mock(MergeCallback.class);
        inputStream = mock(InputStream.class);
        SharedPGPCertificateDirectory mocked = mock(SharedPGPCertificateDirectory.class);
        store = new SharedPGPCertificateDirectoryAdapter(mocked);
        // bad name
        when(mocked.getBySpecialName(invalidSpecialName))
                .thenThrow(new BadNameException());
        when(mocked.getBySpecialNameIfChanged(eq(invalidSpecialName), any()))
                .thenThrow(new BadNameException());
        when(mocked.getByFingerprint(invalidFingerprint))
                .thenThrow(new BadNameException());
        when(mocked.getByFingerprintIfChanged(eq(invalidFingerprint), any()))
                .thenThrow(new BadNameException());
        // bad data
        when(mocked.getByFingerprint(badData))
                .thenThrow(new BadDataException());
        when(mocked.getByFingerprintIfChanged(eq(badData), any()))
                .thenThrow(new BadDataException());
        when(mocked.insert(any(), any()))
                .thenThrow(new BadDataException());
        when(mocked.tryInsert(any(), any()))
                .thenThrow(new BadDataException());
        when(mocked.insertWithSpecialName(eq(invalidSpecialName), any(), any()))
                .thenThrow(new BadDataException());
        when(mocked.tryInsertWithSpecialName(eq(invalidSpecialName), any(), any()))
                .thenThrow(new BadDataException());
    }

    @Test
    public void testGetUsingFingerprint_BadNameIsMappedToIAE() {
        assertThrows(IllegalArgumentException.class, () -> store.getCertificate(invalidFingerprint));
        assertThrows(IllegalArgumentException.class, () -> store.getCertificateIfChanged(invalidFingerprint, "tag"));
    }

    @Test
    public void testGetUsingSpecialName_BadNameIsMappedToIAE() {
        assertThrows(IllegalArgumentException.class, () -> store.getCertificate(invalidSpecialName));
        assertThrows(IllegalArgumentException.class, () -> store.getCertificateIfChanged(invalidSpecialName, "tag"));
    }

    @Test
    public void testGet_BadDataIsMappedToIOE() {
        assertThrows(IOException.class, () -> store.getCertificate(badData));
        assertThrows(IOException.class, () -> store.getCertificateIfChanged(badData, "tag"));
    }

    @Test
    public void testInsert_BadDataIsMappedToIOE() {
        assertThrows(IOException.class, () -> store.insertCertificate(inputStream, mergeCallback));
        assertThrows(IOException.class, () -> store.insertCertificateBySpecialName(invalidSpecialName, inputStream, mergeCallback));

        assertThrows(IOException.class, () -> store.tryInsertCertificate(inputStream, mergeCallback));
        assertThrows(IOException.class, () -> store.tryInsertCertificateBySpecialName(invalidSpecialName, inputStream, mergeCallback));
    }
}
