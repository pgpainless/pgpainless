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

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.pgpainless.certificate_store.SharedPGPCertificateDirectoryAdapter;
import pgp.cert_d.SharedPGPCertificateDirectory;
import pgp.cert_d.exception.BadDataException;
import pgp.cert_d.exception.BadNameException;
import pgp.certificate_store.CertificateStore;

public class SharedPGPCertificateDirectoryAdapterMockTest {

    private static final String invalidSpecialName = "trust-root";
    private static final String invalidFingerprint = "invalidFingerprint";
    private static final String badData = "badData";

    private static CertificateStore store;

    @BeforeAll
    public static void mockComponents() throws BadNameException, IOException, BadDataException {
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
    }

    @Test
    public void testGetUsingFingerprint_BadNameIsMappedToIAE() {
        assertThrows(IllegalArgumentException.class, () -> store.getCertificate(invalidFingerprint));
    }

    @Test
    public void testGetUsingSpecialName_BadNameIsMappedToIAE() {
        assertThrows(IllegalArgumentException.class, () -> store.getCertificate(invalidSpecialName));
    }

    @Test
    public void testGet_BadDataIsMappedToIOE() {
        assertThrows(IOException.class, () -> store.getCertificate(badData));
    }
}
