// SPDX-FileCopyrightText: 2026 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package investigations;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.MessageMetadata;
import org.pgpainless.exception.ModificationDetectionException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TestFaultyMDCDoesNotAllowMetadataExtraction {

    /**
     * Test for defect 13 from GHSA-5fmp-48ff-rx9p.
     *
     * @throws IOException
     * @throws PGPException
     */
    @Test
    public void testCatchingMDCExceptionDoesNotAllowLaterAccessToMetadata() throws IOException, PGPException {
        String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "Comment: 39B4 CB0F 6FDE C790 AD9A  2032 5819 5900 4144 ACA6\n" +
                "Comment: Alice\n" +
                "\n" +
                "lFgEajPmoxYJKwYBBAHaRw8BAQdA7WOYp6fiVl9YbX/B8EQtwJtDs96xfIX8Ib6n\n" +
                "BK2AJA4AAQDxFR9tHlLrCJ0QoNIozsJvoPUqwnoST4I5C0rUoXjD1w8vtAVBbGlj\n" +
                "ZcKfBBMWCgBRCRBYGVkAQUSsphahBDm0yw9v3seQrZogMlgZWQBBRKymBYJqM+aj\n" +
                "ApsBBRUKCQgLBRYCAwEABAsJCAcJJwkBCQIJAwgBAp4JBYkJZgGAApkBAABxhAEA\n" +
                "/Tu6R8ILbGl9W3Q4swIEhezYSzQD6sDUg7GlGiYco3AA/RIcfdibkFVv70TKmoZz\n" +
                "cQmL4w/DS6rZ+NccTdeZ0XgMnF0EajPmoxIKKwYBBAGXVQEFAQEHQBVuRB829bHk\n" +
                "i9175dNUH5fGcMRUo31j+zOGtUnCv/xfAwEIBwAA/2mGE9rQLOIYqvbGyy9U6/M+\n" +
                "/dyrDgklLTFwsLipSN24Eh3CeAQYFgoAKgkQWBlZAEFErKYWoQQ5tMsPb97HkK2a\n" +
                "IDJYGVkAQUSspgWCajPmowKbDAAAFHYBAPphVHzKoySCTPFhOUfxU4PrskCAgqy2\n" +
                "JwbCNgxTMh0zAQCQVVTbDKkcSH6K80JdeyKzxgWgdzvi/IRKN6eti4xeCpxYBGoz\n" +
                "5qMWCSsGAQQB2kcPAQEHQPOuNQmeArfra9iIYJX7ZHQdzk5FglyysIaFU1CBL3S+\n" +
                "AAEAsdLruCNoOPtvXnIFEjTd+ma1pY+aAsQid0IPEVyk2vEPu8LALwQYFgoAoQkQ\n" +
                "WBlZAEFErKYWoQQ5tMsPb97HkK2aIDJYGVkAQUSspgWCajPmowKbAnYgBBkWCgAd\n" +
                "BYJqM+ajFiEEz+FByU0QqiiYz8f90NApHLHjgIkACgkQ0NApHLHjgIkGEQD7Bcli\n" +
                "WcJUAa3cDFrY7CoU83Vlw4Kk5wL5Mr0oO27FjPwA/2NEujH7+5e/fP57soRTMz7n\n" +
                "mCN4s51A1N+j3KfWZsQHAADVogEAyHg+KFr8Np+ABIo/QXq9SKRqM54bnQBCFIjF\n" +
                "OMjPHbMA/1u7Pl09dhZHOAyU9hhkg8RXFA7e6crX/o0cEpZa4k0C\n" +
                "=cDwx\n" +
                "-----END PGP PRIVATE KEY BLOCK-----";

        // Message has the checksum in the SEIPDv1 MDC packet modified.
        String MSG = "-----BEGIN PGP MESSAGE-----\n" +
                "Version: PGPainless\n" +
                "\n" +
                "wV4Dz06rE7z3j00SAQdAt3EXGENfdn6Jl1UrMbr60IB8cR1sPG9h3YWRpEIurDAw\n" +
                "vr3d8rHtNbvu7zKymRUZ59Yfe3Xsi2mcpQZgNci4n40XENyKtkN6FElBEmAdLaju\n" +
                "0sAFAf2DtkdCZaK6eO5vN1nKz1auU7viOpreTHlIDaWOq0wyv0eFjGMZCwW7bG1u\n" +
                "I2IUSuJuQUg1BAqwj0DN5K/FBlWDWAGU52cwDPnkrsOXr0z/CB1ce2pJfV5lvzZD\n" +
                "ExVOFLi9Z1J84pVGAFSbwfBi0T5gQQgkbAu8dg7VL9rTv205+zRDIsbGiu3atlQ4\n" +
                "E7p0c44jS2H1YyyaqUQa6uybbmie/9TiBw6LeBWbczFirwB+QKrZMMm1JA7DNKyi\n" +
                "P9jMqefNq9I=\n" + // "P9jMqeeNq9I=\n"
                "-----END PGP MESSAGE-----";

        PGPainless api = PGPainless.getInstance();
        OpenPGPKey key = api.readKey().parseKey(KEY);

        ByteArrayInputStream bIn = new ByteArrayInputStream(MSG.getBytes(StandardCharsets.UTF_8));
        DecryptionStream decIn = api.processMessage()
                .onInputStream(bIn)
                .withOptions(ConsumerOptions.get(api)
                        .setDisableAsciiArmorCRC(true)
                        .addVerificationCert(key.toCertificate())
                        .addDecryptionKey(key));

        try {
            Streams.drain(decIn);
            decIn.close();
        } catch (ModificationDetectionException e) {
            // ignore
        }

        assertThrows(ModificationDetectionException.class, () -> {
            decIn.close();
            MessageMetadata metadata = decIn.getMetadata();
            assertTrue(metadata.isVerifiedSigned());
        });
    }
}
