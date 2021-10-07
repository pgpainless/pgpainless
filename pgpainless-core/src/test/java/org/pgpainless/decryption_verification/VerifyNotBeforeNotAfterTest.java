// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.key.TestKeys;
import org.pgpainless.util.DateUtil;

public class VerifyNotBeforeNotAfterTest {

    private static final byte[] data = "Hello, World!\n".getBytes(StandardCharsets.UTF_8);

    private static final byte[] inlineSigned = ("" +
            "-----BEGIN PGP MESSAGE-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "kA0DAAoTVzbmkxrPNwwAyxRiAAAAAABIZWxsbywgV29ybGQhCoh1BAATCgAGBQJh\n" +
            "G7iQACEJEFc25pMazzcMFiEET2ZcTcLEZgvGQl5BVzbmkxrPNwxH7AEAsEyOCQPG\n" +
            "3F2JSWK/8AYyvsk17Gtb9TGn5SWqLo5Ac8YBAIlijYnSIHm0aatlMsK6t/rAB3bU\n" +
            "eHyT9/mVlk9qrOWs\n" +
            "=vkxO\n" +
            "-----END PGP MESSAGE-----").getBytes(StandardCharsets.UTF_8);

    private static final byte[] detachedSignature = ("" +
            "-----BEGIN PGP SIGNATURE-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "iHUEABMKAAYFAmEbuJAAIQkQVzbmkxrPNwwWIQRPZlxNwsRmC8ZCXkFXNuaTGs83\n" +
            "DEfsAQDNXmvhkh92aoUp9KNCpCqA6nvHmT5O0n1Lr0BmBccHtgD8CVR3VElemas+\n" +
            "aH5l06cDUW1peQQs+xZ0FHltWmk5PJw=\n" +
            "=RJDi\n" +
            "-----END PGP SIGNATURE-----").getBytes(StandardCharsets.UTF_8);

    private static final Date signatureCreationDate = DateUtil.parseUTCDate("2021-08-17 13:24:32 UTC");
    private static final Date T0 = DateUtil.parseUTCDate("2021-08-17 12:30:00 UTC");
    private static final Date T1 = signatureCreationDate;
    private static final Date T2 = DateUtil.parseUTCDate("2021-08-17 13:30:00 UTC");
    private static PGPPublicKeyRing certificate;
    private static SubkeyIdentifier signingKey;

    @BeforeAll
    public static void setup() throws IOException {
        certificate = TestKeys.getEmilPublicKeyRing();
        signingKey = new SubkeyIdentifier(certificate);
    }

    @Test
    public void noConstraintsVerifyInlineSig() throws PGPException, IOException {
        ConsumerOptions options = new ConsumerOptions()
                .addVerificationCert(certificate);
        DecryptionStream verifier = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(inlineSigned))
                .withOptions(options);

        OpenPgpMetadata metadata = processSignedData(verifier);
        assertTrue(metadata.getVerifiedSignatures().containsKey(new SubkeyIdentifier(certificate)));
    }

    @Test
    public void noConstraintsVerifyDetachedSig() throws PGPException, IOException {
        ConsumerOptions options = new ConsumerOptions()
                .addVerificationCert(certificate)
                .addVerificationOfDetachedSignatures(new ByteArrayInputStream(detachedSignature));
        DecryptionStream verifier = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(data))
                .withOptions(options);

        OpenPgpMetadata metadata = processSignedData(verifier);
        assertTrue(metadata.containsVerifiedSignatureFrom(certificate));
    }

    @Test
    public void notBeforeT1DoesNotRejectInlineSigMadeAtT1() throws PGPException, IOException {
        ConsumerOptions options = new ConsumerOptions()
                .verifyNotBefore(T1)
                .addVerificationCert(certificate);
        DecryptionStream verifier = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(inlineSigned))
                .withOptions(options);
        OpenPgpMetadata metadata = processSignedData(verifier);
        assertTrue(metadata.getVerifiedSignatures().containsKey(signingKey));
    }

    @Test
    public void notBeforeT1DoesNotRejectDetachedSigMadeAtT1() throws PGPException, IOException {
        ConsumerOptions options = new ConsumerOptions()
                .verifyNotBefore(T1)
                .addVerificationCert(certificate)
                .addVerificationOfDetachedSignatures(new ByteArrayInputStream(detachedSignature));
        DecryptionStream verifier = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(data))
                .withOptions(options);
        OpenPgpMetadata metadata = processSignedData(verifier);
        assertTrue(metadata.getVerifiedSignatures().containsKey(signingKey));
    }

    @Test
    public void verifyNotBeforeT2DoesRejectInlineSignatureMadeAtT1() throws PGPException, IOException {
        ConsumerOptions options = new ConsumerOptions()
                .verifyNotBefore(T2)
                .addVerificationCert(certificate);
        DecryptionStream verifier = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(inlineSigned))
                .withOptions(options);
        OpenPgpMetadata metadata = processSignedData(verifier);
        assertFalse(metadata.getVerifiedSignatures().containsKey(signingKey));
    }

    @Test
    public void verifyNotBeforeT2DoesRejectDetachedSigMadeAtT1() throws PGPException, IOException {
        ConsumerOptions options = new ConsumerOptions()
                .verifyNotBefore(T2)
                .addVerificationCert(certificate)
                .addVerificationOfDetachedSignatures(new ByteArrayInputStream(detachedSignature));
        DecryptionStream verifier = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(data))
                .withOptions(options);
        OpenPgpMetadata metadata = processSignedData(verifier);
        assertFalse(metadata.getVerifiedSignatures().containsKey(signingKey));
    }

    @Test
    public void verifyNotAfterT1DoesNotRejectInlineSigMadeAtT1() throws PGPException, IOException {
        ConsumerOptions options = new ConsumerOptions()
                .verifyNotAfter(T1)
                .addVerificationCert(certificate);
        DecryptionStream verifier = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(inlineSigned))
                .withOptions(options);
        OpenPgpMetadata metadata = processSignedData(verifier);
        assertTrue(metadata.getVerifiedSignatures().containsKey(signingKey));
    }

    @Test
    public void verifyNotAfterT1DoesRejectDetachedSigMadeAtT1() throws PGPException, IOException {
        ConsumerOptions options = new ConsumerOptions()
                .verifyNotAfter(T1)
                .addVerificationCert(certificate)
                .addVerificationOfDetachedSignatures(new ByteArrayInputStream(detachedSignature));
        DecryptionStream verifier = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(data))
                .withOptions(options);
        OpenPgpMetadata metadata = processSignedData(verifier);
        assertTrue(metadata.getVerifiedSignatures().containsKey(signingKey));
    }

    @Test
    public void verifyNotAfterT0DoesRejectInlineSigMadeAtT1() throws PGPException, IOException {
        ConsumerOptions options = new ConsumerOptions()
                .verifyNotAfter(T0)
                .addVerificationCert(certificate);
        DecryptionStream verifier = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(inlineSigned))
                .withOptions(options);
        OpenPgpMetadata metadata = processSignedData(verifier);
        assertFalse(metadata.getVerifiedSignatures().containsKey(signingKey));
    }

    @Test
    public void verifyNotAfterT0DoesRejectDetachedSigMadeAtT1() throws PGPException, IOException {
        ConsumerOptions options = new ConsumerOptions()
                .verifyNotAfter(T0)
                .addVerificationCert(certificate)
                .addVerificationOfDetachedSignatures(new ByteArrayInputStream(detachedSignature));
        DecryptionStream verifier = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(data))
                .withOptions(options);
        OpenPgpMetadata metadata = processSignedData(verifier);
        assertFalse(metadata.getVerifiedSignatures().containsKey(signingKey));
    }

    private OpenPgpMetadata processSignedData(DecryptionStream verifier) throws IOException {
        Streams.drain(verifier);
        verifier.close();
        return verifier.getResult();
    }
}
