// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.junit.JUtils;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.signature.SignatureUtils;
import org.pgpainless.util.DateUtil;

import java.io.IOException;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class TestMergeCertificate {

    private static final String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 9F3E C7B3 3FCF 807E 516D  5DA1 C102 B0FC 9A1C 69E9\n" +
            "Comment: Revik Okemi <rev@oke.mi>\n" +
            "\n" +
            "lFgEYxXwbRYJKwYBBAHaRw8BAQdAtAWpi1+uUUpe37nSQqybiLpcAoa5KhlpLZmk\n" +
            "IkqLXn8AAP4s+6jp7OInR4PqasuH0YefMEfPu9ZY5ZHjq3HFoaqEpxTxtBhSZXZp\n" +
            "ayBPa2VtaSA8cmV2QG9rZS5taT6IjwQTFgoAQQUCYxXwbQkQwQKw/JocaekWIQSf\n" +
            "PsezP8+AflFtXaHBArD8mhxp6QKeAQKbAQUWAgMBAAQLCQgHBRUKCQgLApkBAAAi\n" +
            "SAEApd8RdhvF33eiUgXlMBU3/ob1/NdMIbVJCBUXj7URYzUBAKxH+BwesiSagsXO\n" +
            "KbQEOjzu1R7Nd2Hmf+gue9AVQQ0BnF0EYxXwbRIKKwYBBAGXVQEFAQEHQPLc0OH8\n" +
            "8v+govDgUQs7gnM5NK3H+haFCsq/ILMBb48YAwEIBwAA/2CXgEXUIi4s38GaVbDK\n" +
            "ts7nj3CWwEOAqtLsO8+QcXmoEyuIdQQYFgoAHQUCYxXwbQKeAQKbDAUWAgMBAAQL\n" +
            "CQgHBRUKCQgLAAoJEMECsPyaHGnpO7AA/2zF7j5cgxCZ+Ws+ENj6Uzgq47kqsRxa\n" +
            "Ii4kPjW1HmCtAP4rie2Z0ra/1alG/wu2bUtxHgEkeTBsHP8pOM5Xz4JVDZxYBGMV\n" +
            "8G0WCSsGAQQB2kcPAQEHQHofxjdBzpFaLsiyEDRaotbB5/New7vdtAHV7t5rv1BU\n" +
            "AAD/fnI4ilbhsRYaGSGX5ma7VfkgWiK7UQi04YpJVV3HOEYO/ojVBBgWCgB9BQJj\n" +
            "FfBtAp4BApsCBRYCAwEABAsJCAcFFQoJCAtfIAQZFgoABgUCYxXwbQAKCRCUM1S1\n" +
            "VUVbouF5AQDQUJIkFikWriyhSMWEUS52l0i3SlllmPCJuDc1dy389AD9FXCU5+W0\n" +
            "GT2N1hRb8eIf+0aDiVLCdV3folVbuPaNvgcACgkQwQKw/Jocaem+GwD+NJD8EIdP\n" +
            "Nf4Q3IvT9YFXEbilk+mKw3IdV68DsQxEtQoBAPkugEJxuI2XNEdl6sigtGF94q3u\n" +
            "IzX9xT12kqD4GtgO\n" +
            "=slQ4\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";

    private static final String SOFT_REVOCATION = "-----BEGIN PGP SIGNATURE-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "iHsEIBYKAC0FAmMV8kcJEMECsPyaHGnpFiEEnz7Hsz/PgH5RbV2hwQKw/JocaekC\n" +
            "hwACHQMAAMTqAP9XbUer/yjcAUOpbggqC35zrhzXi4/zc6QuuM9NSLnePwD/YZCn\n" +
            "NoE+7B24C/SZVr7d4U0ryB2gNWJdvfMfQnGLaQA=\n" +
            "=d2pq\n" +
            "-----END PGP SIGNATURE-----";
    private static final Date SOFT_REVOCATION_DATE = DateUtil.parseUTCDate("2022-09-05 12:57:43 UTC");

    private static final String HARD_REVOCATION = "-----BEGIN PGP SIGNATURE-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "iHsEIBYKAC0FAmMV8pUJEMECsPyaHGnpFiEEnz7Hsz/PgH5RbV2hwQKw/JocaekC\n" +
            "hwACHQIAAFaCAQCZPxqJHe87GqLjaDuMdTPdI1dT8kuHvBC4LfhMP2VobQEAiCgQ\n" +
            "WMqWZTfJmbhubnUhEnTu/+qPFiHChgDnaJmoMAk=\n" +
            "=pl4A\n" +
            "-----END PGP SIGNATURE-----";

    @Test
    public void testRevocationStateWithDifferentRevocationsMerged() throws IOException, PGPException {
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(KEY);
        PGPPublicKeyRing certificate = PGPainless.extractCertificate(secretKeys);

        KeyRingInfo info = PGPainless.inspectKeyRing(certificate);
        assertTrue(info.getRevocationState().isNotRevoked());

        PGPSignature softRevocation = SignatureUtils.readSignatures(SOFT_REVOCATION).get(0);
        PGPPublicKeyRing softRevoked = KeyRingUtils.injectCertification(certificate, softRevocation);

        info = PGPainless.inspectKeyRing(softRevoked, softRevoked.getPublicKey().getCreationTime());
        assertTrue(info.getRevocationState().isNotRevoked(),
                "Expect: Cert is not revoked at creation time, although we already added soft revocation");

        info = KeyRingInfo.evaluateForSignature(softRevoked, softRevocation);
        assertTrue(info.getRevocationState().isSoftRevocation(), "Expect: Cert is now revoked, since now is after soft revocation creation");
        JUtils.assertDateEquals(SOFT_REVOCATION_DATE, info.getRevocationDate());

        PGPSignature hardRevocation = SignatureUtils.readSignatures(HARD_REVOCATION).get(0);
        PGPPublicKeyRing hardRevoked = KeyRingUtils.injectCertification(certificate, hardRevocation);

        info = PGPainless.inspectKeyRing(hardRevoked);
        assertTrue(info.getRevocationState().isHardRevocation());

        info = PGPainless.inspectKeyRing(hardRevoked, hardRevoked.getPublicKey().getCreationTime());
        assertTrue(info.getRevocationState().isHardRevocation(), "Expect: Key is hard revoked, no matter reference time");

        PGPPublicKeyRing merged = PGPainless.mergeCertificate(certificate, softRevoked);
        info = PGPainless.inspectKeyRing(merged);
        assertTrue(info.getRevocationState().isSoftRevocation());

        merged = PGPainless.mergeCertificate(merged, hardRevoked);
        info = PGPainless.inspectKeyRing(merged);
        assertTrue(info.getRevocationState().isHardRevocation());
    }
}
