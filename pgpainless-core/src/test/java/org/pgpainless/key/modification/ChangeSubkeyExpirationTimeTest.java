// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification;

import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.junit.JUtils;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.EncryptionPurpose;
import org.pgpainless.key.OpenPgpFingerprint;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.DateUtil;

import java.io.IOException;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

public class ChangeSubkeyExpirationTimeTest {

    @Test
    public void changeExpirationTimeOfSubkey() {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().modernKeyRing("Alice")
                .getPGPSecretKeyRing();
        Date now = secretKeys.getPublicKey().getCreationTime();
        Date inAnHour = new Date(now.getTime() + 1000 * 60 * 60);
        OpenPGPCertificate.OpenPGPComponentKey encryptionKey = PGPainless.inspectKeyRing(secretKeys)
                .getEncryptionSubkeys(EncryptionPurpose.ANY).get(0);
        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .setExpirationDateOfSubkey(
                        inAnHour,
                        encryptionKey.getKeyIdentifier().getKeyId(),
                        SecretKeyRingProtector.unprotectedKeys())
                .done();

        JUtils.assertDateEquals(inAnHour, PGPainless.inspectKeyRing(secretKeys)
                .getSubkeyExpirationDate(OpenPgpFingerprint.of(encryptionKey.getPGPPublicKey())));
    }

    @Test
    public void changeExpirationTimeOfExpiredSubkey() throws IOException {
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(
                "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                        "Version: PGPainless\n" +
                        "Comment: CA52 4D5D E3D8 9CD9 105B  BA45 3761 076B C6B5 3000\n" +
                        "Comment: Alice <alice@pgpainless.org>\n" +
                        "\n" +
                        "lFgEZXHykRYJKwYBBAHaRw8BAQdATArrVxPEpuA/wcayAxRl/v1tIYJSe4MCA/fO\n" +
                        "84CFgpcAAP9uZkLjoBIQAjUTEiS8Wk3sui3u4mJ4WVQEpNhQSpq37g8gtBxBbGlj\n" +
                        "ZSA8YWxpY2VAcGdwYWlubGVzcy5vcmc+iJUEExYKAEcFAmVx8pIJEDdhB2vGtTAA\n" +
                        "FiEEylJNXePYnNkQW7pFN2EHa8a1MAACngECmwEFFgIDAQAECwkIBwUVCgkICwWJ\n" +
                        "CWYBgAKZAQAAG3oA/0iJbwyjGOTa2RlgBKdmFjlBG5uwMGheKge/aZBbdUd8AQCB\n" +
                        "8NFWmyLlne4hDMM2g8RFf/W156wnyTH7jTQLx2sZDJxYBGVx8pIWCSsGAQQB2kcP\n" +
                        "AQEHQLQt6ns7yTxLvIWXqFCekh6QEvUumhHvCTjZPXa/UxCNAAEA+FHhZ1uik6PN\n" +
                        "Pwli9Tp9QGddf3pwQw+OL/K7gpZO3sgQHYjVBBgWCgB9BQJlcfKSAp4BApsCBRYC\n" +
                        "AwEABAsJCAcFFQoJCAtfIAQZFgoABgUCZXHykgAKCRCRKlHdDPaYKjyZAQD10Km4\n" +
                        "Qs37yF9bntS+z9Va7AMUuBlzYF5H/nXCRuqQTAEA60q++7Xwj94yLfoAfxH0V6Wd\n" +
                        "L2rDJCDZ3FFMlycToQMACgkQN2EHa8a1MADmDgD9EGzH6pPYRW5vWQGXNsr7PMWK\n" +
                        "LlBnevc0DaVWEHTu9tcA/iezQ9R+A90qcE1+HeNIJbSB89yIoJje2vePRV/JakAI\n" +
                        "nF0EZXHykhIKKwYBBAGXVQEFAQEHQOiLc02OQJD9qdpsyR6bJ52Cu8rUMlEJOELz\n" +
                        "1858OoQyAwEIBwAA/3YkHGmnVaQvUpSwlCInOvHvjLNLH9b9Lh/OxiuSoMgIEASI\n" +
                        "dQQYFgoAHQUCZXHykgKeAQKbDAUWAgMBAAQLCQgHBRUKCQgLAAoJEDdhB2vGtTAA\n" +
                        "1nkBAPAUcHxI1O+fE/QzuLANLHDeWc3Mc09KKnWoTkt/kk5VAQCIPlKQAcmmKdYE\n" +
                        "Tiz8woSKLQKswKr/jVMqnUiGPsU/DoiSBBgWCgBECRA3YQdrxrUwABYhBMpSTV3j\n" +
                        "2JzZEFu6RTdhB2vGtTAABYJlcfL6Ap4BApsMBRYCAwEABAsJCAcFFQoJCAsFiQAA\n" +
                        "AGgAAMNmAQDN/TML2zdgBNkfh7TIqbI4Flx54Yi7qEjSXg0Z+tszHgD/e1Bf+xEs\n" +
                        "BC9ewVsyQsnj3B0FliGYaPiQeoY/FGBmYQs=\n" +
                        "=5Ur6\n" +
                        "-----END PGP PRIVATE KEY BLOCK-----"
        );
        assertNotNull(secretKeys);

        // subkey is expired at 2023-12-07 16:29:46 UTC
        OpenPgpFingerprint encryptionSubkey = new OpenPgpV4Fingerprint("2E541354A23C9943375EC27A3EF133ED8720D636");
        JUtils.assertDateEquals(
                DateUtil.parseUTCDate("2023-12-07 16:29:46 UTC"),
                PGPainless.inspectKeyRing(secretKeys).getSubkeyExpirationDate(encryptionSubkey));

        // re-validate the subkey by setting its expiry to null (no expiry)
        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .setExpirationDateOfSubkey(null, encryptionSubkey.getKeyId(), SecretKeyRingProtector.unprotectedKeys())
                .done();

        assertNull(PGPainless.inspectKeyRing(secretKeys).getSubkeyExpirationDate(encryptionSubkey));
    }
}
