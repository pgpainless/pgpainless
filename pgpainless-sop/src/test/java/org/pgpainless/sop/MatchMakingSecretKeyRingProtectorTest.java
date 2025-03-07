// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.util.Passphrase;

public class MatchMakingSecretKeyRingProtectorTest {

    private static final String PROTECTED_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 0221 626A 3B5A 4705 7A41  7EAB 2B9F C90E 44FA 1947\n" +
            "Comment: Alice\n" +
            "\n" +
            "lIYEY3zkcRYJKwYBBAHaRw8BAQdAzww+ctlV7imTD/LSQlVn3onybSvQa54CIUaN\n" +
            "xN9FDFH+CQMCqDw0ZfofkfxgK7+uSfi7btqa6+o+zGkKfKQCvYCuU5gorD7vyOFL\n" +
            "2ezeQOjb17HHaKbJqLrx+p+LS2uU2f3cwa73PFHwNcBoDLRTrUXjzrQFQWxpY2WI\n" +
            "jwQTFgoAQQUCY3zkcQkQK5/JDkT6GUcWIQQCIWJqO1pHBXpBfqsrn8kORPoZRwKe\n" +
            "AQKbAQUWAgMBAAQLCQgHBRUKCQgLApkBAABTCQD9HCDmb8LlO+n/5jJv7n6gAHCA\n" +
            "UUNAe7xU4WcYSxLpTPIBAOxBmbZiDai0QwDOqNihpwrInu82fRi8OEpSjE/9OrEC\n" +
            "nIsEY3zkcRIKKwYBBAGXVQEFAQEHQBsnJtVYXMaGB4BDcUEKB1v/lsXJ1z+favfn\n" +
            "e73/crYEAwEIB/4JAwKoPDRl+h+R/GBdZY7QJt8TPaXckyOR1eZvUejD+Vw/slB1\n" +
            "3KUwGI/3MG2iJYp924wP67DewZI89eYHu24wN75XxVKAGnUX5n7Dr2JIB79liHUE\n" +
            "GBYKAB0FAmN85HECngECmwwFFgIDAQAECwkIBwUVCgkICwAKCRArn8kORPoZR5bF\n" +
            "APsHLmhDRDV2Ra0BsfQRNI2yMXxVRFD/ZzryWFT/BPNGUAEA9cnhItp9ucqBbeWE\n" +
            "PDzf1vdx5BCNYhRpOqGjGtFgMQGchgRjfORxFgkrBgEEAdpHDwEBB0AAvsniUT76\n" +
            "OeLyq9e1bgdsDLiGrtroSt6wR/B94Dm5uP4JAwKoPDRl+h+R/GC8mQnynSzBJXdy\n" +
            "DFDnxOieEOh7390vs3P4NwULTqV12sAQ6i5MbsIHnFMtYCCA9aOPlpofQ0Sm3m6q\n" +
            "T/uyx9RE1LRiceW5iNUEGBYKAH0FAmN85HECngECmwIFFgIDAQAECwkIBwUVCgkI\n" +
            "C18gBBkWCgAGBQJjfORxAAoJEGiOcMMZDPmyw7QBAJuNTLiNWgieuGOVCAmkaN6g\n" +
            "L6JlYYwqFS88zzDLJJq5AQDwKt+jvKco6Mya3b1NEXogBLhWHTle9deL07NrCwp4\n" +
            "AwAKCRArn8kORPoZR7r0AP0TDUKaooNfW2MWqLWHbbIhdWFIQEYIGnGSFj28y6t1\n" +
            "zQD/UFtpzBP5ZlTUtZCdjNqo9SEPktbiOxTS8m4SW7xeNwE=\n" +
            "=91/N\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";
    private static final String PASSWORD = "sw0rdf1sh";
    private static final String UNPROTECTED_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 9A0A F461 3E00 E1D4 4C29  601E AAF1 12F4 64BB 1E8E\n" +
            "Comment: Bob\n" +
            "\n" +
            "lFgEY3zlDBYJKwYBBAHaRw8BAQdAvHofWedfSBvyW2+gCADX9CptwFzqVea4A2tL\n" +
            "zr3wnwsAAP9ICAoMGkgdNLy3LiVP0q4+OljXcQTIAJbJ2wCpIF9Y7g05tANCb2KI\n" +
            "jwQTFgoAQQUCY3zlDAkQqvES9GS7Ho4WIQSaCvRhPgDh1EwpYB6q8RL0ZLsejgKe\n" +
            "AQKbAQUWAgMBAAQLCQgHBRUKCQgLApkBAAAZ8QD/fEW105B77KBt/OmA0QLTq3GG\n" +
            "5PI6kITM8+2cd60VOzEA/ivzkhmtdvHzmOARBl81Y3LfeRWWm45z/dYDnffk/DcI\n" +
            "nF0EY3zlDBIKKwYBBAGXVQEFAQEHQC1sYpvzEsjCoTOKEllFkWA3U51FXsHbbALq\n" +
            "QfprOrYKAwEIBwAA/3H4zdk83/0A55hJxBIgh3v/+EV1RKPDCjMHjI5ULc7AEa6I\n" +
            "dQQYFgoAHQUCY3zlDAKeAQKbDAUWAgMBAAQLCQgHBRUKCQgLAAoJEKrxEvRkux6O\n" +
            "pEsA/imXUEpj6mKkT4ZBioT7Gn2mUR4iMGS/pt7QBscDX2/PAP9FFRzsaDII1K+i\n" +
            "zW5sHEif9EjgX6ThIpg8z4/5/7yQBZxYBGN85QwWCSsGAQQB2kcPAQEHQDTAYxP0\n" +
            "rH0tjpOKOxdoHKq87n4tYXd1t/A9Nzjbl36AAAD+PMBIpNmN+k3THARd9UGQtLo4\n" +
            "nieLnqbuPVtMps0kQjgQxojVBBgWCgB9BQJjfOUMAp4BApsCBRYCAwEABAsJCAcF\n" +
            "FQoJCAtfIAQZFgoABgUCY3zlDAAKCRB0YfQ676jh4zoMAP98SwGcoy8Vzk8QnQ0X\n" +
            "gziC+4HtmTLuiDVAvrMLpPz5cwD8C40DDHEjrOJs9bgyOeTELXtjq40Wrt2Fld0G\n" +
            "3JJpFAwACgkQqvES9GS7Ho7EXwD7BwICVWrg458XKpy2EXGSI3mGA47EbyyFc9X3\n" +
            "lBzjnCgA/jUBlZE2LhpAyMTbjDC9eAD1iXeTALdRKBeqnZrQTL0N\n" +
            "=OypZ\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";

    @Test
    public void addSamePasswordTwice() throws IOException {
        PGPSecretKeyRing key = PGPainless.readKeyRing().secretKeyRing(PROTECTED_KEY);
        MatchMakingSecretKeyRingProtector protector = new MatchMakingSecretKeyRingProtector();
        protector.addPassphrase(Passphrase.fromPassword(PASSWORD));
        protector.addPassphrase(Passphrase.fromPassword(PASSWORD));
        protector.addSecretKey(key);

        assertTrue(protector.hasPassphraseFor(key.getPublicKey().getKeyID()));
    }

    @Test
    public void addKeyTwiceAndEmptyPasswordTest() throws IOException {
        PGPSecretKeyRing unprotectedKey = PGPainless.readKeyRing().secretKeyRing(UNPROTECTED_KEY);
        MatchMakingSecretKeyRingProtector protector = new MatchMakingSecretKeyRingProtector();
        protector.addSecretKey(unprotectedKey);
        protector.addPassphrase(Passphrase.emptyPassphrase());
        protector.addSecretKey(unprotectedKey);
        assertTrue(protector.hasPassphraseFor(unprotectedKey.getPublicKey().getKeyID()));
    }

    @Test
    public void getEncryptorTest() throws IOException, PGPException {
        PGPSecretKeyRing unprotectedKey = PGPainless.readKeyRing().secretKeyRing(UNPROTECTED_KEY);
        MatchMakingSecretKeyRingProtector protector = new MatchMakingSecretKeyRingProtector();
        protector.addSecretKey(unprotectedKey);
        assertTrue(protector.hasPassphraseFor(unprotectedKey.getPublicKey().getKeyID()));
        assertNull(protector.getEncryptor(unprotectedKey.getPublicKey()));
        assertNull(protector.getDecryptor(unprotectedKey.getPublicKey().getKeyID()));

        PGPSecretKeyRing protectedKey = PGPainless.readKeyRing().secretKeyRing(PROTECTED_KEY);
        protector.addSecretKey(protectedKey);
        protector.addPassphrase(Passphrase.fromPassword(PASSWORD));
        assertNotNull(protector.getEncryptor(protectedKey.getPublicKey()));
        assertNotNull(protector.getDecryptor(protectedKey.getPublicKey().getKeyID()));
    }
}
