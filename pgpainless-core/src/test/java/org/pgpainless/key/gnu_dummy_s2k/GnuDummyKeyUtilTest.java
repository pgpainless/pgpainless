// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.gnu_dummy_s2k;

import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.util.KeyIdUtil;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class GnuDummyKeyUtilTest {
    // normal, non-hw-backed key
    private static final String FULL_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 01FD AB6C E04A 5078 79FE  4A18 C312 C97D A9F7 6A4F\n" +
            "Comment: Hardy Hardware <hardy@hard.ware>\n" +
            "\n" +
            "lFgEY1vSiBYJKwYBBAHaRw8BAQdAQ58lZn/HOtg+1b1KS18odyQ6M4LaDdbJAyRf\n" +
            "eBwCeTQAAPwJN+Xmr0jjN7RA9jgqXnxC/rcWHmdp/j9NdEd7K2Wbxw/rtCBIYXJk\n" +
            "eSBIYXJkd2FyZSA8aGFyZHlAaGFyZC53YXJlPoiPBBMWCgBBBQJjW9KICRDDEsl9\n" +
            "qfdqTxYhBAH9q2zgSlB4ef5KGMMSyX2p92pPAp4BApsBBRYCAwEABAsJCAcFFQoJ\n" +
            "CAsCmQEAAPk2AP922T5TQ7hukFlpxX3ThMhieJnECGY5Eqt5U0/vEY1XdgD/eE1M\n" +
            "l9qqx6QGcaNKe8deMe3EhTant6mS9tqMHp2/3gmcXQRjW9KIEgorBgEEAZdVAQUB\n" +
            "AQdAVXBLNvNmFh9KX6iLmdNJM28Zc9PGnzEoAD9+T4p0lDwDAQgHAAD/fw9hnzeH\n" +
            "VtBaHi6efXvnc4rdVj8zWk0LKo1clFd3bTAN+oh1BBgWCgAdBQJjW9KIAp4BApsM\n" +
            "BRYCAwEABAsJCAcFFQoJCAsACgkQwxLJfan3ak/JyQD9GBj0vjtYZAf5Fi0eEKdi\n" +
            "Ags0yZrQPkMs6eL+83te770A/jG0DeJy+88fOfWTj+mixO98PZPnQ0MybWC/1QUT\n" +
            "vP0BnFgEY1vSiBYJKwYBBAHaRw8BAQdAvSYTD60t8vx10dSEBACUoIfVCpeOB30D\n" +
            "6nfwJtbDT0YAAQCgnCsN9iX7s2TQd8NPggWs4QdhaFpb6olt3SlAvUy/wRBDiNUE\n" +
            "GBYKAH0FAmNb0ogCngECmwIFFgIDAQAECwkIBwUVCgkIC18gBBkWCgAGBQJjW9KI\n" +
            "AAoJEJQCL6VtwFtJDmMBAKqsGfRFQxJXyPgugWBgEaO5lt9fMM0yUxa76cmSWe5f\n" +
            "AQD2oLSEW1GOgIs64+Z3gvtXopmeupT09HhI7ger98zDAwAKCRDDEsl9qfdqTwR6\n" +
            "AP9Xftw8xZ7/MWhYImk/xheqPy07K4qo3T1pGKUvUqjWQQEAhE3r0oTcJn+KVCwG\n" +
            "jF6AYiLOzO/R1x5bSlYD3FeJ3Qo=\n" +
            "=+vXp\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";

    private static final long primaryKeyId = KeyIdUtil.fromLongKeyId("C312C97DA9F76A4F");
    private static final long encryptionKeyId = KeyIdUtil.fromLongKeyId("6924D066714CE8C6");
    private static final long signatureKeyId = KeyIdUtil.fromLongKeyId("94022FA56DC05B49");
    private static final byte[] cardSerial = new byte[] {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    public static final String ALL_KEYS_ON_CARD = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 01FD AB6C E04A 5078 79FE  4A18 C312 C97D A9F7 6A4F\n" +
            "Comment: Hardy Hardware <hardy@hard.ware>\n" +
            "\n" +
            "lEwEY1vSiBYJKwYBBAHaRw8BAQdAQ58lZn/HOtg+1b1KS18odyQ6M4LaDdbJAyRf\n" +
            "eBwCeTT/AGUAR05VAhAAAQIDBAUGBwgJCgsMDQ4PtCBIYXJkeSBIYXJkd2FyZSA8\n" +
            "aGFyZHlAaGFyZC53YXJlPoiPBBMWCgBBBQJjW9KICRDDEsl9qfdqTxYhBAH9q2zg\n" +
            "SlB4ef5KGMMSyX2p92pPAp4BApsBBRYCAwEABAsJCAcFFQoJCAsCmQEAAPk2AP92\n" +
            "2T5TQ7hukFlpxX3ThMhieJnECGY5Eqt5U0/vEY1XdgD/eE1Ml9qqx6QGcaNKe8de\n" +
            "Me3EhTant6mS9tqMHp2/3gmcUQRjW9KIEgorBgEEAZdVAQUBAQdAVXBLNvNmFh9K\n" +
            "X6iLmdNJM28Zc9PGnzEoAD9+T4p0lDwDAQgH/wBlAEdOVQIQAAECAwQFBgcICQoL\n" +
            "DA0OD4h1BBgWCgAdBQJjW9KIAp4BApsMBRYCAwEABAsJCAcFFQoJCAsACgkQwxLJ\n" +
            "fan3ak/JyQD9GBj0vjtYZAf5Fi0eEKdiAgs0yZrQPkMs6eL+83te770A/jG0DeJy\n" +
            "+88fOfWTj+mixO98PZPnQ0MybWC/1QUTvP0BnEwEY1vSiBYJKwYBBAHaRw8BAQdA\n" +
            "vSYTD60t8vx10dSEBACUoIfVCpeOB30D6nfwJtbDT0b/AGUAR05VAhAAAQIDBAUG\n" +
            "BwgJCgsMDQ4PiNUEGBYKAH0FAmNb0ogCngECmwIFFgIDAQAECwkIBwUVCgkIC18g\n" +
            "BBkWCgAGBQJjW9KIAAoJEJQCL6VtwFtJDmMBAKqsGfRFQxJXyPgugWBgEaO5lt9f\n" +
            "MM0yUxa76cmSWe5fAQD2oLSEW1GOgIs64+Z3gvtXopmeupT09HhI7ger98zDAwAK\n" +
            "CRDDEsl9qfdqTwR6AP9Xftw8xZ7/MWhYImk/xheqPy07K4qo3T1pGKUvUqjWQQEA\n" +
            "hE3r0oTcJn+KVCwGjF6AYiLOzO/R1x5bSlYD3FeJ3Qo=\n" +
            "=wsFa\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    public static final String PRIMARY_KEY_ON_CARD = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 01FD AB6C E04A 5078 79FE  4A18 C312 C97D A9F7 6A4F\n" +
            "Comment: Hardy Hardware <hardy@hard.ware>\n" +
            "\n" +
            "lEwEY1vSiBYJKwYBBAHaRw8BAQdAQ58lZn/HOtg+1b1KS18odyQ6M4LaDdbJAyRf\n" +
            "eBwCeTT/AGUAR05VAhAAAQIDBAUGBwgJCgsMDQ4PtCBIYXJkeSBIYXJkd2FyZSA8\n" +
            "aGFyZHlAaGFyZC53YXJlPoiPBBMWCgBBBQJjW9KICRDDEsl9qfdqTxYhBAH9q2zg\n" +
            "SlB4ef5KGMMSyX2p92pPAp4BApsBBRYCAwEABAsJCAcFFQoJCAsCmQEAAPk2AP92\n" +
            "2T5TQ7hukFlpxX3ThMhieJnECGY5Eqt5U0/vEY1XdgD/eE1Ml9qqx6QGcaNKe8de\n" +
            "Me3EhTant6mS9tqMHp2/3gmcXQRjW9KIEgorBgEEAZdVAQUBAQdAVXBLNvNmFh9K\n" +
            "X6iLmdNJM28Zc9PGnzEoAD9+T4p0lDwDAQgHAAD/fw9hnzeHVtBaHi6efXvnc4rd\n" +
            "Vj8zWk0LKo1clFd3bTAN+oh1BBgWCgAdBQJjW9KIAp4BApsMBRYCAwEABAsJCAcF\n" +
            "FQoJCAsACgkQwxLJfan3ak/JyQD9GBj0vjtYZAf5Fi0eEKdiAgs0yZrQPkMs6eL+\n" +
            "83te770A/jG0DeJy+88fOfWTj+mixO98PZPnQ0MybWC/1QUTvP0BnFgEY1vSiBYJ\n" +
            "KwYBBAHaRw8BAQdAvSYTD60t8vx10dSEBACUoIfVCpeOB30D6nfwJtbDT0YAAQCg\n" +
            "nCsN9iX7s2TQd8NPggWs4QdhaFpb6olt3SlAvUy/wRBDiNUEGBYKAH0FAmNb0ogC\n" +
            "ngECmwIFFgIDAQAECwkIBwUVCgkIC18gBBkWCgAGBQJjW9KIAAoJEJQCL6VtwFtJ\n" +
            "DmMBAKqsGfRFQxJXyPgugWBgEaO5lt9fMM0yUxa76cmSWe5fAQD2oLSEW1GOgIs6\n" +
            "4+Z3gvtXopmeupT09HhI7ger98zDAwAKCRDDEsl9qfdqTwR6AP9Xftw8xZ7/MWhY\n" +
            "Imk/xheqPy07K4qo3T1pGKUvUqjWQQEAhE3r0oTcJn+KVCwGjF6AYiLOzO/R1x5b\n" +
            "SlYD3FeJ3Qo=\n" +
            "=s+B1\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    public static final String ENCRYPTION_KEY_ON_CARD = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 01FD AB6C E04A 5078 79FE  4A18 C312 C97D A9F7 6A4F\n" +
            "Comment: Hardy Hardware <hardy@hard.ware>\n" +
            "\n" +
            "lFgEY1vSiBYJKwYBBAHaRw8BAQdAQ58lZn/HOtg+1b1KS18odyQ6M4LaDdbJAyRf\n" +
            "eBwCeTQAAPwJN+Xmr0jjN7RA9jgqXnxC/rcWHmdp/j9NdEd7K2Wbxw/rtCBIYXJk\n" +
            "eSBIYXJkd2FyZSA8aGFyZHlAaGFyZC53YXJlPoiPBBMWCgBBBQJjW9KICRDDEsl9\n" +
            "qfdqTxYhBAH9q2zgSlB4ef5KGMMSyX2p92pPAp4BApsBBRYCAwEABAsJCAcFFQoJ\n" +
            "CAsCmQEAAPk2AP922T5TQ7hukFlpxX3ThMhieJnECGY5Eqt5U0/vEY1XdgD/eE1M\n" +
            "l9qqx6QGcaNKe8deMe3EhTant6mS9tqMHp2/3gmcUQRjW9KIEgorBgEEAZdVAQUB\n" +
            "AQdAVXBLNvNmFh9KX6iLmdNJM28Zc9PGnzEoAD9+T4p0lDwDAQgH/wBlAEdOVQIQ\n" +
            "AAECAwQFBgcICQoLDA0OD4h1BBgWCgAdBQJjW9KIAp4BApsMBRYCAwEABAsJCAcF\n" +
            "FQoJCAsACgkQwxLJfan3ak/JyQD9GBj0vjtYZAf5Fi0eEKdiAgs0yZrQPkMs6eL+\n" +
            "83te770A/jG0DeJy+88fOfWTj+mixO98PZPnQ0MybWC/1QUTvP0BnFgEY1vSiBYJ\n" +
            "KwYBBAHaRw8BAQdAvSYTD60t8vx10dSEBACUoIfVCpeOB30D6nfwJtbDT0YAAQCg\n" +
            "nCsN9iX7s2TQd8NPggWs4QdhaFpb6olt3SlAvUy/wRBDiNUEGBYKAH0FAmNb0ogC\n" +
            "ngECmwIFFgIDAQAECwkIBwUVCgkIC18gBBkWCgAGBQJjW9KIAAoJEJQCL6VtwFtJ\n" +
            "DmMBAKqsGfRFQxJXyPgugWBgEaO5lt9fMM0yUxa76cmSWe5fAQD2oLSEW1GOgIs6\n" +
            "4+Z3gvtXopmeupT09HhI7ger98zDAwAKCRDDEsl9qfdqTwR6AP9Xftw8xZ7/MWhY\n" +
            "Imk/xheqPy07K4qo3T1pGKUvUqjWQQEAhE3r0oTcJn+KVCwGjF6AYiLOzO/R1x5b\n" +
            "SlYD3FeJ3Qo=\n" +
            "=TPAl\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    public static final String SIGNATURE_KEY_ON_CARD = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 01FD AB6C E04A 5078 79FE  4A18 C312 C97D A9F7 6A4F\n" +
            "Comment: Hardy Hardware <hardy@hard.ware>\n" +
            "\n" +
            "lFgEY1vSiBYJKwYBBAHaRw8BAQdAQ58lZn/HOtg+1b1KS18odyQ6M4LaDdbJAyRf\n" +
            "eBwCeTQAAPwJN+Xmr0jjN7RA9jgqXnxC/rcWHmdp/j9NdEd7K2Wbxw/rtCBIYXJk\n" +
            "eSBIYXJkd2FyZSA8aGFyZHlAaGFyZC53YXJlPoiPBBMWCgBBBQJjW9KICRDDEsl9\n" +
            "qfdqTxYhBAH9q2zgSlB4ef5KGMMSyX2p92pPAp4BApsBBRYCAwEABAsJCAcFFQoJ\n" +
            "CAsCmQEAAPk2AP922T5TQ7hukFlpxX3ThMhieJnECGY5Eqt5U0/vEY1XdgD/eE1M\n" +
            "l9qqx6QGcaNKe8deMe3EhTant6mS9tqMHp2/3gmcXQRjW9KIEgorBgEEAZdVAQUB\n" +
            "AQdAVXBLNvNmFh9KX6iLmdNJM28Zc9PGnzEoAD9+T4p0lDwDAQgHAAD/fw9hnzeH\n" +
            "VtBaHi6efXvnc4rdVj8zWk0LKo1clFd3bTAN+oh1BBgWCgAdBQJjW9KIAp4BApsM\n" +
            "BRYCAwEABAsJCAcFFQoJCAsACgkQwxLJfan3ak/JyQD9GBj0vjtYZAf5Fi0eEKdi\n" +
            "Ags0yZrQPkMs6eL+83te770A/jG0DeJy+88fOfWTj+mixO98PZPnQ0MybWC/1QUT\n" +
            "vP0BnEwEY1vSiBYJKwYBBAHaRw8BAQdAvSYTD60t8vx10dSEBACUoIfVCpeOB30D\n" +
            "6nfwJtbDT0b/AGUAR05VAhAAAQIDBAUGBwgJCgsMDQ4PiNUEGBYKAH0FAmNb0ogC\n" +
            "ngECmwIFFgIDAQAECwkIBwUVCgkIC18gBBkWCgAGBQJjW9KIAAoJEJQCL6VtwFtJ\n" +
            "DmMBAKqsGfRFQxJXyPgugWBgEaO5lt9fMM0yUxa76cmSWe5fAQD2oLSEW1GOgIs6\n" +
            "4+Z3gvtXopmeupT09HhI7ger98zDAwAKCRDDEsl9qfdqTwR6AP9Xftw8xZ7/MWhY\n" +
            "Imk/xheqPy07K4qo3T1pGKUvUqjWQQEAhE3r0oTcJn+KVCwGjF6AYiLOzO/R1x5b\n" +
            "SlYD3FeJ3Qo=\n" +
            "=p8I9\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    @Test
    public void testMoveAllKeysToCard() throws IOException {
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(FULL_KEY);
        PGPSecretKeyRing expected = PGPainless.readKeyRing().secretKeyRing(ALL_KEYS_ON_CARD);

        PGPSecretKeyRing onCard = GnuDummyKeyUtil.modify(secretKeys)
                .divertPrivateKeysToCard(GnuDummyKeyUtil.KeyFilter.any(), cardSerial);

        for (PGPSecretKey key : onCard) {
            assertEquals(255, key.getS2KUsage());
            S2K s2K = key.getS2K();
            assertEquals(S2K.GNU_PROTECTION_MODE_DIVERT_TO_CARD, s2K.getProtectionMode());
        }

        assertArrayEquals(expected.getEncoded(), onCard.getEncoded());
    }

    @Test
    public void testMovePrimaryKeyToCard() throws IOException {
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(FULL_KEY);
        PGPSecretKeyRing expected = PGPainless.readKeyRing().secretKeyRing(PRIMARY_KEY_ON_CARD);

        PGPSecretKeyRing onCard = GnuDummyKeyUtil.modify(secretKeys)
                .divertPrivateKeysToCard(GnuDummyKeyUtil.KeyFilter.only(primaryKeyId), cardSerial);

        assertArrayEquals(expected.getEncoded(), onCard.getEncoded());
    }

    @Test
    public void testMoveEncryptionKeyToCard() throws IOException {
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(FULL_KEY);
        PGPSecretKeyRing expected = PGPainless.readKeyRing().secretKeyRing(ENCRYPTION_KEY_ON_CARD);

        PGPSecretKeyRing onCard = GnuDummyKeyUtil.modify(secretKeys)
                .divertPrivateKeysToCard(GnuDummyKeyUtil.KeyFilter.only(encryptionKeyId), cardSerial);

        assertArrayEquals(expected.getEncoded(), onCard.getEncoded());
    }

    @Test
    public void testMoveSigningKeyToCard() throws IOException {
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(FULL_KEY);
        PGPSecretKeyRing expected = PGPainless.readKeyRing().secretKeyRing(SIGNATURE_KEY_ON_CARD);

        PGPSecretKeyRing onCard = GnuDummyKeyUtil.modify(secretKeys)
                .divertPrivateKeysToCard(GnuDummyKeyUtil.KeyFilter.only(signatureKeyId), cardSerial);

        assertArrayEquals(expected.getEncoded(), onCard.getEncoded());
    }
}
