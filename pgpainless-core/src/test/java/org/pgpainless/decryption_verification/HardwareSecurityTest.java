// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.key.gnu_dummy_s2k.GnuPGDummyKeyUtil;
import org.pgpainless.key.util.KeyIdUtil;

public class HardwareSecurityTest {

    private static final String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: DE2E 9AB2 6650 8191 53E7  D599 C176 507F 2B5D 43B3\n" +
            "Comment: Alice <alice@pgpainless.org>\n" +
            "\n" +
            "lFgEY1vjgRYJKwYBBAHaRw8BAQdAXjLoPTOIOdvlFT2Nt3rcvLTVx5ujPBGghZ5S\n" +
            "D5tEnyoAAP0fAUJTiPrxZYdzs6MP0KFo+Nmr/wb1PJHTkzmYpt4wkRKBtBxBbGlj\n" +
            "ZSA8YWxpY2VAcGdwYWlubGVzcy5vcmc+iI8EExYKAEEFAmNb44EJEMF2UH8rXUOz\n" +
            "FiEE3i6asmZQgZFT59WZwXZQfytdQ7MCngECmwEFFgIDAQAECwkIBwUVCgkICwKZ\n" +
            "AQAAHLYA/AgW+YrpU+UqrwX2dhY6RAfgHTTMU89RHjaTHJx8pLrBAP4gthGof00a\n" +
            "XEjwTWteDOO049SIp2AUfj9deJqtrQcHD5xdBGNb44ESCisGAQQBl1UBBQEBB0DN\n" +
            "vUT3awa3YLmwf41LRpPrm7B87AOHfYIP8S9QJ4GDJgMBCAcAAP9bwlSaF+lti8JY\n" +
            "qKFO3qt3ZYQMu1l/LRBle89ZB4zD+BDOiHUEGBYKAB0FAmNb44ECngECmwwFFgID\n" +
            "AQAECwkIBwUVCgkICwAKCRDBdlB/K11Ds/TsAP9kvpUrCWnrWGq+a9n1CqEfCMX5\n" +
            "cT+qzrwNf+J0L22KowD+M9SVO0qssiAqutLE9h9dGYLbEiFvsHzK3WSnjKYbIgac\n" +
            "WARjW+OBFgkrBgEEAdpHDwEBB0BCPh8M5TnXSmG6Ygwp4j5RR4u3hmxl8CYjX4h/\n" +
            "XtvvNwAA/RP04coSrLHVI6vUfbJk4MhWYeyhJBRYY0vGp7yq+wVtEpKI1QQYFgoA\n" +
            "fQUCY1vjgQKeAQKbAgUWAgMBAAQLCQgHBRUKCQgLXyAEGRYKAAYFAmNb44EACgkQ\n" +
            "mlozJSF7rXQW+AD/TA3YBxTd+YbBSwfgqzWNbfT9BBcFrdn3uPCsbvfmqXoA/3oj\n" +
            "oupkgoaXesrGxn2k9hW9/GBXSvNcgY2txZ6/oYoIAAoJEMF2UH8rXUOziZ4A/0Xl\n" +
            "xSZJWmkRpBh5AO8Cnqosz6j947IYAxS16ay+sIOHAP9aN9CUNJIIdHnHdFHO4GZz\n" +
            "ejjknn4wt8NVJP97JxlnBQ==\n" +
            "=qSQb\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    @Test
    public void testGetSingleIdOfHardwareBackedKey() throws IOException {
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(KEY);
        assertTrue(HardwareSecurity.getIdsOfHardwareBackedKeys(secretKeys).isEmpty());
        long encryptionKeyId = KeyIdUtil.fromLongKeyId("0AAD8F5891262F50");

        PGPSecretKeyRing withHardwareBackedEncryptionKey = GnuPGDummyKeyUtil.modify(secretKeys)
                .divertPrivateKeysToCard(GnuPGDummyKeyUtil.KeyFilter.only(encryptionKeyId));

        Set<SubkeyIdentifier> hardwareBackedKeys = HardwareSecurity
                .getIdsOfHardwareBackedKeys(withHardwareBackedEncryptionKey);
        assertEquals(Collections.singleton(new SubkeyIdentifier(secretKeys, encryptionKeyId)), hardwareBackedKeys);
    }


    @Test
    public void testGetIdsOfFullyHardwareBackedKey() throws IOException {
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(KEY);
        assertTrue(HardwareSecurity.getIdsOfHardwareBackedKeys(secretKeys).isEmpty());

        PGPSecretKeyRing withHardwareBackedEncryptionKey = GnuPGDummyKeyUtil.modify(secretKeys)
                .divertPrivateKeysToCard(GnuPGDummyKeyUtil.KeyFilter.any());
        Set<SubkeyIdentifier> expected = new HashSet<>();
        for (PGPSecretKey key : secretKeys) {
            expected.add(new SubkeyIdentifier(secretKeys, key.getKeyID()));
        }

        Set<SubkeyIdentifier> hardwareBackedKeys = HardwareSecurity
                .getIdsOfHardwareBackedKeys(withHardwareBackedEncryptionKey);

        assertEquals(expected, hardwareBackedKeys);
    }
}
