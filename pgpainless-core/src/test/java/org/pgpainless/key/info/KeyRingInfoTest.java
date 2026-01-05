// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>, 2021 Flowcrypt a.s.
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.info;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.junit.JUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.EncryptionPurpose;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.OpenPGPKeyVersion;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.bouncycastle.extensions.PGPSecretKeyExtensionsKt;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa_legacy.EdDSALegacyCurve;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnprotectedKeysProtector;
import org.pgpainless.key.util.RevocationAttributes;
import org.pgpainless.util.DateUtil;
import org.pgpainless.util.Passphrase;
import org.pgpainless.util.TestAllImplementations;

public class KeyRingInfoTest {

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testWithEmilsKeys() throws IOException, PGPException {
        PGPainless api = PGPainless.getInstance();

        OpenPGPKey secretKeys = TestKeys.getEmilKey();
        OpenPGPCertificate publicKeys = TestKeys.getEmilCertificate();
        KeyRingInfo sInfo = api.inspect(secretKeys);
        KeyRingInfo pInfo = api.inspect(publicKeys);

        assertEquals(TestKeys.EMIL_KEY_ID, sInfo.getKeyIdentifier().getKeyId());
        assertEquals(TestKeys.EMIL_KEY_ID, pInfo.getKeyIdentifier().getKeyId());
        assertEquals(TestKeys.EMIL_FINGERPRINT, sInfo.getFingerprint());
        assertEquals(TestKeys.EMIL_FINGERPRINT, pInfo.getFingerprint());
        assertEquals(PublicKeyAlgorithm.ECDSA, sInfo.getAlgorithm());
        assertEquals(PublicKeyAlgorithm.ECDSA, pInfo.getAlgorithm());

        assertEquals(Arrays.asList(KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA, KeyFlag.AUTHENTICATION), pInfo.getKeyFlagsOf(TestKeys.EMIL_UID));
        assertEquals(Arrays.asList(KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA, KeyFlag.AUTHENTICATION), sInfo.getKeyFlagsOf(TestKeys.EMIL_UID));
        assertEquals(Collections.emptyList(), pInfo.getKeyFlagsOf("invalid@user.id"));
        assertEquals(Collections.emptyList(), sInfo.getKeyFlagsOf("invalid@user.id"));

        assertEquals(2, sInfo.getPublicKeys().size());
        assertEquals(2, pInfo.getPublicKeys().size());

        assertEquals(2, sInfo.getSecretKeys().size());
        assertEquals(0, pInfo.getSecretKeys().size());

        assertEquals(Collections.singletonList("<emil@email.user>"), sInfo.getUserIds());
        assertEquals(Collections.singletonList("<emil@email.user>"), pInfo.getUserIds());
        assertEquals(Collections.singletonList("emil@email.user"), sInfo.getEmailAddresses());
        assertEquals(Collections.singletonList("emil@email.user"), pInfo.getEmailAddresses());
        assertEquals(OpenPGPKeyVersion.v4, sInfo.getVersion());
        assertEquals(OpenPGPKeyVersion.v4, pInfo.getVersion());

        assertTrue(sInfo.isSecretKey());
        assertFalse(pInfo.isSecretKey());
        assertTrue(sInfo.isFullyDecrypted());
        assertTrue(pInfo.isFullyDecrypted());

        assertEquals(TestKeys.EMIL_CREATION_DATE, sInfo.getCreationDate());
        assertEquals(TestKeys.EMIL_CREATION_DATE, pInfo.getCreationDate());
        assertNull(sInfo.getPrimaryKeyExpirationDate());
        assertNull(pInfo.getPrimaryKeyExpirationDate());
        assertEquals(TestKeys.EMIL_CREATION_DATE.getTime(), sInfo.getLastModified().getTime(), 50);
        assertEquals(TestKeys.EMIL_CREATION_DATE.getTime(), pInfo.getLastModified().getTime(), 50);

        assertNull(sInfo.getRevocationDate());
        assertNull(pInfo.getRevocationDate());
        Date revocationDate = DateUtil.now();
        OpenPGPKey revoked = api.modify(secretKeys).revoke(
                new UnprotectedKeysProtector(),
                RevocationAttributes.createKeyRevocation()
                        .withReason(RevocationAttributes.Reason.KEY_RETIRED)
                        .withoutDescription()
        ).done();
        KeyRingInfo rInfo = api.inspect(revoked);
        assertNotNull(rInfo.getRevocationDate());
        assertEquals(revocationDate.getTime(), rInfo.getRevocationDate().getTime(), 5);
        assertEquals(revocationDate.getTime(), rInfo.getLastModified().getTime(), 5);

        assertFalse(pInfo.isKeyValidlyBound(new KeyIdentifier(1230)));
        assertFalse(sInfo.isKeyValidlyBound(new KeyIdentifier(1230)));
    }

    @Test
    public void testIsFullyDecrypted() throws IOException, PGPException {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = TestKeys.getEmilKey();
        KeyRingInfo info = api.inspect(secretKeys);

        assertTrue(info.isFullyDecrypted());

        secretKeys = encryptSecretKeys(secretKeys, api);
        info = api.inspect(secretKeys);

        assertFalse(info.isFullyDecrypted());
    }

    @Test
    public void testIsFullyEncrypted() throws IOException, PGPException {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = TestKeys.getEmilKey();
        KeyRingInfo info = api.inspect(secretKeys);

        assertFalse(info.isFullyEncrypted());

        secretKeys = encryptSecretKeys(secretKeys, api);
        info = api.inspect(secretKeys);

        assertTrue(info.isFullyEncrypted());
    }

    private static OpenPGPKey encryptSecretKeys(OpenPGPKey secretKeys, PGPainless api) throws PGPException {
        return api.modify(secretKeys)
                .changePassphraseFromOldPassphrase(Passphrase.emptyPassphrase())
                .withSecureDefaultSettings()
                .toNewPassphrase(Passphrase.fromPassword("sw0rdf1sh"))
                .done();
    }


    @Test
    public void testGetSecretKey() throws IOException, PGPException {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = TestKeys.getCryptieKey();
        OpenPGPCertificate publicKeys = secretKeys.toCertificate();

        KeyRingInfo info = api.inspect(secretKeys);
        OpenPGPKey.OpenPGPSecretKey primarySecretKey = info.getSecretKey();
        assertNotNull(primarySecretKey);
        assertEquals(secretKeys.getPrimarySecretKey().getPGPSecretKey(), primarySecretKey.getPGPSecretKey());

        info = api.inspect(publicKeys);
        assertNull(info.getSecretKey());
    }

    @Test
    public void testGetPublicKey() throws IOException, PGPException {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = TestKeys.getCryptieKey();

        KeyRingInfo info = api.inspect(secretKeys);
        assertEquals(secretKeys.getPrimaryKey().getPGPPublicKey(), info.getPrimaryKey().getPGPPublicKey());

        assertEquals(secretKeys.getPrimarySecretKey().getPGPSecretKey(),
                secretKeys.getPGPSecretKeyRing().getSecretKey(secretKeys.getKeyIdentifier()));
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void dummyS2KTest() throws IOException {

        String withDummyS2K = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "\n" +
                "lQCVBFZuSwwBBAC04VdUUq2REb7+IF/x21yOV3kIn798XRl7A7RiGcE9VpBjT5xM\n" +
                "xtghWhH1mxyT+nrS36OJxdvtgJb3NB6hhh3qBQC6DmCGbWe61tT6TfyFbN6OvzZK\n" +
                "MEa6RMunyd+2ErX4RLOcO+9X7a0weVASH5wRYjjqQtvPvt1/k25sloPnZQARAQAB\n" +
                "/gNlAkdOVQG0EyA8dGVzdEBleGFtcGxlLmNvbT6IuAQTAQIAIgUCVm5LDAIbLwYL\n" +
                "CQgHAwIGFQgCCQoLBBYCAwECHgECF4AACgkQwaXYFkPfLEVROQP/RF4GXi/yGm6y\n" +
                "QoDNXFkFiwNhJndayfZxf5Qa+JWz1ltLyal7Dm1c+U6/R/7D25gmEslI+5YrHpbE\n" +
                "xWXyfG8DbX/5Ef9Be04e9IvjoZboeRpxmyb8IflEw90tJGL8YAK2xWohvayigPnj\n" +
                "jhycZQPMuMK9X35o89oJs+p1MxcC9EOwAgAAnQH9BFZuSwwBBADBDfq8oUK8Jr8I\n" +
                "VkQEEEZzQ7AWh03oTVodROebMz4vAk34HkrebZuxT4U/8yFIP+kJ3Yie3T8V6F8j\n" +
                "F3a3ZUHNj2ghgxMbPH+kRKwBphvX8Fb5GtoFVbJq1tNMDaLhVRIkDLBTqQp/20sp\n" +
                "cuU5+OMzQRUt+Z6GxMaUwt5zLHPUgwARAQAB/gMDAvozhXZdexxPYMKrp7yC2FNN\n" +
                "pVAC61hD0VQKvFeeeXZIGOBx57F1wVBNjuPyglji0kaX0m9yYI+I1V546END4aV/\n" +
                "hXlZve3r6qYVE9W+T1imwx1NXPSb0j/nMmdiFYFXuyz70yEO+cDwHONzmRLdBZlP\n" +
                "1DKYBcjF7rwF0gWuIoWgDYdfECo/aANSRQtKw5Q6UowQLzpHTV+X6iL/CbjIL5f8\n" +
                "1KXPMO1AubxzAW+iatzI7jfL0MvA1FxRpMjpHc1uyT8oIfic17PklbjcnLe5GH78\n" +
                "2AEGhXwn4bY1H+ss0bxmkJV9HkcMokJUVMQxKw+a6+/IuLXdFtcA5z4CDeIbt9rv\n" +
                "+b8s0bfq9aW4kDxG3PDcyoMTrTuJLBd6/XwJgdtrmLSCtlU4fLzZEoAd2FVyWbS6\n" +
                "Nys3eXgIBkRRokzKANknne78LpvIiamzinb0iJk2X+AYnRKoy1pUsC+unqaXm9YH\n" +
                "fdpxv/OXLe13zhSJAT0EGAECAAkFAlZuSwwCGy4AqAkQwaXYFkPfLEWdIAQZAQIA\n" +
                "BgUCVm5LDAAKCRBv1XiTGF5T/qsmA/9LOUNetM1QtsJ71OVdXE3dutUZULE/27DT\n" +
                "rA/vvSfhzSFj3U3FnyI7AVsiiiwmnJnthf0zaa2HYBL844Bm7drtzGBNVvddgIJZ\n" +
                "KBE0x2vUlTVc661e2FBhtLh6xX2nhEy9owc+C7PR9OXvGiET8tTRnUDUO3PgPkyA\n" +
                "LkHfQMWMR11sA/0YQl4wf3knjk83DVVhFK5fT2lW4hmSO74tuCAA4V71C8B5rJzV\n" +
                "q2vy1L2bGHAroe+LtX30LtZM5qWKzZzK7jjo1/eaXimOkJcnnpg6jmUP7TMkWpU7\n" +
                "hlOQ3ZHjS2K5xJYJqBwP86TWPtDLxYD3mTlYtp2dDT8ogV/sEPPd44yWlrACAAA=\n" +
                "=gU+0\n" +
                "-----END PGP PRIVATE KEY BLOCK-----\n";

        OpenPGPKey secretKeys = PGPainless.getInstance().readKey().parseKey(withDummyS2K);
        assertTrue(PGPSecretKeyExtensionsKt.hasDummyS2K(secretKeys.getPrimarySecretKey().getPGPSecretKey()));
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testGetKeysWithFlagsAndExpiry() throws PGPException {
        Date oneHourAgo = new Date(new Date().getTime() - 1000 * 60 * 60);
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = api._buildKey(OpenPGPKeyVersion.v4, oneHourAgo)
                .withPrimaryKey()
                .addEncryptionSubkey()
                .addSigningSubkey()
                .addUserId("Alice <alice@pgpainless.org>")
                .build();

        Iterator<PGPSecretKey> keys = secretKeys.getPGPSecretKeyRing().iterator();
        Date now = DateUtil.now();

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(now);
        calendar.add(Calendar.DATE, 5);
        Date primaryKeyExpiration = calendar.getTime(); // in 5 days
        PGPSecretKey primaryKey = keys.next();

        calendar.setTime(now);
        calendar.add(Calendar.DATE, 10);
        PGPSecretKey encryptionKey = keys.next();

        calendar.setTime(now);
        calendar.add(Calendar.DATE, 3);
        PGPSecretKey signingKey = keys.next();

        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();
        secretKeys = api.modify(secretKeys)
                .setExpirationDate(primaryKeyExpiration, protector)
                .done();

        KeyRingInfo info = api.inspect(secretKeys);

        List<OpenPGPCertificate.OpenPGPComponentKey> encryptionKeys = info.getKeysWithKeyFlag(KeyFlag.ENCRYPT_STORAGE);
        assertEquals(1, encryptionKeys.size());
        assertEquals(encryptionKey.getKeyIdentifier(), encryptionKeys.get(0).getKeyIdentifier());

        List<OpenPGPCertificate.OpenPGPComponentKey> signingKeys = info.getKeysWithKeyFlag(KeyFlag.SIGN_DATA);
        assertEquals(1, signingKeys.size());
        assertEquals(signingKey.getKeyIdentifier(), signingKeys.get(0).getKeyIdentifier());

        List<OpenPGPCertificate.OpenPGPComponentKey> certKeys = info.getKeysWithKeyFlag(KeyFlag.CERTIFY_OTHER);
        assertEquals(1, certKeys.size());
        assertEquals(primaryKey.getKeyIdentifier(), certKeys.get(0).getKeyIdentifier());

        assertNotNull(info.getPrimaryKeyExpirationDate());
        assertEquals(primaryKeyExpiration.getTime(), info.getPrimaryKeyExpirationDate().getTime(), 5);

        // Encryption key expires after primary key, so we return primary key expiration instead.
        Date encryptExpDate = info.getExpirationDateForUse(KeyFlag.ENCRYPT_STORAGE);
        assertNotNull(encryptExpDate);
        assertEquals(primaryKeyExpiration.getTime(), encryptExpDate.getTime(), 5);

    }

    @Test
    public void subkeyIsHardRevokedTest() throws IOException {
        String KEY = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
                "\n" +
                "xsBNBFpJegABCAC1ePFquP0135m8DYhcybhv7l+ecojitFOd/jRM7hCczIqKgalD\n" +
                "1Ro1gNr3VmH6FjRIKIvGT+sOzCKne1v3KyAAPoxtwxjkATTKdOGo15I6v5ZjmO1d\n" +
                "rLQOLSt1TF7XbQSt+ns6PUZWJL907DvECUU5b9FkNUqfQ14QqY+gi7MOyAQez3b7\n" +
                "Pg5Cyz/kVWQ6TSMW/myDEDEertQ4rDBsptEDFHCC2+iF4hO2LqfiCriu5qyLcKCQ\n" +
                "pd6dEuwJQ/jjT0D9A9Fwf+i04x6ZPKSU9oNAWqn8OSAq3/0B/hu9V+0U0iHPnJxe\n" +
                "quykvJk7maxhiGhxBWYXTvDJmoon0NOles7LABEBAAHCwHwEHwEKAA8Fgl4L4QAC\n" +
                "FQoCmwMCHgEAIQkQaE+tYtwDj7sWIQTy0VCk/piSXVHpFTloT61i3AOPu8ffB/9Q\n" +
                "60dg60qhA2rPnd/1dCL2B+c8RWnq44PpijE3gA1RQvcRQE5jNzMSo/MnG0mSL5wH\n" +
                "eTsjSd/DRI3nHP06rs6Qub11NoKhNuya3maz9gyzeZMc/jNib83/BzFCrxsSQm+9\n" +
                "WHurxXeWXOPMLZs3xS/jG0EDtCJ2Fm4UF19fcIydwN/ssF4NGpfCY82+wTSx4joI\n" +
                "3cRKObCFJaaBgG5nl+eFr7cfjEIuqCJCaQsXiqBe7d6V3KqN18t+CgSaybMZXcys\n" +
                "Q/USxEkLhIB2pOZwcz4E3TTFgxRAxcr4cs4Bd2PRz3Z5FKTzo0ma/Ft0UfFJR+fC\n" +
                "cs55+n6kC9K0y/E7BY2hwsB8BB8BCgAPBYJaSXoAAhUKApsDAh4BACEJEGhPrWLc\n" +
                "A4+7FiEE8tFQpP6Ykl1R6RU5aE+tYtwDj7uqDQf7BqTD6GNTwXPOt/0kHQPYmbdI\n" +
                "tX+pWP+o3jaB6VTHDXcn27bttA5M82EXZfae4+bC1dMB+1uLal4ciVgO9ImJC9Nw\n" +
                "s5fc3JH4R5uuSvpjzjudkJsGu3cAKE3hwiT93Mi6t6ENpLCDSxqxzAmfoOQbVJYW\n" +
                "Y7gP7Z4Cj0IAP29aprEc0JWoMjHKpKgYF6u0sWgHWBuEXk/6o6GYb2HZYK4ycpY2\n" +
                "WXKgVhy7/iQDYO1FOfcWQXHVGLn8OzILjobKohNenTT20ZhAASi3LUDSDMTQfxSS\n" +
                "Vt0nhzWuXJJ4R8PzUVeRJ0A0oMyjZVHivHC6GwMsiQuSUTx8e/GnOByOqfGne80S\n" +
                "anVsaWV0QGV4YW1wbGUub3JnwsBzBBMBCgAGBYJaSXoAACEJEGhPrWLcA4+7FiEE\n" +
                "8tFQpP6Ykl1R6RU5aE+tYtwDj7tDfQf+PnxsIFu/0juKBUjjtAYfRzkrrYtMepPj\n" +
                "taTvGfo1SzUkX/6F/GjdSeVg5Iq6YcBrj8c+cB3EoZpHnScTgWQHwceWQLd9Hhbg\n" +
                "TrUNvW1eg2CVzN0RBuYMtWu9JM4pH7ssJW1NmN+/N9B67qb2y+JfBwH/la508NzC\n" +
                "rl3xWTxjT5wNy+FGkNZg23s/0qlO2uxCjc+mRAuAlp5EmTOVWOIBbM0xttjBOx39\n" +
                "ZmWWQKJZ0nrFjK1jppHqazwWWNX7RHkK81tlbSUtOPoTIJDz38NaiyMcZH3p9okN\n" +
                "3DU4XtF+oE18M+Z/E0xUQmumbkajFzcUjmd7enozP5BnGESzdNS5Xc7ATQRaSsuA\n" +
                "AQgAykb8tqlWXtqHGGkBqAq3EnpmvBqrKvqejjtZKAXqEszJ9NlibCGUuLwnNOVO\n" +
                "R/hcOUlOGH+cyMcApBWJB+7d/83K1eCCdv88nDFVav7hKLKlEBbZJNHgHpJ313pl\n" +
                "etzCR4x3STEISrEtO71l2HBdrKSYXaxGgILxYwcSi3i2EjzxRDy+0zyy8s7d+OD5\n" +
                "ShFYexgSrKH3Xx1cxQAJzGGJVx75HHU9GVh3xHwJ7nDm26KzHegG2XPIBXJ2z8vm\n" +
                "sSVTWyj0AjT4kVVapN0f84AKKjyQ7fguCzXGHFV9jmxDx+YH+9HhjIrHSzbDx6+4\n" +
                "wyRsxj7Su+hu/bogJ28nnbTzQwARAQABwsBzBCgBCgAGBYJcKq2AACEJEGhPrWLc\n" +
                "A4+7FiEE8tFQpP6Ykl1R6RU5aE+tYtwDj7u9+wf/Wl2BqJzeAw06pbpT8AEn8Sw4\n" +
                "Hmv5o5LiTOMgCLlX8vK9aIwFGJj/BZW0BAY70JUWUrk0nSjYD16vlVUwKJ8SifTu\n" +
                "eElBYp2I/wkin3FSng3Ewv1iRN5XoQMallKf3EHCbf4LnO1UqzzuIlKWLShl7oIZ\n" +
                "hIQIqzelLJ0Y/2eOTAgoh9Wd3+aLLo7Yp7cUO6yrxBjTOS31yC2gQ3mQv7TWiQ+Z\n" +
                "I0oUTfxFdUAF2efEqpfePYnPDgy0W0fhJEShO/jyAKqhiwT6YdV2Q+IONL1k7su2\n" +
                "N6DkV7T4myGhRAaey/XOEZzLxYg9Jlromc6PZxVLug1nyQOc3ETrUslTfZ1hHMLB\n" +
                "rAQYAQoACQWCXgvhAAKbAgFXCRBoT61i3AOPu8B0oAQZAQoABgWCXgvhAAAhCRBK\n" +
                "cjSjoSE6ZRYhBFF5LA5I4v2pTpO5EUpyNKOhITplp0kIAIrv83RJh3+lm8H27P3O\n" +
                "hTm3z8Rrsy5EK+H2SnKivNTLUdZodVlSyUYF1uLvHB7Wch+aU4Z4DHFIss1rGtIO\n" +
                "iWs/MOrK/1r93tanUwiE7JDK1gg2qA4Q9rXgI5lrpPbvGQTye8YZnvkP1EPdMaJk\n" +
                "PzXQiWn4q5Ng7Pdqeze0SkhEtSssAYXzjSWz8NU3WfTLbPgxo5LnGG3vmcz8ay6V\n" +
                "l7q9QUhhKgbUwBlt3Uv8acAWDZYWrFx42DK+B3iGGGDsfqEeSYA2KFX6dpNA8Cv0\n" +
                "F6IG42vv1Y7/i613TWNLdWwN+RTZ5et+zPIgja17yKERQEWzcoHvHP40lhjywf7S\n" +
                "MjYWIQTy0VCk/piSXVHpFTloT61i3AOPuxS8CACtRp4DTJ67sVjOBKIISk0pija3\n" +
                "eqf3d1rHfsttNfQOzc/uDsnZBA75jVVYZVHH4Dn9i+gX+t8HTdIaPjg4QrjUqh3u\n" +
                "jS9TYXSE2zBpw3Sm+eyCAfQriRaSC5/S2dRIuiTxKZqYkhGi/lSbdXzJ33PI7RfD\n" +
                "d1nEVXybKtWrJV3vDaYO9PWFYJtjl7DVoJLZfX3IruBDU8m0Bo6TfVk2tWlNZ5JK\n" +
                "OjVKCH47TPjzuFVO8dNDPnUybGBoZ3PehLU/BH0gCBQSmUQJDARYRHHZMWvIQiiN\n" +
                "/p8iN4E6tE3BUk98MtOQJqFe8JYM1ADLFuzFdjaRu3ybpdkO6bisPrnQVHNEwsGs\n" +
                "BBgBCgAJBYJa6P+AApsCAVcJEGhPrWLcA4+7wHSgBBkBCgAGBYJa6P+AACEJEEpy\n" +
                "NKOhITplFiEEUXksDkji/alOk7kRSnI0o6EhOmXhRwf/do4VE16xIIaOg2IZlRbl\n" +
                "2tzRoQIyMmaN8mBzKC/Wmdw1Mo8YQMkQ6SNgq2oUOCbD4Xo9pvt3x1mt+P7W+ZqR\n" +
                "2BVhGoUL3VkhQnFO6djVCnKtszQOosTtvn0EIZm62EfkxcWJoS4whlDbdeBP12iC\n" +
                "9VcT0DgOSm4kT6WvAbFDZTYpPQEj1sp9GQNK4ydWVe5yWq11W7mQxHFA7g5t3AOb\n" +
                "bqe47gfH089gQ3INymvjnDxM9BoGX6vSuNHYt6/SBywYTTx4nhVSI/Y/ycjJ071T\n" +
                "nHjNyf0W9DAliVW1zQSqUTA4mwkIfu326skBDP8yKZpNE4AaU2WajD9IMWHViJk9\n" +
                "SBYhBPLRUKT+mJJdUekVOWhPrWLcA4+7TrYIAIYAKrzgdeNi9kpEt2SHcLoQLViz\n" +
                "xwrRMATqhrT/GdtOK6gJm5ycps6O+/jk/kknJw068MzlCZwotKj1MX7sYbx8ZwcQ\n" +
                "SI2qDHBfvoirKhdb3+lrlzo2ydTfCNPKQdp4obeTMSGfazBg3gEo+/V+yPSY87Hd\n" +
                "9DlRn02cst1cmD8XCep/7GaHDZmk79PxfCt04q0h+iQ13WOc4q0YvfRid0fgC+js\n" +
                "8awobryxUhLSESa1uV1X4N8IXNFw/uSfUbB6C997m/WYUBxSrI639JxmGxBcDIUn\n" +
                "crH02GDG8CotAnEHkLTz9GPO80q8mowzBV0EtHsXb4TeAFw5T5Qd0a5I+wk=\n" +
                "=Vcb3\n" +
                "-----END PGP ARMORED FILE-----\n";
        PGPainless api = PGPainless.getInstance();
        OpenPGPCertificate certificate = api.readKey().parseCertificate(KEY);

        KeyRingInfo info = api.inspect(certificate, DateUtil.parseUTCDate("2021-10-10 00:00:00 UTC"));
        // Subkey is hard revoked
        assertFalse(info.isKeyValidlyBound(new KeyIdentifier(5364407983539305061L)));
    }

    @Test
    public void subkeyIsSoftRevokedTest() throws IOException {
        String KEY = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
                "\n" +
                "xsBNBFpJegABCAC1ePFquP0135m8DYhcybhv7l+ecojitFOd/jRM7hCczIqKgalD\n" +
                "1Ro1gNr3VmH6FjRIKIvGT+sOzCKne1v3KyAAPoxtwxjkATTKdOGo15I6v5ZjmO1d\n" +
                "rLQOLSt1TF7XbQSt+ns6PUZWJL907DvECUU5b9FkNUqfQ14QqY+gi7MOyAQez3b7\n" +
                "Pg5Cyz/kVWQ6TSMW/myDEDEertQ4rDBsptEDFHCC2+iF4hO2LqfiCriu5qyLcKCQ\n" +
                "pd6dEuwJQ/jjT0D9A9Fwf+i04x6ZPKSU9oNAWqn8OSAq3/0B/hu9V+0U0iHPnJxe\n" +
                "quykvJk7maxhiGhxBWYXTvDJmoon0NOles7LABEBAAHCwHwEHwEKAA8Fgl4L4QAC\n" +
                "FQoCmwMCHgEAIQkQaE+tYtwDj7sWIQTy0VCk/piSXVHpFTloT61i3AOPu8ffB/9Q\n" +
                "60dg60qhA2rPnd/1dCL2B+c8RWnq44PpijE3gA1RQvcRQE5jNzMSo/MnG0mSL5wH\n" +
                "eTsjSd/DRI3nHP06rs6Qub11NoKhNuya3maz9gyzeZMc/jNib83/BzFCrxsSQm+9\n" +
                "WHurxXeWXOPMLZs3xS/jG0EDtCJ2Fm4UF19fcIydwN/ssF4NGpfCY82+wTSx4joI\n" +
                "3cRKObCFJaaBgG5nl+eFr7cfjEIuqCJCaQsXiqBe7d6V3KqN18t+CgSaybMZXcys\n" +
                "Q/USxEkLhIB2pOZwcz4E3TTFgxRAxcr4cs4Bd2PRz3Z5FKTzo0ma/Ft0UfFJR+fC\n" +
                "cs55+n6kC9K0y/E7BY2hwsB8BB8BCgAPBYJaSXoAAhUKApsDAh4BACEJEGhPrWLc\n" +
                "A4+7FiEE8tFQpP6Ykl1R6RU5aE+tYtwDj7uqDQf7BqTD6GNTwXPOt/0kHQPYmbdI\n" +
                "tX+pWP+o3jaB6VTHDXcn27bttA5M82EXZfae4+bC1dMB+1uLal4ciVgO9ImJC9Nw\n" +
                "s5fc3JH4R5uuSvpjzjudkJsGu3cAKE3hwiT93Mi6t6ENpLCDSxqxzAmfoOQbVJYW\n" +
                "Y7gP7Z4Cj0IAP29aprEc0JWoMjHKpKgYF6u0sWgHWBuEXk/6o6GYb2HZYK4ycpY2\n" +
                "WXKgVhy7/iQDYO1FOfcWQXHVGLn8OzILjobKohNenTT20ZhAASi3LUDSDMTQfxSS\n" +
                "Vt0nhzWuXJJ4R8PzUVeRJ0A0oMyjZVHivHC6GwMsiQuSUTx8e/GnOByOqfGne80S\n" +
                "anVsaWV0QGV4YW1wbGUub3JnwsBzBBMBCgAGBYJaSXoAACEJEGhPrWLcA4+7FiEE\n" +
                "8tFQpP6Ykl1R6RU5aE+tYtwDj7tDfQf+PnxsIFu/0juKBUjjtAYfRzkrrYtMepPj\n" +
                "taTvGfo1SzUkX/6F/GjdSeVg5Iq6YcBrj8c+cB3EoZpHnScTgWQHwceWQLd9Hhbg\n" +
                "TrUNvW1eg2CVzN0RBuYMtWu9JM4pH7ssJW1NmN+/N9B67qb2y+JfBwH/la508NzC\n" +
                "rl3xWTxjT5wNy+FGkNZg23s/0qlO2uxCjc+mRAuAlp5EmTOVWOIBbM0xttjBOx39\n" +
                "ZmWWQKJZ0nrFjK1jppHqazwWWNX7RHkK81tlbSUtOPoTIJDz38NaiyMcZH3p9okN\n" +
                "3DU4XtF+oE18M+Z/E0xUQmumbkajFzcUjmd7enozP5BnGESzdNS5Xc7ATQRaSsuA\n" +
                "AQgAykb8tqlWXtqHGGkBqAq3EnpmvBqrKvqejjtZKAXqEszJ9NlibCGUuLwnNOVO\n" +
                "R/hcOUlOGH+cyMcApBWJB+7d/83K1eCCdv88nDFVav7hKLKlEBbZJNHgHpJ313pl\n" +
                "etzCR4x3STEISrEtO71l2HBdrKSYXaxGgILxYwcSi3i2EjzxRDy+0zyy8s7d+OD5\n" +
                "ShFYexgSrKH3Xx1cxQAJzGGJVx75HHU9GVh3xHwJ7nDm26KzHegG2XPIBXJ2z8vm\n" +
                "sSVTWyj0AjT4kVVapN0f84AKKjyQ7fguCzXGHFV9jmxDx+YH+9HhjIrHSzbDx6+4\n" +
                "wyRsxj7Su+hu/bogJ28nnbTzQwARAQABwsCHBCgBCgAaBYJcKq2AEx0BS2V5IGlz\n" +
                "IHN1cGVyc2VkZWQAIQkQaE+tYtwDj7sWIQTy0VCk/piSXVHpFTloT61i3AOPuxBk\n" +
                "CACOpX6rx67fE33qOGStis1toGfDxcgDjfCC9VKXQ6DY5LSKNf2d32OJq5iPeuFb\n" +
                "ZNBrSr+jE5kF2Zit3P1/cCLKb6sfyTLswWLiQaFNd/D1tWZR4W5H7cgC44NNIXbh\n" +
                "jGvJWGPJZT9FgFCaZzq4Oxya+wwvFEvvtvl+tMPqaYUiDQKjRqi0OWCGTuIpblQf\n" +
                "suc6Jw9qzE6TT2zhaTNWFvDvsLoqgJKsxa8sCZXCuUBB8fKaURTQBDMJSiTyeHgz\n" +
                "4t/n9LKGmTGlTwy12Yhpsyp3yz/uFsJPoM32FWkFtd/bSdXiAxR5Al9mn+fuJLW2\n" +
                "VeILEUjzY1/MfLq6KBlT7EePwsGsBBgBCgAJBYJeC+EAApsCAVcJEGhPrWLcA4+7\n" +
                "wHSgBBkBCgAGBYJeC+EAACEJEEpyNKOhITplFiEEUXksDkji/alOk7kRSnI0o6Eh\n" +
                "OmWnSQgAiu/zdEmHf6Wbwfbs/c6FObfPxGuzLkQr4fZKcqK81MtR1mh1WVLJRgXW\n" +
                "4u8cHtZyH5pThngMcUiyzWsa0g6Jaz8w6sr/Wv3e1qdTCITskMrWCDaoDhD2teAj\n" +
                "mWuk9u8ZBPJ7xhme+Q/UQ90xomQ/NdCJafirk2Ds92p7N7RKSES1KywBhfONJbPw\n" +
                "1TdZ9Mts+DGjkucYbe+ZzPxrLpWXur1BSGEqBtTAGW3dS/xpwBYNlhasXHjYMr4H\n" +
                "eIYYYOx+oR5JgDYoVfp2k0DwK/QXogbja+/Vjv+LrXdNY0t1bA35FNnl637M8iCN\n" +
                "rXvIoRFARbNyge8c/jSWGPLB/tIyNhYhBPLRUKT+mJJdUekVOWhPrWLcA4+7FLwI\n" +
                "AK1GngNMnruxWM4EoghKTSmKNrd6p/d3Wsd+y2019A7Nz+4OydkEDvmNVVhlUcfg\n" +
                "Of2L6Bf63wdN0ho+ODhCuNSqHe6NL1NhdITbMGnDdKb57IIB9CuJFpILn9LZ1Ei6\n" +
                "JPEpmpiSEaL+VJt1fMnfc8jtF8N3WcRVfJsq1aslXe8Npg709YVgm2OXsNWgktl9\n" +
                "fciu4ENTybQGjpN9WTa1aU1nkko6NUoIfjtM+PO4VU7x00M+dTJsYGhnc96EtT8E\n" +
                "fSAIFBKZRAkMBFhEcdkxa8hCKI3+nyI3gTq0TcFST3wy05AmoV7wlgzUAMsW7MV2\n" +
                "NpG7fJul2Q7puKw+udBUc0TCwawEGAEKAAkFglro/4ACmwIBVwkQaE+tYtwDj7vA\n" +
                "dKAEGQEKAAYFglro/4AAIQkQSnI0o6EhOmUWIQRReSwOSOL9qU6TuRFKcjSjoSE6\n" +
                "ZeFHB/92jhUTXrEgho6DYhmVFuXa3NGhAjIyZo3yYHMoL9aZ3DUyjxhAyRDpI2Cr\n" +
                "ahQ4JsPhej2m+3fHWa34/tb5mpHYFWEahQvdWSFCcU7p2NUKcq2zNA6ixO2+fQQh\n" +
                "mbrYR+TFxYmhLjCGUNt14E/XaIL1VxPQOA5KbiRPpa8BsUNlNik9ASPWyn0ZA0rj\n" +
                "J1ZV7nJarXVbuZDEcUDuDm3cA5tup7juB8fTz2BDcg3Ka+OcPEz0GgZfq9K40di3\n" +
                "r9IHLBhNPHieFVIj9j/JyMnTvVOceM3J/Rb0MCWJVbXNBKpRMDibCQh+7fbqyQEM\n" +
                "/zIpmk0TgBpTZZqMP0gxYdWImT1IFiEE8tFQpP6Ykl1R6RU5aE+tYtwDj7tOtggA\n" +
                "hgAqvOB142L2SkS3ZIdwuhAtWLPHCtEwBOqGtP8Z204rqAmbnJymzo77+OT+SScn\n" +
                "DTrwzOUJnCi0qPUxfuxhvHxnBxBIjaoMcF++iKsqF1vf6WuXOjbJ1N8I08pB2nih\n" +
                "t5MxIZ9rMGDeASj79X7I9Jjzsd30OVGfTZyy3VyYPxcJ6n/sZocNmaTv0/F8K3Ti\n" +
                "rSH6JDXdY5zirRi99GJ3R+AL6OzxrChuvLFSEtIRJrW5XVfg3whc0XD+5J9RsHoL\n" +
                "33ub9ZhQHFKsjrf0nGYbEFwMhSdysfTYYMbwKi0CcQeQtPP0Y87zSryajDMFXQS0\n" +
                "exdvhN4AXDlPlB3Rrkj7CQ==\n" +
                "=7Feh\n" +
                "-----END PGP ARMORED FILE-----\n";

        PGPainless api = PGPainless.getInstance();
        OpenPGPCertificate certificate = api.readKey().parseCertificate(KEY);
        final KeyIdentifier subkeyId = new KeyIdentifier(5364407983539305061L);

        KeyRingInfo inspectDuringRevokedPeriod = api.inspect(certificate, DateUtil.parseUTCDate("2019-01-02 00:00:00 UTC"));
        assertFalse(inspectDuringRevokedPeriod.isKeyValidlyBound(subkeyId));
        assertNotNull(inspectDuringRevokedPeriod.getSubkeyRevocationSignature(subkeyId));

        KeyRingInfo inspectAfterRebinding = api.inspect(certificate, DateUtil.parseUTCDate("2020-01-02 00:00:00 UTC"));
        assertTrue(inspectAfterRebinding.isKeyValidlyBound(subkeyId));
    }

    @Test
    public void primaryKeyIsHardRevokedTest() throws IOException {
        String KEY = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
                "\n" +
                "xsBNBFpJegABCAC1ePFquP0135m8DYhcybhv7l+ecojitFOd/jRM7hCczIqKgalD\n" +
                "1Ro1gNr3VmH6FjRIKIvGT+sOzCKne1v3KyAAPoxtwxjkATTKdOGo15I6v5ZjmO1d\n" +
                "rLQOLSt1TF7XbQSt+ns6PUZWJL907DvECUU5b9FkNUqfQ14QqY+gi7MOyAQez3b7\n" +
                "Pg5Cyz/kVWQ6TSMW/myDEDEertQ4rDBsptEDFHCC2+iF4hO2LqfiCriu5qyLcKCQ\n" +
                "pd6dEuwJQ/jjT0D9A9Fwf+i04x6ZPKSU9oNAWqn8OSAq3/0B/hu9V+0U0iHPnJxe\n" +
                "quykvJk7maxhiGhxBWYXTvDJmoon0NOles7LABEBAAHCwJMEIAEKACYFglwqrYAf\n" +
                "HchVbmtub3duIHJldm9jYXRpb24gcmVhc29uIDIwMAAhCRBoT61i3AOPuxYhBPLR\n" +
                "UKT+mJJdUekVOWhPrWLcA4+7yUoH/1KmYWve5h9Tsl1dAguIwVhqNw5fQjxYQCy2\n" +
                "kq+1XBBjKSalNpoFIgV0fJWo+x8i3neNH0pnWRPR9lddiW3C/TjsjGp69QvYaZnM\n" +
                "NXGymkvb6JMFGtTBwpM6R8iH0UqQHWK984nEcD4ZTU2zWY5Q3zr/ahKDoMKooqbc\n" +
                "tBlMumQ3KhSmDrJlU7xxn0K3A5bZoHd/ZlIxk7FX7yoSBUffy6gRdT0IFk9X93Vn\n" +
                "GuUpo+vTjEBO3PQuKOMOT0qJxqZHCUN0LWHDdH3IwmfrlRSRWq63pbO6pyHyEehS\n" +
                "5LQ7NbP994BNxT9yYQ3REvk/ngJk4aK5xRHXdPL529Dio4XWZ4rCwHwEHwEKAA8F\n" +
                "gl4L4QACFQoCmwMCHgEAIQkQaE+tYtwDj7sWIQTy0VCk/piSXVHpFTloT61i3AOP\n" +
                "u8ffB/9Q60dg60qhA2rPnd/1dCL2B+c8RWnq44PpijE3gA1RQvcRQE5jNzMSo/Mn\n" +
                "G0mSL5wHeTsjSd/DRI3nHP06rs6Qub11NoKhNuya3maz9gyzeZMc/jNib83/BzFC\n" +
                "rxsSQm+9WHurxXeWXOPMLZs3xS/jG0EDtCJ2Fm4UF19fcIydwN/ssF4NGpfCY82+\n" +
                "wTSx4joI3cRKObCFJaaBgG5nl+eFr7cfjEIuqCJCaQsXiqBe7d6V3KqN18t+CgSa\n" +
                "ybMZXcysQ/USxEkLhIB2pOZwcz4E3TTFgxRAxcr4cs4Bd2PRz3Z5FKTzo0ma/Ft0\n" +
                "UfFJR+fCcs55+n6kC9K0y/E7BY2hwsB8BB8BCgAPBYJaSXoAAhUKApsDAh4BACEJ\n" +
                "EGhPrWLcA4+7FiEE8tFQpP6Ykl1R6RU5aE+tYtwDj7uqDQf7BqTD6GNTwXPOt/0k\n" +
                "HQPYmbdItX+pWP+o3jaB6VTHDXcn27bttA5M82EXZfae4+bC1dMB+1uLal4ciVgO\n" +
                "9ImJC9Nws5fc3JH4R5uuSvpjzjudkJsGu3cAKE3hwiT93Mi6t6ENpLCDSxqxzAmf\n" +
                "oOQbVJYWY7gP7Z4Cj0IAP29aprEc0JWoMjHKpKgYF6u0sWgHWBuEXk/6o6GYb2HZ\n" +
                "YK4ycpY2WXKgVhy7/iQDYO1FOfcWQXHVGLn8OzILjobKohNenTT20ZhAASi3LUDS\n" +
                "DMTQfxSSVt0nhzWuXJJ4R8PzUVeRJ0A0oMyjZVHivHC6GwMsiQuSUTx8e/GnOByO\n" +
                "qfGne80SanVsaWV0QGV4YW1wbGUub3JnwsBzBBMBCgAGBYJaSXoAACEJEGhPrWLc\n" +
                "A4+7FiEE8tFQpP6Ykl1R6RU5aE+tYtwDj7tDfQf+PnxsIFu/0juKBUjjtAYfRzkr\n" +
                "rYtMepPjtaTvGfo1SzUkX/6F/GjdSeVg5Iq6YcBrj8c+cB3EoZpHnScTgWQHwceW\n" +
                "QLd9HhbgTrUNvW1eg2CVzN0RBuYMtWu9JM4pH7ssJW1NmN+/N9B67qb2y+JfBwH/\n" +
                "la508NzCrl3xWTxjT5wNy+FGkNZg23s/0qlO2uxCjc+mRAuAlp5EmTOVWOIBbM0x\n" +
                "ttjBOx39ZmWWQKJZ0nrFjK1jppHqazwWWNX7RHkK81tlbSUtOPoTIJDz38NaiyMc\n" +
                "ZH3p9okN3DU4XtF+oE18M+Z/E0xUQmumbkajFzcUjmd7enozP5BnGESzdNS5Xc7A\n" +
                "TQRaSsuAAQgAykb8tqlWXtqHGGkBqAq3EnpmvBqrKvqejjtZKAXqEszJ9NlibCGU\n" +
                "uLwnNOVOR/hcOUlOGH+cyMcApBWJB+7d/83K1eCCdv88nDFVav7hKLKlEBbZJNHg\n" +
                "HpJ313pletzCR4x3STEISrEtO71l2HBdrKSYXaxGgILxYwcSi3i2EjzxRDy+0zyy\n" +
                "8s7d+OD5ShFYexgSrKH3Xx1cxQAJzGGJVx75HHU9GVh3xHwJ7nDm26KzHegG2XPI\n" +
                "BXJ2z8vmsSVTWyj0AjT4kVVapN0f84AKKjyQ7fguCzXGHFV9jmxDx+YH+9HhjIrH\n" +
                "SzbDx6+4wyRsxj7Su+hu/bogJ28nnbTzQwARAQABwsGsBBgBCgAJBYJeC+EAApsC\n" +
                "AVcJEGhPrWLcA4+7wHSgBBkBCgAGBYJeC+EAACEJEEpyNKOhITplFiEEUXksDkji\n" +
                "/alOk7kRSnI0o6EhOmWnSQgAiu/zdEmHf6Wbwfbs/c6FObfPxGuzLkQr4fZKcqK8\n" +
                "1MtR1mh1WVLJRgXW4u8cHtZyH5pThngMcUiyzWsa0g6Jaz8w6sr/Wv3e1qdTCITs\n" +
                "kMrWCDaoDhD2teAjmWuk9u8ZBPJ7xhme+Q/UQ90xomQ/NdCJafirk2Ds92p7N7RK\n" +
                "SES1KywBhfONJbPw1TdZ9Mts+DGjkucYbe+ZzPxrLpWXur1BSGEqBtTAGW3dS/xp\n" +
                "wBYNlhasXHjYMr4HeIYYYOx+oR5JgDYoVfp2k0DwK/QXogbja+/Vjv+LrXdNY0t1\n" +
                "bA35FNnl637M8iCNrXvIoRFARbNyge8c/jSWGPLB/tIyNhYhBPLRUKT+mJJdUekV\n" +
                "OWhPrWLcA4+7FLwIAK1GngNMnruxWM4EoghKTSmKNrd6p/d3Wsd+y2019A7Nz+4O\n" +
                "ydkEDvmNVVhlUcfgOf2L6Bf63wdN0ho+ODhCuNSqHe6NL1NhdITbMGnDdKb57IIB\n" +
                "9CuJFpILn9LZ1Ei6JPEpmpiSEaL+VJt1fMnfc8jtF8N3WcRVfJsq1aslXe8Npg70\n" +
                "9YVgm2OXsNWgktl9fciu4ENTybQGjpN9WTa1aU1nkko6NUoIfjtM+PO4VU7x00M+\n" +
                "dTJsYGhnc96EtT8EfSAIFBKZRAkMBFhEcdkxa8hCKI3+nyI3gTq0TcFST3wy05Am\n" +
                "oV7wlgzUAMsW7MV2NpG7fJul2Q7puKw+udBUc0TCwawEGAEKAAkFglro/4ACmwIB\n" +
                "VwkQaE+tYtwDj7vAdKAEGQEKAAYFglro/4AAIQkQSnI0o6EhOmUWIQRReSwOSOL9\n" +
                "qU6TuRFKcjSjoSE6ZeFHB/92jhUTXrEgho6DYhmVFuXa3NGhAjIyZo3yYHMoL9aZ\n" +
                "3DUyjxhAyRDpI2CrahQ4JsPhej2m+3fHWa34/tb5mpHYFWEahQvdWSFCcU7p2NUK\n" +
                "cq2zNA6ixO2+fQQhmbrYR+TFxYmhLjCGUNt14E/XaIL1VxPQOA5KbiRPpa8BsUNl\n" +
                "Nik9ASPWyn0ZA0rjJ1ZV7nJarXVbuZDEcUDuDm3cA5tup7juB8fTz2BDcg3Ka+Oc\n" +
                "PEz0GgZfq9K40di3r9IHLBhNPHieFVIj9j/JyMnTvVOceM3J/Rb0MCWJVbXNBKpR\n" +
                "MDibCQh+7fbqyQEM/zIpmk0TgBpTZZqMP0gxYdWImT1IFiEE8tFQpP6Ykl1R6RU5\n" +
                "aE+tYtwDj7tOtggAhgAqvOB142L2SkS3ZIdwuhAtWLPHCtEwBOqGtP8Z204rqAmb\n" +
                "nJymzo77+OT+SScnDTrwzOUJnCi0qPUxfuxhvHxnBxBIjaoMcF++iKsqF1vf6WuX\n" +
                "OjbJ1N8I08pB2niht5MxIZ9rMGDeASj79X7I9Jjzsd30OVGfTZyy3VyYPxcJ6n/s\n" +
                "ZocNmaTv0/F8K3TirSH6JDXdY5zirRi99GJ3R+AL6OzxrChuvLFSEtIRJrW5XVfg\n" +
                "3whc0XD+5J9RsHoL33ub9ZhQHFKsjrf0nGYbEFwMhSdysfTYYMbwKi0CcQeQtPP0\n" +
                "Y87zSryajDMFXQS0exdvhN4AXDlPlB3Rrkj7CQ==\n" +
                "=MhJL\n" +
                "-----END PGP ARMORED FILE-----\n";

        PGPainless api = PGPainless.getInstance();
        OpenPGPCertificate keys = api.readKey().parseCertificate(KEY);

        KeyRingInfo info = api.inspect(keys);
        // Primary key is hard revoked
        assertFalse(info.isKeyValidlyBound(keys.getKeyIdentifier()));
        assertFalse(info.isFullyEncrypted());
    }

    @Test
    public void getSecretKeyTest() {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = api.generateKey().modernKeyRing("Alice");
        KeyRingInfo info = api.inspect(secretKeys);

        OpenPgpV4Fingerprint primaryKeyFingerprint = new OpenPgpV4Fingerprint(secretKeys);
        OpenPGPKey.OpenPGPSecretKey primaryKey = info.getSecretKey(primaryKeyFingerprint);
        assertNotNull(primaryKey);
        assertEquals(secretKeys.getPrimarySecretKey().getKeyIdentifier(), primaryKey.getKeyIdentifier());
    }

    @Test
    public void testGetLatestKeyCreationDate() throws PGPException, IOException {
        OpenPGPKey secretKeys = TestKeys.getEmilKey();
        Date latestCreationDate = DateUtil.parseUTCDate("2020-01-12 18:01:44 UTC");

        KeyRingInfo info = PGPainless.getInstance().inspect(secretKeys);
        JUtils.assertDateEquals(latestCreationDate, info.getLatestKeyCreationDate());
    }

    @Test
    public void testGetExpirationDateForUse_SPLIT() throws PGPException, IOException {
        OpenPGPKey secretKeys = TestKeys.getEmilKey();
        KeyRingInfo info = PGPainless.getInstance().inspect(secretKeys);
        assertThrows(IllegalArgumentException.class, () -> info.getExpirationDateForUse(KeyFlag.SPLIT));
    }

    @Test
    public void testGetExpirationDateForUse_SHARED() throws PGPException, IOException {
        OpenPGPKey secretKeys = TestKeys.getEmilKey();
        KeyRingInfo info = PGPainless.getInstance().inspect(secretKeys);
        assertThrows(IllegalArgumentException.class, () -> info.getExpirationDateForUse(KeyFlag.SHARED));
    }

    @Test
    public void testGetExpirationDateForUse_NoSuchKey() {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = PGPainless.buildKeyRing()
                .addUserId("Alice")
                .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519), KeyFlag.CERTIFY_OTHER))
                .build();

        KeyRingInfo info = api.inspect(secretKeys);

        assertThrows(NoSuchElementException.class, () -> info.getExpirationDateForUse(KeyFlag.ENCRYPT_COMMS));
    }

    @Test
    public void testGetPreferredAlgorithms() throws IOException {
        String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "Version: PGPainless\n" +
                "Comment: AC6F E854 F1F8 FC2C 121F  64BC 5C33 8C29 81C0 25F0\n" +
                "Comment: Alice\n" +
                "\n" +
                "lFgEYWWA1BYJKwYBBAHaRw8BAQdAdrm6pbGxiF810GBTscYRc5Nj3ds1BS3OoMOK\n" +
                "Ae7LPEoAAQDqwu/sBr0UQbxwinbc5SxajwkIZFmZppLugkEu19eNIRB8tAVBbGlj\n" +
                "ZYh4BBMWCgAgBQJhZYDUAhsBBRYCAwEABRUKCQgLBAsJCAcCHgECGQEACgkQXDOM\n" +
                "KYHAJfAqLwEA1H99UN3+/iJZjD0ZecqDZGeH2axtFj9WRr1hqokwFv0A/jXyBV+Q\n" +
                "Y+bQYiKcmHwk2n7VxHC4PBNY0pEDI/iDwYcBnF0EYWWA1BIKKwYBBAGXVQEFAQEH\n" +
                "QMDczPpxXth89G/sJ84tYrg2WPIut04H4z8Ys49FuH0GAwEIBwAA/0ASQkU3tbCD\n" +
                "jqwbnJ69qqQ9Qko+CnwuMcxXBCy5rNBYDl2IdQQYFgoAHQUCYWWA1AIbDAUWAgMB\n" +
                "AAUVCgkICwQLCQgHAh4BAAoJEFwzjCmBwCXwcBoBAKhQxSlacUPB27OJ0KVUXJsQ\n" +
                "CGoZ4wcOsstla9N1da8uAP9+W6zxc4VFYFZa3L9PsGLaQ01NTgngWJmPG+gRVu9h\n" +
                "BJxYBGFlgNQWCSsGAQQB2kcPAQEHQFW53p+2ZwsazALz7P5dYzx0LaQ7lv0veR8e\n" +
                "DjKAeAMVAAD6AlUAJfkp19PmEEDWW7I3iSpXB3e5njEDbGs12Kt2XLoOwIjVBBgW\n" +
                "CgB9BQJhZYDUAhsCBRYCAwEABRUKCQgLBAsJCAcCHgFfIAQZFgoABgUCYWWA1AAK\n" +
                "CRDShjEjcUDsWJA+AQCtbMUCXa8M3znR95V22zxptRmPsapGpw21/t2U4YHYhgD/\n" +
                "aFFrxG7Q3pbjHJa42u9jakpCm4zIhyfWI0wasPuaBwMACgkQXDOMKYHAJfCTYgD/\n" +
                "Uc9F3P6UQM0KpeUbensec/fKs8tp67WLLBvBa+p0YBIA/272CXdHaJurCEJoDYaG\n" +
                "/+XL+qMMgLHaQ25aA11GVAkC\n" +
                "=7gbt\n" +
                "-----END PGP PRIVATE KEY BLOCK-----";
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = api.readKey().parseKey(KEY);
        final KeyIdentifier pkid = new KeyIdentifier(6643807985200014832L);
        final KeyIdentifier skid1 = new KeyIdentifier(-2328413746552029063L);
        final KeyIdentifier skid2 = new KeyIdentifier(-3276877650571760552L);
        Set<HashAlgorithm> preferredHashAlgorithms = new LinkedHashSet<>(
                Arrays.asList(HashAlgorithm.SHA512, HashAlgorithm.SHA384, HashAlgorithm.SHA256, HashAlgorithm.SHA224));
        Set<CompressionAlgorithm> preferredCompressionAlgorithms = new LinkedHashSet<>(
                Arrays.asList(CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZIP2, CompressionAlgorithm.ZIP, CompressionAlgorithm.UNCOMPRESSED));
        Set<SymmetricKeyAlgorithm> preferredSymmetricAlgorithms = new LinkedHashSet<>(
                Arrays.asList(SymmetricKeyAlgorithm.AES_256, SymmetricKeyAlgorithm.AES_192, SymmetricKeyAlgorithm.AES_128));
        KeyRingInfo info = api.inspect(secretKeys);

        // Bob is an invalid userId
        assertThrows(NoSuchElementException.class, () -> info.getPreferredSymmetricKeyAlgorithms("Bob"));
        // 123 is an invalid keyid
        assertThrows(NoSuchElementException.class, () -> info.getPreferredSymmetricKeyAlgorithms(new KeyIdentifier(123L)));

        assertEquals(preferredHashAlgorithms, info.getPreferredHashAlgorithms("Alice"));
        assertEquals(preferredHashAlgorithms, info.getPreferredHashAlgorithms(pkid));
        assertEquals(preferredHashAlgorithms, info.getPreferredHashAlgorithms(skid1));
        assertEquals(preferredHashAlgorithms, info.getPreferredHashAlgorithms(skid2));

        // Bob is an invalid userId
        assertThrows(NoSuchElementException.class, () -> info.getPreferredCompressionAlgorithms("Bob"));
        // 123 is an invalid keyid
        assertThrows(NoSuchElementException.class, () -> info.getPreferredCompressionAlgorithms(new KeyIdentifier(123L)));

        assertEquals(preferredCompressionAlgorithms, info.getPreferredCompressionAlgorithms("Alice"));
        assertEquals(preferredCompressionAlgorithms, info.getPreferredCompressionAlgorithms(pkid));
        assertEquals(preferredCompressionAlgorithms, info.getPreferredCompressionAlgorithms(skid1));
        assertEquals(preferredCompressionAlgorithms, info.getPreferredCompressionAlgorithms(skid2));

        // Bob is an invalid userId
        assertThrows(NoSuchElementException.class, () -> info.getPreferredSymmetricKeyAlgorithms("Bob"));
        // 123 is an invalid keyid
        assertThrows(NoSuchElementException.class, () -> info.getPreferredSymmetricKeyAlgorithms(new KeyIdentifier(123L)));

        assertEquals(preferredSymmetricAlgorithms, info.getPreferredSymmetricKeyAlgorithms("Alice"));
        assertEquals(preferredSymmetricAlgorithms, info.getPreferredSymmetricKeyAlgorithms(pkid));
        assertEquals(preferredSymmetricAlgorithms, info.getPreferredSymmetricKeyAlgorithms(skid1));
        assertEquals(preferredSymmetricAlgorithms, info.getPreferredSymmetricKeyAlgorithms(skid2));

    }

    @Test
    public void testUnboundSubkeyIsIgnored() throws IOException {
        // Contains unbound subkey D622C916384E0F6D364907E55D918BBD521CCD10
        String KEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                "\n" +
                "xsDNBF2lnPIBDAC5cL9PQoQLTMuhjbYvb4Ncuuo0bfmgPRFywX53jPhoFf4Zg6mv\n" +
                "/seOXpgecTdOcVttfzC8ycIKrt3aQTiwOG/ctaR4Bk/t6ayNFfdUNxHWk4WCKzdz\n" +
                "/56fW2O0F23qIRd8UUJp5IIlN4RDdRCtdhVQIAuzvp2oVy/LaS2kxQoKvph/5pQ/\n" +
                "5whqsyroEWDJoSV0yOb25B/iwk/pLUFoyhDG9bj0kIzDxrEqW+7Ba8nocQlecMF3\n" +
                "X5KMN5kp2zraLv9dlBBpWW43XktjcCZgMy20SouraVma8Je/ECwUWYUiAZxLIlMv\n" +
                "9CurEOtxUw6N3RdOtLmYZS9uEnn5y1UkF88o8Nku890uk6BrewFzJyLAx5wRZ4F0\n" +
                "qV/yq36UWQ0JB/AUGhHVPdFf6pl6eaxBwT5GXvbBUibtf8YI2og5RsgTWtXfU7eb\n" +
                "SGXrl5ZMpbA6mbfhd0R8aPxWfmDWiIOhBufhMCvUHh1sApMKVZnvIff9/0Dca3wb\n" +
                "vLIwa3T4CyshfT0AEQEAAc0hQm9iIEJhYmJhZ2UgPGJvYkBvcGVucGdwLmV4YW1w\n" +
                "bGU+wsEOBBMBCgA4AhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAFiEE0aZuGiOx\n" +
                "gsmYD3iM+/zIKgFeczAFAl2lnvoACgkQ+/zIKgFeczBvbAv/VNk90a6hG8Od9xTz\n" +
                "XxH5YRFUSGfIA1yjPIVOnKqhMwps2U+sWE3urL+MvjyQRlyRV8oY9IOhQ5Esm6DO\n" +
                "ZYrTnE7qVETm1ajIAP2OFChEc55uH88x/anpPOXOJY7S8jbn3naC9qad75BrZ+3g\n" +
                "9EBUWiy5p8TykP05WSnSxNRt7vFKLfEB4nGkehpwHXOVF0CRNwYle42bg8lpmdXF\n" +
                "DcCZCi+qEbafmTQzkAqyzS3nCh3IAqq6Y0kBuaKLm2tSNUOlZbD+OHYQNZ5Jix7c\n" +
                "ZUzs6Xh4+I55NRWl5smrLq66yOQoFPy9jot/Qxikx/wP3MsAzeGaZSEPc0fHp5G1\n" +
                "6rlGbxQ3vl8/usUV7W+TMEMljgwd5x8POR6HC8EaCDfVnUBCPi/Gv+egLjsIbPJZ\n" +
                "ZEroiE40e6/UoCiQtlpQB5exPJYSd1Q1txCwueih99PHepsDhmUQKiACszNU+RRo\n" +
                "zAYau2VdHqnRJ7QYdxHDiH49jPK4NTMyb/tJh2TiIwcmsIpGzsDNBF2lnPIBDADW\n" +
                "ML9cbGMrp12CtF9b2P6z9TTT74S8iyBOzaSvdGDQY/sUtZXRg21HWamXnn9sSXvI\n" +
                "DEINOQ6A9QxdxoqWdCHrOuW3ofneYXoG+zeKc4dC86wa1TR2q9vW+RMXSO4uImA+\n" +
                "Uzula/6k1DogDf28qhCxMwG/i/m9g1c/0aApuDyKdQ1PXsHHNlgd/Dn6rrd5y2AO\n" +
                "baifV7wIhEJnvqgFXDN2RXGjLeCOHV4Q2WTYPg/S4k1nMXVDwZXrvIsA0YwIMgIT\n" +
                "86Rafp1qKlgPNbiIlC1g9RY/iFaGN2b4Ir6GDohBQSfZW2+LXoPZuVE/wGlQ01rh\n" +
                "827KVZW4lXvqsge+wtnWlszcselGATyzqOK9LdHPdZGzROZYI2e8c+paLNDdVPL6\n" +
                "vdRBUnkCaEkOtl1mr2JpQi5nTU+gTX4IeInC7E+1a9UDF/Y85ybUz8XV8rUnR76U\n" +
                "qVC7KidNepdHbZjjXCt8/Zo+Tec9JNbYNQB/e9ExmDntmlHEsSEQzFwzj8sxH48A\n" +
                "EQEAAcLA9gQYAQoAIBYhBNGmbhojsYLJmA94jPv8yCoBXnMwBQJdpZzyAhsMAAoJ\n" +
                "EPv8yCoBXnMw6f8L/26C34dkjBffTzMj5Bdzm8MtF67OYneJ4TQMw7+41IL4rVcS\n" +
                "KhIhk/3Ud5knaRtP2ef1+5F66h9/RPQOJ5+tvBwhBAcUWSupKnUrdVaZQanYmtSx\n" +
                "cVV2PL9+QEiNN3tzluhaWO//rACxJ+K/ZXQlIzwQVTpNhfGzAaMVV9zpf3u0k14i\n" +
                "tcv6alKY8+rLZvO1wIIeRZLmU0tZDD5HtWDvUV7rIFI1WuoLb+KZgbYn3OWjCPHV\n" +
                "dTrdZ2CqnZbG3SXw6awH9bzRLV9EXkbhIMez0deCVdeo+wFFklh8/5VK2b0vk/+w\n" +
                "qMJxfpa1lHvJLobzOP9fvrswsr92MA2+k901WeISR7qEzcI0Fdg8AyFAExaEK6Vy\n" +
                "jP7SXGLwvfisw34OxuZr3qmx1Sufu4toH3XrB7QJN8XyqqbsGxUCBqWif9RSK4xj\n" +
                "zRTe56iPeiSJJOIciMP9i2ldI+KgLycyeDvGoBj0HCLO3gVaBe4ubVrj5KjhX2PV\n" +
                "NEJd3XZRzaXZE2aAMc7ATQRhaDWyAQgA1CaZPxLUMm7sH0i/KTWVqqFgTTxVJjy+\n" +
                "Aj3vjhrzAsQw1gqtbLXTlwBVVqhGIisEf7ZsFBBIzXNXi2Gk2O8HiZoKyey87f4R\n" +
                "MkVCmHZKJyL2vBhsl8bfHI8rK41XeVmmpGnM+pUgD2MSoBbyDZKqhr3+zsnJD4gt\n" +
                "hNMEYmZkqOzO20c1TO/92qPmmNn8hFa7sRqcff4TEzy3SsYUxsXvV/FjCfVNC3ij\n" +
                "2u3RlB/8xljVjXhtrvlyl5uwmjJYs2fR9RHQPfhQt0YvcXw5ihCcLK0mu2FP0qT+\n" +
                "C9h35EjDuD+1COXUOoW2B8LX6m2yf8cY72K70QgtGemj7UWhXL5u/wARAQAB\n" +
                "=A3B8\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        PGPainless api = PGPainless.getInstance();
        OpenPGPCertificate certificate = api.readKey().parseCertificate(KEY);
        OpenPgpV4Fingerprint unboundKey = new OpenPgpV4Fingerprint("D622C916384E0F6D364907E55D918BBD521CCD10");
        KeyRingInfo info = api.inspect(certificate);

        assertFalse(info.isKeyValidlyBound(unboundKey.getKeyIdentifier()));

        List<OpenPGPCertificate.OpenPGPComponentKey> encryptionSubkeys = info.getEncryptionSubkeys(EncryptionPurpose.ANY);
        assertTrue(encryptionSubkeys.stream()
                        .map(it -> new OpenPgpV4Fingerprint(it.getPGPPublicKey()))
                        .noneMatch(f -> f.equals(unboundKey)),
                "Unbound subkey MUST NOT be considered a valid encryption subkey");

        List<OpenPGPCertificate.OpenPGPComponentKey> signingSubkeys = info.getSigningSubkeys();
        assertTrue(signingSubkeys.stream()
                        .map(it -> new OpenPgpV4Fingerprint(it.getPGPPublicKey()))
                        .noneMatch(f -> f.equals(unboundKey)),
                "Unbound subkey MUST NOT be considered a valid signing subkey");

        assertTrue(info.getKeyFlagsOf(unboundKey.getKeyIdentifier()).isEmpty());

        Date latestModification = info.getLastModified();
        Date latestKeyCreation = info.getLatestKeyCreationDate();
        Date unboundKeyCreation = certificate.getKey(unboundKey.getKeyIdentifier()).getCreationTime();
        assertTrue(unboundKeyCreation.after(latestModification));
        assertTrue(unboundKeyCreation.after(latestKeyCreation));
    }

    @Test
    public void getEmailsTest() throws IOException {
        // NOTE: The User-ID Format for the ID "Alice Anderson <alice@email.tld> [Primary Mail Address]" is incorrect.
        // TODO: Fix?
        String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "Version: PGPainless\n" +
                "Comment: B4A8 9FE8 9D59 31E6 BCF7  DC2F 6BA1 2CC7 9A08 8D73\n" +
                "Comment: Alice Anderson <alice@email.tld> [Primary Mail Address]\n" +
                "Comment: Alice A. <alice@pgpainless.org>\n" +
                "Comment: <alice@openpgp.org>\n" +
                "Comment: alice@rfc4880.spec\n" +
                "Comment: alice anderson@invalid.mail\n" +
                "Comment: Alice Anderson <alice anderson@invalid.mail>\n" +
                "\n" +
                "lFgEYh39eBYJKwYBBAHaRw8BAQdAegaKui2AnIZ7D4fRozwqEvbHePpU/agSN6Kr\n" +
                "11uVHKoAAP4xCyRezCJ04di6+NICghNDPqWBJLtk3MI1ndlBLwcgjw9LtDdBbGlj\n" +
                "ZSBBbmRlcnNvbiA8YWxpY2VAZW1haWwudGxkPiBbUHJpbWFyeSBNYWlsIEFkZHJl\n" +
                "c3NdiI8EExYKAEEFAmId/XgJEGuhLMeaCI1zFiEEtKif6J1ZMea899wva6Esx5oI\n" +
                "jXMCngECmwEFFgIDAQAECwkIBwUVCgkICwKZAQAA1MoBALzi4qecj+tnLdQEWbTI\n" +
                "uHIc6NVoUb7p4B8Jro/ehJ1fAQDjt3+VfLUZ8QaX+TtTDGnWHyEOoJ0VxiIKdMmv\n" +
                "2dYtCrQfQWxpY2UgQS4gPGFsaWNlQHBncGFpbmxlc3Mub3JnPoiMBBMWCgA+BQJi\n" +
                "Hf14CRBroSzHmgiNcxYhBLSon+idWTHmvPfcL2uhLMeaCI1zAp4BApsBBRYCAwEA\n" +
                "BAsJCAcFFQoJCAsAAABCAP9jSCveW6JxpszuxOiGJyQSCDp39lql6BU35UgOb2fJ\n" +
                "5QD+K00v724rDpqjKphMMr9B8CYXuU+jTDoUHquSCRhJrge0EzxhbGljZUBvcGVu\n" +
                "cGdwLm9yZz6IjAQTFgoAPgUCYh39eAkQa6Esx5oIjXMWIQS0qJ/onVkx5rz33C9r\n" +
                "oSzHmgiNcwKeAQKbAQUWAgMBAAQLCQgHBRUKCQgLAAD50AEAv/MkwkK9wojSH+uV\n" +
                "0Y3Dnm4bZsA5bIWGAgAxmKsh/IMA/11NwGhx+YwRmerO9zVxWcEnnbSQP4Re4ALe\n" +
                "AZTcx88GtBJhbGljZUByZmM0ODgwLnNwZWOIjAQTFgoAPgUCYh39eAkQa6Esx5oI\n" +
                "jXMWIQS0qJ/onVkx5rz33C9roSzHmgiNcwKeAQKbAQUWAgMBAAQLCQgHBRUKCQgL\n" +
                "AAC26wD+NDz1j3PB2v2QAKadzyYgod5IcSGAgzBUwf16edvsWCoBAL3nkb2ahPW/\n" +
                "vk946LzejWPQToGSrRxmY7VjNutTNRQGtBthbGljZSBhbmRlcnNvbkBpbnZhbGlk\n" +
                "Lm1haWyIjAQTFgoAPgUCYh39eAkQa6Esx5oIjXMWIQS0qJ/onVkx5rz33C9roSzH\n" +
                "mgiNcwKeAQKbAQUWAgMBAAQLCQgHBRUKCQgLAAAxIwEAs/rtMrGAXfDO/yssC3B/\n" +
                "8ZSVoExPi8B5jzJqMVb4kuQBAJVqpSSUNVPwNJsH7EP74iXPCyWn9oy1p4G53BxV\n" +
                "8eQEtCxBbGljZSBBbmRlcnNvbiA8YWxpY2UgYW5kZXJzb25AaW52YWxpZC5tYWls\n" +
                "PoiMBBMWCgA+BQJiHf14CRBroSzHmgiNcxYhBLSon+idWTHmvPfcL2uhLMeaCI1z\n" +
                "Ap4BApsBBRYCAwEABAsJCAcFFQoJCAsAAA2cAP9ygQbt8oQtRc4oPm/LLPDjH89u\n" +
                "LBMVywN0yBdEWO/ASgEAmgl1kgyMRyf28SjISAWAHiTGs0mRAn9kdwJGU4+27AGc\n" +
                "XQRiHf14EgorBgEEAZdVAQUBAQdAIvJYcrgjLhPGjJ9YCaPKZcZrgpf93v3zlE/v\n" +
                "GGUQrT8DAQgHAAD/WWQiuS/2UBFt97J4htg14ICcjoMnOrI4mimeZwYTtoAPrYh1\n" +
                "BBgWCgAdBQJiHf14Ap4BApsMBRYCAwEABAsJCAcFFQoJCAsACgkQa6Esx5oIjXOo\n" +
                "qQEAlmUF0RIpnqWqWmtKtbbTSYj6+UgV0L5n2RWtlOVdfMIA/34+rQ45pUqelgCc\n" +
                "yzfUm8wDlJjT9ogVGsvtDnLokv4BnFgEYh39eBYJKwYBBAHaRw8BAQdAnQCPdWgk\n" +
                "X02oa5RBIRNCAEkdf1FooxlzlDCXBUUMaMoAAP9EhqmoCsUBplDMfnMUtu1g6BLq\n" +
                "qGIAOtm/HXtQ4UUo2xCFiNUEGBYKAH0FAmId/XgCngECmwIFFgIDAQAECwkIBwUV\n" +
                "CgkIC18gBBkWCgAGBQJiHf14AAoJEIEZZ8Ab4jMdYsUA/ilgaT94y0hEEkEFF2Dm\n" +
                "vle6KXtHHPo/G0fkcGras8W9AQDo+IQSzTJylS+AJQfTSTuGUEP8hWPG/1f7SWVo\n" +
                "z6/eBgAKCRBroSzHmgiNc7A7AQDEGMAPe4guEgkCfZRFRZoWb8ahpKB3y6cYQ7t1\n" +
                "qDzPRwEAhdVBeryRUcwjgwHX0xmMFK7vLkdonn8BR2++nXBO2g8=\n" +
                "=ZRAy\n" +
                "-----END PGP PRIVATE KEY BLOCK-----\n";
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = api.readKey().parseKey(KEY);
        KeyRingInfo info = api.inspect(secretKeys);

        List<String> emails = info.getEmailAddresses();
        assertEquals(emails, Arrays.asList("alice@email.tld", "alice@pgpainless.org", "alice@openpgp.org", "alice@rfc4880.spec"));
    }

    @Test
    public void isUsableForEncryptionTest_base() throws IOException {
        String CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                "Version: PGPainless\n" +
                "Comment: 9B6A C43E A67C 11BB C023  4CC3 69D5 9A7C 29C0 F858\n" +
                "Comment: Usable <usable@pgpainless.org>\n" +
                "\n" +
                "mDMEYiS54BYJKwYBBAHaRw8BAQdAr0FXsDQtIpF54UwfjQb+8XJ3jxt3LkpCh0e7\n" +
                "lH59Vzy0HlVzYWJsZSA8dXNhYmxlQHBncGFpbmxlc3Mub3JnPoiPBBMWCgBBBQJi\n" +
                "JLngCRBp1Zp8KcD4WBYhBJtqxD6mfBG7wCNMw2nVmnwpwPhYAp4BApsBBRYCAwEA\n" +
                "BAsJCAcFFQoJCAsCmQEAACuNAQDX+7/ffM2B9qaW+F9MkeUJeq9u8MLk+BcaotQZ\n" +
                "/c+8pQD/RhaVmKTLjm+RmpG2O1lrkta4L5CQQBXYdNMnebhlLAu4OARiJLngEgor\n" +
                "BgEEAZdVAQUBAQdA8Et257jQXR0oJOimAWU9Z5Erq5OcfguBI28ixgw5z2IDAQgH\n" +
                "iHUEGBYKAB0FAmIkueACngECmwwFFgIDAQAECwkIBwUVCgkICwAKCRBp1Zp8KcD4\n" +
                "WDQYAQDtJG06gAiFk7D1EqdtoTgBeIXi6pdKJ8VQA17/Sel1PgEAjO7Gy+RishFG\n" +
                "eT0WwimGAGWOFgyIB8GCmuk1sEN+9wO4MwRiJLngFgkrBgEEAdpHDwEBB0BNGWZx\n" +
                "IiCzs6Acu/e7Di9E+uUZmEA7geObWgwPleedLYjVBBgWCgB9BQJiJLngAp4BApsC\n" +
                "BRYCAwEABAsJCAcFFQoJCAtfIAQZFgoABgUCYiS54AAKCRBsyz3UPPzzw6bTAQCZ\n" +
                "4NnXfhuyw2itPKNnVSvPl72GgHzfVb2MZi2QBPFJyQD+K7Xl6qNcaI9VyMos8zSy\n" +
                "VT74iE7Sraqu2Fck27y1wgMACgkQadWafCnA+FjLFwEAxb/GFdAoUgmY6DGIbatO\n" +
                "LOIorswrgSQVZ8B1yLh1gxcA/2K3XO1Tl68O961SW60CijoBY/16EFC+mkQIzxTT\n" +
                "J5wP\n" +
                "=nFoO\n" +
                "-----END PGP PUBLIC KEY BLOCK-----";
        PGPainless api = PGPainless.getInstance();
        OpenPGPCertificate cert = api.readKey().parseCertificate(CERT);
        KeyRingInfo info = api.inspect(cert);
        assertTrue(info.isUsableForEncryption());
    }

    @Test
    public void isUsableForEncryptionTest_commsOnly() throws IOException {
        String CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                "Version: PGPainless\n" +
                "Comment: B2EE 493D 1DAC 943A 1CBD  B151 5F15 42D1 ACB7 D26F\n" +
                "Comment: Comms Only <comms-only@pgpainless.org>\n" +
                "\n" +
                "mG8EYiS7mhMFK4EEACIDAwTENCF226L9l1i24ZpHuTK9P9kEc7neMZ1cQbJFSX9p\n" +
                "ZP89dp4dnjZcAop5jzdvqjU98BgX9STZB6q2qYEG46luZoanDA0dpwzm0TENAvcr\n" +
                "KoeIMqjv6dkKs5k11qtFx/K0JkNvbW1zIE9ubHkgPGNvbW1zLW9ubHlAcGdwYWlu\n" +
                "bGVzcy5vcmc+iK8EExMKAEEFAmIku5sJEF8VQtGst9JvFiEEsu5JPR2slDocvbFR\n" +
                "XxVC0ay30m8CngECmwMFFgIDAQAECwkIBwUVCgkICwKZAQAA3u4BgOl888SnxXys\n" +
                "Ft/sPRh/hT8n0ObrxDHUgaAR5J7Sc3097u1r3ecCYaY045FYKKb23QGAjGSEEFG1\n" +
                "TLbM1JMsE5H7xjjjJ5tTM6l45vkkrk3uMhsCL+QLv9pp251ctTF/JSCvuHMEYiS7\n" +
                "mxIFK4EEACIDAwToE6c42GWSI0zmalisYewWvV/2Sfdo9KKgxfzX3rfldrOWFkN1\n" +
                "fkLy6b01AUt3RqfwEBIJK6OrSXOlmdCiRV1Oqf20f2MGsDNXAttDApSSDJIHwV24\n" +
                "3i6qylin0ujQ9KIDAQgHiJUEGBMKAB0FAmIku5sCngECmwQFFgIDAQAECwkIBwUV\n" +
                "CgkICwAKCRBfFULRrLfSbwoYAYCzcZ29xIRUEHzZvAXWeHselBLdLGztZSBZKd9T\n" +
                "m045mewePa780jk5o2z5Nt4Bj0EBfRxoiWt/czpy0nWpyfEeTHOx32jHHoTStjIF\n" +
                "2XO/hpB2T8VXFfFKwj7U9LGkX+ciLg==\n" +
                "=etPP\n" +
                "-----END PGP PUBLIC KEY BLOCK-----";
        PGPainless api = PGPainless.getInstance();
        OpenPGPCertificate publicKeys = api.readKey().parseCertificate(CERT);
        KeyRingInfo info = api.inspect(publicKeys);

        assertTrue(info.isUsableForEncryption(EncryptionPurpose.COMMUNICATIONS));
        assertTrue(info.isUsableForEncryption(EncryptionPurpose.ANY));

        assertFalse(info.isUsableForEncryption(EncryptionPurpose.STORAGE));
    }

    @Test
    public void isUsableForEncryptionTest_encryptionKeyRevoked() throws IOException {
        // encryption subkey is revoked
        String CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                "Version: PGPainless\n" +
                "Comment: CE65 608D 8639 E20C 61BF  077B F010 3226 1C64 5EA7\n" +
                "Comment: Revoked <revoked@pgpainless.org>\n" +
                "\n" +
                "mDMEYiS8+hYJKwYBBAHaRw8BAQdATvSKAaY5yvyOdJtZXBEXbyiWSsExOwnP2L35\n" +
                "AyMPe7u0IFJldm9rZWQgPHJldm9rZWRAcGdwYWlubGVzcy5vcmc+iI8EExYKAEEF\n" +
                "AmIkvPoJEPAQMiYcZF6nFiEEzmVgjYY54gxhvwd78BAyJhxkXqcCngECmwEFFgID\n" +
                "AQAECwkIBwUVCgkICwKZAQAAYFQA/02fMgRnneYK17Vsxc8DJEj0pVmTDHIOQH8K\n" +
                "O8BuTkvhAP9zXtnJ7BsWO3Kg/ajIlaZEzMl6/lK2FTnAzBhs1UtrD7g4BGIkvPoS\n" +
                "CisGAQQBl1UBBQEBB0AO8Bzm66ydlFhKtesh9EX66k4yyODeO0X3y3JUbrAnFQMB\n" +
                "CAeIdQQYFgoAHQUCYiS8+gKeAQKbDAUWAgMBAAQLCQgHBRUKCQgLAAoJEPAQMiYc\n" +
                "ZF6nTB0BAPjF6pUUrS3wv8CvrIM3S4BCtCOp+oQyPsie72As+47SAP41KfnvzYF3\n" +
                "Y0WBp94Dqiy1MkvMZ9Q2x8BQt/L1UsoTBIh7BCgWCgAtBQJiJLz8CRDwEDImHGRe\n" +
                "pxYhBM5lYI2GOeIMYb8He/AQMiYcZF6nAocAAh0DAAABqgD/TJpSDZ5fX3zNHqmN\n" +
                "4TOuJ1GEkiYpPjBhem2C+U9jHjoBAJxQqzDB2VMiUDfe2+LLVIYa4EwhT2rT12qg\n" +
                "aJ+TXWAJuDMEYiS8+hYJKwYBBAHaRw8BAQdAR0y6K6GPt4ddNyaRX16duqDFZwQi\n" +
                "jeflFZ+UGLQ5GgSI1QQYFgoAfQUCYiS8+gKeAQKbAgUWAgMBAAQLCQgHBRUKCQgL\n" +
                "XyAEGRYKAAYFAmIkvPoACgkQCX8koK2POrbPywEA3mbeGX8vWwnENtiFeMBjXNox\n" +
                "oHAIuULBsvOdc1xrH0QBALezsulAJoziQ/t+EUrNHgTELDq3F8Y8tmLAJykb/nQB\n" +
                "AAoJEPAQMiYcZF6n6CAA/0HadYoqOUbMjgu3Tle0HSXiTCJfBrTox5trTOKUsQ8z\n" +
                "AQCjeV+3VT+u1movwIYv4XkzB6gB+B2C+DK9nvG5sXZhBg==\n" +
                "=uqmO\n" +
                "-----END PGP PUBLIC KEY BLOCK-----";
        PGPainless api = PGPainless.getInstance();
        OpenPGPCertificate publicKeys = api.readKey().parseCertificate(CERT);
        KeyRingInfo info = api.inspect(publicKeys);

        assertFalse(info.isUsableForEncryption());
        assertFalse(info.isUsableForEncryption(EncryptionPurpose.ANY));
        assertFalse(info.isUsableForEncryption(EncryptionPurpose.COMMUNICATIONS));
        assertFalse(info.isUsableForEncryption(EncryptionPurpose.STORAGE));
    }
}
