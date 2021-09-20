/*
 * Copyright 2020 Paul Schaub. Copyright 2021 Flowcrypt a.s.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.key.info;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.ecc.EllipticCurve;
import org.pgpainless.key.generation.type.eddsa.EdDSACurve;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnprotectedKeysProtector;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.key.util.UserId;
import org.pgpainless.util.DateUtil;
import org.pgpainless.util.Passphrase;

public class KeyRingInfoTest {

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestImplementationFactoryProvider#provideImplementationFactories")
    public void testWithEmilsKeys(ImplementationFactory implementationFactory) throws IOException, PGPException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);

        PGPSecretKeyRing secretKeys = TestKeys.getEmilSecretKeyRing();
        PGPPublicKeyRing publicKeys = TestKeys.getEmilPublicKeyRing();
        KeyRingInfo sInfo = PGPainless.inspectKeyRing(secretKeys);
        KeyRingInfo pInfo = PGPainless.inspectKeyRing(publicKeys);

        assertEquals(TestKeys.EMIL_KEY_ID, sInfo.getKeyId());
        assertEquals(TestKeys.EMIL_KEY_ID, pInfo.getKeyId());
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
        assertEquals(4, sInfo.getVersion());
        assertEquals(4, pInfo.getVersion());

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
        PGPSecretKeyRing revoked = PGPainless.modifyKeyRing(secretKeys).revoke(new UnprotectedKeysProtector()).done();
        KeyRingInfo rInfo = PGPainless.inspectKeyRing(revoked);
        assertNotNull(rInfo.getRevocationDate());
        assertEquals(revocationDate.getTime(), rInfo.getRevocationDate().getTime(), 5);
        assertEquals(revocationDate.getTime(), rInfo.getLastModified().getTime(), 5);

        assertFalse(pInfo.isKeyValidlyBound(1230));
        assertFalse(sInfo.isKeyValidlyBound(1230));
    }

    @Test
    public void testIsFullyDecrypted() throws IOException, PGPException {
        PGPSecretKeyRing secretKeys = TestKeys.getEmilSecretKeyRing();
        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);

        assertTrue(info.isFullyDecrypted());

        secretKeys = encryptSecretKeys(secretKeys);
        info = PGPainless.inspectKeyRing(secretKeys);

        assertFalse(info.isFullyDecrypted());
    }

    @Test
    public void testIsFullyEncrypted() throws IOException, PGPException {
        PGPSecretKeyRing secretKeys = TestKeys.getEmilSecretKeyRing();
        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);

        assertFalse(info.isFullyEncrypted());

        secretKeys = encryptSecretKeys(secretKeys);
        info = PGPainless.inspectKeyRing(secretKeys);

        assertTrue(info.isFullyEncrypted());
    }

    private static PGPSecretKeyRing encryptSecretKeys(PGPSecretKeyRing secretKeys) throws PGPException {
        return PGPainless.modifyKeyRing(secretKeys)
                .changePassphraseFromOldPassphrase(null)
                .withSecureDefaultSettings()
                .toNewPassphrase(Passphrase.fromPassword("sw0rdf1sh"))
                .done();
    }


    @Test
    public void testGetSecretKey() throws IOException, PGPException {
        PGPSecretKeyRing secretKeys = TestKeys.getCryptieSecretKeyRing();
        PGPPublicKeyRing publicKeys = KeyRingUtils.publicKeyRingFrom(secretKeys);

        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);
        assertEquals(KeyRingUtils.requirePrimarySecretKeyFrom(secretKeys), info.getSecretKey());

        info = PGPainless.inspectKeyRing(publicKeys);
        assertNull(info.getSecretKey());
    }

    @Test
    public void testGetPublicKey() throws IOException, PGPException {
        PGPSecretKeyRing secretKeys = TestKeys.getCryptieSecretKeyRing();

        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);
        assertEquals(KeyRingUtils.requirePrimaryPublicKeyFrom(secretKeys), info.getPublicKey());

        assertEquals(KeyRingUtils.requirePrimarySecretKeyFrom(secretKeys),
                KeyRingUtils.requireSecretKeyFrom(secretKeys, secretKeys.getPublicKey().getKeyID()));
    }

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestImplementationFactoryProvider#provideImplementationFactories")
    public void dummyS2KTest(ImplementationFactory implementationFactory) throws PGPException, IOException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);

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

        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(withDummyS2K);
        assertTrue(new KeyInfo(secretKeys.getSecretKey()).hasDummyS2K());
    }

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestImplementationFactoryProvider#provideImplementationFactories")
    public void testGetKeysWithFlagsAndExpiry(ImplementationFactory implementationFactory) throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);

        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .setPrimaryKey(KeySpec.getBuilder(
                KeyType.EDDSA(EdDSACurve._Ed25519), KeyFlag.CERTIFY_OTHER))
                .addSubkey(KeySpec.getBuilder(
                        KeyType.ECDH(EllipticCurve._BRAINPOOLP384R1),
                        KeyFlag.ENCRYPT_STORAGE))
                .addSubkey(KeySpec.getBuilder(
                        KeyType.ECDSA(EllipticCurve._BRAINPOOLP384R1), KeyFlag.SIGN_DATA))
                .addUserId(UserId.newBuilder().withName("Alice").withEmail("alice@pgpainless.org").build())
                .build();

        Iterator<PGPSecretKey> keys = secretKeys.iterator();
        Date now = DateUtil.now();

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(now);
        calendar.add(Calendar.DATE, 5);
        Date primaryKeyExpiration = calendar.getTime(); // in 5 days
        PGPSecretKey primaryKey = keys.next();

        calendar.setTime(now);
        calendar.add(Calendar.DATE, 10);
        Date encryptionKeyExpiration = calendar.getTime(); // in 10 days
        PGPSecretKey encryptionKey = keys.next();

        calendar.setTime(now);
        calendar.add(Calendar.DATE, 3);
        Date signingKeyExpiration = calendar.getTime(); // in 3 days
        PGPSecretKey signingKey = keys.next();

        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();
        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .setExpirationDate(new OpenPgpV4Fingerprint(primaryKey), primaryKeyExpiration, protector)
                .setExpirationDate(new OpenPgpV4Fingerprint(encryptionKey), encryptionKeyExpiration, protector)
                .setExpirationDate(new OpenPgpV4Fingerprint(signingKey), signingKeyExpiration, protector)
                .done();

        KeyRingInfo info = new KeyRingInfo(secretKeys);

        List<PGPPublicKey> encryptionKeys = info.getKeysWithKeyFlag(KeyFlag.ENCRYPT_STORAGE);
        assertEquals(1, encryptionKeys.size());
        assertEquals(encryptionKey.getKeyID(), encryptionKeys.get(0).getKeyID());

        List<PGPPublicKey> signingKeys = info.getKeysWithKeyFlag(KeyFlag.SIGN_DATA);
        assertEquals(1, signingKeys.size());
        assertEquals(signingKey.getKeyID(), signingKeys.get(0).getKeyID());

        List<PGPPublicKey> certKeys = info.getKeysWithKeyFlag(KeyFlag.CERTIFY_OTHER);
        assertEquals(1, certKeys.size());
        assertEquals(primaryKey.getKeyID(), certKeys.get(0).getKeyID());

        assertEquals(primaryKeyExpiration.getTime(), info.getPrimaryKeyExpirationDate().getTime(), 5);
        assertEquals(signingKeyExpiration.getTime(), info.getExpirationDateForUse(KeyFlag.SIGN_DATA).getTime(), 5);

        // Encryption key expires after primary key, so we return primary key expiration instead.
        assertEquals(primaryKeyExpiration.getTime(), info.getExpirationDateForUse(KeyFlag.ENCRYPT_STORAGE).getTime(), 5);

    }
}
