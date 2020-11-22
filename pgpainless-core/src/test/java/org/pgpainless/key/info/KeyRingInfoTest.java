/*
 * Copyright 2020 Paul Schaub.
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
import java.util.Collections;
import java.util.Date;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.protection.UnprotectedKeysProtector;

public class KeyRingInfoTest {

    @Test
    public void testWithEmilsKeys() throws IOException, PGPException {
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

        assertEquals(2, sInfo.getPublicKeys().size());
        assertEquals(2, pInfo.getPublicKeys().size());

        assertEquals(Collections.singletonList("<emil@email.user>"), sInfo.getUserIds());
        assertEquals(Collections.singletonList("<emil@email.user>"), pInfo.getUserIds());
        assertEquals(Collections.singletonList("emil@email.user"), sInfo.getEmailAddresses());
        assertEquals(Collections.singletonList("emil@email.user"), pInfo.getEmailAddresses());

        assertTrue(sInfo.isSecretKey());
        assertFalse(pInfo.isSecretKey());
        assertTrue(sInfo.isFullyDecrypted());
        assertTrue(pInfo.isFullyDecrypted());

        assertEquals(TestKeys.EMIL_CREATION_DATE, sInfo.getCreationDate());
        assertEquals(TestKeys.EMIL_CREATION_DATE, pInfo.getCreationDate());
        assertNull(sInfo.getExpirationDate());
        assertNull(pInfo.getExpirationDate());
        assertEquals(TestKeys.EMIL_CREATION_DATE.getTime(), sInfo.getLastModified().getTime(), 50);
        assertEquals(TestKeys.EMIL_CREATION_DATE.getTime(), pInfo.getLastModified().getTime(), 50);

        assertNull(sInfo.getRevocationDate());
        assertNull(pInfo.getRevocationDate());
        Date revocationDate = new Date();
        PGPSecretKeyRing revoked = PGPainless.modifyKeyRing(secretKeys).revoke(new UnprotectedKeysProtector()).done();
        KeyRingInfo rInfo = PGPainless.inspectKeyRing(revoked);
        assertNotNull(rInfo.getRevocationDate());
        assertEquals(revocationDate.getTime(), rInfo.getRevocationDate().getTime(), 1000);
        assertEquals(revocationDate.getTime(), rInfo.getLastModified().getTime(), 1000);
    }
}
